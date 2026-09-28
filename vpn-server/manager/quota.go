package manager

// vpn-server/manager/quota.go
//
// ⭐ P3 补丁：**中继配额的运行期复查**（既有洞修复，独立于 P2SP 1b-2）。
//
// 背景（设计 1b-2 时查证出来的既有问题）：
//   - `User.MaxBytes` 的检查**全仓只有一处**：认证时（`quic/authenticator.go`）；
//   - 唯一的运行期踢人入口 `Kick`/`kickAll` 只被**管理员操作**调用；
//   ⇒ 一个已建立的会话只要不重连，就可以**无限超用配额**——面板数字一直涨，
//     但没有任何机制会去断开它。
//
// 本文件补上运行期复查：每 `quotaCheckInterval` 扫一遍**在线账号**，
// `UsedBytes >= MaxBytes`（且 `MaxBytes > 0`）→ 踢掉该账号的全部连接。
//
// 语义与认证时**逐字一致**：
//   - 判据是 `>=`（不是 `>`），且 `MaxBytes == 0` 表示不限；
//   - 账号级：同一账号被多客户端共用时共用一个配额，超限**一次踢掉全部连接**。
//
// ⚠️ 与 P2SP 的关系：直连（1b-2）流量不经过服务端，本文件管不到它——
// 这与 1b-2 定稿的「配额 = 中继流量配额」语义一致（见 `P2SP-阶段1b-2-设计文档.md` §7.4）。

import (
	"log"
	"sort"
	"time"
)

// defaultQuotaCheckInterval 运行期配额复查周期。
//
// 超限最多被容忍这么久（默认 60s）——这是「及时踢人」与「零开销」之间的折中：
//   - 更短：踢得更及时，但每秒都在扫在线列表（收益很小）；
//   - 更长：超用窗口更大。
//
// ⚠️ 它**不决定计量精度**：`UsedBytes` 是随转发实时累加的（`data_server.recordTraffic`），
// 本周期只决定「多久检查一次是否该踢」。
const defaultQuotaCheckInterval = 60 * time.Second

// quotaState 一个账号的配额快照。
//
// ⚠️ `store.Get` 返回的是**副本**，所以这里读 `UsedBytes/MaxBytes` 不会与计费竞争。
type quotaState struct {
	Used  uint64
	Max   uint64 // 0 = 不限
	Known bool   // 账号是否存在
}

// OverQuota 是否已用尽。
//
// ⭐ 必须与认证时的判定保持一致（`authenticator.go`）：
// `user.MaxBytes > 0 && user.UsedBytes >= user.MaxBytes`。
// 两处判据不一致会出现「运行期猛踢、重连又能进」或者「重连被拒、运行期不踢」的怪象。
func (q quotaState) OverQuota() bool {
	return q.Known && q.Max > 0 && q.Used >= q.Max
}

// kickOverQuota 对给定的在线账号做一次配额判定，踢掉超限者并返回被踢账号（字典序）。
//
// 所有外部依赖（配额查询 / 踢人 / 日志）都**注入**，因此可以脱离网络与 Manager 单测。
// 单个账号踢失败不影响其它账号（不中断、不 panic）。
func kickOverQuota(
	usernames []string,
	quota func(string) quotaState,
	kick func(string) error,
	logf func(format string, args ...any),
) []string {
	if len(usernames) == 0 {
		return nil
	}

	// 去重 + 排序：同一账号可能有多条连接（多次出现），排序让日志与测试可复现。
	seen := make(map[string]struct{}, len(usernames))
	uniq := make([]string, 0, len(usernames))
	for _, u := range usernames {
		if u == "" {
			continue
		}
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		uniq = append(uniq, u)
	}
	sort.Strings(uniq)

	var kicked []string
	for _, u := range uniq {
		q := quota(u)
		if !q.OverQuota() {
			continue
		}
		if err := kick(u); err != nil {
			// 最常见的原因是「它刚好自己断开了」——不必当错误刷屏。
			logf("ℹ️ [配额] 断开 %s 未生效（可能已自行断开）: %v", u, err)
			continue
		}
		logf("🚫 [配额] 用户 %s 流量已用尽（%d/%d 字节），已断开其全部连接", u, q.Used, q.Max)
		kicked = append(kicked, u)
	}
	return kicked
}

// onlineUsernames 当前在线的账号列表（同一账号多连接会重复出现，kickOverQuota 会去重）。
//
// 来源是 adminState 的在线表（每个数据面连接在注册时 OnConnect，key 是 VIP）。
func (m *Manager) onlineUsernames() []string {
	if m.adminState == nil {
		return nil
	}
	snap := m.adminState.Snapshot()
	out := make([]string, 0, len(snap.Clients))
	for _, c := range snap.Clients {
		if c != nil && c.Username != "" {
			out = append(out, c.Username)
		}
	}
	return out
}

// userQuota 读某个账号的配额快照（账号不存在时 Known=false）
func (m *Manager) userQuota(username string) quotaState {
	if m.userStore == nil {
		return quotaState{}
	}
	u, ok := m.userStore.Get(username)
	if !ok || u == nil {
		return quotaState{}
	}
	return quotaState{Used: u.UsedBytes, Max: u.MaxBytes, Known: true}
}

// checkQuotaOnce 执行一次复查，返回被踢账号（供测试与调用方记录）。
func (m *Manager) checkQuotaOnce() []string {
	return kickOverQuota(m.onlineUsernames(), m.userQuota, m.Kick, log.Printf)
}

// startQuotaWatchdog 启动运行期复查（幂等：已启动时直接返回）。
func (m *Manager) startQuotaWatchdog() {
	m.mu.Lock()
	if m.quotaStop != nil {
		m.mu.Unlock()
		return
	}
	interval := m.quotaInterval
	if interval <= 0 {
		interval = defaultQuotaCheckInterval
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	m.quotaStop, m.quotaDone = stop, done
	m.mu.Unlock()

	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				m.checkQuotaOnce()
			}
		}
	}()

	log.Printf("⏱️ [配额] 运行期复查已启动（每 %v 检查一次在线账号的中继流量）", interval)
}

// stopQuotaWatchdog 停止复查并等它退出（幂等；未启动时安全）。
//
// ⚠️ 必须先 `close(stop)` 再 `<-done`，且**不能持有 m.mu 等 done**：
// 复查 goroutine 会经 m.Kick 去拿 m.mu.RLock，持锁等待会死锁。
func (m *Manager) stopQuotaWatchdog() {
	m.mu.Lock()
	stop, done := m.quotaStop, m.quotaDone
	m.quotaStop, m.quotaDone = nil, nil
	m.mu.Unlock()

	if stop == nil {
		return
	}
	close(stop)
	<-done
	log.Printf("⏱️ [配额] 运行期复查已停止")
}
