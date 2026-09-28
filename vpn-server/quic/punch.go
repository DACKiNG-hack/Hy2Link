package quic

// vpn-server/quic/punch.go
//
// P2SP 阶段 1b-1：**服务端侧的打洞协调**。
//
// 职责边界（刻意做窄）：
//   - 只做「协调」：校验、限流、把 A 的意图转成对 B 的邀请、把 B 的就绪转给 A；
//   - **不参与打洞、不碰 UDP**：打洞是两端客户端之间的事（realm.Punch），
//     服务端只在信令面上牵线。这样服务端不新增任何监听面。
//
// 状态生命周期：attempt 记录有 TTL（45s，略大于客户端 40s 预算），
// 由**独立 5s ticker** 清理（不用 signalCleanupInterval 的 1 分钟粒度 ——
// attempt 是秒级对象，用分钟粒度会让死记录堆积并污染限流判断）。
//
// 与 admin.SignalRegistry 的关系：**不共享状态**。登记表管「谁能被推送」，
// 本文件管「谁在跟谁打洞」。推送出口仍走 DataChannelServer.PushSignal。

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"vpn-server/admin"
)

const (
	// punchAttemptTTL attempt 记录寿命：客户端预算 40s + 5s 余量
	punchAttemptTTL = 45 * time.Second
	// punchAttemptCleanup 清理周期（独立 ticker，见文件头）
	punchAttemptCleanup = 5 * time.Second
	// punchPairCooldown 同一对 (A,B) 两次协调之间的最小间隔
	punchPairCooldown = 10 * time.Second
	// punchRateLimit / punchRateWindow 发起方滑动窗口限流：5 次 / 分钟
	punchRateLimit  = 5
	punchRateWindow = time.Minute
	// relayMaxResponderInvites 服务端侧的「响应方并发上限」镜像（⭐ 1b-2B）。
	//
	// ⚠️ 必须与客户端常量 `punchMaxResponder`（vpn-tool/backend/quic/punch.go）保持一致：
	// 客户端是「被动忽略多余邀请」，服务端是「提前拒绝并告知发起方忙」——
	// 两者依据必须是同一个数字，否则会出现「服务端说忙但客户端其实空闲」或反之。
	// 客户端测试 `TestPunchMaxResponderMatchesServerMirror` 会盯住这个一致性（见交付说明）。
	relayMaxResponderInvites = 2
)

// punchAttempt 一次打洞协调的记录
type punchAttempt struct {
	id         string
	initiator  string // A 的 VIP
	responder  string // B 的 VIP
	windowMs   int
	createdAt  time.Time
	peerReady  bool // 是否收到过 punch-ready
	peerPushed bool // punch-peer 是否已推给 A（重复 ready 幂等靠它）
}

// punchTable 打洞协调表（并发安全）
type punchTable struct {
	mu       sync.Mutex
	attempts map[string]*punchAttempt
	byPair   map[string]time.Time   // "A|B" → 最近协调时刻（冷却）
	rate     map[string][]time.Time // VIP → 最近的 intent 时刻（滑动窗口）
	now      func() time.Time       // 可注入，便于测试
	stop     chan struct{}
	stopOnce sync.Once
}

func newPunchTable() *punchTable {
	t := &punchTable{
		attempts: make(map[string]*punchAttempt),
		byPair:   make(map[string]time.Time),
		rate:     make(map[string][]time.Time),
		now:      time.Now,
		stop:     make(chan struct{}),
	}
	go t.cleanupLoop()
	return t
}

// close 停止清理 goroutine（幂等）
func (t *punchTable) close() {
	t.stopOnce.Do(func() { close(t.stop) })
}

func (t *punchTable) cleanupLoop() {
	ticker := time.NewTicker(punchAttemptCleanup)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			t.cleanup()
		}
	}
}

// cleanup 删除过期 attempt / 冷却 / 限流记录
func (t *punchTable) cleanup() {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	removed := 0
	for id, a := range t.attempts {
		if now.Sub(a.createdAt) > punchAttemptTTL {
			delete(t.attempts, id)
			removed++
		}
	}
	for k, at := range t.byPair {
		if now.Sub(at) > punchAttemptTTL {
			delete(t.byPair, k)
		}
	}
	for vip, times := range t.rate {
		kept := times[:0:0]
		for _, at := range times {
			if now.Sub(at) <= punchRateWindow {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(t.rate, vip)
		} else {
			t.rate[vip] = kept
		}
	}
	if removed > 0 {
		log.Printf("🧹 [打洞] 清理 %d 条过期协调记录，剩余 %d 条", removed, len(t.attempts))
	}
}

// count 当前活跃协调记录数（监控/测试用）
func (t *punchTable) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.attempts)
}

// start 建立一次协调（含滑动窗口限流 + 每对唯一的检查）。
//
// ⭐ attemptId 由**发起方 A 生成**（设计 §2.2），服务端只做格式校验与查重：
// 用 A 的 ID 当表主键，A 自己的会话、B 在 invite 里看到的 ID、以及 B 回传的
// punch-ready 全都指向同一个值，链路最直。故意重复使用别人的 ID 会被拒。
//
// ⭐⭐ **同一 attemptId 的重复 intent 是幂等的**（existing=true）：
// A 的 intent 有重试（上限 2 次尝试），而重试复用同一个 attemptId ——
// 如果这里回 attempt-exists，重试必然失败，还会把一个**服务端已经建立、
// 邀请可能已经推给 B** 的 attempt 判成失败（真踩过一次）。
// 所以：ID 已存在且**发起方/响应方都一致**且未过期 → 返回既有记录，不重复计数；
// 只有「ID 相同但对端不同」（ID 盗用/碰撞）才回 attempt-exists。
//
// 返回的 error 文本是**稳定原因串**，会原样进 error 消息给客户端（便于 UI 归类）：
//
//	rate-limited    发起方 1 分钟内超过 5 次
//	pair-cooldown   同一对 10 秒内重复发起
//	pair-busy       同一对已有活跃 attempt
//	attempt-exists  该 attemptId 已被**别的对**占用
func (t *punchTable) start(initiator, responder, attemptID string, windowMs int) (a *punchAttempt, existing bool, err error) {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	// ① 幂等：同一 attemptId + 同一对 → 复用既有记录（重试走这条）
	if cur, dup := t.attempts[attemptID]; dup {
		if now.Sub(cur.createdAt) > punchAttemptTTL {
			delete(t.attempts, attemptID)
		} else if cur.initiator == initiator && cur.responder == responder {
			return cur, true, nil
		} else {
			return nil, false, fmt.Errorf("attempt-exists")
		}
	}

	// 滑动窗口限流
	kept := t.rate[initiator][:0:0]
	for _, at := range t.rate[initiator] {
		if now.Sub(at) <= punchRateWindow {
			kept = append(kept, at)
		}
	}
	if len(kept) >= punchRateLimit {
		t.rate[initiator] = kept
		return nil, false, fmt.Errorf("rate-limited")
	}

	pairKey := initiator + "|" + responder
	if at, ok := t.byPair[pairKey]; ok && now.Sub(at) <= punchPairCooldown {
		t.rate[initiator] = kept
		return nil, false, fmt.Errorf("pair-cooldown")
	}
	for _, cur := range t.attempts {
		if cur.initiator == initiator && cur.responder == responder {
			t.rate[initiator] = kept
			return nil, false, fmt.Errorf("pair-busy")
		}
	}

	a = &punchAttempt{
		id:        attemptID,
		initiator: initiator,
		responder: responder,
		windowMs:  windowMs,
		createdAt: now,
	}
	t.attempts[attemptID] = a
	t.byPair[pairKey] = now
	t.rate[initiator] = append(kept, now)
	return a, false, nil
}

// activeResponderCount 该 VIP 目前有多少个**活跃**（未过 TTL）的 attempt 作为响应方。
//
// ⭐ 1b-2B：用于「响应方忙」判定。用活跃 attempt（而不是「未 ready 的 attempt」）是因为
// 客户端响应方会话从接受邀请起就占用配额，直到预算（40s）耗尽；attempt TTL（45s）覆盖它。
func (t *punchTable) activeResponderCount(responder string) int {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, a := range t.attempts {
		if a.responder == responder && now.Sub(a.createdAt) <= punchAttemptTTL {
			n++
		}
	}
	return n
}

// markReady 记录 B 的就绪。返回 (attempt, 是否是第一次推送 punch-peer, 是否找到)。
//
// ⭐ 幂等：同一 attemptId 的重复 punch-ready 只推送一次 punch-peer（其余仍回 peer）。
func (t *punchTable) markReady(id, initiator, responder string) (a *punchAttempt, first bool, ok bool) {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	a, ok = t.attempts[id]
	if !ok || a.initiator != initiator || a.responder != responder {
		return nil, false, false
	}
	if now.Sub(a.createdAt) > punchAttemptTTL {
		delete(t.attempts, id)
		return nil, false, false
	}
	a.peerReady = true
	first = !a.peerPushed
	a.peerPushed = true
	return a, first, true
}

// drop 删除一条协调记录（推送失败等回滚用）
func (t *punchTable) drop(id string) {
	t.mu.Lock()
	delete(t.attempts, id)
	t.mu.Unlock()
}

// dropByVIP 删除与某个 VIP 相关的**全部**协调记录（它作为发起方或响应方都删），返回删除条数。
//
// ⭐ 为什么需要它（真机反馈的 bug，1b-2B.2）：
// 协调记录原本**只靠 TTL(45s) 过期**，客户端断连/掉线时服务端不清理。而 peer-busy 的判据是
//
//	activeResponderCount(peerVIP) >= relayMaxResponderInvites(2)   // 「活跃」= 未过 TTL
//
// 也就是**记在响应方头上**。于是：
//   - 发起方掉线后，它留下的记录仍占着**对端**的名额 ⇒ 45s 内**任何**客户端打那个对端
//     都可能被误判「对端忙」（附带损伤，与掉线者是否重连无关）；
//   - 重连后立刻再打同一对端，也容易被自己的残留误判（用户报的场景）；
//   - 打洞**成功**的记录同样留满 45s（客户端没有「完成通知」），多次尝试会累积。
//
// ⚠️ 调用点必须放在 `unregisterData` 返回 true 的分支里（见 data_server.go 的 defer）：
// 它内部的 `cur != cs` 检查是**重连竞态的防线** —— 旧连接的 defer 跑时新连接可能已注册，
// 无条件删会把新会话的 attempt 误删。
func (t *punchTable) dropByVIP(vip string) int {
	if vip == "" {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	removed := 0
	for id, a := range t.attempts {
		if a.initiator == vip || a.responder == vip {
			delete(t.attempts, id)
			removed++
		}
	}
	return removed
}

// ---------- 信令处理（请求入口） ----------

// punchErr 造一条 error 应答
func punchErr(err error) signalMessage {
	return signalMessage{Type: signalMsgTypeError, Error: err.Error()}
}

// handlePunchIntent 处理 A 的协调请求：
//
//	校验 → 限流 → 建 attempt → 推 punch-invite 给 B → 复用 signalReply 回 peer 给 A
//
// ⭐ punch-intent 是 register 的**超集**：它同样带 publicAddr/natType/metadata，
// 所以这里可以直接复用 signalReply（既回答对端信息，又刷新 A 的登记条目）。
func (s *DataChannelServer) handlePunchIntent(sink signalWriter, cs *clientStream, msg *signalMessage) error {
	if cs == nil || cs.vip == "" {
		return sink.writeMessage(punchErr(fmt.Errorf("no client identity")))
	}
	pt := s.punchTable()
	if pt == nil {
		return sink.writeMessage(punchErr(fmt.Errorf("p2p disabled")))
	}

	peerVIP := strings.TrimSpace(msg.PeerVIP)
	if peerVIP == "" {
		return sink.writeMessage(punchErr(fmt.Errorf("peerVIP required")))
	}
	if peerVIP == cs.vip {
		return sink.writeMessage(punchErr(fmt.Errorf("cannot punch self")))
	}
	if err := admin.ValidatePunchAttemptID(msg.AttemptID); err != nil {
		return sink.writeMessage(punchErr(err))
	}
	if err := admin.ValidatePunchAddr(msg.PunchAddr, false); err != nil {
		return sink.writeMessage(punchErr(err))
	}
	// ⭐ 1b-3（A1）：候选列表校验（同 IP + 数量上限 + 防反射放大）。
	//    锚 = punchAddr 的 IP（A1 阶段只能保证「自报之间一致」；A2 会换成服务端观测值）。
	if err := admin.ValidatePunchAddrs(msg.PunchAddrs, punchAddrIP(msg.PunchAddr)); err != nil {
		return sink.writeMessage(punchErr(err))
	}
	if err := admin.ValidateDirectFingerprint(msg.DirectFingerprint); err != nil {
		return sink.writeMessage(punchErr(err))
	}
	window := admin.ClampPunchWindowMs(msg.WindowMs)

	// ⭐ 先校验「自己的登记字段」（intent 是 register 的超集）——
	// 必须在**建 attempt 之前**做，否则非法字段会在表里留下一条死记录（并污染限流）
	if err := validateSignalSelfFields(msg.PublicAddr, msg.NATType, msg.Metadata); err != nil {
		return sink.writeMessage(punchErr(err))
	}

	// 对端必须在数据面上（否则既没有地址也推不过去）
	if _, online := s.lookupVIP(peerVIP); !online {
		return sink.writeMessage(punchErr(fmt.Errorf("peer-unreachable")))
	}

	// ⭐ 1b-2B：响应方已满 → 立即告知发起方「忙」，不要让它白等 40s。
	//
	// 判定：该响应方**活跃 attempt 数** ≥ relayMaxResponderInvites。
	// 这与响应方客户端自己的 punchMaxResponder=2 语义等价 —— 那些 invite 都是本服务端推的，
	// 且 attempt 的寿命（TTL 45s）覆盖客户端响应方会话的生命周期（预算 40s）。
	if pt.activeResponderCount(peerVIP) >= relayMaxResponderInvites {
		// ① 推送（用户要求的语义）：A 收到就立即收工
		busy := signalMessage{Type: signalMsgTypePunchBusy, AttemptID: msg.AttemptID, PeerVIP: peerVIP}
		if perr := s.PushSignal(cs.vip, busy); perr != nil {
			log.Printf("ℹ️ [打洞] peer-busy 推送失败（%s）：%v（下面的 error 应答仍会让它立即失败）",
				cs.vip, perr)
		}
		// ② 同时在**应答**里回 peer-busy：推送丢了也不会退化成「等 40s 超时」
		log.Printf("ℹ️ [打洞] %s 已满（%d 个活跃 attempt），拒绝 %s 的 intent（attempt=%s）",
			peerVIP, pt.activeResponderCount(peerVIP), cs.vip, msg.AttemptID)
		return sink.writeMessage(punchErr(fmt.Errorf("peer-busy")))
	}

	a, existing, err := pt.start(cs.vip, peerVIP, msg.AttemptID, window)
	if err != nil {
		return sink.writeMessage(punchErr(err))
	}
	if existing {
		// ⭐ 幂等重试：不改任何状态，**重新推一次 invite** ——
		// 上一次的邀请可能正是在「响应丢失」的那次里丢的；
		// B 侧按 attemptId 去重，重复邀请不会造成重复打洞。
		log.Printf("ℹ️ [打洞] 重复 intent（同一 attemptId=%s），幂等处理并重推邀请", a.id)
	}

	invite := signalMessage{
		Type:              signalMsgTypePunchInvite,
		AttemptID:         a.id,
		PeerVIP:           cs.vip,
		PunchAddr:         msg.PunchAddr,
		PunchAddrs:        msg.PunchAddrs, // ⭐ 1b-3：候选列表原样转达给响应方
		NATType:           msg.NATType,
		Metadata:          msg.Metadata,
		DirectFingerprint: msg.DirectFingerprint,
		WindowMs:          window,
	}
	if err := s.PushSignal(peerVIP, invite); err != nil {
		// 推不过去（对端没有 sink / P2P 关了 / 流断了）→ 回滚，不留下死记录
		pt.drop(a.id)
		log.Printf("⚠️ [打洞] 邀请推送失败 %s→%s: %v", cs.vip, peerVIP, err)
		return sink.writeMessage(punchErr(fmt.Errorf("peer-not-ready")))
	}

	log.Printf("📡 [打洞] 协调建立 %s→%s attempt=%s window=%dms", cs.vip, peerVIP, a.id, window)
	// 应答复用 signalReply：A 拿到 B 的 publicAddr/natType/metadata + peerOnline/peerSignalReady
	return sink.writeMessage(s.signalReply(cs, msg))
}

// punchAddrIP 取 punchAddr 的 IP 部分（用于 punchAddrs 的「同 IP」锚定校验）。
//
// 空串/非法 → 返回空串（此时 ValidatePunchAddrs 只做同 IP 自洽检查，不做锚定）。
func punchAddrIP(punchAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(punchAddr))
	if err != nil {
		return ""
	}
	return host
}

// handlePunchReady 处理 B 的就绪回报：
//
//	校验 attempt → （首次）推 punch-peer 给 A → 复用 signalReply 回 peer 给 B
func (s *DataChannelServer) handlePunchReady(sink signalWriter, cs *clientStream, msg *signalMessage) error {
	if cs == nil || cs.vip == "" {
		return sink.writeMessage(punchErr(fmt.Errorf("no client identity")))
	}
	pt := s.punchTable()
	if pt == nil {
		return sink.writeMessage(punchErr(fmt.Errorf("p2p disabled")))
	}

	initiatorVIP := strings.TrimSpace(msg.PeerVIP)
	if initiatorVIP == "" {
		return sink.writeMessage(punchErr(fmt.Errorf("peerVIP required")))
	}
	if err := admin.ValidatePunchAttemptID(msg.AttemptID); err != nil {
		return sink.writeMessage(punchErr(err))
	}
	// punchAddr 允许为空：显式表示「我无法广告打洞地址」（A 侧据此立即收工）
	if err := admin.ValidatePunchAddr(msg.PunchAddr, true); err != nil {
		return sink.writeMessage(punchErr(err))
	}
	// ⭐ 1b-3（A1）：候选列表校验（与 intent 同规则）
	if err := admin.ValidatePunchAddrs(msg.PunchAddrs, punchAddrIP(msg.PunchAddr)); err != nil {
		return sink.writeMessage(punchErr(err))
	}
	// 同 intent：先校验自己的登记字段，避免留下死记录
	if err := validateSignalSelfFields(msg.PublicAddr, msg.NATType, msg.Metadata); err != nil {
		return sink.writeMessage(punchErr(err))
	}

	a, first, ok := pt.markReady(msg.AttemptID, initiatorVIP, cs.vip)
	if !ok {
		return sink.writeMessage(punchErr(fmt.Errorf("unknown-attempt")))
	}

	if first {
		push := signalMessage{
			Type:       signalMsgTypePunchPeer,
			AttemptID:  a.id,
			PeerVIP:    cs.vip,
			PunchAddr:  msg.PunchAddr,
			PunchAddrs: msg.PunchAddrs, // ⭐ 1b-3：B 的候选列表转达给 A
			// ⭐ 1b-3（2.3）：B 的直连指纹转达给 A → A 作为 listener 也固定 B（双向固定）。
			//   旧客户端不发 ⇒ 为空 ⇒ A 退回单向固定（等价 1b-1）。
			DirectFingerprint: msg.DirectFingerprint,
			NATType:           msg.NATType,
			WindowMs:          a.windowMs,
		}
		if err := s.PushSignal(initiatorVIP, push); err != nil {
			// A 收不到会走超时回落；这里只记日志（不回滚，B 已就绪的事实保留）
			log.Printf("⚠️ [打洞] 就绪推送失败 %s→%s: %v", cs.vip, initiatorVIP, err)
		} else {
			log.Printf("📡 [打洞] %s 已就绪，已通知 %s attempt=%s punchAddr=%q",
				cs.vip, initiatorVIP, a.id, msg.PunchAddr)
		}
	}

	return sink.writeMessage(s.signalReply(cs, msg))
}
