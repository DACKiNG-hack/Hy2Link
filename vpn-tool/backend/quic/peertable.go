package quic

// vpn-tool/backend/quic/peertable.go
//
// ⭐ P2SP 1b-4 第 2 步-A：**对端质量表**（内存 + 进程内 TTL，**不落盘**）。
//
// 依据：`P2SP-阶段1b-4-三件套-范围与拍板记录.md` §2（质量表）+ 实施计划 v5。
//
//	键 = 对端 VIP；值 = {结果类型, 原因码, RTT, 丢包, 观测时刻, 过期时刻, 强制重试标记}
//	三档：质量好 / 质量差 / 不可打洞
//	TTL：好/差 30~60min；不可打洞 10~30min（nat-symmetric 取长、punch-timeout 取短）
//
// 三条拍板约束（本文件的硬契约）：
//  1. **内存 + 进程内 TTL，不落盘**；
//  2. **重连不清空** ⇒ 表的唯一 `new` 点是 `NewHysteria2Client`（见 client.go）；
//     `punchManager` / `pathManager` 只持同一实例的引用（它们每次连接都会重建）；
//  3. **TTL 不延长** ⇒ 写入**同一结论**时不重置过期时刻（避免「一直有流量 ⇒ 坏记录永生」）；
//     只有**结论变了**才重算 TTL（并清零强制重试标记）。
//
// 并发与生命周期设计（对应实施计划 §4.1.1 的窗口扫描表 W-1~W-8）：
//   - 所有读写都在同一个 `mu` 临界区内；**没有**「锁外判定 + 锁内动作」的分离（W-7/W-8）；
//   - `TryConsumeForcedRetry` 把「检查 + 置位」合成**一个原子动作**（W-1：否则并发触发会多次放行）；
//   - `Lookup` **不删除**过期记录（只判「过期即 miss」），删除只发生在惰性 `pruneLocked`
//     ⇒ 判定与动作解耦（W-5 无窗口）；
//   - **零新 goroutine**：清理是惰性的（`Record`/`Lookup` 内按计数节流），
//     以保住边界五项第 5 项「无新增监听面 / goroutine」。
//
// ⚠️ 时钟字段 `now` 的时序契约：它是**普通函数字段**（不是原子量），
// 因此 `setClock` 必须在表被并发使用**之前**调用（测试里 = new 之后、注入管理器之前）。
// 生产从不调用 `setClock` ⇒ 恒为 `time.Now`。这与 `pathManager` 的可注入参数同一条契约。

import (
	"sync"
	"time"
)

// ⚠️ **A3a（2026-09-28）后本表的消费者分布 —— 注意：不是「整表无消费者」**：
//
//	· **仍在生产路径上**：
//	  - `Record`（每次 attempt 收尾写入）—— `punch.go` 的 `attemptFor`/收尾路径；
//	  - `Unpunchable` —— `path.go` 的 `offerForcedRetry`：**流量驱动的「强制重试提议」**，
//	    与预打洞**无关**（`Unpunchable` 内部走 `Lookup`，故 `Lookup` 亦间接在用）。
//	· **已无生产消费者**：**`Peek` 的「排优先级」用途**（按 `LastTouch` 排序）——
//	  其唯一调用者是预打洞的 `prePunchCandidates`，随 A3a 删除预打洞发起侧而消失。
//	⇒ **本表整体保留**（**不是死代码**）；只有「排优先级」这一项暂时无调用者。
//	  是否进一步简化 ⇒ **A3b** 评估（与 B1 灰度期启发式一并处理）。
//	📌 试用期**不用**本表（A1 定稿：试用期只看常量与实测样本）⇒ 与 A2 的判负/复用**无关**。

// peerResultKind 上次观测到的**结论**（决定「怎么用它」，不是「原因是什么」）
type peerResultKind int

const (
	// peerGood 质量好
	//
	//	⚠️ 2026-09-28 更正：原注释写「**真正打洞时试用期缩短为 5s / 2 样本**」——该叙述**已作废**：
	//	A1 已删除 `trialWindowShort`，两档 `need` 同为 2、窗口在生产参数下同为 15s
	//	⇒ **质量表命中不再带来任何试用期收益**（见 A1 交付说明 §2 与 `path.go` 的试用期参数口径表）。
	peerGood peerResultKind = iota + 1
	// peerPoor 质量差（通但差）⇒ 预打洞**降优先级但不跳过**（用户拍板：不跳过）
	//
	//	⚠️ A3a 后：该"降优先级"用途随预打洞发起侧删除而**无生产消费者**（见上方总注）。
	peerPoor
	// peerUnpunchable 打不通（对称 NAT / 打洞超时等）⇒ 通信时**软跳过打洞**
	//
	//	⚠️ **仍然有效**：软跳过与「强制重试提议」由 `path.go` 的 `offerForcedRetry`
	//	（流量驱动路径）使用 —— 见上方总注。
	peerUnpunchable
)

func (k peerResultKind) String() string {
	switch k {
	case peerGood:
		return "good"
	case peerPoor:
		return "poor"
	case peerUnpunchable:
		return "unpunchable"
	default:
		return "unknown"
	}
}

const (
	// 好 / 差：30~60min（取 45min 作中间值）
	peerTTLGood = 45 * time.Minute
	peerTTLPoor = 45 * time.Minute
	// 不可打洞：10~30min —— **按原因码分层**
	//   nat-symmetric：拓扑性结论，短期不会变 ⇒ **取长**
	//   punch-timeout / peer-no-punch-addr：可能是暂时性（网络瞬时/对端刚起）⇒ **取短**
	peerTTLUnpunchableSticky    = 30 * time.Minute
	peerTTLUnpunchableTransient = 10 * time.Minute

	// peerTableMaxEntries 表容量上限（超出按 LRU 淘汰最久未使用的一条）。
	//
	// 为什么需要：TTL 只清「已过期」的；长期运行 + 对端 VIP 漂移会让「未过期但已无关」的
	// 记录累积。上限是**兜底**，TTL 是**主力**。1024 远超现实规模（/24 网段最多 254 台）。
	peerTableMaxEntries = 1024

	// peerTablePruneEvery 惰性清理的节流：每 N 次 Record/Lookup 扫一遍过期项（**零新 goroutine**）
	peerTablePruneEvery = 64
)

// peerQuality 一条对端质量记录
type peerQuality struct {
	Kind       peerResultKind
	ReasonCode string // 产生这条记录的原因码（诊断/日志用）
	RTTMs      int64  // 直连 RTT（成功时有意义）
	LossPct    int    // 探针丢包率（0~100）
	// At 观测发生时刻（**首次**记录该结论的时刻）—— 日志/诊断用，**不因读取而改动**
	At time.Time
	// Expire 过期时刻（= At + TTL，或结论变化时重算）
	Expire time.Time
	// ForcedRetryUsed 「不可打洞」记录在本 TTL 内是否已用掉那**1 次**强制重试（D3 软跳过）
	ForcedRetryUsed bool
	NatType         string // 记录时的对端 NAT 类型（诊断用；可能为空）
	Addr            string // 对端公网地址（诊断用；可能为空）
	// LastTouch 最近一次被**读或写**的时刻 —— 只服务 LRU 淘汰，**同时**是预打洞
	// 「加权优先」判据（最近通信过）的来源。
	//
	// ⚠️ 读它请用 `Peek`（不刷新）而不是 `Lookup`（会刷新）：`Lookup` 是「使用」，
	//    顺手看一眼却用 `Lookup` 会把「最近通信」改成「刚刚」（第 2 步-B 追问 1）。
	// ⚠️ 必须与 At 分开：若复用 At，每次 Lookup 都会改动「观测时刻」，让日志与诊断说谎。
	LastTouch time.Time
}

// peerTable 对端质量表（并发安全；内存态、进程内 TTL）
//
// ⚠️ 生命周期：**唯一 new 点是 NewHysteria2Client**（`client.go`）。
// 绝不要在 `startPunchManager` / `Connect` 里重建 —— 那会破坏「重连不清空」这条拍板约束。
type peerTable struct {
	mu sync.Mutex
	m  map[[4]byte]peerQuality
	// now 可注入时钟（测试用；生产 = time.Now）。
	// ⚠️ 普通字段 ⇒ 必须在并发使用之前设置（见文件头契约）。
	now func() time.Time
	// sincePrune 距离上次惰性清理的调用次数（只在 mu 内读写 ⇒ 无竞争）
	sincePrune int
}

func newPeerTable() *peerTable {
	return &peerTable{m: make(map[[4]byte]peerQuality), now: time.Now}
}

// setClock 注入时钟（**仅测试**；必须在表被并发使用之前调用）
func (t *peerTable) setClock(now func() time.Time) { t.now = now }

func (t *peerTable) clock() time.Time {
	if t.now == nil {
		return time.Now()
	}
	return t.now()
}

// ---------- 写 ----------

// peerOutcome 一次打洞的观测结果（调用方只填「事实」，TTL/合并规则由表决定）
type peerOutcome struct {
	Kind    peerResultKind
	Reason  string
	RTTMs   int64
	LossPct int
	NatType string
	Addr    string
}

// Record 写入一次观测结果。
//
// 合并规则（实施计划 §2.5 + §9.3，两句话）：
//   - **结论变了**（Kind 不同）⇒ 覆盖 + **重算 TTL** + 清零 `ForcedRetryUsed`；
//   - **同结论重复写** ⇒ 只更新度量（RTT/丢包/原因码/NAT/地址），
//     **`At` / `Expire` / `ForcedRetryUsed` 全部不变** ⇒ 「TTL 不延长」。
//
// 这条规则同时满足两个要求：
//   - 拍板项「TTL 不延长」（坏记录不会因为一直有流量而永生）；
//   - D3「强制重试失败不双罚」（强制重试失败是**同结论** ⇒ 过期时刻不变，用户不用多等）。
func (t *peerTable) Record(vip [4]byte, o peerOutcome) {
	now := t.clock()
	ttl := peerTTLFor(o.Kind, o.Reason)

	t.mu.Lock()
	defer t.mu.Unlock()
	t.sincePrune++
	if t.sincePrune >= peerTablePruneEvery {
		t.pruneLocked(now)
	}

	if old, ok := t.m[vip]; ok && old.Kind == o.Kind && now.Before(old.Expire) {
		// 同结论 + 未过期 ⇒ 只刷度量，**不动** At/Expire/ForcedRetryUsed
		old.ReasonCode = o.Reason
		old.RTTMs = o.RTTMs
		old.LossPct = o.LossPct
		old.NatType = o.NatType
		old.Addr = o.Addr
		old.LastTouch = now
		t.m[vip] = old
		return
	}
	// 结论变化 / 首次 / 旧记录已过期 ⇒ 新记录（重算 TTL、清强制重试标记）
	t.evictIfFullLocked(vip)
	t.m[vip] = peerQuality{
		Kind: o.Kind, ReasonCode: o.Reason, RTTMs: o.RTTMs, LossPct: o.LossPct,
		At: now, Expire: now.Add(ttl),
		NatType: o.NatType, Addr: o.Addr,
		ForcedRetryUsed: false,
		LastTouch:       now,
	}
}

// TryConsumeForcedRetry 原子地「消费」本 TTL 内的那 1 次强制重试机会。
//
// 返回 true = 本次放行（调用方继续发起打洞）；false = 本 TTL 内已用过 ⇒ 调用方应跳过。
//
// ⚠️ **必须原子**（W-1）：`handleTrigger` 会被同一对端的多个包并发触发，
// 「读标记 → 判断 → 写标记」拆开会**多次放行**，直接违反 D3 的「TTL 内 1 次」。
//
// ⚠️ **调用时机**（W-2）：只在「真的会发起打洞」时调用（过完信号门 + 让路 + 拿到额度，
// `punchWithTrigger` 之前）。读到记录就消费会在「对端离线 / 冷却 / 限流」时白消费一次。
//
// 语义：只有**不可打洞且未过期**的记录才涉及强制重试；其余情形返回 true（不参与本机制）。
func (t *peerTable) TryConsumeForcedRetry(vip [4]byte) bool {
	now := t.clock()
	t.mu.Lock()
	defer t.mu.Unlock()
	q, ok := t.m[vip]
	if !ok || q.Kind != peerUnpunchable || !now.Before(q.Expire) {
		return true // 不涉及「不可打洞」机制 ⇒ 放行（由其它判据决定要不要打）
	}
	if q.ForcedRetryUsed {
		return false
	}
	q.ForcedRetryUsed = true
	q.LastTouch = now
	t.m[vip] = q
	return true
}

// ---------- 读 ----------

// Lookup 查一条**未过期**的记录（过期即 miss；**不删除**，删除交给惰性清理）
func (t *peerTable) Lookup(vip [4]byte) (peerQuality, bool) {
	now := t.clock()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sincePrune++
	if t.sincePrune >= peerTablePruneEvery {
		t.pruneLocked(now)
	}
	q, ok := t.m[vip]
	if !ok || !now.Before(q.Expire) {
		return peerQuality{}, false
	}
	q.LastTouch = now // 服务 LRU（**不动 At** ⇒ 观测时刻不被读取篡改）
	t.m[vip] = q
	return q, true
}

// Peek 查一条**未过期**的记录，**但不刷新 `LastTouch`**（只读的「看一眼」）。
//
// ⭐ 第 2 步-B review 追问 1：`Lookup` 一个函数背了**两个语义** ——
//
//	「读值」+「刷新 LRU 的最近使用时刻」。对**顺手看一眼**的调用方（预打洞筛候选）
//	来说，后一个语义是污染：
//	- 它把 `LastTouch` 刷成「现在」⇒ **加权排序**用的「最近通信时刻」失真
//	  （预打洞看了一眼，这个对端就变成「刚通信过」）；
//	- 它扰乱了容量兜底的 **LRU 淘汰顺序**（读取行为参与淘汰，本末倒置）。
//
// ⚠️ 语义分工（**别混用**）：
//
//	`Peek`   —— 只读值；**不产生任何副作用** ⇒ 原用于「预打洞筛候选 + 批量诊断」（`prepunch.go`）。
//	             ⚠️ A3a（2026-09-28）删除预打洞发起侧后**暂无生产调用者**，
//	             但**语义仍然成立**：需要「纯读、不刷 `LastTouch`」时用它（**勿**改用 `Lookup`）。
//	`Lookup` —— 读值 + 刷新 `LastTouch`（服务 LRU）⇒ 真正的「使用」动作
//	             （`Unpunchable`（数据面触发）与各处诊断读取都走它）
//
// ⚠️ `Peek` 只读，不触发惰性清理（`Lookup`/`Record` 会触发）⇒ 不会因「只看一眼」
//
//	而产生删除副作用。过期项在这里同样视为 miss（与 `Lookup` 一致）。
func (t *peerTable) Peek(vip [4]byte) (peerQuality, bool) {
	now := t.clock()
	t.mu.Lock()
	defer t.mu.Unlock()
	q, ok := t.m[vip]
	if !ok || !now.Before(q.Expire) {
		return peerQuality{}, false
	}
	return q, true
}

// ⭐ A1（2026-09-27）：`HasGoodQuality` 已**删除**。
//
//	它唯一的生产调用者 `directPath.hasGoodQualityRecord()` 随「试用期不再依赖质量表」一起删掉
//	⇒ 留着就是死接口。
//
//	需要「是否有未过期的质量好记录」时**按意图选读法**（两者**判据等价**，但**副作用不同**）：
//
//	  · **只想看一眼**（候选筛选 / 诊断，不得产生副作用）
//	    ⇒ `q, ok := tbl.Peek(vip); ok && q.Kind == peerGood`
//	  · 确认这是一次**真正的「使用」**（愿意刷新 LRU 的最近使用时刻）
//	    ⇒ `q, ok := tbl.Lookup(vip); ok && q.Kind == peerGood`
//
//	⚠️ 别把后者用在前者上：`Lookup` **会刷新 `LastTouch`**（见其说明）⇒ 预打洞筛候选时
//
//	"看一眼"会把该对端的「最近通信时刻」顶成现在 ⇒ ① 加权排序失真；
//	② LRU 容量兜底的淘汰顺序被**读取行为**扰乱。（这正是当初引入 `Peek` 的原因。）

// Unpunchable 该对端是否有「不可打洞」的未过期记录（软跳过的判据）
func (t *peerTable) Unpunchable(vip [4]byte) (peerQuality, bool) {
	q, ok := t.Lookup(vip)
	if !ok || q.Kind != peerUnpunchable {
		return peerQuality{}, false
	}
	return q, true
}

// Len 当前表内条数（**含已过期但尚未清理**的项；测试用）
func (t *peerTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// ---------- 内部 ----------

// peerTTLFor 三档 TTL（不可打洞按原因码分层：粘性长、瞬时长）
func peerTTLFor(kind peerResultKind, reason string) time.Duration {
	switch kind {
	case peerGood:
		return peerTTLGood
	case peerPoor:
		return peerTTLPoor
	case peerUnpunchable:
		if reason == P2PReasonNATSymmetric {
			return peerTTLUnpunchableSticky
		}
		return peerTTLUnpunchableTransient
	default:
		return peerTTLPoor
	}
}

// pruneLocked 惰性清理过期项（**调用方必须已持 mu**；零 I/O、零回调）
//
// 每 peerTablePruneEvery 次 Record/Lookup 触发一次 ⇒ 无需新 goroutine
// （边界五项第 5 项）。顺带把「已过期」的先清掉 ⇒ 容量上限几乎不会被触发。
func (t *peerTable) pruneLocked(now time.Time) {
	t.sincePrune = 0
	for k, q := range t.m {
		if !now.Before(q.Expire) {
			delete(t.m, k)
		}
	}
}

// evictIfFullLocked 容量兜底：表满时淘汰 **LastTouch 最久** 的一条（LRU）。
// 调用方必须已持 mu；只为**新键**腾位（更新已有键不需要）。
//
// ⚠️ **LastTouch 相同时淘汰顺序不定**（review 追问 2 明确要求写下来）：
// 生产里**同一毫秒写入多条完全可能**（多个会话同时结束 ⇒ `Record` 用真实时钟、
// `UnixMilli`/`time.Time` 精度下同刻），此时 `q.LastTouch.Before(oldest)` 对所有并列者都为 false，
// 于是选中哪条取决于 **map 的随机遍历顺序** ⇒ 每次运行可能不同。
//
// 为什么可接受（不修）：
//   - **不致命**：并列者都是「同样久没被用到」的等价候选，淘汰任何一个都不改变正确性；
//   - 上限（1024）远超现实规模（/24 网段最多 254 台）⇒ 正常永远碰不到淘汰；
//   - 想要确定性就得引入序号/时间戳单调递增，为一个「几乎不触发」的兜底路径增加状态不划算。
//
// ⚠️ 但**诊断时要知道**：若在日志/复现里看到「淘汰的不是我预期的那条」，
// 先确认是不是同一毫秒并列 —— 那是这个已知的非确定性，不是 LRU 写错了。
func (t *peerTable) evictIfFullLocked(incoming [4]byte) {
	if len(t.m) < peerTableMaxEntries {
		return
	}
	if _, exists := t.m[incoming]; exists {
		return // 更新已有键：不需要腾位
	}
	var victim [4]byte
	var oldest time.Time
	first := true
	for k, q := range t.m {
		if first || q.LastTouch.Before(oldest) {
			victim, oldest, first = k, q.LastTouch, false
		}
	}
	if !first {
		delete(t.m, victim)
	}
}
