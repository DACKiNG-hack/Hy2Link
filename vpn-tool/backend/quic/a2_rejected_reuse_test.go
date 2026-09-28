package quic

// vpn-tool/backend/quic/a2_rejected_reuse_test.go
//
// ⭐⭐ A2 切片（方案 A：判负侧**保留连接** + 复用）—— **19 条用例，先全红，再改状态机**。
//
// 语义定稿（见 `P2SP-阶段1b-4-A2-方案A-实施计划与进度.md` §1）：
//
//	新状态：`pathStateRejected`（判负但保留连接）／`pathStateReusing`（复用重跑试用期）／
//	        `pathStateRejectedSettling`（收尾中间态）
//	三道门：`closeOnce`（连接生命周期，**不可重置**）／`settled atomic.Bool`（收尾门，可重置）
//	        ／`trialDone`（判定门，可重置）；`reuseCount atomic.Int32`（路径级，**不重置**）
//	幂等：`terminateOnce` **只给 `terminateDown` 独占**；`releaseRejected` 靠 state CAS + `settled`
//	      （⚠️ 共用 terminateOnce 会连接泄漏 + PATH-LEAK 亮 —— 设计期已排除的方案）
//	`Done()` 永远走 `terminateDown`；`terminateDown` 在 Rejected 态也走 Down（**真死优先**）
//	复用 CAS 后**先终检** `conn.Context().Err()`：已断 ⇒ 回滚转 Down
//	`alive()` 纳入 Rejected/Reusing（**不**纳入 RejectedSettling）；`Paths()` 过滤三者；`pathCount()` 仍计入
//	登记：Rejected/Reusing 期间**继续留在 `m.trialPaths`**（保留连接能被 TTL/面板看见的前提）；
//	⚠️ **但 `releaseRejected` 必须 `untrack()`**：释放后状态是 `RejectedSettling`，而 TTL 白名单
//	只认 `Rejected` ⇒ 若把摘登记留给 prune 扫，这条登记**永远不会被淘汰 = 真泄漏**（见 path.go）。
//	TTL：扩 `pruneLoop`（`evictIdle`）扫描范围，**白名单：只淘汰 `Rejected` 且超 `trialRejectedTTL`**
//	     ⇒ 边界五项第 5 项：**基线（B1 之后）= 0 ⇒ 本切片保持 0**（复用已有 pruneLoop，零新增 goroutine）
//	       ⚠️ 2026-09-28 更正：此处原写「保持 +1」是**过时表述** —— `+1` 是 B1 之前（预打洞调度器还在）的基线
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ **A2 待实现 API 清单**（本文件先落、编译错误即权威清单）：
//
//	path.go 新增/改名：
//	  · `func (p *directPath) rejectTrial()`                    判负 ⇒ Rejected（保留连接）
//	  · `func (p *directPath) reuseRejected() bool`             CAS Rejected→Reusing（含 conn 终检）
//	  · `func (p *directPath) releaseRejected()`              专用清理（state CAS + settled；不排退避）
//	  · `func (p *directPath) terminateDown(reason string)`     真死（`demote` 亦走它）
//	  · `func (p *directPath) Done()`                           ⇒ 永远走 terminateDown
//	  · 字段 `settled atomic.Bool` / `reuseCount atomic.Int32` / `rejectedAt atomic.Int64`
//	  · 常量 `trialRejectedTTL = 60 * time.Second`
//	  · `alive()` 纳入 Rejected/Reusing；`Paths()` 过滤三者
//	  · `evictIdle()` 扫描范围扩到 `trialPathsSnapshot()`（只淘汰超 TTL 的 Rejected）
//	  · `demoteOnce` → `terminateOnce`（**只给 terminateDown 独占**）
// ─────────────────────────────────────────────────────────────────────────────

import (
	"sync"
	"testing"
	"time"
)

const a2PeerVIP = "192.168.30.13"

// connClosedForTest 测试助手：这条路径的连接是否已关闭（仅认 `*fakeConn`；nil/真实 conn 返回 false）。
//
// ⚠️ 这是**测试侧**助手（不属于 A2 待实现 API）——生产侧不需要它。
func (p *directPath) connClosedForTest() bool {
	if fc, ok := p.conn.(*fakeConn); ok {
		return fc.closed.Load()
	}
	return false
}

// a2Path 造一条「已装表 Up」的路径（复用 B3 的助手；`newTestPath` 内部 installRoute + passTrialForTest）。
func a2Path(t *testing.T, pm *pathManager, host *fakeHost) *directPath {
	t.Helper()
	p, _ := newTestPathOwned(t, pm, host, a2PeerVIP, pathRoleInitiator)
	return p
}

// a2Rejected 造一条处于 `Rejected` 的路径（登记仍在 `trialPaths`、**连接未关** —— 与生产一致）。
//
// ⚠️ **形态 A（2026-09-28 起）**：走 `newTestPathNoPass` —— 它**不调 `passTrialForTest`**，
// 因此 `detachTrialPath` 的**一次性闭包未被消费**。这才是生产形态（`handleEstablished` 里
// `newDirectPath` 之后直接 `addTrialPath + run()`，从不经过装表流程）。
//
//	旧夹具用 `newTestPath`（`installRoute` + `passTrialForTest` + `run()`）⇒ 闭包被烧掉，
//	之后再 `addTrialPath` 补登记 ⇒ 释放时 `p.untrack()` 成 **no-op** ⇒ 登记残留
//	（`TestTrialRejectedCleansUpOnPeerClose` 因此红）。那是**夹具构造问题，不是生产 bug**。
func a2Rejected(t *testing.T, pm *pathManager, host *fakeHost) *directPath {
	t.Helper()
	p, _ := newTestPathNoPass(t, pm, host, a2PeerVIP, pathRoleInitiator)
	p.rejectTrial()
	if got := p.state.Load(); got != pathStateRejected {
		t.Fatalf("前置：应为 Rejected，实际 %s", pathStateName(got))
	}
	if !inTrialPaths(pm, p) {
		t.Fatal("前置：Rejected 路径必须仍在 `trialPaths` 登记里（TTL 淘汰靠扫它）")
	}
	return p
}

// ---------- §3.1 方案 A 核心（7 条） ----------

// TestTrialRejectedKeepsConnection 判负后：连接**不关**、仍在登记里、alive() 为真。
func TestTrialRejectedKeepsConnection(t *testing.T) {
	_, pm, host := b3Harness(t)
	// ⚠️ 形态 A（2026-09-28）：`newTestPathNoPass` 已含「**锁内** `addTrialPath` + `run()`」，
	//	且 `untrack` 闭包**未消费**（不调 `passTrialForTest`）⇒ 无需再补登记、也无需重置
	//	`state`/`trialDone`（`newDirectPath` 原生即 Trial 态）。
	p, conn := newTestPathNoPass(t, pm, host, a2PeerVIP, pathRoleInitiator)
	p.rejectTrial()

	if got := p.state.Load(); got != pathStateRejected {
		t.Fatalf("判负应进入 Rejected（保留连接），实际 %s", pathStateName(got))
	}
	if conn.closed.Load() {
		t.Fatal("判负侧**不得**关闭连接（方案 A 的全部意义：对端可能仍在用）")
	}
	if !p.alive() {
		t.Fatal("Rejected 必须纳入 alive()（否则探针/读写协程全停 ⇒ 对端 probe-timeout）")
	}
	var found bool
	for _, q := range pm.trialPathsSnapshot() {
		if q == p {
			found = true
		}
	}
	if !found {
		t.Fatal("Rejected 路径必须留在 m.trialPaths 登记里（TTL 淘汰靠它扫）")
	}
}

// TestTrialRejectedStillEchoes 判负后仍能**回显对端探针**。
//
// ⚠️ 测法说明：`ctrlLoop` 的回显分支（`case ctrlProbe:` → `writeCtrl(ctrlProbeEcho)`）**没有任何
// state 门**，只依赖「ctrl 流还在 + 连接还活」。这里断言这两个前提（结构级代理），
// 端到端回显由既有 ctrl 用例覆盖。
func TestTrialRejectedStillEchoes(t *testing.T) {
	_, pm, host := b3Harness(t)
	p, conn := newTestPathNoPass(t, pm, host, a2PeerVIP, pathRoleInitiator)

	// ⚠️ `run()` 只**启动**协程，`setup()` 在独立协程里建流 ⇒ 必须**等 ctrl 流建好**再判负，
	//	否则本用例是 **flaky**（夹具快慢不同 ⇒ 红/绿不定；2026-09-28 实测）。
	waitFor(t, "控制流建立", func() bool {
		_, _, ctrl := p.streams()
		return ctrl != nil
	})

	p.rejectTrial()

	_, _, ctrl := p.streams()
	if ctrl == nil {
		t.Fatal("判负后控制流必须仍在（否则对端拿不到回显 ⇒ 它自己那条也会判负 = 双侧都关）")
	}
	if conn.closed.Load() {
		t.Fatal("判负后连接必须仍活")
	}
	if !p.alive() {
		t.Fatal("Rejected 必须 alive（ctrlLoop/watchLoop 才有机会跑）")
	}
}

// TestTrialRejectedNotInstalled 判负侧**不装表**（本侧不主动发数据）。
func TestTrialRejectedNotInstalled(t *testing.T) {
	_, pm, host := b3Harness(t)
	p := a2Rejected(t, pm, host)

	if rt := pm.routes.Load(); rt != nil {
		if got := (*rt)[ip4(a2PeerVIP)]; got == p {
			t.Fatal("Rejected 路径**不得**进路由表（本侧明确不用它承载流量）")
		}
	}
	if ok, _ := pm.HasUsablePath(ip4(a2PeerVIP)); ok {
		t.Fatal("Rejected 在 HasUsablePath 里应**不算**可用（A2 登记的 2 行扩展）")
	}
}

// TestTrialRejectedHasTTL 超 `trialRejectedTTL` 由 **pruneLoop（同一协程）** 清理；不误杀正常 trial。
func TestTrialRejectedHasTTL(t *testing.T) {
	_, pm, host := b3Harness(t)

	old := a2Rejected(t, pm, host)
	old.rejectedAt.Store(time.Now().Add(-trialRejectedTTL - time.Second).UnixMilli())

	fresh := a2Rejected(t, pm, host)
	fresh.rejectedAt.Store(time.Now().UnixMilli())

	trial := a2Path(t, pm, host) // 正常试用期路径（年轻）
	trial.setState(pathStateTrial)

	pm.evictIdle() // pruneLoop 的那一拍

	if !old.connClosedForTest() {
		t.Fatal("超过 TTL 的 Rejected 登记应被淘汰（连接关闭）")
	}
	// ⚠️ 2026-09-28 补：**登记也必须被摘**。原用例只断言"连接关了"，对**泄漏是盲的**
	//	（旧夹具的 `untrack` 闭包已被 `passTrialForTest` 烧掉 ⇒ 连接关了、登记却残留，
	//	本用例照样绿）。这里与 `TestTrialRejectedCleansUpOnPeerClose` 守**同一不变量**。
	if inTrialPaths(pm, old) {
		t.Fatal("超 TTL 被释放后**登记必须摘除**（否则 pruneLoop 每拍都扫到它 = 泄漏 + 空转）")
	}
	if fresh.connClosedForTest() {
		t.Fatal("未超 TTL 的 Rejected **不得**被淘汰")
	}
	if trial.connClosedForTest() {
		t.Fatal("⚠️ 正在跑试用期的路径**绝不能**被 TTL 淘汰（否则误杀正常直连）")
	}
}

// TestTrialRejectedCleansUpOnPeerClose 对端真的关闭 ⇒ 专用清理生效：登记摘除、连接关、
// **不新增退避**、且不发「质量差」事件。
//
// ⚠️ 「不排退避」的**正确断言是"不变"而不是"为空"**：进入本用例前 `rejectTrial` 已经写过
//
//	那条 30s 短冷却（那是**判负**的冷却，不是本次清理造成的）⇒ 断言 `until.IsZero()` 会
//	把正确实现判成红。这里用 before/after 对照：**不得新增、不得延长、不得推进档位**。
func TestTrialRejectedCleansUpOnPeerClose(t *testing.T) {
	_, pm, host := b3Harness(t)
	p, _ := a2Rejected(t, pm, host), (*fakeConn)(nil)
	dst := ip4(a2PeerVIP)
	before := pm.backoffSnapshot(dst)
	p.releaseRejected()

	if !p.settled.Load() {
		t.Fatal("releaseRejected 必须置 `settled`（收尾门，保证幂等）")
	}
	if !p.connClosedForTest() {
		t.Fatal("对端已关闭 ⇒ 本侧必须释放连接")
	}
	var still bool
	for _, q := range pm.trialPathsSnapshot() {
		if q == p {
			still = true
		}
	}
	if still {
		t.Fatal("终止后必须摘掉登记（否则 TTL 永远扫不到 ⇒ 泄漏）")
	}
	// ⚠️ 「不变」三断言（见函数头）：新增/延长/推进档位 任一发生都红
	after := pm.backoffSnapshot(dst)
	if !after.until.Equal(before.until) {
		t.Fatalf("releaseRejected **不得**新增/延长退避：前 %v 后 %v", before.until, after.until)
	}
	if after.step != before.step || after.qualityStep != before.qualityStep {
		t.Fatalf("releaseRejected 不得推进档位：前 step=%d quality=%d，后 step=%d quality=%d",
			before.step, before.qualityStep, after.step, after.qualityStep)
	}
	if after.lastErr != before.lastErr {
		t.Fatalf("releaseRejected 不得改写历史原因 lastErr：前 %q 后 %q", before.lastErr, after.lastErr)
	}
}

// TestTrialRejectedShortCooldown 本侧判负后**短冷却**生效（与 peer-closed 冷却分开记账）。
func TestTrialRejectedShortCooldown(t *testing.T) {
	_, pm, host := b3Harness(t)
	a2Rejected(t, pm, host)

	st := pm.backoffSnapshot(ip4(a2PeerVIP))
	if st.until.IsZero() {
		t.Fatal("判负保留连接后必须写**短冷却**（否则流量立刻再触发 ⇒ 重试风暴 + 旧连接占资源）")
	}
	if d := time.Until(st.until); d < 25*time.Second || d > 35*time.Second {
		t.Fatalf("短冷却应为 backoffBusy=%v 量级，实际 %v", backoffBusy, d.Round(time.Second))
	}
	if st.qualityStep != 0 {
		t.Fatalf("判负保留连接**不推进**质量 streak（复用会重跑试用期，不是新失败）：实际 %d", st.qualityStep)
	}
}

// TestTrialRejectedNoRetryStorm 判负 + 短冷却内，流量触发**不得**立刻新增 attempt。
func TestTrialRejectedNoRetryStorm(t *testing.T) {
	_, pm, host := b3Harness(t)
	host.addPeer(a2PeerVIP) // 让信号门可过（若退避门失效，就会真的发起打洞）
	a2Rejected(t, pm, host)

	pm.handleTrigger(ip4(a2PeerVIP))
	time.Sleep(80 * time.Millisecond)
	if n := host.punchCount(); n != 0 {
		t.Fatalf("短冷却期内不得新增打洞 attempt（重试风暴），实际 %d 次", n)
	}
}

// ---------- §3.2 生命周期与幂等（8 条） ----------

// TestTrialRejectedReuseTransitions Rejected → Reusing →（重新试用）同一对象转换。
func TestTrialRejectedReuseTransitions(t *testing.T) {
	_, pm, host := b3Harness(t)
	p := a2Rejected(t, pm, host)

	if !p.reuseRejected() {
		t.Fatal("连接还在 ⇒ 复用 CAS 应成功")
	}
	// ⚠️ 末态**已定为 `Trial`**（Q3 拍板）：`Reusing` 只是函数内的 CAS 保护窗口。
	//	⇒ 这条断言**不再是**"`Reusing` 存在"的证据（也不该是：那种"或"断言在删掉 `Reusing`
	//	后照样绿 = 假绿）。真正的守卫是 `TestReleaseRejectedIgnoredOutsideRejectedState`
	//	（验"复用窗口内的连接不许被释放"）。
	if got := p.state.Load(); got != pathStateTrial {
		t.Fatalf("复用后应直接进入 Trial（`Reusing` 只作 CAS 窗口），实际 %s", pathStateName(got))
	}
	if p.settled.Load() {
		t.Fatal("复用必须**重新武装** settled（收尾门可重置）")
	}
	if p.trialDone.Load() {
		t.Fatal("复用必须**重新武装** trialDone（判定门可重置）")
	}
	if got := p.reuseCount.Load(); got != 1 {
		t.Fatalf("reuseCount 应 +1，实际 %d", got)
	}
}

// TestReuseResetsTrialBaseline ⭐ 开工清单第 1 条：`trialLastEcho` 重置为**复用那一刻的 lastEcho**（不是 0）。
//
// ⚠️ 有牙（review 要求确认）：把实现里的 `p.trialLastEcho.Store(p.lastEcho.Load())`
//
//	写成 `p.trialLastEcho.Store(0)` ⇒ **本用例红**（`got != echoNow`）。
//	语义后果：写成 0 会让「复用后第一个采样窗内**任何**旧回显」都算好样本
//	（判据是 `lastEcho > trialLastEcho`），与"建路径基线"口径不一致 ⇒ 复用后的试用期虚高通过。
func TestReuseResetsTrialBaseline(t *testing.T) {
	_, pm, host := b3Harness(t)
	p := a2Rejected(t, pm, host)

	p.trialGood.Store(2)
	p.trialSamples.Store(3)
	echoNow := time.Now().UnixMilli()
	p.lastEcho.Store(echoNow)

	if !p.reuseRejected() {
		t.Fatal("前置：复用应成功")
	}
	if got := p.trialLastEcho.Load(); got != echoNow {
		t.Fatalf("`trialLastEcho` 必须重置为**复用那一刻的 lastEcho**（%d），实际 %d"+
			"（写成 0 会把复用后第一个采样窗内的旧回显算成好样本）", echoNow, got)
	}
	if p.trialGood.Load() != 0 || p.trialSamples.Load() != 0 {
		t.Fatalf("复用后样本计数必须归零：good=%d samples=%d", p.trialGood.Load(), p.trialSamples.Load())
	}
	if p.trialStartedAt.Load() == 0 {
		t.Fatal("复用后必须重落 trialStartedAt（新一轮判定的起点）")
	}
}

// TestReuseCountNotReset 复用计数只增不减（路径级、不重置）。
func TestReuseCountNotReset(t *testing.T) {
	_, pm, host := b3Harness(t)
	p := a2Rejected(t, pm, host)

	for i := 1; i <= 2; i++ {
		if !p.reuseRejected() {
			t.Fatalf("第 %d 次复用应成功（连接仍在）", i)
		}
		if got := p.reuseCount.Load(); got != int32(i) {
			t.Fatalf("reuseCount 应累计到 %d，实际 %d（不得被重置）", i, got)
		}
		p.rejectTrial() // 再判负一次，准备下一轮复用
	}
}

// TestReuseCASChecksConnContext 复用 CAS 后**终检** conn：已断 ⇒ 回滚转 Down。
func TestReuseCASChecksConnContext(t *testing.T) {
	_, pm, host := b3Harness(t)
	p, conn := newTestPathNoPass(t, pm, host, a2PeerVIP, pathRoleInitiator)
	p.rejectTrial()

	_ = conn.CloseWithError(0, "peer gone") // 对端已断（close 包到达）
	if p.reuseRejected() {
		t.Fatal("连接已断时复用必须失败（不得留下「复用中的死连接」）")
	}
	if got := p.state.Load(); got != pathStateDown {
		t.Fatalf("复用失败必须**回滚转 Down**，实际 %s", pathStateName(got))
	}
}

// TestReleaseRejectedIdempotent 并发/重复调用 releaseRejected ⇒ 只关一次、不 panic。
func TestReleaseRejectedIdempotent(t *testing.T) {
	_, pm, host := b3Harness(t)
	p := a2Rejected(t, pm, host)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p.releaseRejected() }()
	}
	wg.Wait()
	if !p.connClosedForTest() {
		t.Fatal("releaseRejected 后连接必须关闭")
	}
	p.releaseRejected() // 再调一次：必须幂等（不 panic、不重复摘登记）
}

// TestTerminateOnceOnlyForDown ⭐ 守住「terminateOnce **只给 terminateDown 独占**」的纪律。
//
// 判据：`terminateDown` 只跑一次（钩子计数 = 1）；而 `releaseRejected` **不**消耗 terminateOnce
// ⇒ 之后 `terminateDown` 仍能正常跑（若共用 once，这一步就会静默失效 ⇒ 连接泄漏）。
//
// ⚠️ **有牙构造（review 要求写进注释）**：完整时序是
//
//	判负 → `releaseRejected()`（收尾，此时连接可能仍在）→ **复用**（`reuseRejected()`）
//	→ 连接**真断**（对端关闭 / 超时）→ `Done()` ⇒ 必须真的执行 `close()`
//
//	若把 `releaseRejected` 也接上 `terminateOnce`，则「复用后真断」这一步的 close()
//	会被 once 吞掉 ⇒ **连接泄漏 + `PATH-LEAK` 亮**。本用例用「PathClosed 钩子恰好 1 次」
//	把这条纪律钉在当前这条路径上（等价于上述时序的末段）。
//
// ⚠️ 有牙（mutation）：让 `releaseRejected` 也调 `terminateOnce.Do(...)` ⇒ 本用例红（closes=0）。
func TestTerminateOnceOnlyForDown(t *testing.T) {
	_, pm, host := b3Harness(t)
	var closes int32
	var mu sync.Mutex
	pm.hooks = &pathHooks{PathClosed: func(string) { mu.Lock(); closes++; mu.Unlock() }}

	p := a2Rejected(t, pm, host)
	p.releaseRejected() // 不得消耗 terminateOnce
	p.terminateDown(P2PReasonDirectLost)
	p.terminateDown(P2PReasonDirectLost) // 第二次必须无效

	mu.Lock()
	defer mu.Unlock()
	if closes != 1 {
		t.Fatalf("terminateDown 应恰好跑一次（且不能被 releaseRejected 抢先消耗），实际 %d", closes)
	}
}

// TestDoneAlwaysTerminatesDown `Done()` 在 Rejected 态也走 Down（真死优先）。
func TestDoneAlwaysTerminatesDown(t *testing.T) {
	_, pm, host := b3Harness(t)
	p := a2Rejected(t, pm, host)

	p.Done()
	if got := p.state.Load(); got != pathStateDown {
		t.Fatalf("Done() 必须永远走 terminateDown（真死优先于保留），实际 %s", pathStateName(got))
	}
}

// TestRejectedSettlingNotAlive 收尾中间态**不**纳入 alive（防止收尾期间再产生样本）。
func TestRejectedSettlingNotAlive(t *testing.T) {
	_, pm, host := b3Harness(t)
	p := a2Rejected(t, pm, host)

	p.setState(pathStateRejectedSettling)
	if p.alive() {
		t.Fatal("RejectedSettling 必须**不**纳入 alive（此刻已决定不再使用这条连接）")
	}
}

// ---------- §3.3 登记/枚举/淘汰（3 条） ----------

// TestPathsFiltersNewStates 面板快照过滤三者（Rejected/Reusing/RejectedSettling）。
//
// ⚠️ **与 #17 的边界（review 要求划清）**：
//
//	本用例管 **`Paths()`（面板可见性）** —— Rejected 是「本侧明确不用」的连接，
//	列进面板会让用户以为在走直连 ⇒ **必须过滤**；
//	#17 管 **`pathCount()`（容量记账）** —— 它**仍计入**这三种状态（登记占着资源、
//	占 `pathMaxPaths` 名额）⇒ **不得过滤**。两者语义相反，**不是**同一个判据抄两遍。
func TestPathsFiltersNewStates(t *testing.T) {
	_, pm, host := b3Harness(t)

	// ⚠️⚠️ **每条路径必须用不同 VIP**（2026-09-28 修正，交接 ④ 第 6 项）：
	//	旧版 4 条路径**共用 `a2PeerVIP`** ⇒ 路由表 `map[peer]*directPath` **只有一个槽**，
	//	后建的 `installRoute` 把先建的**顶掉**，而 `removeRoute` 只摘自己 ⇒ `up` 被顶掉后，
	//	本用例**因"恰好只剩 1 条"而绿 = 假绿**（它守的不是"过滤生效"，是"路由槽被搅乱"）。
	//	新夹具（形态 A）不再经 `installRoute`，路由槽不再被搅乱 ⇒ **缺陷当场暴露**。
	newTestPathOwned(t, pm, host, "192.168.30.10", pathRoleInitiator) // 真·Up（在路由表里）⇒ **必须可见**

	mk := func(vip string, st int32) {
		t.Helper()
		p, _ := newTestPathNoPass(t, pm, host, vip, pathRoleInitiator)
		p.setState(st)
	}
	mk("192.168.30.11", pathStateTrial)            // ⚠️ **Trial 必须可见**（面板显示"测试中"）
	mk("192.168.30.12", pathStateRejected)         // ⇒ 过滤
	mk("192.168.30.13", pathStateReusing)          // ⇒ 过滤
	mk("192.168.30.14", pathStateRejectedSettling) // ⇒ 过滤

	// ⚠️ 期望值 = **2**（Up + Trial），不是 1：`Paths()` 只过滤 A2 的三个新状态，
	//	**不过滤 `Trial`**（`path.go` 的 `Paths()`：routes 全收 + trialPaths 仅排除那三态）。
	//	把 `Trial` 一起过滤掉是**另一处回归**（用户会看不到"测试中"）⇒ 这里显式钉住。
	if got := len(pm.Paths()); got != 2 {
		t.Fatalf("Paths() 只许过滤 Rejected/Reusing/RejectedSettling（Up 与 Trial 必须可见），实际返回 %d 条", got)
	}
}

// TestPathCountStillCountsRejected ⭐ 记账：`pathCount()` **仍计入**新状态
// ⇒ 最坏 `1 Up + 2 Rejected` ⇒ 用户最多等 60s 才能新建路径（这条是有意保留的语义）。
//
// ⚠️ **与 #16 的边界**：`pathCount()` 是**容量记账**（登记占资源、占 `pathMaxPaths` 名额）
// ⇒ 必须计入 Rejected/Reusing/RejectedSettling；而 `Paths()` 是**面板可见性** ⇒ 必须过滤。
// 两者取向相反，改任一处都不得顺手把另一处改成同款。
func TestPathCountStillCountsRejected(t *testing.T) {
	_, pm, host := b3Harness(t)
	pm.replaceRoutes(nil)

	a2Rejected(t, pm, host)
	a2Rejected(t, pm, host)
	// 第二条同 peer：`trialPaths` 是同 peer 多条（不做顶替）⇒ 计数应为 2
	if got := pm.pathCount(); got != 2 {
		t.Fatalf("pathCount 应计入 Rejected（记账口径），实际 %d", got)
	}
}

// inTrialPaths 该路径是否仍在「非路由表路径登记」里（A2 的 TTL 扫描与 `pathCount` 都靠它）。
//
// ⚠️ **调用前必须确认不持 `routeMu`**：本函数内部调 `trialPathsSnapshot()`，它自己取
//
//	**`routeMu`**（`path.go:921-923`）⇒ Go 的 `sync.Mutex` **不可重入**，持锁再调 = **自死锁**
//	（本轮实测挂死过一次）。
//	需要"查后再加"的场景：**先取快照（不持锁）再决定是否加锁写入**；若只是新建对象，
//	直接 `routeMu.Lock(); addTrialPath; Unlock()` 即可（新建对象天然不在表里，无需查）。
//
// ⚠️ 为什么断言要包含它：只断言 `state != Down` 或"连接没关"都是**弱守卫** ——
//
//	有人只改状态不摘登记（或反之）就不会红。A2 里「释放」的完整语义是四条：
//	状态落 Down / 连接关闭 / 登记摘除 / 不再新增退避。
func inTrialPaths(pm *pathManager, p *directPath) bool {
	for _, q := range pm.trialPathsSnapshot() {
		if q == p {
			return true
		}
	}
	return false
}

// 📌 **已删除 `registerTrialPath`（2026-09-28）** —— 它的存在理由（"夹具不登记 `trialPaths` ⇒ 补上"）
// 已被 `newTestPathNoPass`（形态 A：锁内 `addTrialPath` + `run()`，`untrack` 闭包未消费）取代。
//
//	⚠️ 那个"补登记"本身就是缺陷成因：夹具先经 `passTrialForTest` **烧掉一次性闭包**，再把登记
//	**加回来** ⇒ 释放时 `untrack()` 成 no-op ⇒ 登记永远摘不掉（泄漏）。
//	⚠️ 它顺带记下的**锁纪律仍然有效**：`inTrialPaths` 自取 `routeMu` ⇒ **持锁调它会自死锁**
//	（`sync.Mutex` 不可重入，本轮实测挂死过）；已并入 `inTrialPaths` 的函数头注释。

// TestReleaseRejectedIgnoredOutsideRejectedState ⭐⭐ 状态白名单守卫（review 2026-09-27）。
//
//	`releaseRejected()` 只许碰 `Rejected`/`RejectedSettling`；其余状态必须**一律 no-op** ——
//	尤其 **`Reusing`**（那是**正在复用**的连接：把它关了就是复用中被打断）。
//
// ⚠️ 为什么这条比"Reusing 是个状态"锋利：即使将来把 `Reusing` 整个删掉（CAS 直接
//
//	`Rejected → Trial`），本用例仍要求 `Trial` 态被挡住 ⇒ **不会假绿**。
//
// ⚠️ 有牙（mutation）：删掉状态白名单守卫 ⇒ 四个子例全部红（连接被误关）。
//
//	⚠️ 并附**对照**：`Rejected` 态**必须**真的被释放 —— 否则"什么都没做"的实现也能全绿。
func TestReleaseRejectedIgnoredOutsideRejectedState(t *testing.T) {
	cases := []struct {
		name string
		st   int32
	}{
		{"Reusing（正在复用：绝不能被释放）", pathStateReusing},
		{"Trial（正在跑试用期）", pathStateTrial},
		{"Up（承载流量）", pathStateUp},
		{"Standby（降级但连接保留）", pathStateStandby},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, pm, host := b3Harness(t)
			p, _ := newTestPathOwned(t, pm, host, a2PeerVIP, pathRoleInitiator)
			p.setState(c.st)
			p.releaseRejected()
			if p.connClosedForTest() {
				t.Fatalf("状态 %s 下 releaseRejected 必须 no-op（不得关连接）", c.name)
			}
			if p.settled.Load() {
				t.Fatalf("状态 %s 下不得消耗收尾门 settled（no-op 要彻底）", c.name)
			}
		})
	}
	// 对照：`Rejected` 态**必须**真的释放（防"什么都没做"也能全绿）
	t.Run("对照：Rejected 必须被释放", func(t *testing.T) {
		_, pm, host := b3Harness(t)
		p := a2Rejected(t, pm, host)
		p.releaseRejected()
		if !p.connClosedForTest() {
			t.Fatal("Rejected 态必须真的释放连接（否则本用例是假绿）")
		}
	})
}

// TestPruneOnlyEvictsRejectedState ⭐ 白名单淘汰：**只有 Rejected 且超 TTL** 会被淘汰，
// 其余状态（Trial / Reusing / RejectedSettling / Up / Standby）**一律不动**。
//
// ⚠️ 为什么用**白名单**而不是「非 Up 且非 Standby 且非 Rejecting」：否定式既没定义
//
//	"Rejecting" 指 `Reusing` 还是 `RejectedSettling`（还是两者），又容易漏掉 `Trial`
//	（漏 Trial = 误杀正在跑试用期的正常路径）⇒ review 2026-09-27 修正为白名单。
//
// ⚠️ 有牙：把条件放宽成「非 Up」⇒ 本用例红（Trial/Reusing/RejectedSettling 会被误杀）。
func TestPruneOnlyEvictsRejectedState(t *testing.T) {
	_, pm, host := b3Harness(t)

	// 超期基准：把这几个状态都设成「早已超过 TTL」
	expired := func(p *directPath) *directPath {
		p.rejectedAt.Store(time.Now().Add(-trialRejectedTTL - time.Second).UnixMilli())
		return p
	}

	// 唯一**应被淘汰**的：Rejected + 超期
	rej := a2Rejected(t, pm, host)
	expired(rej)

	// 以下都**不得**被淘汰（即使 rejectedAt 已超期）
	trial := a2Path(t, pm, host)
	trial.setState(pathStateTrial)
	expired(trial)

	reusing := a2Rejected(t, pm, host)
	if !reusing.reuseRejected() {
		t.Fatal("前置：复用应成功")
	}
	expired(reusing)

	settling := a2Rejected(t, pm, host)
	settling.setState(pathStateRejectedSettling)
	expired(settling)

	up := a2Path(t, pm, host) // Up（在路由表里）
	expired(up)

	standby := a2Path(t, pm, host)
	standby.setState(pathStateStandby)
	expired(standby)

	pm.evictIdle() // pruneLoop 的那一拍

	// ① 唯一应被淘汰的
	if !rej.connClosedForTest() {
		t.Fatal("Rejected 且超 TTL 必须被淘汰（否则登记永久泄漏）")
	}
	// ② 其余 5 种状态逐一断言**未**被淘汰
	for _, c := range []struct {
		name string
		p    *directPath
	}{
		{"Trial（正在跑试用期）", trial},
		{"Reusing（复用中）", reusing},
		{"RejectedSettling（收尾中）", settling},
		{"Up（承载流量）", up},
		{"Standby（降级但连接保留）", standby},
	} {
		if c.p.connClosedForTest() {
			t.Fatalf("%s 不得被 TTL 淘汰（白名单只认 Rejected）", c.name)
		}
	}
}

// TestPruneDeadRegistrationsOnlyEvictsDown ⭐ A2 兜底白名单（2026-09-28，第 6 项）：
// `pruneDeadRegistrations()` 只摘 **state == Down** 的死登记；其余**七态里的六态一律不动**。
//
// 为什么需要这个兜底：`p.untrack` 是**一次性闭包**（`sync.Once` 包着"摘一次 + break"），
// 而 `addTrialPath` **不幂等** ⇒ 同一指针被登记两次时只能摘掉一条 ⇒ 残留那条永远留在表里
// （`pruneLoop` 每拍扫到它、`evictIdle` 白名单又直接 `continue` ⇒ **空转 + 泄漏**）。
//
// ⚠️ 有牙（mutation）：把白名单从 `== Down` 放宽成 `!= Up`（或删掉 `continue` 前的判断）
// ⇒ 下面"其余六态不得被摘"的断言全红。
//
// ⚠️ **每条路径用不同 VIP**（《工程纪律》§3 第 8 条）：同 VIP 多路径会互顶路由槽，
// 让"条数类"断言假绿。
func TestPruneDeadRegistrationsOnlyEvictsDown(t *testing.T) {
	_, pm, host := b3Harness(t)
	mk := func(vip string, st int32) *directPath {
		t.Helper()
		p, _ := newTestPathNoPass(t, pm, host, vip, pathRoleInitiator)
		p.setState(st)
		return p
	}
	down := mk("192.168.30.10", pathStateDown) // 唯一应被摘的
	trial := mk("192.168.30.11", pathStateTrial)
	up := mk("192.168.30.12", pathStateUp)
	standby := mk("192.168.30.13", pathStateStandby)
	rejected := mk("192.168.30.14", pathStateRejected)
	reusing := mk("192.168.30.15", pathStateReusing)
	settling := mk("192.168.30.16", pathStateRejectedSettling)

	pm.pruneDeadRegistrations()

	if inTrialPaths(pm, down) {
		t.Fatal("state=Down 的死登记**必须**被兜底摘除（否则 pruneLoop 每拍扫到它 = 泄漏 + 空转）")
	}
	for _, c := range []struct {
		name string
		p    *directPath
	}{
		{"Trial", trial}, {"Up", up}, {"Standby", standby},
		{"Rejected", rejected}, {"Reusing", reusing}, {"RejectedSettling", settling},
	} {
		if !inTrialPaths(pm, c.p) {
			t.Fatalf("state=%s 的登记**不得**被兜底摘除（兜底白名单只有 Down）", c.name)
		}
	}
}
