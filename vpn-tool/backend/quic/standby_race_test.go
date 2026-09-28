package quic

// vpn-tool/backend/quic/standby_race_test.go
//
// ⭐ 1b-4 收尾切片：`evalStandby` 的「检查与操作不互斥」修复（交付说明 §4.2.1 的处方 1）。
//
// 缺陷形态（与第三个缺陷同款）：
//
//	`evalStandby` 在开头读出 `state`，随后可能调用 `refreshRelayRTT()` —— 那是**一次同步的
//	隧道内信令往返**（几十 ms 到秒级）。窗口内路径若已 `demote`（连接断 / L1 / L2 / 被仲裁丢弃），
//	`evalStandby` 仍用**陈旧的局部 state** 决策 ⇒ 把 `Down` 覆写成 `Standby`（`alive()` 为 true
//	但连接已关）并 emit 假的 `quality-degraded`；反向（`exitStandby`）更坏：把 `Down` 覆写成
//	`Up`，而 `sinkFor` 只认 Up ⇒ **流量会被发给一条已关闭的连接**。
//
// 复现手法（照搬 `TestTrialCancelGateNoDoubleWrite` 的思路，但把「窗口」做成**可控**的）：
// 注入一个**会阻塞的 `signalQuery`**，让 `refreshRelayRTT` 停在中途；在窗口内并发 `demote`；
// 然后放行。断言「最终状态与事件不矛盾」。
//
// ⚠️ 必须让 refresh **只阻塞第一次**：`demote` 之后看门狗不再处理这条路径（`!alive()` 即返回），
// 但 `pm.close()` 之前的最后一拍仍可能走到 `refreshRelayRTT`；若每次都阻塞，用例会卡在收尾。

import (
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pathStubBlockLimit 桩的默认自重放行上界。
//
// ⚠️ 必须**远大于**用例刻意制造的阻塞窗口（毫秒级）：否则窗口还没关上就被自动放行，
// 用例会退化成「测不到竞态」（假绿）。5s 只作为「用例漏了 release」的最后一道保险。
const pathStubBlockLimit = 5 * time.Second

// blockingQueryHost 包一层 fakeHost，让**第一次** signalQuery 阻塞在测试手里。
//
// ⚠️ 为什么必须带 `stopped`（第 3 步-C 修复）：这个桩是**唯一**能永久阻塞的测试桩，
// 而 `pathHost.signalQuery` 的签名**不带 ctx** ⇒ 桩无法用 ctx 解除阻塞。
// 实测后果（`-race -count=50` 长跑，卡了 **29 分钟**）：
//
//	goroutine [chan receive, 29 minutes]
//	  (*blockingQueryHost).signalQuery        standby_race_test.go:41
//	  (*directPath).refreshRelayRTT           path.go:2865
//	  (*directPath).evalStandby               path.go:2910
//	  TestStandbyNormalTransitionsStillWork   standby_race_test.go:346
//
// 即：某个用例忘了（或来不及）`release`，该调用就永久挂住，还会把收尾的 `pm.close()` 一起拖死
// （`close()` 会 `p.wait()` 等这条路径的数据面协程，而它正等在 signalQuery 里）。
//
// `stopped` 由 `t.Cleanup` 关闭 ⇒ 除非用例**明确**要靠阻塞来制造窗口，否则任何调用都会在收尾时立刻放行。
type blockingQueryHost struct {
	*fakeHost
	entered chan struct{} // 已进入第一次查询（close 一次）
	release chan struct{} // 放行（close 一次）
	stopped chan struct{} // 收尾兜底（t.Cleanup 里 close）
	// ⭐ 自重放行上界（第 3 步-C）：**测试主体可能同步调用 `evalStandby()`**，
	//    此时它自己就卡在桩里、`t.Cleanup` 要等测试体返回才跑 ⇒ `stopped` 兜底来不及。
	//    实测（`-race -count=20` 全包，卡 21.5 分钟）：
	//      (*blockingQueryHost).signalQuery ← refreshRelayRTT ← evalStandby
	//      ← TestStandbyNormalTransitionsStillWork（**测试体本身**）
	//    ⇒ 桩必须**自己有界**：到上界就放行（并记一条告警，便于发现用例漏放行）。
	//    取值远大于用例刻意制造的窗口（毫秒级）⇒ 不破坏用例语义。
	blockLimit time.Duration
	once       sync.Once
	// releaseOnce / stopOnce 保证两个「放行」入口都幂等：用例显式调用与收尾兜底都可能触发，
	// 直接 close 两次会 panic（close of closed channel）。
	releaseOnce sync.Once
	stopOnce    sync.Once
	calls       atomic.Int32
}

// releaseNow 幂等放行第一次查询（用例显式调用与 t.Cleanup 兜底共用）。
func (h *blockingQueryHost) releaseNow() { h.releaseOnce.Do(func() { close(h.release) }) }

// stopNow 幂等触发兜底放行（收尾时用；用例也可显式调用以模拟「忘了放行」）。
func (h *blockingQueryHost) stopNow() { h.stopOnce.Do(func() { close(h.stopped) }) }

func (h *blockingQueryHost) signalQuery(vip string) (SignalPeer, error) {
	if h.calls.Add(1) == 1 {
		h.once.Do(func() { close(h.entered) })
		limit := h.blockLimit
		if limit <= 0 {
			limit = pathStubBlockLimit
		}
		t := time.NewTimer(limit)
		defer t.Stop()
		select {
		case <-h.release:
		case <-h.stopped: // 兜底一：收尾放行
		case <-t.C: // 兜底二：自重放行（测试体自己卡住时唯一能救的一条）
			log.Printf("⚠️ [测试] blockingQueryHost 自重放行（%v 内未被显式 release）——"+
				"该用例可能漏了 releaseNow()", limit)
		}
	}
	return h.fakeHost.signalQuery(vip)
}

// newStandbyRacePath 造一条已装表、Up 的路径（**不走试用期**，本文件考察的是 standby 判定），
// 并把 standby 参数压到测试友好；refresh 的阻塞窗口由 blockingQueryHost 控制。
func newStandbyRacePath(t *testing.T, peerRelayRTTMs int) (*pathManager, *directPath, *blockingQueryHost, *fakeConn) {
	t.Helper()
	fh := newFakeHost()
	fh.addPeer("192.168.30.12")
	fh.mu.Lock()
	fh.peers["192.168.30.12"] = SignalPeer{
		VIP: "192.168.30.12", Online: true, SignalReady: true, RelayRTTMs: peerRelayRTTMs,
	}
	fh.mu.Unlock()
	bh := &blockingQueryHost{
		fakeHost: fh,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		stopped:  make(chan struct{}),
	}

	// ⚠️ 两层放行，注册顺序关键（`t.Cleanup` 是 **LIFO**）：
	//   - `stop` 先注册 ⇒ **最后**执行：`pm.close()` 万一被桩卡住，它能解开（否则整个包卡死）；
	//   - `preCloseRelease` 后注册 ⇒ **先**执行：把任何悬着的 signalQuery 放行，
	//     再让 `pm.close()` 去优雅停机。少了它，close 自己就会被桩卡住。
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { bh.stopNow() }) }
	// 幂等放行由桩自己的 releaseOnce 保证（用例显式放行 + 这里兜底，可能都触发）
	preCloseRelease := func() { bh.releaseNow() }
	t.Cleanup(stop)
	pm := newPathManager(bh)
	// ⚠️ 时序契约：全部可注入参数在 run() 之前写好（见 path.go 的说明）。
	// checkInterval 放长 ⇒ 让**测试自己**驱动 evalStandby（不看门狗），并发才可控。
	pm.checkInterval = time.Hour
	pm.probeInterval = 20 * time.Millisecond
	pm.probeMissLimit = 1000
	pm.relayRttRefreshInterval = time.Millisecond
	pm.standbyRatio = 1.2
	pm.standbyExitRatio = 1.0
	pm.standbyDegradeFor = time.Millisecond
	pm.standbyEvalInterval = time.Millisecond
	// LIFO 执行序：preCloseRelease → pm.close → stop
	// （preCloseRelease 先把桩放行，再让 close 优雅停机；stop 最后兜底）
	t.Cleanup(pm.close)
	t.Cleanup(preCloseRelease)

	conn := newFakeConn()
	p, err := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"),
		role: pathRoleInitiator, conn: conn, myVIP: fh.vip,
		closers: []func() error{func() error { return nil }},
	})
	if err != nil {
		t.Fatalf("newDirectPath: %v", err)
	}
	p.setupTimeout = 300 * time.Millisecond
	p.passTrialForTest() // 直接进 Up（等价于先验后切已通过）
	p.run()
	waitFor(t, "控制流建立", func() bool {
		_, _, ctrl := p.streams()
		return ctrl != nil
	})
	return pm, p, bh, conn
}

// waitEntered 等「第一次 signalQuery 已进入」——即 refresh 窗口已打开。
func waitEntered(t *testing.T, bh *blockingQueryHost) {
	t.Helper()
	select {
	case <-bh.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("refreshRelayRTT 未走到 signalQuery（前置条件不成立：基准没被判定为过期？）")
	}
}

// TestBlockingQueryHostReleaseFallback ⭐ 第 3 步-C 回归（**有牙**）：
//
//	用例**故意不放行** `release` 时，`t.Cleanup` 里的兜底（`stopped`）必须能解除阻塞，
//	让收尾完成 —— 这是长跑里「卡 29 分钟」那个缺陷的直接对抗用例。
//
// 实测缺陷形态（`-race -count=50`，29 分钟）：
//
//	goroutine [chan receive, 29 minutes]
//	  (*blockingQueryHost).signalQuery   ← 只有 `<-h.release` 一条路
//	  (*directPath).refreshRelayRTT → evalStandby → TestStandbyNormalTransitionsStillWork
//
// 有牙验证方式：去掉 `signalQuery` 里的 `case <-h.stopped` ⇒ 本用例必然超时（桩永久阻塞）。
func TestBlockingQueryHostReleaseFallback(t *testing.T) {
	pm, p, bh, _ := newStandbyRacePath(t, 100)
	_ = pm

	p.relayRtt.Store(int64(100 * time.Millisecond))
	// 让基准过期 ⇒ 下一拍 evalStandby 必走 refreshRelayRTT（即 signalQuery）
	p.relayRttTriedAt.Store(time.Now().Add(-time.Hour).UnixMilli())

	done := make(chan struct{})
	go func() { defer close(done); p.evalStandby() }()
	waitEntered(t, bh) // 确认真的堵在桩里了

	// ⭐ 故意**不放行** release，只走兜底路径：等价于「用例挂了/忘了放行」的最坏情形
	bh.stopNow() // 幂等：收尾 cleanup 也会调它，不会 double close

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("兜底放行后 signalQuery 仍未返回 —— 桩会永久阻塞（第 3 步-C 修的正是这个）")
	}
}

// eventBaseline 统计事件条数（断言用**增量**：建路径时 passTrialForTest 本来就发一条 direct，
// 绝对值断言会把它算进来 —— 本文件第一版就是被这个绊倒的）。
//
// eventBaseline(host) 返回一个取增量的闭包：delta(P2PStateStandby) 表示「此刻比基线多几条」。
func eventBaseline(h *fakeHost, states ...string) func(string) int {
	counts := map[string]int{}
	h.mu.Lock()
	for _, e := range h.events {
		counts[e.State]++
	}
	h.mu.Unlock()
	return func(state string) int {
		h.mu.Lock()
		defer h.mu.Unlock()
		n := 0
		for _, e := range h.events {
			if e.State == state {
				n++
			}
		}
		return n - counts[state]
	}
}

// TestStandbyEnterRaceWithDemote ⭐ 主复现：#1 变体 —— refresh 窗口内 demote，
// `evalStandby` 不得把 Down 覆写成 Standby、不得 emit 假 standby。
func TestStandbyEnterRaceWithDemote(t *testing.T) {
	pm, p, bh, _ := newStandbyRacePath(t, 7)
	delta := eventBaseline(bh.fakeHost)
	p.relayRtt.Store(int64(100 * time.Millisecond))
	p.relayRttTriedAt.Store(time.Now().Add(-time.Hour).UnixMilli()) // 基准过期 ⇒ 必刷新
	p.rtt.Store(int64(500 * time.Millisecond))                      // 5× 中继 ⇒ 劣化判据成立
	p.degradeSince.Store(time.Now().Add(-time.Second).UnixMilli())  // 劣化「已持续」⇒ 会真的进 standby

	// ① 在测试 goroutine 里跑 evalStandby：它会停在 refreshRelayRTT 的信令往返里
	evalDone := make(chan struct{})
	go func() { defer close(evalDone); p.evalStandby() }()
	waitEntered(t, bh)

	// ② 窗口内路径结束（连接断/L1/L2/被仲裁丢弃）
	p.demote(P2PReasonDirectLost)
	select {
	case <-p.demoted():
	case <-time.After(5 * time.Second):
		t.Fatal("demote 未完成")
	}
	if got := p.state.Load(); got != pathStateDown {
		t.Fatalf("前置条件：demote 后应为 Down，实际 %v", got)
	}

	// ③ 放行 refresh ⇒ evalStandby 拿到「新鲜的中继 RTT」继续用**陈旧 state** 决策
	bh.releaseNow()
	select {
	case <-evalDone:
	case <-time.After(5 * time.Second):
		t.Fatal("evalStandby 未在放行后返回")
	}

	// ④ 断言：状态不得被覆写，事件不得出现假的 standby
	if got := p.state.Load(); got != pathStateDown {
		t.Fatalf("路径已降级，评测不得把它覆写成 %v（§4.2.1 的 Down→Standby 缺陷）", got)
	}
	if (*pm.routes.Load())[p.peer] == p {
		t.Fatal("已降级的路径不得还在路由表里")
	}
	if n := delta(P2PStateStandby); n != 0 {
		t.Fatalf("已降级的路径不得 emit 假 standby 事件（实际 %d 条）", n)
	}
	if n := delta(P2PStateFailed); n != 1 {
		t.Fatalf("应恰好一条 failed 事件（demoteOnce 保护），实际 %d", n)
	}
}

// TestStandbyExitRaceWithDemote ⭐ 主复现的**更坏那一半**：standby 复查窗口内 demote，
// `evalStandby` 不得把 Down 覆写成 Up（那会把流量发给一条已关闭的连接）。
func TestStandbyExitRaceWithDemote(t *testing.T) {
	// ⚠️ 对端返回的 relayRttMs 必须与**陈旧基准**同量级（都 ≥ 直连 RTT）：
	//    退出判据 `direct ≤ relay × exitRatio` 是用**刷新后**的 relay 算的；
	//    若陈旧基准 100ms、刷新后却变 7ms，判据会因 10 > 7 自己否决 ⇒
	//    `exitStandby` 根本不会被调用，用例就「假通过」了（第一版就是这么写的）。
	pm, p, bh, _ := newStandbyRacePath(t, 100)
	delta := eventBaseline(bh.fakeHost)
	// 置成 standby：直接写状态（本用例考察的是「退出判定」的竞态，不是进入路径）
	p.setState(pathStateStandby)
	p.relayRtt.Store(int64(100 * time.Millisecond))
	p.relayRttTriedAt.Store(time.Now().Add(-time.Hour).UnixMilli()) // 基准过期 ⇒ 必刷新
	p.rtt.Store(int64(10 * time.Millisecond))                       // ≤ 中继×1.0 ⇒ 恢复判据成立
	p.lastStandbyEval.Store(time.Now().Add(-time.Hour).UnixMilli()) // 复查间隔已过
	evalDone := make(chan struct{})
	go func() { defer close(evalDone); p.evalStandby() }()
	waitEntered(t, bh)

	p.demote(P2PReasonDirectLost)
	select {
	case <-p.demoted():
	case <-time.After(5 * time.Second):
		t.Fatal("demote 未完成")
	}

	bh.releaseNow()
	select {
	case <-evalDone:
	case <-time.After(5 * time.Second):
		t.Fatal("evalStandby 未在放行后返回")
	}

	if got := p.state.Load(); got != pathStateDown {
		t.Fatalf("路径已降级，复查不得把它覆写成 %v（会把流量发给已关闭的连接）", got)
	}
	if (*pm.routes.Load())[p.peer] == p {
		t.Fatal("已降级的路径不得回到路由表里（sinkFor 只认 Up ⇒ 会发给死连接）")
	}
	if ch := pm.sinkFor(p.peer, planeTCP); ch != nil {
		t.Fatal("sinkFor 必须返回 nil（不得把流量发给已关闭的连接）")
	}
	if n := delta(P2PStateDirect); n != 0 {
		t.Fatalf("已降级的路径不得 emit 假 direct 事件（实际 %d 条）", n)
	}
	if n := delta(P2PStateFailed); n != 1 {
		t.Fatalf("应恰好一条 failed 事件，实际 %d", n)
	}
}

// TestStandbyRaceRepeatedTwoInterleavings ⭐ 量测两种交错（照搬第三个缺陷复现用例的写法）：
// 上面两条用**可控窗口**把「demote 先赢」钉死（确定性 = 有牙的那一半）；
// 这里把两种交错各跑 25 轮，确认修复后**两种都收敛**、且各自的事件语义正确。
//
// ⚠️ 不能笼统地断言「不得出现 standby 事件」：若 `evalStandby` 先拿到状态（它赢），
//
//	进 standby 就是**合法**的，随后 demote 再把它带走 —— 那不是缺陷，是正常交错。
//	真正的缺陷形态是「demote 已经赢了、评测还在写」⇒ 只在该交错下断言「零 standby 事件」。
func TestStandbyRaceRepeatedTwoInterleavings(t *testing.T) {
	// ---------- 交错一：demote 先赢（评测被阻塞在 refresh 里）----------
	// 期望：不得覆写、不得发假 standby、恰一条 failed。
	for round := 0; round < 25; round++ {
		pm, p, bh, _ := newStandbyRacePath(t, 7)
		delta := eventBaseline(bh.fakeHost)
		p.relayRtt.Store(int64(100 * time.Millisecond))
		p.relayRttTriedAt.Store(time.Now().Add(-time.Hour).UnixMilli())
		p.rtt.Store(int64(500 * time.Millisecond))
		p.degradeSince.Store(time.Now().Add(-time.Second).UnixMilli())

		evalDone := make(chan struct{})
		go func() { defer close(evalDone); p.evalStandby() }()
		waitEntered(t, bh) // 评测已停在 refresh 窗口里
		p.demote(P2PReasonDirectLost)
		select {
		case <-p.demoted():
		case <-time.After(5 * time.Second):
			t.Fatalf("第 %d 轮：demote 未完成", round)
		}
		bh.releaseNow()
		select {
		case <-evalDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("第 %d 轮：evalStandby 未返回", round)
		}

		if got := p.state.Load(); got != pathStateDown {
			t.Fatalf("第 %d 轮[demote 先赢]：最终状态必须为 Down，实际 %v", round, got)
		}
		if (*pm.routes.Load())[p.peer] == p {
			t.Fatalf("第 %d 轮[demote 先赢]：已降级的路径不得还在路由表里", round)
		}
		if n := delta(P2PStateStandby); n != 0 {
			t.Fatalf("第 %d 轮[demote 先赢]：不得出现假 standby 事件（实际 %d 条）", round, n)
		}
		if n := delta(P2PStateFailed); n != 1 {
			t.Fatalf("第 %d 轮[demote 先赢]：failed 事件应恰好一条，实际 %d", round, n)
		}
	}

	// ---------- 交错二：两者自由竞争（不看门狗；放行时机逐轮变化）----------
	// 期望：**无论谁先赢都收敛到 Down**（demote 无前置门，必然跑完）；
	//       事件最多一条 standby（赢家合法发的那条）。
	for round := 0; round < 25; round++ {
		pm, p, bh, _ := newStandbyRacePath(t, 7)
		delta := eventBaseline(bh.fakeHost)
		p.relayRtt.Store(int64(100 * time.Millisecond))
		p.relayRttTriedAt.Store(time.Now().Add(-time.Hour).UnixMilli())
		p.rtt.Store(int64(500 * time.Millisecond))
		p.degradeSince.Store(time.Now().Add(-time.Second).UnixMilli())

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); p.evalStandby() }()
		go func() { defer wg.Done(); p.demote(P2PReasonDirectLost) }()
		// 放行可能早于/晚于 demote：两种交错都要收敛
		time.Sleep(time.Duration(round%3) * time.Millisecond)
		bh.releaseNow()
		wg.Wait()
		select {
		case <-p.demoted():
		case <-time.After(5 * time.Second):
			t.Fatalf("第 %d 轮：demote 未完成", round)
		}

		if got := p.state.Load(); got != pathStateDown {
			t.Fatalf("第 %d 轮[自由竞争]：demote 跑完后状态必须为 Down，实际 %v", round, got)
		}
		if (*pm.routes.Load())[p.peer] == p {
			t.Fatalf("第 %d 轮[自由竞争]：已降级的路径不得还在路由表里", round)
		}
		if n := delta(P2PStateStandby); n > 1 {
			t.Fatalf("第 %d 轮[自由竞争]：standby 事件最多一条（赢家那条），实际 %d", round, n)
		}
		if n := delta(P2PStateFailed); n != 1 {
			t.Fatalf("第 %d 轮[自由竞争]：failed 事件应恰好一条，实际 %d", round, n)
		}
	}
}

// TestStandbyNormalTransitionsStillWork ⭐ 反向保护（防「修竞态把正常路径也挡掉」）：
// 没有并发 demote 时，进/出 standby 必须照常工作，且返回值语义正确。
func TestStandbyNormalTransitionsStillWork(t *testing.T) {
	// ① 进入：Up → Standby（不阻塞 refresh：relay 基准新鲜）
	_, p, bh, _ := newStandbyRacePath(t, 7)
	delta := eventBaseline(bh.fakeHost)
	p.relayRtt.Store(int64(7 * time.Millisecond))
	p.relayRttTriedAt.Store(time.Now().UnixMilli())
	p.rtt.Store(int64(500 * time.Millisecond))
	p.degradeSince.Store(time.Now().Add(-time.Second).UnixMilli())
	p.evalStandby()
	if got := p.state.Load(); got != pathStateStandby {
		t.Fatalf("正常劣化必须进 standby，实际 %v", got)
	}
	if n := delta(P2PStateStandby); n != 1 {
		t.Fatalf("进 standby 应恰好一条事件，实际 %d", n)
	}
	// 再次评测（已不在 Up）⇒ 不得重复 emit
	p.degradeSince.Store(time.Now().Add(-time.Second).UnixMilli())
	if p.enterStandby(500, 7) {
		t.Fatal("已不在 Up 时 enterStandby 必须拒绝（否则会重复发事件）")
	}
	if n := delta(P2PStateStandby); n != 1 {
		t.Fatalf("重复调用不得再发 standby 事件，实际 %d", n)
	}

	// ② 退出：Standby → Up
	p.rtt.Store(int64(5 * time.Millisecond))
	p.lastStandbyEval.Store(time.Now().Add(-time.Hour).UnixMilli())
	p.evalStandby()
	if got := p.state.Load(); got != pathStateUp {
		t.Fatalf("质量恢复必须切回 Up，实际 %v", got)
	}
	if n := delta(P2PStateDirect); n != 1 {
		t.Fatalf("切回 direct 应恰好一条事件，实际 %d", n)
	}
	if p.exitStandby(5, 7) {
		t.Fatal("已不在 Standby 时 exitStandby 必须拒绝")
	}
	if n := delta(P2PStateDirect); n != 1 {
		t.Fatalf("重复调用不得再发 direct 事件，实际 %d", n)
	}
	// ③ 退出后 lastStandbyEval 必须清零：否则「下次进 standby 的首次复查」会被上一次的
	//    时间戳节流掉（退化为「一直留在 standby 直到周期到点」）
	if got := p.lastStandbyEval.Load(); got != 0 {
		t.Fatalf("退出 standby 必须清零 lastStandbyEval，实际 %d", got)
	}
}

// TestStandbyKeepsStableSinceContract ⭐ review 追问 1 的回归用例：
// **进入 Standby 必须清 `stableSince`；退出时必须重新置 now。**
//
// 为什么需要这条：CAS 只写 `state`，`stableSince` 得**另外补写**。第一版修复漏了「进 Standby 清 0」
// ⇒ 路径会带着 Up 期间正在跑的计时器停在 Standby（当前读侧靠 `state != Up` 挡住，所以不表现症状，
// 但「离开 Up ⇒ stableSince 清零」这条不变量已被破坏）。本用例把该不变量钉死：
//   - 如果哪天有人把「进 Standby 清 0」删掉 ⇒ 本用例红；
//   - 如果哪天有人把读侧顺序改成「先读 stableSince 再读 state」⇒ 那种误判需要
//     「state=Standby + stableSince=旧 Up 时刻」这个组合存在才可能发生 ⇒ 本用例同样会红。
func TestStandbyKeepsStableSinceContract(t *testing.T) {
	_, p, _, _ := newStandbyRacePath(t, 7)
	if p.stableSince.Load() == 0 {
		t.Fatal("前置条件：passTrialForTest 后应在 Up 且 stableSince 已置位")
	}

	// ① 进 Standby ⇒ stableSince 必须清 0（离开 Up 的转移）
	if !p.enterStandby(500, 7) {
		t.Fatal("前置条件：Up 时应能进 standby")
	}
	if got := p.stableSince.Load(); got != 0 {
		t.Fatalf("进入 standby 必须清零 stableSince（实际 %d）；"+
			"否则会带着 Up 期间的计时器停在 Standby，读侧一旦改序即误判为「已稳定 5min」", got)
	}
	// 同步双证：stableEnoughToClearFailures 也必须为 false（它是读侧唯一的判据）
	if p.stableEnoughToClearFailures(time.Now().Add(time.Hour)) {
		t.Fatal("standby 期间绝不得判定为「已稳定」")
	}
	// 直接调用也必须被状态判据挡住（`state != Up` 先行）
	if p.enterStandby(500, 7) {
		t.Fatal("已在 standby 时不得重复进入")
	}
	if got := p.stableSince.Load(); got != 0 {
		t.Fatalf("重复调用不得改动 stableSince，实际 %d", got)
	}

	// ② 出 Standby ⇒ stableSince 必须重新记「这一刻」（稳定计时从真正转 Up 开始）
	time.Sleep(2 * time.Millisecond) // 避开同毫秒（Windows 上踩过）
	if !p.exitStandby(5, 7) {
		t.Fatal("前置条件：Standby 时应能退出")
	}
	since := p.stableSince.Load()
	if since == 0 {
		t.Fatal("退出 standby（转 Up）必须重新置位 stableSince")
	}
	if p.stableEnoughToClearFailures(time.Now()) {
		t.Fatal("刚转 Up 不得立刻判定为已稳定")
	}
	if !p.stableEnoughToClearFailures(time.UnixMilli(since).Add(stableClearFailuresAfter)) {
		t.Fatal("重新置位后满窗口应判定为稳定（计时从转 Up 起算）")
	}
}

// TestStandbyRejectsDoNotTouchStateFields ⭐ 复核被拒时**不得**产生任何副作用：
// CAS 失败即「什么都没做」——不写 degradeSince / lastStandbyEval / stableSince，也不发事件。
func TestStandbyRejectsDoNotTouchStateFields(t *testing.T) {
	_, p, bh, _ := newStandbyRacePath(t, 7)
	delta := eventBaseline(bh.fakeHost)
	p.setState(pathStateDown)
	p.degradeSince.Store(12345)
	p.lastStandbyEval.Store(67890)

	if p.enterStandby(500, 7) || p.exitStandby(5, 7) {
		t.Fatal("Down 状态下两个动作都必须被拒")
	}
	if got := p.degradeSince.Load(); got != 12345 {
		t.Fatalf("被拒时不得改动 degradeSince，实际 %d", got)
	}
	if got := p.lastStandbyEval.Load(); got != 67890 {
		t.Fatalf("被拒时不得改动 lastStandbyEval，实际 %d", got)
	}
	if got := p.stableSince.Load(); got != 0 {
		t.Fatalf("被拒时不得改动 stableSince，实际 %d", got)
	}
	if n := delta(P2PStateStandby) + delta(P2PStateDirect); n != 0 {
		t.Fatalf("被拒时不得发出任何 standby/direct 事件，实际 %d 条", n)
	}
}

// TestStandbyDownNeverPromoted ⭐ 动作前复核的直接用例（不需要并发）：
// Down 状态下两个动作都必须拒绝 —— 这是 §4.2.1 缺陷的最小形态。
func TestStandbyDownNeverPromoted(t *testing.T) {
	_, p, bh, _ := newStandbyRacePath(t, 7)
	delta := eventBaseline(bh.fakeHost)
	p.setState(pathStateDown)

	if p.enterStandby(500, 7) {
		t.Fatal("Down 不得进 standby（会造出「还活着」的假象）")
	}
	if p.exitStandby(5, 7) {
		t.Fatal("Down 绝不得被推回 Up（会把流量发给已关闭的连接）")
	}
	if got := p.state.Load(); got != pathStateDown {
		t.Fatalf("状态必须保持 Down，实际 %v", got)
	}
	if n := delta(P2PStateStandby) + delta(P2PStateDirect); n != 0 {
		t.Fatalf("不得发出任何 standby/direct 事件，实际 %d 条", n)
	}
	// closed 之后同样不得被推回任何「活着」的状态
	p.close()
	if p.enterStandby(500, 7) || p.exitStandby(5, 7) {
		t.Fatal("已关闭的路径绝不得被推回 standby/Up")
	}
	if got := p.state.Load(); got != pathStateDown {
		t.Fatalf("关闭后状态必须保持 Down，实际 %v", got)
	}
}
