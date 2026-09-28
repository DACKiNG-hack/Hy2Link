package quic

// vpn-tool/backend/quic/standby_test.go
//
// ⭐ 1b-2B 客户端侧测试：standby（质量降级）+ 周期重评估 + punch-busy。
//
// 对应你的 standby 专项验收：
//  1. 注入「直连 RTT 恒定劣于中继」→ 30s 内切 standby
//  2. 注入「直连恢复」→ 5 分钟内切回 direct
//  3. 注入「L1 降级」→ 关闭路径（不走 standby 分支）
//  4. standby 期间探针继续跑
//
// 以及 relayRttMs 兼容性与 punch-busy 的两条验收。

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// standbyTestPath 造一条路径并把时间参数压到测试友好（全部改**实例**字段）
func standbyTestPath(t *testing.T, host *fakeHost) (*pathManager, *directPath, *fakeConn) {
	t.Helper()
	pm := newPathManager(host)
	pm.standbyDegradeFor = 60 * time.Millisecond
	pm.standbyEvalInterval = 120 * time.Millisecond
	pm.relayRttRefreshInterval = 50 * time.Millisecond
	pm.probeInterval = 20 * time.Millisecond
	pm.checkInterval = 20 * time.Millisecond
	// ⚠️ 这些用例不模拟「对端回显探针」，所以把「无回显判死」的阈值调高：
	//    否则路径会在 ~60ms 内被 L1/L2 判死，测不到 standby（那条链路由
	//    TestNoEchoDemotesPath / TestL1StillClosesPathInStandby 专门覆盖）。
	pm.probeMissLimit = 1000
	p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	waitFor(t, "bulk 流建立", func() bool { return conn.bulkStream() != nil })
	return pm, p, conn
}

// setRTTs 注入直连 RTT 与中继估计（直接写原子量：判据的输入）
func setRTTs(p *directPath, direct, relay time.Duration) {
	p.rtt.Store(int64(direct))
	p.relayRtt.Store(int64(relay))
	p.relayRttTriedAt.Store(time.Now().UnixMilli())
}

// TestStandbyDefaultsMatchSpec 钉住 standby 的**默认值本身**（需求给定：1.2× / 30s / 5 分钟）。
//
// ⚠️ 上面几条机制测试都注入压缩后的时间（60ms/120ms/20ms），因此**测不出**
// 「默认值被顺手改成 3s 或 1.05×」这类回归 —— 那条路径只有本测试覆盖
// （与 TestIdleEvictDefaultsAreUserFriendly 同一分工）。
func TestStandbyDefaultsMatchSpec(t *testing.T) {
	if defaultStandbyRatio != 1.2 {
		t.Fatalf("劣化倍率默认值应为 1.2（relayRttMs 近似误差 10~20%%、阈值不能再小），实际 %v",
			defaultStandbyRatio)
	}
	// ⭐ review 追问 1：退出阈值必须**松于**进入阈值，形成死区（否则阈值附近来回切）
	if defaultStandbyExitRatio != 1.0 {
		t.Fatalf("退出倍率默认值应为 1.0，实际 %v", defaultStandbyExitRatio)
	}
	if defaultStandbyExitRatio >= defaultStandbyRatio {
		t.Fatalf("退出阈值(%v) 必须**小于**进入阈值(%v)：否则没有死区，会在阈值附近振荡",
			defaultStandbyExitRatio, defaultStandbyRatio)
	}
	if defaultStandbyDegradeFor != 30*time.Second {
		t.Fatalf("劣化持续门槛应为 30s（防 RTT 抖动误切），实际 %v", defaultStandbyDegradeFor)
	}
	if defaultStandbyEvalInterval != 5*time.Minute {
		t.Fatalf("standby 复查间隔应为 5 分钟，实际 %v", defaultStandbyEvalInterval)
	}
	if defaultRelayRttRefreshInterval != 5*time.Minute {
		t.Fatalf("中继 RTT 基准刷新间隔应为 5 分钟，实际 %v", defaultRelayRttRefreshInterval)
	}
	if defaultCheckInterval > time.Second {
		t.Fatalf("看门狗节拍 %v 太长：劣化判定的时间精度受它限制", defaultCheckInterval)
	}
	// 新建实例必须**采用**这些默认值（防「常量改了但忘了在 newPathManager 里接上」）
	pm := newPathManager(newFakeHost())
	defer pm.close()
	if pm.standbyRatio != defaultStandbyRatio ||
		pm.standbyExitRatio != defaultStandbyExitRatio ||
		pm.standbyDegradeFor != defaultStandbyDegradeFor ||
		pm.standbyEvalInterval != defaultStandbyEvalInterval ||
		pm.relayRttRefreshInterval != defaultRelayRttRefreshInterval ||
		pm.checkInterval != defaultCheckInterval {
		t.Fatalf("新建管理器未采用 standby 默认值：ratio=%v exit=%v degrade=%v eval=%v refresh=%v check=%v",
			pm.standbyRatio, pm.standbyExitRatio, pm.standbyDegradeFor, pm.standbyEvalInterval,
			pm.relayRttRefreshInterval, pm.checkInterval)
	}
}

// TestStandbyEmitsStandbyStatusNotFailure ⭐ 回归测试：standby **不是失败**。
//
// 背景（实测发现的 UX 缺陷）：进入 standby 时如果复用 `P2PStateFailed`，前端会
// 弹红色错误提示「直连失败：…」+ 记 warn 日志 —— 而这一刻系统**正在按设计工作**
// （直连还活着，只是更慢，流量已自动回中继）。这条测试把语义钉死：
//   - 进入 standby → State=standby、ReasonCode=quality-degraded（文案来自表内、
//     不能落到「直连不可用」兜底）、Retryable=false、Path=relay、PathState=standby；
//   - 同一过程中**不得**出现任何 failed 事件；
//   - 复查恢复 → State=direct、ReasonCode=ok-direct。
func TestStandbyEmitsStandbyStatusNotFailure(t *testing.T) {
	host := newFakeHost()
	pm, p, _ := standbyTestPath(t, host)
	defer pm.close()

	setRTTs(p, 100*time.Millisecond, 10*time.Millisecond)
	waitFor(t, "进入 standby", func() bool { return p.state.Load() == pathStateStandby })

	waitFor(t, "standby 状态事件", func() bool {
		_, ok := findStatusEvent(statusEvents(host), P2PStateStandby, P2PReasonQualityDegraded)
		return ok
	})
	evs := statusEvents(host)
	st, _ := findStatusEvent(evs, P2PStateStandby, P2PReasonQualityDegraded)
	if want := P2PReasonText(P2PReasonQualityDegraded); st.ReasonText != want {
		t.Fatalf("原因文案应取自文案表 %q，实际 %q（落到兜底会让用户看不懂）",
			want, st.ReasonText)
	}
	if st.Retryable {
		t.Fatal("standby 会自动复查并切回，不应标成可重试")
	}
	if st.Path != "relay" {
		t.Fatalf("standby 期间流量走中继，Path 应为 relay，实际 %q", st.Path)
	}
	if st.PathState != "standby" {
		t.Fatalf("PathState 应为 standby，实际 %q", st.PathState)
	}
	for _, e := range evs {
		if e.State == P2PStateFailed {
			t.Fatalf("standby 期间不得发 failed 事件（前端会弹错误提示）：%+v", e)
		}
	}

	// 复查恢复 → direct / ok-direct
	before := eventCount(host)
	setRTTs(p, 8*time.Millisecond, 10*time.Millisecond)
	waitFor(t, "恢复状态事件", func() bool {
		_, ok := findStatusEvent(statusEvents(host)[before:], P2PStateDirect, P2PReasonOKDirect)
		return ok
	})
}

// statusEvents 取状态事件快照（加锁拷贝，避免与后台 goroutine 竞态）
func statusEvents(host *fakeHost) []P2PStatus {
	host.mu.Lock()
	defer host.mu.Unlock()
	out := make([]P2PStatus, len(host.events))
	copy(out, host.events)
	return out
}

// eventCount 当前事件条数（用于「只看这之后的新事件」）
func eventCount(host *fakeHost) int {
	host.mu.Lock()
	defer host.mu.Unlock()
	return len(host.events)
}

// findStatusEvent 在快照里找一条 (状态, 原因码) 都匹配的事件
func findStatusEvent(evs []P2PStatus, state, reason string) (P2PStatus, bool) {
	for _, e := range evs {
		if e.State == state && e.ReasonCode == reason {
			return e, true
		}
	}
	return P2PStatus{}, false
}

// TestStandbyHysteresisHasDeadband ⭐ review 追问 1：进/出阈值之间必须有死区。
//
// 进入 direct > relay×1.2，退出 direct ≤ relay×1.0。把 RTT 放在死区里
// （relay=10ms → 退出阈值 10ms、进入阈值 12ms）：
//   - 100ms（10×）先进 standby；
//   - 调到 11ms（1.1×，**在死区内**）→ 跨过多个复查周期也必须**留在 standby**
//     （若进出共用一个阈值，这里就会切回 → 5 分钟一次的来回振荡）；
//   - 调到 9ms（0.9×，低于退出阈值）→ 才切回。
//
// 关键：死区断言之后要确认**期间真的复查过**（lastStandbyEval 有推进），
// 否则「没切回」可能只是评估循环没跑，测试就白绿了。
func TestStandbyHysteresisHasDeadband(t *testing.T) {
	host := newFakeHost()
	pm, p, _ := standbyTestPath(t, host)
	defer pm.close()

	setRTTs(p, 100*time.Millisecond, 10*time.Millisecond)
	waitFor(t, "进入 standby", func() bool { return p.state.Load() == pathStateStandby })
	enteredAt := p.lastStandbyEval.Load()

	// 死区内：11ms > 退出阈值(10ms)，且 < 进入阈值(12ms)
	setRTTs(p, 11*time.Millisecond, 10*time.Millisecond)
	time.Sleep(400 * time.Millisecond) // evalInterval 被压到 120ms → 期间应复查多次

	if got := p.state.Load(); got != pathStateStandby {
		t.Fatalf("死区内(1.1×)不得切回直连（否则阈值附近会来回振荡），实际 %v", got)
	}
	if now := p.lastStandbyEval.Load(); now <= enteredAt {
		t.Fatalf("复查时刻没有推进（%d → %d）：说明评估根本没跑，上面的「留在 standby」结论无效",
			enteredAt, now)
	}

	// 低于退出阈值 → 切回
	setRTTs(p, 9*time.Millisecond, 10*time.Millisecond)
	waitFor(t, "切回 direct", func() bool { return p.state.Load() == pathStateUp })
}

// TestStandbyDeadbandDoesNotEnterFromUp 死区的另一半：在 Up 状态下，
// 比值落在死区（1.1×）**不得**进入 standby（进入必须 > 1.2×）。
func TestStandbyDeadbandDoesNotEnterFromUp(t *testing.T) {
	host := newFakeHost()
	pm, p, _ := standbyTestPath(t, host)
	defer pm.close()

	setRTTs(p, 11*time.Millisecond, 10*time.Millisecond) // 1.1×，死区内
	time.Sleep(300 * time.Millisecond)                   // 远超 degradeFor(60ms)
	if got := p.state.Load(); got != pathStateUp {
		t.Fatalf("死区内(1.1×)不得进入 standby（进入门槛是 1.2×），实际 %v", got)
	}
}

// TestRelayRTTUnknownDoesNotSpamSignal ⭐ review 追问 1（CPU 开销的实证部分）：
// 服务端**一直返回 0**（旧服务端 / 对端刚连上）时，刷新必须照样被
// relayRttRefreshInterval 节流，绝不能每拍（1s）每路径打一次完整信令往返。
//
// 这条测试能发现「节流按『拿到值的时刻』算」的写法：那种写法下 relay 恒为 0
// 会绕过节流，300ms 内会打出 ~15 次查询（本用例 checkInterval=20ms）。
func TestRelayRTTUnknownDoesNotSpamSignal(t *testing.T) {
	host := newFakeHost()
	pm, p, _ := standbyTestPath(t, host)
	defer pm.close()

	host.mu.Lock()
	// 服务端认识这个对端，但中继 RTT 未知 → 永远返回 0
	host.peers["192.168.30.12"] = SignalPeer{
		VIP: "192.168.30.12", Online: true, SignalReady: true, RelayRTTMs: 0,
	}
	host.mu.Unlock()
	p.relayRtt.Store(0)
	p.relayRttTriedAt.Store(0)
	p.rtt.Store(int64(50 * time.Millisecond))

	// 刷新间隔被压到 50ms；300ms 内应约 7 次（若每拍都刷则是 ~15 次）
	time.Sleep(300 * time.Millisecond)
	n := host.queryCount()
	if n == 0 {
		t.Fatal("从未查询过信令：节流不该把「学会中继 RTT」这个功能也节掉")
	}
	if n > 8 {
		t.Fatalf("中继 RTT 未知时打信令过频：300ms 内 %d 次（应被 relayRttRefreshInterval 节流到 ~7 次）", n)
	}
}

// waitForLong 与 waitFor 相同，但允许自定义超时（真实时长验证要用分钟级）
func waitForLong(t *testing.T, what string, timeout time.Duration, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := start.Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return time.Since(start)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等待超时（%v）：%s", timeout, what)
	return 0
}

// TestStandbyRealTimingsManual 真实时长验证（review 追问 3）：用**产品默认值**跑满
// 「劣化 30s 才切」「5 分钟才复查」。默认跳过（约 5.5 分钟，不进常规门禁）。
//
// 显式开启（Windows PowerShell）：
//
//	$env:HY2_REAL_STANDBY_TEST="1"
//	go test ./backend/quic/ -run TestStandbyRealTimingsManual -v -timeout 12m
//
// ⚠️ 它验证的是**状态机 + 默认时长**（1.2× / 30s / 5min / 退出 1.0×），
// 不是真实 NAT/链路行为；真实链路请配合单机冒烟看 🐢/⚡ 日志。
func TestStandbyRealTimingsManual(t *testing.T) {
	if os.Getenv("HY2_REAL_STANDBY_TEST") == "" {
		t.Skip("真实时长验证默认跳过；用 HY2_REAL_STANDBY_TEST=1 显式开启（约 5.5 分钟）")
	}

	host := newFakeHost()
	pm := newPathManager(host) // ⭐ 不注入任何时间参数：用产品默认值
	pm.probeMissLimit = 1000   // 本用例不模拟探针回显，避免被 L2 判死
	defer pm.close()

	host.mu.Lock()
	host.peers["192.168.30.12"] = SignalPeer{
		VIP: "192.168.30.12", Online: true, SignalReady: true, RelayRTTMs: 10,
	}
	host.mu.Unlock()

	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	setRTTs(p, 100*time.Millisecond, 10*time.Millisecond) // 10× → 远超进入阈值

	enter := waitForLong(t, "进入 standby", 90*time.Second, func() bool {
		return p.state.Load() == pathStateStandby
	})
	if enter < 30*time.Second {
		t.Fatalf("进入 standby 用了 %v：必须「劣化持续满 30s」才切（提前说明持续门槛没生效）",
			enter.Round(time.Millisecond))
	}
	t.Logf("✅ 进入 standby 实测 = %v（默认门槛 30s）", enter.Round(time.Second))

	setRTTs(p, 5*time.Millisecond, 10*time.Millisecond) // 5ms ≤ 10ms×1.0 → 满足退出条件
	back := waitForLong(t, "切回 direct", 7*time.Minute, func() bool {
		return p.state.Load() == pathStateUp
	})
	if back < 4*time.Minute+50*time.Second {
		t.Fatalf("切回直连用了 %v：复查间隔应约 5 分钟", back.Round(time.Second))
	}
	t.Logf("✅ 切回直连实测 = %v（默认复查间隔 5min）", back.Round(time.Second))
}

// TestStandbyOnDegradedDirectRTT ① 直连持续劣于中继 → 切 standby（只切流量、连接保留）
func TestStandbyOnDegradedDirectRTT(t *testing.T) {
	host := newFakeHost()
	pm, p, conn := standbyTestPath(t, host)
	defer pm.close()

	// 直连 100ms，中继估计 10ms → 100 > 10×1.2 ⇒ 劣化
	setRTTs(p, 100*time.Millisecond, 10*time.Millisecond)

	waitFor(t, "进入 standby", func() bool { return p.state.Load() == pathStateStandby })
	if conn.Context().Err() != nil {
		t.Fatal("standby 不该关闭连接（要保留，等恢复）")
	}
	// 流量必须回中继：sinkFor 只认 Up
	if ch := pm.sinkFor(p.peer, planeTCP); ch != nil {
		t.Fatal("standby 期间不应再走直连队列（流量回中继）")
	}
	// 路径仍在路由表里（Paths 能看到 standby）
	infos := pm.Paths()
	if len(infos) != 1 || infos[0].State != "standby" {
		t.Fatalf("快照应显示 standby，实际 %+v", infos)
	}
}

// TestStandbyRecoversToDirect ② 恢复 → 复查后切回 direct（连接一直活着，零重建）
func TestStandbyRecoversToDirect(t *testing.T) {
	host := newFakeHost()
	pm, p, _ := standbyTestPath(t, host)
	defer pm.close()

	setRTTs(p, 100*time.Millisecond, 10*time.Millisecond)
	waitFor(t, "先进入 standby", func() bool { return p.state.Load() == pathStateStandby })

	// 直连恢复到 8ms ≤ 10×1.2 → 下一次复查应切回
	setRTTs(p, 8*time.Millisecond, 10*time.Millisecond)
	waitFor(t, "切回 direct", func() bool { return p.state.Load() == pathStateUp })
	if ch := pm.sinkFor(p.peer, planeTCP); ch == nil {
		t.Fatal("切回 direct 后流量必须重新走直连")
	}
}

// TestL1StillClosesPathInStandby ③ L1 走自己的分支：standby 期间连接关闭 → 关路径（不是 standby）
func TestL1StillClosesPathInStandby(t *testing.T) {
	host := newFakeHost()
	pm, p, conn := standbyTestPath(t, host)
	defer pm.close()

	setRTTs(p, 100*time.Millisecond, 10*time.Millisecond)
	waitFor(t, "先进入 standby", func() bool { return p.state.Load() == pathStateStandby })

	// L1-c：QUIC 连接被关（idle timeout / CONNECTION_CLOSE）
	_ = conn.CloseWithError(0, "test close")

	select {
	case <-p.demoted():
	case <-time.After(5 * time.Second):
		t.Fatal("standby 期间遇到 L1 也必须关闭路径（不能只停在中继）")
	}
	if _, ok := pm.routeVIP(p.peer); ok {
		t.Fatal("L1 之后路由必须已摘除")
	}
	pm.mu.Lock()
	_, backed := pm.backoff[p.peer]
	pm.mu.Unlock()
	if !backed {
		t.Fatal("L1 之后必须排退避（standby 分支不排退避）")
	}
}

// TestProbesContinueDuringStandby ④ standby 期间探针不中断（周期重评估的基础）
func TestProbesContinueDuringStandby(t *testing.T) {
	host := newFakeHost()
	pm, p, conn := standbyTestPath(t, host)
	defer pm.close()

	setRTTs(p, 100*time.Millisecond, 10*time.Millisecond)
	waitFor(t, "先进入 standby", func() bool { return p.state.Load() == pathStateStandby })

	countProbes := func() int {
		n := 0
		for _, f := range conn.ctrlStream().frames() {
			var m pathCtrlMsg
			if json.Unmarshal(f, &m) == nil && m.Type == ctrlProbe {
				n++
			}
		}
		return n
	}
	before := countProbes()
	time.Sleep(150 * time.Millisecond) // 跨过好几个探测周期
	if after := countProbes(); after <= before {
		t.Fatalf("standby 期间探针必须继续跑（前 %d 后 %d）", before, after)
	}
	if p.state.Load() != pathStateStandby {
		t.Fatal("探针继续跑不应把状态改回 direct（判据只看 RTT）")
	}
}

// TestNoStandbyWhenRelayRTTUnknown relayRttMs=0（旧服务端 / 服务端不知道）→ 不做 standby
func TestNoStandbyWhenRelayRTTUnknown(t *testing.T) {
	host := newFakeHost()
	pm, p, _ := standbyTestPath(t, host)
	defer pm.close()
	host.mu.Lock()
	host.peers["192.168.30.12"] = SignalPeer{VIP: "192.168.30.12", Online: true, SignalReady: true, RelayRTTMs: 0}
	host.mu.Unlock()

	// 直连很慢，但中继估计未知
	p.rtt.Store(int64(500 * time.Millisecond))
	p.relayRtt.Store(0)
	p.relayRttTriedAt.Store(0)

	time.Sleep(200 * time.Millisecond)
	if p.state.Load() != pathStateUp {
		t.Fatal("中继 RTT 未知时不得进入 standby（等价 1b-2A 行为）")
	}
}

// TestRelayRTTRefreshedFromSignalQuery 基准来自信令查询（服务端下发的 relayRttMs）
func TestRelayRTTRefreshedFromSignalQuery(t *testing.T) {
	host := newFakeHost()
	pm, p, _ := standbyTestPath(t, host)
	defer pm.close()

	host.mu.Lock()
	host.peers["192.168.30.12"] = SignalPeer{
		VIP: "192.168.30.12", Online: true, SignalReady: true, RelayRTTMs: 42,
	}
	host.mu.Unlock()

	p.refreshRelayRTT()
	if got := time.Duration(p.relayRtt.Load()); got != 42*time.Millisecond {
		t.Fatalf("relayRtt 应为 42ms，实际 %v", got)
	}
	if p.relayRttTriedAt.Load() == 0 {
		t.Fatal("刷新后必须记录时刻（用于「基准过期」判断）")
	}
}

// TestRelayRTTBaselineStalenessTriggersRefresh 基准超过 5 分钟未刷新 → 判断前先查一次
func TestRelayRTTBaselineStalenessTriggersRefresh(t *testing.T) {
	host := newFakeHost()
	pm, p, _ := standbyTestPath(t, host)
	defer pm.close()

	host.mu.Lock()
	host.peers["192.168.30.12"] = SignalPeer{
		VIP: "192.168.30.12", Online: true, SignalReady: true, RelayRTTMs: 7,
	}
	host.mu.Unlock()

	// 基准很旧（1 小时前）→ 应触发刷新
	p.relayRtt.Store(int64(999 * time.Millisecond))
	p.relayRttTriedAt.Store(time.Now().Add(-time.Hour).UnixMilli())
	p.rtt.Store(int64(5 * time.Millisecond))
	p.evalStandby()

	if got := time.Duration(p.relayRtt.Load()); got != 7*time.Millisecond {
		t.Fatalf("过期基准应被刷新成 7ms，实际 %v", got)
	}
	if n := host.queryCount(); n == 0 {
		t.Fatal("过期基准在判断前必须先查一次信令")
	}
}

// TestResponderCapMirror ⭐ 客户端上限必须与服务端镜像常量 relayMaxResponderInvites 一致。
//
// 服务端侧对应测试：`vpn-server/quic/b2b_test.go` 的 `TestResponderCapMirrorIsTwo`。
func TestResponderCapMirror(t *testing.T) {
	if punchMaxResponder != 2 {
		t.Fatalf("punchMaxResponder 必须与服务端 relayMaxResponderInvites 一致（=2），实际 %d",
			punchMaxResponder)
	}
}

// TestCooldownShorterForBusy 「忙」用短冷却（30s），不是失败台阶的 60s
func TestCooldownShorterForBusy(t *testing.T) {
	if cooldownForReason(P2PReasonPeerBusy) != punchBusyCooldown {
		t.Fatal("peer-busy 应使用 30s 短冷却")
	}
	if cooldownForReason(P2PReasonRateLimited) != punchBusyCooldown {
		t.Fatal("rate-limited 也应使用短冷却（都是暂时状态）")
	}
	if cooldownForReason(P2PReasonPunchTimeout) != punchCooldown {
		t.Fatal("真失败应使用完整冷却")
	}
}

// TestPunchBusyPushFailsLiveAttempt punch-busy 推送 → 立即失败该 attempt，原因码 peer-busy
func TestPunchBusyPushFailsLiveAttempt(t *testing.T) {
	rec := newStatusRecorder()
	cli := newSignalTestClient()
	mgr := attachLoopbackManager(t, cli, rec)

	// 造一个「正在等对端」的发起方会话（不发包，只验证推送处理）
	s := mgr.newSession("0123456789abcdef", "192.168.30.12", pathRoleInitiator,
		10000, strings.Repeat("ab", 32), "", netip.AddrPort{})
	s.trigger = P2PTriggerTraffic
	mgr.mu.Lock()
	mgr.sessions[s.id] = s
	mgr.mu.Unlock()
	s.state.Store(P2PStateIntent)

	mgr.handleBusyPush(signalMessage{Type: signalMsgTypePunchBusy, AttemptID: s.id, PeerVIP: "192.168.30.12"})

	select {
	case <-s.doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("收到 punch-busy 必须立即结束该 attempt")
	}
	if r, _ := s.reason.Load().(string); r != P2PReasonPeerBusy {
		t.Fatalf("原因码应为 peer-busy，实际 %q", r)
	}
	if got := rec.lastReason("192.168.30.12"); got != P2PReasonPeerBusy {
		t.Fatalf("应发出带 peer-busy 的状态事件，实际 %q", got)
	}
}

// TestPunchBusyPushIgnoredWhenNotMine 不属于自己的 attemptId → 忽略（不得影响别的会话/panic）
func TestPunchBusyPushIgnoredWhenNotMine(t *testing.T) {
	rec := newStatusRecorder()
	cli := newSignalTestClient()
	mgr := attachLoopbackManager(t, cli, rec)

	mgr.handleBusyPush(signalMessage{Type: signalMsgTypePunchBusy, AttemptID: "ffffffffffffffff"})
	if got := rec.lastReason("192.168.30.12"); got != "" {
		t.Fatalf("无对应会话时不应产生状态事件，实际 %q", got)
	}
}

// TestPunchBusyIsDisjointFromOtherSets 三集合两两不相交（客户端侧锁）
func TestPunchBusyIsDisjointFromOtherSets(t *testing.T) {
	req := map[string]bool{}
	resp := map[string]bool{}
	for _, t1 := range signalRequestTypes {
		req[t1] = true
	}
	for _, t1 := range signalResponseTypes {
		resp[t1] = true
	}
	for _, push := range signalPushTypes {
		if req[push] || resp[push] {
			t.Fatalf("推送类型 %q 与请求/应答集合相交（违反约束 1）", push)
		}
	}
	if !isPunchPushType(signalMsgTypePunchBusy) {
		t.Fatal("punch-busy 必须被 isPunchPushType 认成打洞推送（否则不会被 punchManager 处理）")
	}
	if !strings.Contains(signalMsgTypePunchBusy, "busy") {
		t.Fatal("类型名应含 busy（便于日志排障）")
	}
}
