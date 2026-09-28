package quic

// vpn-tool/backend/quic/trial_state_test.go
//
// ⭐ 1b-4 第一步（切片 2 · 前置原语）测试：
//   - trial 路径状态：alive()=true（探针继续跑）、pathStateName()="trial"（面板能看到）、
//     但仍**不进路由表** ⇒ sinkFor 返回 nil（数据走中继）；
//   - stableSince：离开 Up 即清零 ⇒「稳定 ≥5min」是**持续**语义而非累计；
//   - resetBackoffFor：两个 streak 一起清（且只清退避、不碰在飞路径）。

import (
	"testing"
	"time"
)

// TestTrialPathAliveNamedAndNotRouted ⭐ trial 的三个关键语义
func TestTrialPathAliveNamedAndNotRouted(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)

	// ① Up：在路由表里、alive、名字 direct
	if got := pathStateName(p.state.Load()); got != "direct" {
		t.Fatalf("Up 应命名 direct，实际 %q", got)
	}
	if !p.alive() {
		t.Fatal("Up 必须 alive")
	}
	if ch := pm.sinkFor(p.peer, planeTCP); ch == nil {
		t.Fatal("Up 必须能被 sinkFor 选中（前置条件）")
	}

	// ② trial：alive（探针/读写协程要继续跑）但**不再承载流量**
	p.setState(pathStateTrial)
	if !p.alive() {
		t.Fatal("trial 必须 alive —— 否则探针/读写协程会退出，试用期永远拿不到样本（Q2 的前提）")
	}
	if got := pathStateName(p.state.Load()); got != "trial" {
		t.Fatalf("trial 应命名 trial（面板/p2p:status 两条通道都靠它），实际 %q", got)
	}
	if ch := pm.sinkFor(p.peer, planeTCP); ch != nil {
		t.Fatal("trial 期间数据必须走中继（sinkFor 只认 Up）")
	}

	// ③ 对照：把路由摘掉再进 Up —— sinkFor 仍应为 nil（证明 ② 的 nil 不是「因为摘了路由」）
	pm.removeRoute(p.peer, p)
	p.setState(pathStateUp)
	if ch := pm.sinkFor(p.peer, planeTCP); ch != nil {
		t.Fatal("不在路由表里时 sinkFor 必须为 nil（对照组）")
	}
}

// TestStableSinceIsSustainedNotCumulative ⭐「稳定 ≥5min」必须是持续成功
//
//	Up 4min → 降级 → 再 Up 4min ⇒ **不清**（累计 8min 但从未连续 5min）；
//	连续 Up 5min ⇒ 清。
func TestStableSinceIsSustainedNotCumulative(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()
	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)

	// 进入 Up → 4 分钟（不够）
	p.setState(pathStateUp)
	since := p.stableSince.Load()
	if since == 0 {
		t.Fatal("进入 Up 必须置 stableSince（否则该机制永不触发 —— review 提醒 3）")
	}
	if p.stableEnoughToClearFailures(time.UnixMilli(since).Add(4 * time.Minute)) {
		t.Fatal("连续 4 分钟不应清失败记录")
	}
	// 5 分钟 → 够
	if !p.stableEnoughToClearFailures(time.UnixMilli(since).Add(5 * time.Minute)) {
		t.Fatal("连续 5 分钟应清失败记录")
	}

	// 降级（离开 Up）⇒ stableSince 清零
	p.setState(pathStateStandby)
	if p.stableSince.Load() != 0 {
		t.Fatal("离开 Up 必须清零 stableSince")
	}
	if p.stableEnoughToClearFailures(time.Now().Add(time.Hour)) {
		t.Fatal("不在 Up 状态时不得判定「稳定」")
	}

	// 再回到 Up：又只过了 4 分钟 ⇒ 仍不清（累计 8 分钟但从未连续 5 分钟）
	// ⚠️ 先睡 2ms：Windows 上两次 UnixMilli() 可能落在同一毫秒（踩过），
	//    不睡的话「时刻被刷新」这条断言会假失败。
	time.Sleep(2 * time.Millisecond)
	p.setState(pathStateUp)
	since2 := p.stableSince.Load()
	if since2 == since {
		t.Fatal("重新进入 Up 应刷新 stableSince 时刻")
	}
	if p.stableEnoughToClearFailures(time.UnixMilli(since2).Add(4 * time.Minute)) {
		t.Fatal("累计时长不算数：重新进入 Up 后 4 分钟不得清记录（必须是持续成功）")
	}
}

// TestResetBackoffForClearsBothStreaks ⭐ 5 条重置的统一落点
func TestResetBackoffForClearsBothStreaks(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()
	dst := ip4("192.168.30.12")

	// 造一条「两个 streak 都非 0」的记录
	pm.onPunchFailed("192.168.30.12", P2PReasonPunchTimeout) // step=1
	pm.onPunchFailed("192.168.30.12", P2PReasonPunchTimeout) // step=2
	pm.onPunchFailed("192.168.30.12", P2PReasonProbeTimeout) // qualityStep=1
	pm.mu.Lock()
	st := pm.backoff[dst]
	pm.mu.Unlock()
	if st.step != 2 || st.qualityStep != 1 {
		t.Fatalf("前置条件：两条 streak 应分别推进（step=2, qualityStep=1），实际 step=%d quality=%d",
			st.step, st.qualityStep)
	}

	pm.resetBackoffFor(dst)
	pm.mu.Lock()
	_, ok := pm.backoff[dst]
	pm.mu.Unlock()
	if ok {
		t.Fatal("resetBackoffFor 必须清掉该对端的整条记录（两个 streak 一起清）")
	}
	// 清完之后下一次失败应从第 0 档开始（证明 streak 真的归零）
	pm.onPunchFailed("192.168.30.12", P2PReasonPunchTimeout)
	pm.mu.Lock()
	st = pm.backoff[dst]
	pm.mu.Unlock()
	if st.step != 1 {
		t.Fatalf("重置后首次失败应回到第 0 档（step=1），实际 %d", st.step)
	}
}
