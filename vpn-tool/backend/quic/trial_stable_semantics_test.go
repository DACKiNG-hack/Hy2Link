package quic

// vpn-tool/backend/quic/trial_stable_semantics_test.go
//
// ⭐ 1b-4（review 语义确认 1）：`stableSince` 的置位语义
//
//	「稳定」= **已建立直连并稳定运行**；**trial 期间不算**。
//	⇒ setState(pathStateTrial) 必须清 0；直到 installRoute（setState(pathStateUp)）才置位，
//	   并且必须**重新计时**（不能沿用 trial 之前的旧时刻）。

import (
	"testing"
	"time"
)

func TestStableSinceSemanticsAroundTrial(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()
	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)

	// ① 当前新建路径是 Up（状态机本体尚未接线）⇒ stableSince 已置位
	if p.stableSince.Load() == 0 {
		t.Fatal("Up 状态必须置位 stableSince")
	}

	// ② 进入 trial（= 装表前）⇒ 必须清零：trial 不算「稳定运行」
	p.setState(pathStateTrial)
	if p.stableSince.Load() != 0 {
		t.Fatal("trial 期间不得保留 stableSince（语义：稳定 = 已建立直连并稳定运行）")
	}
	if p.stableEnoughToClearFailures(time.Now().Add(time.Hour)) {
		t.Fatal("trial 期间不得判定为「稳定」（否则会提前清掉失败记录）")
	}

	// ③ installRoute 时转 Up ⇒ 重新置位，且从这一刻重新计时
	time.Sleep(2 * time.Millisecond) // 避免与上一时刻落在同一毫秒（Windows 上踩过）
	p.setState(pathStateUp)
	since := p.stableSince.Load()
	if since == 0 {
		t.Fatal("转 Up（installRoute）时必须重新置位 stableSince")
	}
	if p.stableEnoughToClearFailures(time.UnixMilli(since).Add(4 * time.Minute)) {
		t.Fatal("重新置位后 4 分钟不算稳定（必须是本次连续 Up 的时长）")
	}
	if !p.stableEnoughToClearFailures(time.UnixMilli(since).Add(5 * time.Minute)) {
		t.Fatal("重新置位后连续 5 分钟应判定稳定")
	}
}
