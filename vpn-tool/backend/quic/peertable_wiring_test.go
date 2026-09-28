package quic

// vpn-tool/backend/quic/peertable_wiring_test.go
//
// ⭐ 1b-4 第 2 步-A（I3）：质量表**接线**的用例。
//
// 覆盖实施计划 §5 里属于 I3 的四组：
//   - 写表映射（**只写四类**；`peer-unreachable` 等绝不写 —— 对端离线≠链路质量）
//   - 软跳过四分支（D3：首次放行 → 用掉后跳过 → 过期恢复 → 成功覆盖为「好」）
//   - 重连不清空（连续 3 次 stop/start，同一 client 的表实例不变）
//   - 等价窗口（§9.2.2：表空 ⇒ 与旧版逐字等价；写入 ⇒ 生效；过期 ⇒ 回到等价）
//   - 试用期接线（命中「质量好」⇒ 5s / 2 样本）

import (
	"math"
	"net/netip"
	"testing"
	"time"
)

// ---------- 写表映射（只写四类） ----------

// TestPoorQualityLossThresholdMirrorsTrial ⭐ 追问 4：质量表的「差」判据**由试用期常量推导**，
// 不另立 10%/90%，且边界语义与试用期**严格一致**（恰好 90% 的成功率 = 恰好 10% 丢包 = 不算差）。
//
// 这条用例的牙：
//   - 若有人把 `isPoorQualityLoss` 改回硬编码 10，`trialMinProbeSuccess` 变了它就不同步 ⇒ 红；
//   - 若有人把 `>` 写成 `>=`（或试用期改成 `>`），边界那条会红。
func TestPoorQualityLossThresholdMirrorsTrial(t *testing.T) {
	// 阈值本身由常量推出（0.90 ⇒ 丢包 > 10%）
	lossLimit := int(math.Ceil((1 - trialMinProbeSuccess) * 100))

	// 边界：恰好等于阈值 ⇒ **不算差**（与试用期 `success >= 0.90` 判「好」严格互补）
	if isPoorQualityLoss(lossLimit) {
		t.Fatalf("丢包恰好 %d%%（成功率恰好 %.0f%%）不得判「差」——试用期此时判「好」，两者必须互补",
			lossLimit, trialMinProbeSuccess*100)
	}
	// 超过阈值 1% ⇒ 算差
	if !isPoorQualityLoss(lossLimit + 1) {
		t.Fatalf("丢包 %d%%（超过阈值 %d%%）应判「差」", lossLimit+1, lossLimit)
	}
	// 无丢包 ⇒ 好
	if isPoorQualityLoss(0) {
		t.Fatal("零丢包不得判「差」")
	}
	// 全丢 ⇒ 差
	if !isPoorQualityLoss(100) {
		t.Fatal("100%% 丢包必须判「差」")
	}

	// 与试用期判据**逐点对照**（同一组 (成功, 丢包) 在两个判据下必须互补）
	for _, loss := range []int{0, 5, 10, 11, 50, 100} {
		success := float64(100-loss) / 100
		goodByTrial := trialSampleGood(10*time.Millisecond, 100*time.Millisecond, success)
		poorByTable := isPoorQualityLoss(loss)
		if goodByTrial == poorByTable {
			t.Fatalf("丢包 %d%%（成功率 %.2f）：试用期判「好」=%v，质量表判「差」=%v —— 两者必须互补",
				loss, success, goodByTrial, poorByTable)
		}
	}
}

// TestNotePeerQualityOnlyWritesFourCategories ⭐ §8-1 裁决的落地：
// 只有四类结果写表；尤其 **peer-unreachable 必须不写**（否则对端下次上线会被误跳过）。
func TestNotePeerQualityOnlyWritesFourCategories(t *testing.T) {
	peerVIP := "192.168.30.12"
	dst := ip4(peerVIP)

	cases := []struct {
		name     string
		reason   string
		gotAll   bool // 探针全部有回显
		want     bool // 是否应写表
		wantKind peerResultKind
	}{
		{"探针成功", P2PReasonOKDirect, true, true, peerGood},
		{"probe-timeout ⇒ 差", P2PReasonProbeTimeout, false, true, peerPoor},
		{"direct-lost ⇒ 差", P2PReasonDirectLost, false, true, peerPoor},
		{"quality-poor ⇒ 差", P2PReasonQualityPoor, false, true, peerPoor},
		{"nat-symmetric ⇒ 不可打洞", P2PReasonNATSymmetric, false, true, peerUnpunchable},
		{"punch-timeout ⇒ 不可打洞", P2PReasonPunchTimeout, false, true, peerUnpunchable},
		{"peer-no-punch-addr ⇒ 不可打洞", P2PReasonPeerNoPunchAddr, false, true, peerUnpunchable},
		// ↓↓↓ 以下一律**不写**（用户特别强调 peer-unreachable）
		{"peer-unreachable 不写", P2PReasonPeerUnreachable, false, false, 0},
		{"peer-not-ready 不写", P2PReasonPeerNotReady, false, false, 0},
		{"attempt-timeout 不写", P2PReasonAttemptTimeout, false, false, 0},
		{"local-no-punch-addr 不写", P2PReasonLocalNoPunchAddr, false, false, 0},
		{"peer-busy 不写", P2PReasonPeerBusy, false, false, 0},
		{"rate-limited 不写", P2PReasonRateLimited, false, false, 0},
		{"cancelled 不写", P2PReasonCancelled, false, false, 0},
		{"fingerprint-mismatch 不写", P2PReasonFingerprintMismatch, false, false, 0},
		{"server-p2p-disabled 不写", P2PReasonServerP2PDisabled, false, false, 0},
		{"direct-handshake-failed 不写", P2PReasonDirectHandshakeFailed, false, false, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
			mgr := newPunchManager(c)
			tbl := newPeerTable()
			mgr.setQualityTable(tbl)

			s := mgr.newSession("0123456789abcdef", peerVIP, pathRoleInitiator,
				3000, "seed", "", netip.MustParseAddrPort("1.2.3.4:30001"))
			s.reason.Store(tc.reason)
			s.rttDirect.Store(int64(9 * time.Millisecond))
			s.probeTotal.Store(int32(punchProbeRounds))
			if tc.gotAll {
				s.probeGot.Store(int32(punchProbeRounds))
			}
			s.peerNATType.Store(string(NATSymmetric))

			mgr.notePeerQuality(s)

			q, ok := tbl.Peek(dst)
			if ok != tc.want {
				t.Fatalf("原因 %q 写表期望 %v，实际 %v（q=%+v）", tc.reason, tc.want, ok, q)
			}
			if tc.want && q.Kind != tc.wantKind {
				t.Fatalf("原因 %q 的结论应为 %v，实际 %v", tc.reason, tc.wantKind, q.Kind)
			}
			if tc.want && q.NatType != string(NATSymmetric) {
				t.Fatalf("应带上诊断用的对端 NAT 类型，实际 %q", q.NatType)
			}
		})
	}
}

// TestNotePeerQualityNoTableIsSafe 表未注入（P2P 未生效 / 单测省略）⇒ 不 panic、不记录
func TestNotePeerQualityNoTableIsSafe(t *testing.T) {
	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	mgr := newPunchManager(c) // 故意不注入表
	s := mgr.newSession("0123456789abcdef", "192.168.30.12", pathRoleInitiator,
		3000, "seed", "", netip.MustParseAddrPort("1.2.3.4:30001"))
	s.reason.Store(P2PReasonOKDirect)
	mgr.notePeerQuality(s) // 不得 panic（与「表为空」等价）
}

// ---------- 软跳过四分支（D3） ----------

// softSkipHarness 造一个「已装表 Up 的路径 + 已注入空表」的管理器，用于驱动 handleTrigger
func softSkipHarness(t *testing.T) (*pathManager, *fakeHost, *peerTable) {
	t.Helper()
	host := newFakeHost()
	host.addPeer("192.168.30.12")
	pm := newPathManager(host)
	// ⚠️ 时序契约：可注入参数在 start() 之前写好
	pm.tiebreakDelay = time.Millisecond
	tbl := newPeerTable()
	pm.setQualityTable(tbl)
	t.Cleanup(pm.close)

	// ⚠️ 第 3 步-D：用 `newTestPathOwned` —— 本用例下面会 `pm.replaceRoutes(nil)`
	//    把路径与管理器解绑，普通 `newTestPath` 造出的路径会因此永不关闭（协程泄漏）。
	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	if p.state.Load() != pathStateUp {
		t.Fatalf("前置条件：路径应在 Up，实际 %v", p.state.Load())
	}
	return pm, host, tbl
}

// clearBackoffFor 清掉该对端在 pathManager 里的退避窗口。
//
// ⚠️ 为什么必须清：`attemptFor` 在失败后调 `setBackoffTransient`（30s），
// 而 `handleTrigger` 的**退避门**在软跳过门之前 ⇒ 不清就测不到「第二次触发」。
// 这不是绕过被测逻辑：软跳过与退避是两个独立机制，用例只考察前者。
func clearBackoffFor(pm *pathManager, dst [4]byte) {
	pm.mu.Lock()
	delete(pm.backoff, dst)
	pm.mu.Unlock()
}

// TestHandleTriggerSoftSkipFourBranches ⭐ D3 软跳过的四个分支
func TestHandleTriggerSoftSkipFourBranches(t *testing.T) {
	pm, host, tbl := softSkipHarness(t)
	dst := ip4("192.168.30.12")

	// 前置：先删掉 newTestPath 装的路由（本用例只考察 trigger 门，不考察分流）
	pm.replaceRoutes(nil)

	// 记一条「不可打洞」（nat-symmetric）
	tbl.Record(dst, peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonNATSymmetric})

	// ① 首次触发 ⇒ **放行**（打洞真的被触发）
	pm.handleTrigger(dst)
	waitFor(t, "首次触发应真的发起打洞", func() bool { return host.punchCount() == 1 })
	q, _ := tbl.Peek(dst)
	if !q.ForcedRetryUsed {
		t.Fatal("首次放行后必须已消费掉那 1 次强制重试（在提交点原子消费）")
	}

	// ② 用掉之后再触发 ⇒ **跳过**（不发 intent）
	clearBackoffFor(pm, dst)
	pm.handleTrigger(dst)
	time.Sleep(80 * time.Millisecond)
	if n := host.punchCount(); n != 1 {
		t.Fatalf("强制重试已用掉后不得再发起打洞，实际累计 %d 次", n)
	}

	// ③ 记录换成「好」（等价于过期后重新侦察成功）⇒ 恢复：不再软跳过
	tbl.Record(dst, peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect, RTTMs: 5})
	clearBackoffFor(pm, dst)
	pm.handleTrigger(dst)
	waitFor(t, "记录变为「好」后应恢复打洞", func() bool { return host.punchCount() == 2 })

	// ④ 成功的真实打洞把记录覆盖为「好」⇒ 不再命中 Unpunchable
	if _, ok := tbl.Unpunchable(dst); ok {
		t.Fatal("覆盖为「好」后不得再算「不可打洞」")
	}
	if q, ok := tbl.Peek(dst); !ok || q.Kind != peerGood {
		t.Fatal("覆盖为「好」后应命中 Kind==peerGood")
	}
}

// TestHandleTriggerSoftSkipExpiryRecovers ⭐ 分支③的另一半：记录**过期**即恢复
func TestHandleTriggerSoftSkipExpiryRecovers(t *testing.T) {
	pm, host, tbl := softSkipHarness(t)
	dst := ip4("192.168.30.12")
	pm.replaceRoutes(nil)

	clk := newFakeClock()
	tbl.setClock(clk.now)
	tbl.Record(dst, peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonNATSymmetric})
	if !tbl.TryConsumeForcedRetry(dst) {
		t.Fatal("前置：应能用掉那次强制重试")
	}
	// 用掉 ⇒ 跳过
	clearBackoffFor(pm, dst)
	pm.handleTrigger(dst)
	time.Sleep(60 * time.Millisecond)
	if n := host.punchCount(); n != 0 {
		t.Fatalf("用掉后应跳过，实际发起 %d 次", n)
	}
	// 过期 ⇒ 记录消失 ⇒ 恢复
	clk.advance(peerTTLUnpunchableSticky + time.Second)
	clearBackoffFor(pm, dst)
	pm.handleTrigger(dst)
	waitFor(t, "记录过期后应恢复打洞", func() bool { return host.punchCount() == 1 })
}

// ---------- 重连不清空（§9.2.1） ----------

// TestQualityTableSurvivesReconnect ⭐ 拍板项：**重连不清空**（连续 3 次 stop/start）
func TestQualityTableSurvivesReconnect(t *testing.T) {
	c := NewHysteria2Client("127.0.0.1", 443, 8444, "u", "p", true, "", "", true)
	c.p2pServerEnabled = true
	c.p2pLocalEnabled = true

	tbl := c.qualityTable()
	dst := ip4("192.168.30.12")
	tbl.Record(dst, peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect, RTTMs: 7})
	before, _ := tbl.Peek(dst)

	for i := 0; i < 3; i++ {
		c.stopPunchManager()
		c.startPunchManager()
		if got := c.qualityTable(); got != tbl {
			t.Fatalf("第 %d 次重连换了新表实例（重连清空 ⇒ 破坏拍板项）", i+1)
		}
		q, ok := tbl.Peek(dst)
		if !ok {
			t.Fatalf("第 %d 次重连后记录丢失", i+1)
		}
		if !q.Expire.Equal(before.Expire) {
			t.Fatalf("第 %d 次重连不得改动 TTL：前 %v 后 %v", i+1, before.Expire, q.Expire)
		}
		// 两个短生命周期管理器都必须拿到**同一张**表
		pm := c.pathManagerOrNil()
		if pm == nil {
			t.Fatalf("第 %d 次重连后应有 pathManager", i+1)
		}
		if pm.qualityTable() != tbl {
			t.Fatalf("第 %d 次重连后 pathManager 持有的不是同一张表", i+1)
		}
	}
	c.stopPunchManager()
}

// ---------- 等价窗口（§9.2.2） ----------

// TestQualityTableEquivalenceWindow ⭐ 质量表**不影响试用期**（A1，2026-09-27 改写）
//
//	旧版用例断言「命中质量表 ⇒ 试用期 5s」；A1 起**试用期与质量表解耦**
//	（`hasGoodQualityRecord` / `trialWindowShort` / `trialWindowFor` 均已删除）
//	⇒ 本用例改写为新契约：**无论表里有什么，窗口恒为 `trialWindowNormal`（或采样下界）**，
//	而质量表对**软跳过**（真正还在用它的地方）依然生效。
func TestQualityTableEquivalenceWindow(t *testing.T) {
	host := newFakeHost()
	host.addPeer("192.168.30.12") // 信号门要求对端在线，否则走不到打洞
	pm := newPathManager(host)
	tbl := newPeerTable()
	pm.setQualityTable(tbl)
	pm.start()
	defer pm.close()
	clk := newFakeClock()
	tbl.setClock(clk.now)

	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)

	// ① 表空 ⇒ 窗口 = 正常档（或采样下界）
	if got := p.trialWindow(); got < trialWindowNormal {
		t.Fatalf("表空时窗口应 ≥ %v，实际 %v", trialWindowNormal, got)
	}
	// handleTrigger 也不跳过（无记录 ⇒ 不涉及软跳过）
	pm.replaceRoutes(nil)
	pm.handleTrigger(ip4("192.168.30.12"))
	waitFor(t, "表空时应正常打洞", func() bool { return host.punchCount() >= 1 })

	// ② 写入「好」⇒ **窗口不变**（这是 A1 的核心契约）
	tbl.Record(ip4("192.168.30.12"), peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect})
	if got := p.trialWindow(); got < trialWindowNormal {
		t.Fatalf("命中「质量好」**不得**改变窗口（A1 起试用期与质量表解耦），实际 %v", got)
	}
	if got := p.trialWindow(); got < p.trialSampleFloor() {
		t.Fatalf("窗口 %v 仍必须 ≥ 采样下界 %v（否则必然「样本不足」判负）", got, p.trialSampleFloor())
	}
	if got := p.trialNeedGood(); got != trialNeedGoodNormal {
		t.Fatalf("need 不得随质量表变化（应恒为 %d），实际 %d", trialNeedGoodNormal, got)
	}

	// ③ 记录过期 ⇒ 窗口仍不变（可逆性是平凡的：它从来没被表影响过）
	clk.advance(peerTTLGood + time.Second)
	if got := p.trialWindow(); got < trialWindowNormal {
		t.Fatalf("记录过期后窗口仍应 ≥ %v，实际 %v", trialWindowNormal, got)
	}
}

// TestSoftSkipStillUsesQualityTable ⭐ 质量表**仍然生效的唯一职责**：软跳过（A1 后）
//
//	`handleTrigger` 读 `Unpunchable`（不可打洞记录）⇒ 不再白打洞。
//	本用例守「删掉试用期接线时**别把软跳过一起删掉**」。
func TestSoftSkipStillUsesQualityTable(t *testing.T) {
	pm, host, tbl := softSkipHarness(t)
	dst := ip4("192.168.30.12")
	pm.replaceRoutes(nil)

	tbl.Record(dst, peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonNATSymmetric})
	pm.handleTrigger(dst)
	waitFor(t, "首次触发应真的发起打洞（软跳过允许 1 次强制重试）",
		func() bool { return host.punchCount() == 1 })
	if _, ok := tbl.Unpunchable(dst); !ok {
		t.Fatal("前置：应仍有「不可打洞」记录")
	}
	// 第二次（强制重试已用掉）⇒ 跳过
	clearBackoffFor(pm, dst)
	pm.handleTrigger(dst)
	time.Sleep(80 * time.Millisecond)
	if n := host.punchCount(); n != 1 {
		t.Fatalf("软跳过仍须生效（质量表仍是它的数据源），实际累计发起 %d 次", n)
	}
}

// ---------- 试用期参数接线（A1 起与质量表无关） ----------

// TestTrialWindowIsIndependentOfQualityTable ⭐ A1 契约：试用期参数**只**由常量与
// 采样下界决定，与质量表无关。
//
// ⚠️ 有牙：把 `trialWindow()` 改回读质量表（例如又加一个 5s 缩短档）⇒ 本用例红。
func TestTrialWindowIsIndependentOfQualityTable(t *testing.T) {
	// ① 无记录
	hPlain := newRawTrialPath(t, trialCfg{
		window: 0, probeEvery: 40 * time.Millisecond,
		checkEvery: 20 * time.Millisecond, relaySeed: 100 * time.Millisecond,
	})
	// ⚠️ `trialCfg.window=0` ⇒ 不覆盖 ⇒ 走生产参数逻辑（probeInterval 已注入 40ms）
	wPlain, nPlain := hPlain.path.trialWindow(), hPlain.path.trialNeedGood()

	// ② 命中「质量好」
	hGood := newRawTrialPath(t, trialCfg{
		window: 0, probeEvery: 40 * time.Millisecond,
		checkEvery: 20 * time.Millisecond, relaySeed: 100 * time.Millisecond,
		goodRecord: true, // 夹具在建路径**之前**写表（避免数据竞争）
	})
	wGood, nGood := hGood.path.trialWindow(), hGood.path.trialNeedGood()

	if wGood != wPlain || nGood != nPlain {
		t.Fatalf("质量表**不得**影响试用期参数（A1 起解耦）：窗口 %v vs %v、need %d vs %d",
			wGood, wPlain, nGood, nPlain)
	}
	if nGood != trialNeedGoodNormal {
		t.Fatalf("need 应恒为 %d，实际 %d", trialNeedGoodNormal, nGood)
	}
}
