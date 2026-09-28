package quic

// vpn-tool/backend/quic/trial_reset_conflict_test.go
//
// ⭐ 1b-4（review 补充）：**在飞 trial + 退避重置** 不冲突。
//
// 语义（已确认）：resetBackoffFor 只清退避记录，**不动在飞的路径** ——
// NAT 重探测成功 / VIP 变更时，正在试用期的路径仍然有效（对端 VIP 没变），
// 让它照常跑完试用期；清退避只影响「下次失败从第 0 档开始」。

import "testing"

func TestResetBackoffDuringTrialKeepsInFlightTrial(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	// ⭐ 1b-4：这里**不能**用 newTestPath（它会把试用期结算掉），要的是**真正在 trial 里**的路径。
	// 直接按 handleEstablished 的方式建：newDirectPath → 登记进表（trial 状态）。
	conn := newFakeConn()
	p, err := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleInitiator,
		conn: conn, myVIP: host.vip, closers: []func() error{func() error { return nil }},
	})
	if err != nil {
		t.Fatalf("newDirectPath: %v", err)
	}
	pm.installRoute(p.peer, p)
	p.run()
	if got := p.state.Load(); got != pathStateTrial {
		t.Fatalf("前置条件：新路径必须在 trial 里，实际 %v", got)
	}

	// 造一条失败记录（模拟「NAT 重探测成功之前」留下的退避）
	pm.onPunchFailed("192.168.30.12", P2PReasonPunchTimeout)
	pm.mu.Lock()
	_, had := pm.backoff[p.peer]
	pm.mu.Unlock()
	if !had {
		t.Fatal("前置条件：应有退避记录")
	}

	// NAT 重探测成功 ⇒ 重置退避（5 条重置之一）
	pm.resetBackoffFor(p.peer)

	// ① 退避确实被清
	pm.mu.Lock()
	_, still := pm.backoff[p.peer]
	pm.mu.Unlock()
	if still {
		t.Fatal("重置后不应还有退避记录")
	}
	// ② 在飞 trial **不受影响**：状态仍在 trial、仍 alive、数据仍走中继
	//    （trial 路径**登记在路由表里**（面板要看得见、管理器关得掉），但 `sinkFor` 只认 Up
	//      ⇒ 数据仍走中继；这就是「先验后切」的落点）
	if got := p.state.Load(); got != pathStateTrial {
		t.Fatalf("重置不得改动在飞 trial 的状态，实际 %v", got)
	}
	if !p.alive() {
		t.Fatal("重置后 trial 仍必须 alive（否则探针/读写会退出，试用期卡死）")
	}
	if ch := pm.sinkFor(p.peer, planeTCP); ch != nil {
		t.Fatal("trial 期间数据仍必须走中继（重置不该把它提前接上）")
	}
	// ③ 重置**不能**破坏「试用期继续跑」：它仍能正常完成（通过 ⇒ 装表 ⇒ 走直连）
	//    ⭐ 1b-4：走真实的结算路径（取消门 + 装表仲裁临界区），而不是手工 setState/installRoute。
	p.passTrialForTest()
	if ch := pm.sinkFor(p.peer, planeTCP); ch == nil {
		t.Fatal("试用期通过并装表后，sinkFor 应能选中该路径（重置不该留下副作用）")
	}
}
