package quic

// vpn-tool/backend/quic/local_switch_test.go
//
// ⭐ 1b-2A（UI 块）：本机 P2P 开关参与判定的边界测试。
//
// 逐条对应验收要求：
//  1. 本机开关关 → PunchTo 报错「本机已禁用 P2P」
//  2. 本机开关关 → 流量驱动不触发
//  3. 本机开关关 → 已有直连路径立即降级（清空路由 + 关闭连接）
//  4. 本机开关切回开 → 不自动重建，等流量
//  5. 服务端开关关 + 本机开关开 → 仍不触发（服务端优先）

import (
	"strings"
	"testing"
	"time"
)

// TestP2PEffectiveRequiresBothSwitches 判据：服务端 && 本机
func TestP2PEffectiveRequiresBothSwitches(t *testing.T) {
	cases := []struct {
		server, local, want bool
	}{
		{false, false, false},
		{false, true, false}, // 服务端优先：它关着，本机开着也不生效
		{true, false, false}, // 本机否决
		{true, true, true},
	}
	for _, c := range cases {
		c := c
		cli := &Hysteria2Client{p2pServerEnabled: c.server, p2pLocalEnabled: c.local}
		if got := cli.P2PEffective(); got != c.want {
			t.Fatalf("server=%v local=%v 时 P2PEffective 应为 %v，实际 %v", c.server, c.local, c.want, got)
		}
		// 触发门的判据必须与 P2PEffective 同源（否则「面板显示关闭但还在打洞」）
		if got := cli.p2pEnabled(); got != c.want {
			t.Fatalf("p2pEnabled 必须等于 P2PEffective（触发门同源），实际 %v", got)
		}
		if got := cli.controlledP2PEnabled(); got != c.want {
			t.Fatalf("controlledP2PEnabled 必须等于 P2PEffective，实际 %v", got)
		}
	}
}

// TestPunchRejectedWhenLocalDisabled ①：本机开关关 → PunchTo 明确报「本机已禁用 P2P」
func TestPunchRejectedWhenLocalDisabled(t *testing.T) {
	cli := &Hysteria2Client{p2pServerEnabled: true, p2pLocalEnabled: false}
	if _, err := cli.PunchTo("192.168.30.12"); err == nil {
		t.Fatal("本机禁用 P2P 时 PunchTo 必须报错")
	} else if !strings.Contains(err.Error(), "本机已禁用 P2P") {
		t.Fatalf("错误文案应指明是本机禁用（便于排障），实际 %q", err.Error())
	}

	// 服务端关 + 本机开：文案应指向服务端
	cli2 := &Hysteria2Client{p2pServerEnabled: false, p2pLocalEnabled: true}
	if _, err := cli2.PunchTo("192.168.30.12"); err == nil {
		t.Fatal("服务端关时 PunchTo 必须报错")
	} else if !strings.Contains(err.Error(), "服务端未启用 P2P") {
		t.Fatalf("错误文案应指向服务端开关，实际 %q", err.Error())
	}
}

// TestTrafficTriggerSkippedWhenP2PDisabled ②⑤：流量驱动在 P2P 不生效时**完全不触发**
//
// 覆盖两种「不生效」：本机否决（server=true/local=false）与服务端关（server=false/local=true）。
func TestTrafficTriggerSkippedWhenP2PDisabled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		serverOn bool
		localOn  bool
	}{
		{"本机开关关", true, false},
		{"服务端开关关", false, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			host := newFakeHost() // fakeHost 的 p2p 字段 = 「P2PEffective」的替身
			host.p2p = tc.serverOn && tc.localOn
			host.addPeer("192.168.30.12")
			pm := newPathManager(host)
			pm.start()
			defer pm.close()

			for i := 0; i < 5; i++ {
				pm.handleTrigger(ip4("192.168.30.12"))
			}
			time.Sleep(200 * time.Millisecond)
			if n := host.punchCount(); n != 0 {
				t.Fatalf("%s：不应触发任何打洞，实际 %d 次", tc.name, n)
			}
			if n := host.queryCount(); n != 0 {
				t.Fatalf("%s：连信号门查询都不该发生，实际 %d 次", tc.name, n)
			}
		})
	}
}

// TestApplyP2PLocalFalseClosesExistingPaths ③：运行期关掉 → 立即清空路由 + 关闭已有直连
func TestApplyP2PLocalFalseClosesExistingPaths(t *testing.T) {
	cli := &Hysteria2Client{p2pServerEnabled: true, p2pLocalEnabled: true}
	host := newFakeHost()
	pm := newPathManager(cli) // host 就是客户端本身（p2pEnabled() 走 P2PEffective）
	pm.start()
	cli.pathMgr = pm
	defer pm.close()
	_ = host

	conn := newFakeConn()
	closed := false
	pm.handleEstablished(establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleInitiator,
		conn: conn, closers: []func() error{func() error { closed = true; return nil }},
		myVIP: ip4("192.168.30.11"),
	})
	// ⭐ 1b-4：先验后切 ⇒ 手工把试用期结算为「通过」，本用例才有「已装表」的前置条件
	if p := forceTrialPass(t, pm, "192.168.30.12"); p == nil {
		t.Fatal("前置条件：handleEstablished 后应有一条 trial 路径")
	}
	if _, ok := pm.routeVIP(ip4("192.168.30.12")); !ok {
		t.Fatal("前置条件：应已装表")
	}

	cli.ApplyP2PLocal(false) // 关掉

	if _, ok := pm.routeVIP(ip4("192.168.30.12")); ok {
		t.Fatal("本机禁用 P2P 后路由必须立即清空（流量回中继）")
	}
	if n := len(pm.snapshotPaths()); n != 0 {
		t.Fatalf("禁用后不应还有路径，实际 %d", n)
	}
	if !closed {
		t.Fatal("禁用后必须关闭已有直连路径的资源")
	}
	if conn.Context().Err() == nil {
		t.Fatal("禁用后直连连接必须已关闭")
	}
	if cli.P2PEffective() {
		t.Fatal("禁用后 P2PEffective 应为 false")
	}
}

// TestApplyP2PLocalTrueDoesNotAutoRebuild ④：切回开 → 不自动重建，等流量
func TestApplyP2PLocalTrueDoesNotAutoRebuild(t *testing.T) {
	cli := &Hysteria2Client{p2pServerEnabled: true, p2pLocalEnabled: false}
	pm := newPathManager(cli)
	pm.start()
	cli.pathMgr = pm
	defer pm.close()

	cli.ApplyP2PLocal(true)
	if !cli.P2PEffective() {
		t.Fatal("切回开后 P2PEffective 应为 true")
	}
	// 没有任何流量/触发 → 不该凭空出现路径
	time.Sleep(150 * time.Millisecond)
	if n := len(pm.snapshotPaths()); n != 0 {
		t.Fatalf("切回开之后不应自动重建路径（等服务流量驱动），实际 %d 条", n)
	}
	// 幂等：重复设置同一个值不应有副作用
	cli.ApplyP2PLocal(true)
	cli.ApplyP2PLocal(true)
	if !cli.P2PEffective() {
		t.Fatal("重复设置不应改变状态")
	}
}

// TestApplyP2PLocalIdempotentNoLog 同一个值重复设置不算「变化」（避免刷日志与重复清理）
func TestApplyP2PLocalIdempotent(t *testing.T) {
	cli := &Hysteria2Client{p2pServerEnabled: true, p2pLocalEnabled: false}
	pm := newPathManager(cli)
	cli.pathMgr = pm
	defer pm.close()

	before := cli.p2pLocalEnabled
	cli.ApplyP2PLocal(before) // 同值
	if cli.p2pLocalEnabled != before {
		t.Fatal("同值设置不应改变状态")
	}
}
