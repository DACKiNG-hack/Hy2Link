package quic

// vpn-server/quic/b2b_test.go
//
// ⭐ 1b-2B 服务端侧测试：
//   - 中继 RTT 估计（peer 应答新增 relayRttMs）
//   - punch-busy 推送（响应方达并发上限时立即告知发起方）
//
// 协议一致性（三集合两两不相交、字段名清单）在 signal_stream_test.go / punch_test.go 里自动检查。

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------- 中继 RTT ----------

// TestRelayRTTMsSumsBothSides 两个分量相加：RTT(查询方↔S) + RTT(S↔对端)
func TestRelayRTTMsSumsBothSides(t *testing.T) {
	srv, _ := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")

	old := relayRTTLookup
	defer func() { relayRTTLookup = old }()
	relayRTTLookup = func(cs *clientStream) int {
		switch cs.vip {
		case alice.vip:
			return 12
		case bob.vip:
			return 8
		}
		return 0
	}

	if got := relayRTTMsFor(srv, alice, bob.vip); got != 20 {
		t.Fatalf("relayRttMs 应为 12+8=20，实际 %d", got)
	}
}

// TestRelayRTTMsZeroWhenUnknown 任一侧未知（0）→ 整体 0（客户端据此不做 standby 判断）
func TestRelayRTTMsZeroWhenUnknown(t *testing.T) {
	srv, _ := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")

	old := relayRTTLookup
	defer func() { relayRTTLookup = old }()

	relayRTTLookup = func(cs *clientStream) int { return 0 }
	if got := relayRTTMsFor(srv, alice, bob.vip); got != 0 {
		t.Fatalf("两侧都未知时应为 0，实际 %d", got)
	}

	relayRTTLookup = func(cs *clientStream) int {
		if cs.vip == alice.vip {
			return 15
		}
		return 0 // 对端未知
	}
	if got := relayRTTMsFor(srv, alice, bob.vip); got != 0 {
		t.Fatalf("对端未知时应为 0（不能用一半的估计值），实际 %d", got)
	}

	// 对端不在线（查询不到）→ 0
	if got := relayRTTMsFor(srv, alice, "192.168.30.99"); got != 0 {
		t.Fatalf("对端不在线时应为 0，实际 %d", got)
	}
}

// TestPeerReplyCarriesRelayRTT peer 应答必须带上 relayRttMs（且 0 时因 omitempty 不下发）
func TestPeerReplyCarriesRelayRTT(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	_ = reg.Update(bob.vip, "5.6.7.8:40002", "symmetric", "")

	old := relayRTTLookup
	defer func() { relayRTTLookup = old }()
	relayRTTLookup = func(cs *clientStream) int { return 10 }

	resp := srv.signalReply(alice, &signalMessage{
		Type: signalMsgTypeRegister, PeerVIP: bob.vip,
		PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	})
	if resp.Type != signalMsgTypePeer {
		t.Fatalf("应回 peer，实际 %+v", resp)
	}
	if resp.RelayRttMs != 20 {
		t.Fatalf("relayRttMs 应为 10+10=20，实际 %d", resp.RelayRttMs)
	}
	// 线上可见
	raw, _ := json.Marshal(resp)
	if !strings.Contains(string(raw), `"relayRttMs":20`) {
		t.Fatalf("报文里应出现 relayRttMs，实际 %s", raw)
	}

	// 未知 → 0 → omitempty → 字段不下发（旧客户端/老服务端场景的兼容基础）
	relayRTTLookup = func(cs *clientStream) int { return 0 }
	resp2 := srv.signalReply(alice, &signalMessage{
		Type: signalMsgTypeRegister, PeerVIP: bob.vip,
		PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	})
	if resp2.RelayRttMs != 0 {
		t.Fatalf("未知时应为 0，实际 %d", resp2.RelayRttMs)
	}
	raw2, _ := json.Marshal(resp2)
	if strings.Contains(string(raw2), "relayRttMs") {
		t.Fatalf("0 值不应下发（omitempty），实际 %s", raw2)
	}
}

// ---------- punch-busy ----------

// TestPunchBusyRejectedWhenResponderAtCap 响应方满 → 立即回 peer-busy + 推送 punch-busy
func TestPunchBusyRejectedWhenResponderAtCap(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	carol := registerStream(srv, "192.168.30.13", "carol")
	dave := registerStream(srv, "192.168.30.14", "dave")
	_ = reg.Update(bob.vip, "5.6.7.8:40002", "symmetric", "")
	// bob 必须挂上 sink：否则 invite 推不过去，intent 会以 peer-not-ready 被拒
	reg.AttachSink(bob.vip, &recordingSink{})

	// A 的推送出口（断言收到 punch-busy）
	aliceSink := &recordingSink{}
	reg.AttachSink(alice.vip, aliceSink)

	// 先用 carol / dave 把 bob 的响应方名额占满（上限 = relayMaxResponderInvites）
	for _, init := range []*clientStream{carol, dave} {
		msg := testIntent(bob.vip)
		msg.AttemptID = nextID()
		if err := srv.handlePunchIntent(&recordingSink{}, init, msg); err != nil {
			t.Fatalf("前置 intent 失败: %v", err)
		}
	}
	if n := srv.punchTable().activeResponderCount(bob.vip); n != relayMaxResponderInvites {
		t.Fatalf("前置条件：bob 应有 %d 个活跃 attempt，实际 %d", relayMaxResponderInvites, n)
	}

	// alice 再来 → 必须立即被拒（而不是让 alice 白等 40s）
	out := &recordingSink{}
	msg := testIntent(bob.vip)
	msg.AttemptID = nextID()
	if err := srv.handlePunchIntent(out, alice, msg); err != nil {
		t.Fatalf("handlePunchIntent 本身不应返回 error: %v", err)
	}
	msgs := out.all()
	if len(msgs) != 1 || msgs[0].Type != signalMsgTypeError {
		t.Fatalf("应回一条 error 应答，实际 %+v", msgs)
	}
	if !strings.Contains(msgs[0].Error, "peer-busy") {
		t.Fatalf("error 里应含 peer-busy（客户端据此归类为「忙」），实际 %q", msgs[0].Error)
	}

	// 同时推送 punch-busy 给发起方（用户要求的语义）
	pushed := aliceSink.all()
	found := false
	for _, m := range pushed {
		if m.Type == signalMsgTypePunchBusy {
			found = true
			if m.AttemptID != msg.AttemptID {
				t.Fatalf("punch-busy 应带 attemptId=%s，实际 %q", msg.AttemptID, m.AttemptID)
			}
			if m.PeerVIP != bob.vip {
				t.Fatalf("punch-busy 应带 peerVIP=%s，实际 %q", bob.vip, m.PeerVIP)
			}
		}
	}
	if !found {
		t.Fatalf("应向发起方推送 punch-busy，实际收到 %+v", pushed)
	}

	// 被拒的 intent 不得在表里留下记录
	if n := srv.punchTable().activeResponderCount(bob.vip); n != relayMaxResponderInvites {
		t.Fatalf("被拒的 intent 不应占用名额，实际 %d", n)
	}
}

// TestResponderCapMirrorIsTwo ⭐ 服务端镜像常量必须与客户端 punchMaxResponder 一致。
//
// 两端各有一个「响应方并发上限」：客户端用它**被动忽略**多余邀请，服务端用它**提前拒绝**
// 并告知发起方「忙」。数字不一致会出现「服务端说忙但客户端其实空闲」（白拒）或反之。
// ⚠️ 这是跨模块常量，编译期无法互相引用，所以两边各有一条测试钉住数值 = 2。
func TestResponderCapMirrorIsTwo(t *testing.T) {
	if relayMaxResponderInvites != 2 {
		t.Fatalf("relayMaxResponderInvites 必须与客户端 punchMaxResponder 一致（=2），实际 %d",
			relayMaxResponderInvites)
	}
}

// TestPunchAllowedBelowCap 未达上限时照常协调（不能把能力做小了）
func TestPunchAllowedBelowCap(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	_ = reg.Update(bob.vip, "5.6.7.8:40002", "symmetric", "")
	reg.AttachSink(bob.vip, &recordingSink{}) // invite 要推得过去

	out := &recordingSink{}
	msg := testIntent(bob.vip)
	msg.AttemptID = nextID()
	if err := srv.handlePunchIntent(out, alice, msg); err != nil {
		t.Fatalf("handlePunchIntent: %v", err)
	}
	msgs := out.all()
	if len(msgs) != 1 || msgs[0].Type != signalMsgTypePeer {
		t.Fatalf("未达上限时应正常回 peer，实际 %+v", msgs)
	}
}
