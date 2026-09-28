package quic

// vpn-server/quic/stage1b3_test.go
//
// ⭐ 1b-3（A1 + 2.3）服务端侧测试：
//   A1  —— punch-intent 的候选列表必须被校验并**原样转达**给响应方（invite），
//          punch-ready 的候选列表必须转达给发起方（punch-peer）。
//   2.3 —— B 的直连指纹必须随 punch-peer 转达给 A（A 才能双向固定）。
//
// 这些字段是「转发型」的：服务端不解释内容，但**必须搬过去**，否则两端各自
// 以为自己在双向固定/多候选打洞，实际链路里根本没有这些数据。

import (
	"strings"
	"testing"
)

func TestPunchCoordinationRelaysAddrsAndFingerprint(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	_ = reg.Update(bob.vip, "5.6.7.8:40002", "full-cone", "")

	bobSink := &recordingSink{}
	reg.AttachSink(bob.vip, bobSink)
	aliceSink := &recordingSink{}
	reg.AttachSink(alice.vip, aliceSink)

	// ---- A 侧：punch-intent 带候选列表 ----
	intent := testIntent(bob.vip)
	intent.AttemptID = nextID()
	intent.PunchAddr = "1.2.3.4:50000"
	intent.PunchAddrs = []string{"1.2.3.4:50000", "1.2.3.4:50001", "1.2.3.4:50002"}
	if err := srv.handlePunchIntent(&recordingSink{}, alice, intent); err != nil {
		t.Fatalf("handlePunchIntent: %v", err)
	}

	invite := findMsg(t, bobSink.all(), signalMsgTypePunchInvite)
	if len(invite.PunchAddrs) != 3 {
		t.Fatalf("invite 必须把 A 的候选列表原样转达给 B，实际 %v", invite.PunchAddrs)
	}
	if strings.Join(invite.PunchAddrs, ",") != strings.Join(intent.PunchAddrs, ",") {
		t.Fatalf("invite 的候选列表与 intent 不一致：%v vs %v", invite.PunchAddrs, intent.PunchAddrs)
	}

	// ---- B 侧：punch-ready 带候选列表 + 自己的直连指纹 ----
	//（aliceSink 此刻还只有 intent 阶段的推送，没有 punch-peer）
	ready := testIntent(alice.vip) // 复用「自带 register 字段」的构造，再改成 punch-ready
	ready.Type = signalMsgTypePunchReady
	ready.AttemptID = intent.AttemptID
	ready.PeerVIP = alice.vip
	ready.PunchAddr = "5.6.7.8:40002"
	ready.PunchAddrs = []string{"5.6.7.8:40002", "5.6.7.8:40003"}
	ready.DirectFingerprint = strings.Repeat("cd", 32)
	if err := srv.handlePunchReady(&recordingSink{}, bob, ready); err != nil {
		t.Fatalf("handlePunchReady: %v", err)
	}

	peerPush := findMsg(t, aliceSink.all(), signalMsgTypePunchPeer)
	if len(peerPush.PunchAddrs) != 2 {
		t.Fatalf("punch-peer 必须把 B 的候选列表转达给 A，实际 %v", peerPush.PunchAddrs)
	}
	if peerPush.DirectFingerprint != ready.DirectFingerprint {
		t.Fatalf("punch-peer 必须把 B 的指纹转达给 A（2.3 双向固定）：want %q got %q",
			ready.DirectFingerprint, peerPush.DirectFingerprint)
	}
}

// TestPunchIntentRejectsBadPunchAddrs 服务端必须拒绝非法候选列表（防反射放大）
func TestPunchIntentRejectsBadPunchAddrs(t *testing.T) {
	cases := []struct {
		name  string
		addrs []string
	}{
		{"混入别的 IP", []string{"1.2.3.4:50000", "5.6.7.8:50000"}},
		{"私网地址", []string{"10.0.0.1:50000"}},
		{"超过上限", manyPublicAddrs(33)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, reg := newSignalTestServer(t, true)
			alice := registerStream(srv, "192.168.30.11", "alice")
			bob := registerStream(srv, "192.168.30.12", "bob")
			_ = reg.Update(bob.vip, "5.6.7.8:40002", "full-cone", "")
			bobSink := &recordingSink{}
			reg.AttachSink(bob.vip, bobSink)

			msg := testIntent(bob.vip)
			msg.AttemptID = nextID()
			msg.PunchAddr = "1.2.3.4:50000"
			msg.PunchAddrs = tc.addrs
			out := &recordingSink{}
			if err := srv.handlePunchIntent(out, alice, msg); err != nil {
				t.Fatalf("handlePunchIntent 本身不应返回 error: %v", err)
			}
			msgs := out.all()
			if len(msgs) != 1 || msgs[0].Type != signalMsgTypeError {
				t.Fatalf("应回一条 error 应答，实际 %+v", msgs)
			}
			// 不得给对端推送邀请（否则对端会朝非法地址喷包）
			for _, m := range bobSink.all() {
				if m.Type == signalMsgTypePunchInvite {
					t.Fatal("非法候选列表被拒后不得推送邀请")
				}
			}
		})
	}
}

// findMsg 在消息列表里找指定类型（找不到直接失败）
func findMsg(t *testing.T, msgs []signalMessage, msgType string) signalMessage {
	t.Helper()
	for _, m := range msgs {
		if m.Type == msgType {
			return m
		}
	}
	var got []string
	for _, m := range msgs {
		got = append(got, m.Type)
	}
	t.Fatalf("没有找到 %s；实际收到 %v", msgType, got)
	return signalMessage{}
}

// manyPublicAddrs 造 n 个公网同 IP 候选
func manyPublicAddrs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, "1.2.3.4:"+itoaTest(50000+i))
	}
	return out
}

func itoaTest(v int) string {
	if v == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
