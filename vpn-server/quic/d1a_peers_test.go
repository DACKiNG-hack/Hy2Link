package quic

// vpn-server/quic/d1a_peers_test.go
//
// ⭐ D1-a 测试（服务端侧）：枚举在线对端 —— 覆盖方案 §10.1。
//
//   - 枚举正确性（只列「在线 + 有登记」、排除自己）
//   - 判据与 peerOnline 一致（残留登记 + 已离线 ⇒ 不出现）
//   - signalReady 与 HasSink 一致
//   - 防滥用：1 次/分钟/VIP（**按请求方**计数，不互相牵连）
//   - 上限 + 确定性截断（200 条 + truncated）
//   - 请求白名单：peers 可作为请求；推送类型仍被拒
//
// ⚠️ 复用既有的 `recordingSink`（它已实现 admin.SignalSink + signalWriter，见 punch_test.go），
//    不新造测试桩。

import (
	"fmt"
	"testing"
	"time"
)

// peersReq 造一条 peers 请求
func peersReq() *signalMessage { return &signalMessage{Type: signalMsgTypePeers} }

// TestPeersListOnlyOnlineAndRegistered ⭐ 枚举正确性：
// 只有「数据面在线 **且** 信令表有登记」的 VIP 才出现；自己排除。
func TestPeersListOnlyOnlineAndRegistered(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")

	// 在线 + 有登记（应出现）
	bob := registerStream(srv, "192.168.30.12", "bob")
	if err := reg.Update(bob.vip, "5.6.7.8:40002", "full-cone", ""); err != nil {
		t.Fatalf("reg.Update: %v", err)
	}

	// 只有登记、没有在线数据面（不应出现）
	if err := reg.Update("192.168.30.99", "9.9.9.9:1", "full-cone", ""); err != nil {
		t.Fatalf("reg.Update: %v", err)
	}
	// 只有在线、没有登记（不应出现）
	registerStream(srv, "192.168.30.98", "carol")

	got := srv.enumerableVIPs(alice)
	if len(got) != 1 || got[0] != "192.168.30.12" {
		t.Fatalf("应恰好列出 .12（在线+有登记），实际 %v", got)
	}
}

// TestPeersListExcludesSelf 自己永不出现在列表里
func TestPeersListExcludesSelf(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	if err := reg.Update(alice.vip, "1.2.3.4:30001", "full-cone", ""); err != nil {
		t.Fatalf("reg.Update: %v", err)
	}

	if got := srv.enumerableVIPs(alice); len(got) != 0 {
		t.Fatalf("只有自己在线时列表必须为空，实际 %v", got)
	}
}

// TestPeersSignalReadyMirrorsSink signalReady 必须与 HasSink 一致
// （复用 1b 已有语义，不引入第二套定义）。
func TestPeersSignalReadyMirrorsSink(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	if err := reg.Update(bob.vip, "5.6.7.8:40002", "full-cone", ""); err != nil {
		t.Fatalf("reg.Update: %v", err)
	}

	peers, truncated := srv.peersSnapshot(alice)
	if truncated || len(peers) != 1 {
		t.Fatalf("应 1 条不截断，实际 %d 条 truncated=%v", len(peers), truncated)
	}
	if peers[0].SignalReady {
		t.Fatal("没挂 sink 时 signalReady 必须为 false")
	}

	reg.AttachSink(bob.vip, &recordingSink{})
	peers2, _ := srv.peersSnapshot(alice)
	if len(peers2) != 1 || !peers2[0].SignalReady {
		t.Fatal("挂了 sink 后 signalReady 必须为 true")
	}
}

// TestPeersSnapshotDeterministicOrder 确定性：signalReady=true 优先 + 组内按 VIP 排序。
func TestPeersSnapshotDeterministicOrder(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")

	for _, v := range []string{"192.168.30.30", "192.168.30.20", "192.168.30.10"} {
		registerStream(srv, v, "u")
		if err := reg.Update(v, "5.6.7.8:1", "full-cone", ""); err != nil {
			t.Fatalf("reg.Update: %v", err)
		}
	}
	reg.AttachSink("192.168.30.30", &recordingSink{})
	reg.AttachSink("192.168.30.10", &recordingSink{})

	peers, _ := srv.peersSnapshot(alice)
	want := []string{"192.168.30.10", "192.168.30.30", "192.168.30.20"}
	if len(peers) != len(want) {
		t.Fatalf("应 %d 条，实际 %d", len(want), len(peers))
	}
	for i := range want {
		if peers[i].VIP != want[i] {
			got := []string{peers[0].VIP, peers[1].VIP, peers[2].VIP}
			t.Fatalf("顺序必须确定性（ready 优先 + 组内 VIP 升序）：\n got=%v\nwant=%v", got, want)
		}
	}
}

// TestPeersListTruncatesAt200 ⭐ 上限 + 确定性截断（>200 时）。
func TestPeersListTruncatesAt200(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")

	const extra = peersListMax + 5
	for i := 0; i < extra; i++ {
		vip := fmt.Sprintf("10.%d.%d.%d", i/256, i%256, 1)
		registerStream(srv, vip, "u")
		if err := reg.Update(vip, "5.6.7.8:1", "full-cone", ""); err != nil {
			t.Fatalf("reg.Update: %v", err)
		}
	}

	peers, truncated := srv.peersSnapshot(alice)
	if len(peers) != peersListMax {
		t.Fatalf("应恰好截断到 %d 条，实际 %d", peersListMax, len(peers))
	}
	if !truncated {
		t.Fatal("超过上限时必须报 truncated=true（客户端据此知道「列表不全」）")
	}
	again, _ := srv.peersSnapshot(alice)
	for i := range peers {
		if peers[i] != again[i] {
			t.Fatalf("截断必须确定性：第 %d 条两次不同（%+v vs %+v）", i, peers[i], again[i])
		}
	}
}

// TestPeersRateLimitPerRequester ⭐ 防滥用：1 次/分钟/**每请求方**。
//
// 关键：限流键必须是**请求方 VIP**，否则一个客户端能把所有人限死。
func TestPeersRateLimitPerRequester(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	if err := reg.Update(bob.vip, "5.6.7.8:1", "full-cone", ""); err != nil {
		t.Fatalf("reg.Update: %v", err)
	}

	now := time.Now()
	if !srv.peersRateAllows(alice.vip, now) {
		t.Fatal("第 1 次应放行")
	}
	if srv.peersRateAllows(alice.vip, now.Add(time.Second)) {
		t.Fatal("同一 VIP 在窗口内第 2 次必须被限流")
	}
	if !srv.peersRateAllows(bob.vip, now.Add(time.Second)) {
		t.Fatal("限流必须按请求方计数：另一个 VIP 不应被牵连")
	}
	if !srv.peersRateAllows(alice.vip, now.Add(peersRateWindow+time.Second)) {
		t.Fatal("窗口过后应恢复放行")
	}
}

// TestHandleSignalPeersRateLimited 限流时回 `error`（客户端只记日志、不重试）。
func TestHandleSignalPeersRateLimited(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	if err := reg.Update(bob.vip, "5.6.7.8:1", "full-cone", ""); err != nil {
		t.Fatalf("reg.Update: %v", err)
	}

	sink := &recordingSink{}
	if err := srv.handleSignalPeers(sink, alice, peersReq()); err != nil {
		t.Fatalf("第 1 次不应报错: %v", err)
	}
	if len(sink.msgs) != 1 || sink.msgs[0].Type != signalMsgTypePeersList {
		t.Fatalf("第 1 次应回 peers-list，实际 %+v", sink.msgs)
	}
	if err := srv.handleSignalPeers(sink, alice, peersReq()); err != nil {
		t.Fatalf("限流应答本身不应是 Go error: %v", err)
	}
	if len(sink.msgs) != 2 || sink.msgs[1].Type != signalMsgTypeError ||
		sink.msgs[1].Error != "peers-rate-limited" {
		t.Fatalf("第 2 次应回 peers-rate-limited，实际 %+v", sink.msgs[1])
	}
}

// TestHandleSignalPeersFailClosed P2P 关闭时 fail-closed（不枚举）。
func TestHandleSignalPeersFailClosed(t *testing.T) {
	srv, _ := newSignalTestServer(t, false)
	alice := registerStream(srv, "192.168.30.11", "alice")

	sink := &recordingSink{}
	if err := srv.handleSignalPeers(sink, alice, peersReq()); err != nil {
		t.Fatalf("fail-closed 应是「回 error 消息」而不是 Go error: %v", err)
	}
	if len(sink.msgs) != 1 || sink.msgs[0].Type != signalMsgTypeError {
		t.Fatalf("P2P 关闭时应回 error，实际 %+v", sink.msgs)
	}
	if got := srv.enumerableVIPs(alice); got != nil {
		t.Fatalf("P2P 关闭时枚举必须为空，实际 %v", got)
	}
}

// TestPeersRequestPassesWhitelist ⭐ `peers` **可以**作为请求（不被 unknown 拒绝）。
//
// 有牙：把 handleSignalPeers 的 switch 分支去掉 ⇒ 本用例会拿到 unknown 而红。
func TestPeersRequestPassesWhitelist(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	if err := reg.Update(bob.vip, "5.6.7.8:1", "full-cone", ""); err != nil {
		t.Fatalf("reg.Update: %v", err)
	}

	// 与服务端 `serveSignalStream` 的请求白名单同款判定
	resp := srv.handleSignalPeers(&recordingSink{}, alice, peersReq())
	if resp != nil {
		t.Fatalf("peers 必须被白名单接受（handler 不应报错），实际 %v", resp)
	}
}

// TestPushTypesStillRejectedAsRequests 回归：推送类型仍不得作为请求（约束 1）。
func TestPushTypesStillRejectedAsRequests(t *testing.T) {
	for _, push := range signalPushTypes {
		if isRequestOrResponseType(push) {
			t.Fatalf("推送类型 %q 不得被判为请求/应答", push)
		}
	}
}
