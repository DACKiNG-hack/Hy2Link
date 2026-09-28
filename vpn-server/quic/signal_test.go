package quic

import (
	"net"
	"strings"
	"testing"
	"time"

	"vpn-server/admin"

	"github.com/apernet/quic-go"
)

// newSignalTestServer 构造一个只装配了信令所需依赖的 DataChannelServer
func newSignalTestServer(t *testing.T, p2p bool) (*DataChannelServer, *admin.SignalRegistry) {
	t.Helper()
	auth, alloc := newTestAuth(t)
	srv := NewDataChannelServer(alloc, nil, nil, auth, nil, [4]byte{}, nil, nil, nil)
	reg := admin.NewSignalRegistry(time.Minute)
	srv.EnableP2PSignal(p2p, reg)
	return srv, reg
}

// testConn 造一个"**仅作身份标识**"的 conn 指针。
//
// ⚠️ 2026-09-28（面板趋势图 bug · 修法 1）：`unregisterData` 的身份判据已从 "`cur != cs`" 改为
//
//	"**当前 `cur` 的 `dataConn` 是否仍是**调用方那条连接**"——因为 `cs` 会被"接管复用"
//	（新数据连接把流装到旧 `cs` 上）⇒ 用 `cs` **无法区分新旧连接** ⇒ 旧连接的陈旧收尾会误删新条目
//	（这正是"面板趋势图恒 0"的成因之一）。
//	⚠️ 它**只用于指针比较**：`&quic.Conn{}` 是未初始化对象，**解引用会 panic**
//	（`CloseWithError` 会触碰内部字段）⇒ 测试里**不要**对它调用 `closeAll`（夹具流也不调）。
func testConn() *quic.Conn { return &quic.Conn{} }

// mkStream 造一个已注册的 clientStream（only 用于 lookup/信令身份）
func mkStream(vip, user string) *clientStream {
	var b [4]byte
	copy(b[:], net.ParseIP(vip).To4())
	cs := &clientStream{vip: vip, vipBytes: b, username: user, mode: "multi"}
	cs.dataConn = testConn() // 每流一个独立身份（对应生产里"每条数据连接自己的 conn"）
	return cs
}

// registerStream 造一个已注册的 clientStream（测试夹具）。
//
// ⚠️ 2026-09-28（面板趋势图 bug · 修法 1）：**故意不走生产的 `s.register`**。
//
//	生产的 `register` 在"同 VIP 已存在旧流"时会对旧流调 `old.closeAll("replaced by new connection")`；
//	而本夹具的 `dataConn` 是"仅作身份标识的占位 conn"（`&quic.Conn{}`），
//	`CloseWithError` 会 `<-c.ctx.Done()` ⇒ **零值对象会 panic**（已实测）。
//	⇒ 夹具这里直接做"登记替换"，**不关闭旧流**：本夹具只用于
//	  ① `lookup` 身份相关用例；② 旧流 `cleanupDataConnVIP` 的**陈旧收尾**用例
//	   （那里正是要断言"旧流收尾无权清理"，与是否真被 close 无关）。
func registerStream(s *DataChannelServer, vip, user string) *clientStream {
	cs := mkStream(vip, user)
	shard := s.shards[getShardIndex(cs.vipBytes)]
	shard.mu.Lock()
	shard.conns[cs.vipBytes] = cs
	shard.mu.Unlock()
	return cs
}

// TestSignalReplyIdentityFromServerNotClient 是本阶段最关键的安全断言：
//
//	调用方的 VIP 必须来自服务端（cs.vip），
//	register 消息里**根本没有** myVIP 字段，客户端无法把登记挂到别人 VIP 上。
func TestSignalReplyIdentityFromServerNotClient(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)

	alice := registerStream(srv, "192.168.30.11", "alice")

	// 消息里只有 peerVIP / publicAddr / natType —— 没有任何「我是谁」
	msg := &signalMessage{
		Type:       signalMsgTypeRegister,
		PublicAddr: "1.2.3.4:30001",
		NATType:    "full-cone",
	}
	resp := srv.signalReply(alice, msg)
	if resp.Type != signalMsgTypeRegistered {
		t.Fatalf("应返回 registered，实际 %+v", resp)
	}

	// 登记必须落在 alice 自己的 VIP 下
	got, ok := reg.Get("192.168.30.11")
	if !ok {
		t.Fatal("登记应挂在 cs.vip = 192.168.30.11 下")
	}
	if got.PublicAddr != "1.2.3.4:30001" || got.NATType != "full-cone" {
		t.Fatalf("登记内容不对: %+v", got)
	}

	// 换个身份的 cs，登记就落在另一个 VIP 下（互不影响）
	bob := registerStream(srv, "192.168.30.12", "bob")
	srv.signalReply(bob, &signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "5.6.7.8:40002", NATType: "symmetric",
	})
	if b, _ := reg.Get("192.168.30.12"); b.PublicAddr != "5.6.7.8:40002" {
		t.Fatalf("bob 的登记不对: %+v", b)
	}
	if a, _ := reg.Get("192.168.30.11"); a.PublicAddr != "1.2.3.4:30001" {
		t.Fatalf("alice 的登记被改动了: %+v", a)
	}
}

// TestSignalReplyPeerQuery 对端查询的三种结果
func TestSignalReplyPeerQuery(t *testing.T) {
	srv, _ := newSignalTestServer(t, true)

	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")

	// ① 对端在线但还没登记 → peerOnline=false
	resp := srv.signalReply(alice, &signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
		PeerVIP: "192.168.30.12",
	})
	if resp.Type != signalMsgTypePeer {
		t.Fatalf("应返回 peer，实际 %+v", resp)
	}
	if resp.PeerOnline || resp.PeerPublicAddr != "" {
		t.Fatalf("对端未登记时 peerOnline 应为 false，实际 %+v", resp)
	}

	// ② 对端登记后 → 拿到地址/NAT/（可能的）metadata
	meta := strings.Repeat("ab", admin.MetadataLen)
	srv.signalReply(bob, &signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "5.6.7.8:40002", NATType: "symmetric",
		Metadata: meta, PeerVIP: "192.168.30.11",
	})
	// bob 查询时就该看到 alice 的地址
	resp = srv.signalReply(alice, &signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
		PeerVIP: "192.168.30.12",
	})
	if !resp.PeerOnline || resp.PeerPublicAddr != "5.6.7.8:40002" || resp.PeerNATType != "symmetric" {
		t.Fatalf("应拿到 bob 的地址/NAT，实际 %+v", resp)
	}
	if resp.PeerMetadata != meta {
		t.Fatalf("应转发 bob 的 metadata，实际 %q", resp.PeerMetadata)
	}

	// ③ 对端离线（不在任何数据面上）→ peerOnline=false，即使信令表里有登记
	//    （防止借信令探测/污染任意地址）
	srv.unregisterData(bob.vipBytes, bob.getDataConn())
	resp = srv.signalReply(alice, &signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
		PeerVIP: "192.168.30.12",
	})
	if resp.PeerOnline {
		t.Fatalf("对端已离线时 peerOnline 必须为 false，实际 %+v", resp)
	}

	// ④ 对端 VIP 根本不存在
	resp = srv.signalReply(alice, &signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
		PeerVIP: "192.168.30.199",
	})
	if resp.PeerOnline {
		t.Fatalf("不存在的对端必须 peerOnline=false，实际 %+v", resp)
	}
}

// TestSignalReplyRejectsBadInput 非法输入不得写入登记表
func TestSignalReplyRejectsBadInput(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")

	cases := []*signalMessage{
		{Type: signalMsgTypeRegister, PublicAddr: "", NATType: "full-cone"},
		{Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4", NATType: "full-cone"},
		{Type: signalMsgTypeRegister, PublicAddr: "0.0.0.0:80", NATType: "full-cone"},
		{Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: ""},
		{Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "cone"},
		{Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone", Metadata: "zz"},
		{Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone", Metadata: strings.Repeat("ab", 16)},
	}
	for i, c := range cases {
		resp := srv.signalReply(alice, c)
		if resp.Type != signalMsgTypeError {
			t.Fatalf("第 %d 个非法输入应返回 error，实际 %+v", i, resp)
		}
		if _, ok := reg.Get("192.168.30.11"); ok {
			t.Fatalf("第 %d 个非法输入不应写入登记表", i)
		}
	}
}

// TestShouldLogRegister 登记日志降噪规则（纯函数，可精确断言时间边界）
//
// 背景：客户端首次建信令流时会连发两帧内容相同的 register
// （唤醒帧 + 真正的 register 请求），每次 SignalQuery 也会再登记一次，
// 于是服务端日志里同一个 VIP 会连着出现两行一模一样的「登记」。
// 降噪只影响**日志**，登记本身照常刷新。
func TestShouldLogRegister(t *testing.T) {
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	prev := admin.PeerInfo{VIP: "192.168.30.11", PublicAddr: "1.2.3.4:30001", NATType: "full-cone", LastSeen: base}

	if !shouldLogRegister(admin.PeerInfo{}, false, "1.2.3.4:30001", "full-cone", base) {
		t.Fatal("首次登记必须记日志")
	}
	if shouldLogRegister(prev, true, "1.2.3.4:30001", "full-cone", base.Add(time.Second)) {
		t.Fatal("5 秒内相同 VIP + 相同地址/NAT 不应重复记日志")
	}
	if !shouldLogRegister(prev, true, "1.2.3.4:30001", "full-cone", base.Add(registerLogDedupWindow)) {
		t.Fatal("超过窗口后应重新记日志（窗口边界为 >=）")
	}
	if !shouldLogRegister(prev, true, "1.2.3.4:30002", "full-cone", base.Add(time.Second)) {
		t.Fatal("地址变了必须记日志（NAT 映射变化是关键信息）")
	}
	if !shouldLogRegister(prev, true, "1.2.3.4:30001", "symmetric", base.Add(time.Second)) {
		t.Fatal("NAT 类型变了必须记日志")
	}
}

// TestSignalReplyDuplicateRegisterStillRegisters 降噪不得影响登记语义
//
// 连续两次完全相同的 register（模拟唤醒帧 + 真正的 register 请求）：
// 两次都必须回 registered，登记表里都必须查得到（第二次甚至要刷新 LastSeen）。
func TestSignalReplyDuplicateRegisterStillRegisters(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	msg := &signalMessage{Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone"}

	for i := 1; i <= 2; i++ {
		resp := srv.signalReply(alice, msg)
		if resp.Type != signalMsgTypeRegistered {
			t.Fatalf("第 %d 次 register 应回 registered，实际 %+v", i, resp)
		}
		peer, ok := reg.Get("192.168.30.11")
		if !ok {
			t.Fatalf("第 %d 次 register 后登记表里必须查得到", i)
		}
		if peer.PublicAddr != "1.2.3.4:30001" || peer.NATType != "full-cone" {
			t.Fatalf("第 %d 次 register 后登记内容不对: %+v", i, peer)
		}
	}
	if reg.Count() != 1 {
		t.Fatalf("重复登记不应产生多条条目，实际 %d", reg.Count())
	}
}

// TestSignalReplyFailClosed 缺依赖时必须拒绝而不是放行
func TestSignalReplyFailClosed(t *testing.T) {
	srv, _ := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")

	// 没有 cs（identity 缺失）
	if resp := srv.signalReply(nil, &signalMessage{PublicAddr: "1.2.3.4:1", NATType: "unknown"}); resp.Type != signalMsgTypeError {
		t.Fatalf("cs 为 nil 时应返回 error，实际 %+v", resp)
	}
	// 没有登记表
	bare := &DataChannelServer{}
	if resp := bare.signalReply(alice, &signalMessage{PublicAddr: "1.2.3.4:1", NATType: "unknown"}); resp.Type != signalMsgTypeError {
		t.Fatalf("登记表缺失时应返回 error，实际 %+v", resp)
	}
	// vip 为空
	empty := &clientStream{}
	if resp := srv.signalReply(empty, &signalMessage{PublicAddr: "1.2.3.4:1", NATType: "unknown"}); resp.Type != signalMsgTypeError {
		t.Fatalf("cs.vip 为空时应返回 error，实际 %+v", resp)
	}
}

// TestEnableP2PSignalDisabled 关闭时不得接受信令流（最小攻击面）
func TestEnableP2PSignalDisabled(t *testing.T) {
	srv, reg := newSignalTestServer(t, false)
	if srv.p2pOn() {
		t.Fatal("p2pEnabled 应为 false")
	}
	if srv.signalRegistry() == nil {
		t.Fatal("登记表仍然应当被注入（只是不接受信令流）")
	}
	if reg.Count() != 0 {
		t.Fatalf("初始登记数应为 0，实际 %d", reg.Count())
	}
	// 关闭状态下应答必须 fail-closed
	alice := registerStream(srv, "192.168.30.11", "alice")
	if resp := srv.signalReply(alice, &signalMessage{
		PublicAddr: "1.2.3.4:1", NATType: "unknown",
	}); resp.Type != signalMsgTypeError {
		t.Fatalf("关闭时不应答 registered，实际 %+v", resp)
	}
}
