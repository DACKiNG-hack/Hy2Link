package quic

// vpn-server/quic/punch_reconnect_test.go
//
// ⭐ 1b-2B.2：连接断开时清理该 VIP 的打洞协调记录。
//
// 背景（真机反馈的 bug）：
//   - 协调记录原本**只靠 TTL(45s)** 过期，客户端断连不清理；
//   - 而 peer-busy 的判据 `activeResponderCount(peerVIP) >= 2` 是**记在响应方头上**的，
//     「活跃」= 未过 TTL（不区分「正在打洞」还是「发起方早已掉线」）；
//   - ⇒ 发起方掉线后，残留记录仍占着**对端**名额：45s 内任何客户端打那个对端都可能被
//     误判「对端忙」（附带损伤），重连后打同一对端也会被自己的残留误判。

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testClock 可注入时钟（race 安全：cleanupLoop 与测试会并发读）
func testClock(pt *punchTable) func(d time.Duration) {
	var nanos atomic.Int64
	nanos.Store(time.Now().UnixNano())
	pt.now = func() time.Time { return time.Unix(0, nanos.Load()) }
	return func(d time.Duration) { nanos.Store(time.Unix(0, nanos.Load()).Add(d).UnixNano()) }
}

// TestPunchTableDropByVIPOnDisconnect ⭐ 残留清理生效：发起方/响应方两侧的记录都要被删。
//
// ⚠️ 重要前提（本用例顺带钉住）：**同一对 (A,B) 不可能有 2 条记录** ——
// `start` 里有 pair-busy 守卫（punch.go:「同一对已有活跃 attempt」直接拒绝），
// 所以 B 的 2 个名额只能由**两个不同的发起方**占满。
// 这也意味着：用户报的「A 自己的残留把 B 占满」在**同一对**上不可能发生；
// 真实的残留风险是「A 的记录占着 B 的一个名额」+「另一个客户端的记录占另一个」⇒ 叠加到上限。
func TestPunchTableDropByVIPOnDisconnect(t *testing.T) {
	pt := newPunchTable()
	defer pt.close()
	advance := testClock(pt)

	// 同一对重复 start：必须 pair-busy（这条钉住上面那个前提）
	if _, _, err := pt.start("192.168.30.11", "192.168.30.12", nextID(), 10000); err != nil {
		t.Fatalf("start: %v", err)
	}
	advance(11 * time.Second) // 越过 pair-cooldown
	if _, _, err := pt.start("192.168.30.11", "192.168.30.12", nextID(), 10000); err == nil {
		t.Fatal("同一对 (A,B) 不得有两条记录：pair-busy 守卫应拦下（否则 TTL 内会累积）")
	}
	// 另一个客户端也打 B（不同发起方 ⇒ 允许），再加一条 C→A（A 作为**响应方**）
	if _, _, err := pt.start("192.168.30.13", "192.168.30.12", nextID(), 10000); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, _, err := pt.start("192.168.30.14", "192.168.30.11", nextID(), 10000); err != nil {
		t.Fatalf("start: %v", err)
	}
	if n := pt.activeResponderCount("192.168.30.12"); n != 2 {
		t.Fatalf("前置条件：B 应有 2 条活跃记录，实际 %d", n)
	}

	// A 断开：A→B 与 C→A 两条都要删（发起方/响应方两侧都算）
	if n := pt.dropByVIP("192.168.30.11"); n != 2 {
		t.Fatalf("应删掉 A 相关的 2 条记录（1 条作为发起方 + 1 条作为响应方），实际 %d", n)
	}
	if n := pt.activeResponderCount("192.168.30.12"); n != 1 {
		t.Fatalf("A 断开后 B 应只剩另一客户端的 1 条，实际 %d", n)
	}
	if n := pt.count(); n != 1 {
		t.Fatalf("应只剩另一客户端那条，实际剩 %d 条", n)
	}
}

// TestDropByVIPKeepsReplacedConnAttempts ⭐ **重连竞态防线**（去掉防线这条必须红）：
//
//	旧连接的收尾逻辑在新连接已经顶上来之后才跑时，绝对不能清理 ——
//	否则会把**新会话**的 VIP 释放掉、并误删它的打洞协调记录。
//	防线就是 `unregisterData` 内部的 `cur != cs` 检查，收尾方法只在它返回 true 时清理。
func TestDropByVIPKeepsReplacedConnAttempts(t *testing.T) {
	srv, _ := newSignalTestServer(t, true)
	aliceOld := registerStream(srv, "192.168.30.11", "alice")
	aliceNew := registerStream(srv, "192.168.30.11", "alice") // 同 VIP 重连：顶掉旧连接
	if aliceNew == aliceOld {
		t.Fatal("前置条件：新连接应替换旧连接")
	}

	// 新会话建立后，服务端里已有它的协调记录（模拟「新会话已开始打洞」）
	if _, _, err := srv.punchTable().start("192.168.30.11", "192.168.30.12", nextID(), 10000); err != nil {
		t.Fatalf("start: %v", err)
	}
	if n := srv.punchTable().count(); n != 1 {
		t.Fatalf("前置条件：应有 1 条记录，实际 %d", n)
	}

	// 旧连接的收尾（此时它已不是该 VIP 的当前占用者）
	cleaned := srv.cleanupDataConnVIP(aliceOld.vipBytes, aliceOld.vip, aliceOld.getDataConn(), "alice", "203.0.113.7")
	if cleaned {
		t.Fatal("旧连接的收尾不应执行清理（它已被新连接顶掉）")
	}
	// ⭐ 核心断言：新会话的协调记录必须**原封不动**
	if n := srv.punchTable().count(); n != 1 {
		t.Fatalf("新会话的协调记录被误删了（重连竞态防线失效），实际剩 %d 条", n)
	}
	// 新连接自己的收尾仍然要能正常清理
	if !srv.cleanupDataConnVIP(aliceNew.vipBytes, aliceNew.vip, aliceNew.getDataConn(), "alice", "203.0.113.7") {
		t.Fatal("当前占用者的收尾应执行清理")
	}
	if n := srv.punchTable().count(); n != 0 {
		t.Fatalf("当前占用者断开后应清空其记录，实际剩 %d 条", n)
	}
}

// TestOtherClientsNotFalselyBusyAfterDisconnect ⭐ 附带损伤回归：
//
//	alice 与 dave 各留一条记录占满 B 的名额（**两个不同发起方**，见上面的 pair-busy 前提）；
//	alice 断连被清理后，carol 打 B 不应再被误判 peer-busy。
func TestOtherClientsNotFalselyBusyAfterDisconnect(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	carol := registerStream(srv, "192.168.30.13", "carol")
	dave := registerStream(srv, "192.168.30.14", "dave")
	_ = reg.Update(bob.vip, "5.6.7.8:40002", "full-cone", "")
	bobSink := &recordingSink{}
	reg.AttachSink(bob.vip, bobSink)

	// alice 与 dave 各留一条 → 占满 B 的 2 个名额
	if _, _, err := srv.punchTable().start(alice.vip, bob.vip, nextID(), 10000); err != nil {
		t.Fatalf("start(alice): %v", err)
	}
	if _, _, err := srv.punchTable().start(dave.vip, bob.vip, nextID(), 10000); err != nil {
		t.Fatalf("start(dave): %v", err)
	}
	if n := srv.punchTable().activeResponderCount(bob.vip); n != relayMaxResponderInvites {
		t.Fatalf("前置条件：B 应有 %d 条活跃记录，实际 %d", relayMaxResponderInvites, n)
	}

	// 先证明「不清理就会被误判忙」（否则本用例证明不了附带损伤）
	out := &recordingSink{}
	msg := testIntent(bob.vip)
	msg.AttemptID = nextID()
	if err := srv.handlePunchIntent(out, carol, msg); err != nil {
		t.Fatalf("handlePunchIntent: %v", err)
	}
	if msgs := out.all(); len(msgs) != 1 || !strings.Contains(msgs[0].Error, "peer-busy") {
		t.Fatalf("前置条件：carol 此时应被误判 peer-busy，实际 %+v", msgs)
	}

	// ⭐ alice 断连 → 清理其记录（走生产代码的同一条收尾路径）
	if !srv.cleanupDataConnVIP(alice.vipBytes, alice.vip, alice.getDataConn(), "alice", "203.0.113.7") {
		t.Fatal("alice 是当前占用者，收尾应执行清理")
	}

	// 现在 carol 打 B 必须放行（不再被残留误判）
	out2 := &recordingSink{}
	msg2 := testIntent(bob.vip)
	msg2.AttemptID = nextID()
	if err := srv.handlePunchIntent(out2, carol, msg2); err != nil {
		t.Fatalf("handlePunchIntent: %v", err)
	}
	for _, m := range out2.all() {
		if m.Type == signalMsgTypeError && strings.Contains(m.Error, "peer-busy") {
			t.Fatalf("alice 断开后不应再被判 peer-busy（附带损伤未修复）: %+v", m)
		}
	}
	// 并且真的推出了邀请（说明协调正常建立）
	found := false
	for _, m := range bobSink.all() {
		if m.Type == signalMsgTypePunchInvite && m.AttemptID == msg2.AttemptID {
			found = true
		}
	}
	if !found {
		t.Fatal("清理后应向 B 推送新的 punch-invite")
	}
}
