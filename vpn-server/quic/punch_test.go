package quic

// vpn-server/quic/punch_test.go
//
// 阶段 1b-1 服务端侧测试：三集合不相交、协调表（限流/冷却/TTL/幂等）、
// 两个请求 handler 的正常与拒绝路径、以及并发压测（-race 目标）。

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpn-server/admin"
)

// recordingSink 记录下行 payload 的假 sink（断言推送内容用）
type recordingSink struct {
	mu   sync.Mutex
	msgs []signalMessage
	fail bool
}

func (r *recordingSink) SendSignal(payload []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return fmt.Errorf("sink 故意失败")
	}
	var m signalMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return err
	}
	r.msgs = append(r.msgs, m)
	return nil
}

func (r *recordingSink) CloseSignal() error { return nil }

// writeMessage 让 recordingSink 同时能当 signalWriter（handler 的回包出口）
func (r *recordingSink) writeMessage(msg signalMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, msg)
	return nil
}

func (r *recordingSink) all() []signalMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]signalMessage(nil), r.msgs...)
}

func (r *recordingSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.msgs)
}

const (
	testAttemptID = "0123456789abcdef"
	testPunchAddr = "198.51.100.7:40001"
	testFP        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// idSeq 给测试生成唯一 attemptId（生产里由**发起方 A** 生成，见 punch.go start 的注释）
var idSeq int64

func nextID() string {
	n := atomic.AddInt64(&idSeq, 1)
	return fmt.Sprintf("%016x", n)
}

func testIntent(peerVIP string) *signalMessage {
	return &signalMessage{
		Type:              signalMsgTypePunchIntent,
		AttemptID:         testAttemptID,
		PeerVIP:           peerVIP,
		PublicAddr:        "1.2.3.4:30001",
		NATType:           "full-cone",
		Metadata:          strings.Repeat("ab", admin.MetadataLen),
		PunchAddr:         testPunchAddr,
		DirectFingerprint: testFP,
		WindowMs:          10000,
	}
}

// ---------- 约束 1：三集合两两不相交 ----------

func TestSignalTypeSetsAreDisjoint(t *testing.T) {
	sets := map[string][]string{
		"request":  signalRequestTypes,
		"response": signalResponseTypes,
		"push":     signalPushTypes,
	}
	seen := map[string]string{}
	for name, list := range sets {
		for _, v := range list {
			if v == "" {
				t.Fatalf("%s 集合里有空串", name)
			}
			if prev, dup := seen[v]; dup {
				t.Fatalf("类型 %q 同时出现在 %s 与 %s 集合里（约束 1 被破坏）", v, prev, name)
			}
			seen[v] = name
		}
	}

	// 1a 的应答集合原来必须是 3 个；⭐ D1-a 新增 `peers-list` ⇒ 现在是 4 个
	// （约束 1 的适用范围没变：推送仍必须与「请求 ∪ 应答」不相交）。
	if len(signalResponseTypes) != 4 {
		t.Fatalf("应答类型集合应恰好 4 个（1a 的 3 个 + D1-a 的 peers-list），实际 %d 个 —— 变了就要重新评估约束 1", len(signalResponseTypes))
	}
	// 服务端拒绝列表必须覆盖「请求 ∪ 应答」
	for _, v := range append(append([]string{}, signalRequestTypes...), signalResponseTypes...) {
		if !isRequestOrResponseType(v) {
			t.Fatalf("%q 应在请求/应答集合里", v)
		}
	}
	for _, v := range signalPushTypes {
		if isRequestOrResponseType(v) {
			t.Fatalf("推送类型 %q 不应被判为请求/应答类型（约束 1 被破坏）", v)
		}
	}
	// 新增的 4 个类型常量都必须被登记在某个集合里
	for _, v := range []string{
		signalMsgTypePunchIntent, signalMsgTypePunchReady,
		signalMsgTypePunchInvite, signalMsgTypePunchPeer,
	} {
		if _, ok := seen[v]; !ok {
			t.Fatalf("类型常量 %q 没有登记在三张集合里", v)
		}
	}
}

// TestPushSignalRejectsRequestAndResponseTypes 推送出口的运行时兜底（约束 1）
func TestPushSignalRejectsRequestAndResponseTypes(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	registerStream(srv, "192.168.30.11", "alice")
	reg.AttachSink("192.168.30.11", &recordingSink{})

	for _, bad := range append(append([]string{}, signalRequestTypes...), signalResponseTypes...) {
		if err := srv.PushSignal("192.168.30.11", signalMessage{Type: bad}); err == nil {
			t.Fatalf("推送 type=%q 与请求/应答冲突，必须被拒绝", bad)
		}
	}
	if err := srv.PushSignal("192.168.30.11", signalMessage{Type: ""}); err == nil {
		t.Fatal("空 type 推送必须被拒绝")
	}
	for _, good := range signalPushTypes {
		if err := srv.PushSignal("192.168.30.11", signalMessage{Type: good}); err != nil {
			t.Fatalf("合法推送 %q 不应被拒: %v", good, err)
		}
	}
}

// ---------- 协调表 ----------

func TestPunchTableStartLimitsAndCooldown(t *testing.T) {
	pt := newPunchTable()
	defer pt.close()

	now := time.Now()
	pt.now = func() time.Time { return now }

	// 每对唯一：同一对第二次 → pair-cooldown / pair-busy
	if _, _, err := pt.start("A", "B", nextID(), 10000); err != nil {
		t.Fatalf("首次协调应成功: %v", err)
	}
	if _, _, err := pt.start("A", "B", nextID(), 10000); err == nil {
		t.Fatal("同一对 10s 内重复发起必须被拒")
	}
	// 不同对可以并发
	if _, _, err := pt.start("A", "C", nextID(), 10000); err != nil {
		t.Fatalf("不同对应当允许: %v", err)
	}
	if pt.count() != 2 {
		t.Fatalf("应记录 2 条，实际 %d", pt.count())
	}

	// 滑动窗口：A 在 1 分钟内最多 5 次
	now = now.Add(11 * time.Second) // 越过冷却
	for i := 0; i < 3; i++ {
		if _, _, err := pt.start("A", fmt.Sprintf("P%d", i), nextID(), 10000); err != nil {
			t.Fatalf("第 %d 次应当允许: %v", i, err)
		}
	}
	// 此时 A 已有 5 次（2 + 3）→ 第 6 次被限流
	if _, _, err := pt.start("A", "P9", nextID(), 10000); err == nil {
		t.Fatal("1 分钟内第 6 次发起必须被限流")
	} else if err.Error() != "rate-limited" {
		t.Fatalf("限流原因串应为 rate-limited，实际 %q", err.Error())
	}
	// 滑动窗口：61s 后恢复
	now = now.Add(61 * time.Second)
	if _, _, err := pt.start("A", "P10", nextID(), 10000); err != nil {
		t.Fatalf("滑出窗口后应恢复: %v", err)
	}
}

func TestPunchTableMarkReadyIdempotentAndTTL(t *testing.T) {
	pt := newPunchTable()
	defer pt.close()

	now := time.Now()
	pt.now = func() time.Time { return now }

	a, _, err := pt.start("A", "B", nextID(), 10000)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// 参数不匹配 → 找不到（防越权给别人的 attempt 回 ready）
	if _, _, ok := pt.markReady(a.id, "X", "B"); ok {
		t.Fatal("发起方不匹配时不应命中")
	}
	if _, _, ok := pt.markReady(a.id, "A", "X"); ok {
		t.Fatal("响应方不匹配时不应命中")
	}

	// 第一次 → first=true；第二次 → first=false（幂等，不重复推 punch-peer）
	if _, first, ok := pt.markReady(a.id, "A", "B"); !ok || !first {
		t.Fatalf("首次 ready 应为 first=true ok=true，实际 first=%v ok=%v", first, ok)
	}
	if _, first, ok := pt.markReady(a.id, "A", "B"); !ok || first {
		t.Fatalf("重复 ready 应为 first=false ok=true，实际 first=%v ok=%v", first, ok)
	}

	// TTL：过期后 markReady 找不到，cleanup 也会删掉
	now = now.Add(punchAttemptTTL + time.Second)
	if _, _, ok := pt.markReady(a.id, "A", "B"); ok {
		t.Fatal("超过 TTL 的 attempt 不应命中")
	}
	if pt.count() != 0 {
		t.Fatalf("过期后应被删除，实际 %d", pt.count())
	}
}

// TestServerPunchAttemptTableConcurrent（§7.2 #3，-race 目标）
func TestServerPunchAttemptTableConcurrent(t *testing.T) {
	pt := newPunchTable()
	defer pt.close()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			init := fmt.Sprintf("10.0.0.%d", i%4)
			resp := fmt.Sprintf("10.0.1.%d", i%4)
			for j := 0; j < 20; j++ {
				a, _, err := pt.start(init, resp, nextID(), 10000)
				if err == nil {
					_, _, _ = pt.markReady(a.id, init, resp)
					pt.drop(a.id)
				}
				_ = pt.count()
				pt.cleanup()
			}
		}(i)
	}
	wg.Wait()

	// 收尾后表必须干净（无泄漏）
	pt.cleanup()
	for _, a := range pt.attempts {
		pt.drop(a.id)
	}
	if pt.count() != 0 {
		t.Fatalf("并发压测后协调表应归零，实际 %d", pt.count())
	}
}

// ---------- handler ----------

// TestPunchIntentRetryIsIdempotent（review 问题 2）
//
//	A 的 punch-intent 有重试（上限 2 次尝试）且**复用同一个 attemptId**。
//	服务端必须把它当幂等（复用既有记录），不能回 attempt-exists ——
//	否则重试必然失败，还会把一个已经建立、邀请可能已经推给 B 的 attempt 判成失败。
func TestPunchIntentRetryIsIdempotent(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	registerStream(srv, "192.168.30.12", "bob")
	_ = reg.Update("192.168.30.12", "5.6.7.8:40002", "symmetric", "")
	bobSink := &recordingSink{}
	reg.AttachSink("192.168.30.12", bobSink)

	// 第一次
	out1 := &recordingSink{}
	if err := srv.handlePunchIntent(out1, alice, testIntent("192.168.30.12")); err != nil {
		t.Fatalf("首次 intent: %v", err)
	}
	if msgs := out1.all(); len(msgs) != 1 || msgs[0].Type != signalMsgTypePeer {
		t.Fatalf("首次应回 peer，实际 %+v", msgs)
	}

	// 同一个 attemptId 重试（模拟「应答丢了、A 重发」）
	out2 := &recordingSink{}
	if err := srv.handlePunchIntent(out2, alice, testIntent("192.168.30.12")); err != nil {
		t.Fatalf("重试 intent: %v", err)
	}
	msgs := out2.all()
	if len(msgs) != 1 || msgs[0].Type != signalMsgTypePeer {
		t.Fatalf("重试也应回 peer（幂等），实际 %+v", msgs)
	}
	if strings.Contains(msgs[0].Error, "attempt-exists") {
		t.Fatalf("重试不得回 attempt-exists：%q", msgs[0].Error)
	}
	// 表里仍只有一条；邀请被重推了一次（B 侧按 attemptId 去重）
	if srv.punchTable().count() != 1 {
		t.Fatalf("幂等重试不应新建记录，实际 %d 条", srv.punchTable().count())
	}
	if bobSink.count() != 2 {
		t.Fatalf("重试应重推一次邀请（B 侧去重），实际 %d 条邀请", bobSink.count())
	}

	// 重试不应重复消耗限流额度：同一 attemptId 再发 4 次仍应成功
	for i := 0; i < 4; i++ {
		o := &recordingSink{}
		if err := srv.handlePunchIntent(o, alice, testIntent("192.168.30.12")); err != nil {
			t.Fatalf("第 %d 次幂等重试: %v", i, err)
		}
		if got := o.all(); len(got) != 1 || got[0].Type != signalMsgTypePeer {
			t.Fatalf("第 %d 次重试应回 peer，实际 %+v", i, got)
		}
	}

	// ID 相同但**换了对端** → 才回 attempt-exists（ID 盗用/碰撞）
	registerStream(srv, "192.168.30.13", "carol")
	_ = reg.Update("192.168.30.13", "203.0.113.30:40003", "full-cone", "")
	reg.AttachSink("192.168.30.13", &recordingSink{})
	bad := testIntent("192.168.30.13")
	badOut := &recordingSink{}
	if err := srv.handlePunchIntent(badOut, alice, bad); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if got := badOut.all(); len(got) != 1 || !strings.Contains(got[0].Error, "attempt-exists") {
		t.Fatalf("同一 ID 换对端应回 attempt-exists，实际 %+v", got)
	}
}

// TestPunchIntentRequiresRegisterFields（review 问题 3）
//
//	punch-intent / punch-ready 是 register 的**超集**，而服务端复用 signalReply ——
//	后者依赖 publicAddr / natType / metadata 三项。这条测试把该依赖钉住：
//	缺任意一项都必须报错，且**不得留下协调记录**。
func TestPunchIntentRequiresRegisterFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*signalMessage)
	}{
		{"缺 publicAddr", func(m *signalMessage) { m.PublicAddr = "" }},
		{"缺 natType", func(m *signalMessage) { m.NATType = "" }},
		{"natType 不在白名单", func(m *signalMessage) { m.NATType = "cone" }},
		{"metadata 长度不对", func(m *signalMessage) { m.Metadata = "abcd" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, reg := newSignalTestServer(t, true)
			alice := registerStream(srv, "192.168.30.11", "alice")
			registerStream(srv, "192.168.30.12", "bob")
			_ = reg.Update("192.168.30.12", "5.6.7.8:40002", "symmetric", "")
			reg.AttachSink("192.168.30.12", &recordingSink{})

			msg := testIntent("192.168.30.12")
			tc.mutate(msg)
			out := &recordingSink{}
			if err := srv.handlePunchIntent(out, alice, msg); err != nil {
				t.Fatalf("handler 应回 error 消息而不是返回错误: %v", err)
			}
			msgs := out.all()
			if len(msgs) != 1 || msgs[0].Type != signalMsgTypeError {
				t.Fatalf("缺 register 字段时应回 error，实际 %+v", msgs)
			}
			if srv.punchTable().count() != 0 {
				t.Fatalf("被拒的 intent 不得留下协调记录，实际 %d", srv.punchTable().count())
			}
		})
	}

	// 补位：三项都齐时必须成功（否则上面的「缺了就报错」可能是假阳性）
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	registerStream(srv, "192.168.30.12", "bob")
	_ = reg.Update("192.168.30.12", "5.6.7.8:40002", "symmetric", "")
	reg.AttachSink("192.168.30.12", &recordingSink{})
	out := &recordingSink{}
	if err := srv.handlePunchIntent(out, alice, testIntent("192.168.30.12")); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if msgs := out.all(); len(msgs) != 1 || msgs[0].Type != signalMsgTypePeer {
		t.Fatalf("字段齐全时应成功，实际 %+v", msgs)
	}
}

// TestHandlePunchIntentHappyPath 协调成功：推 invite 给 B + 回 peer 给 A
func TestHandlePunchIntentHappyPath(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	registerStream(srv, "192.168.30.12", "bob")
	if err := reg.Update("192.168.30.12", "5.6.7.8:40002", "symmetric", ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
	bobSink := &recordingSink{}
	reg.AttachSink("192.168.30.12", bobSink)

	sink := &recordingSink{}
	if err := srv.handlePunchIntent(sink, alice, testIntent("192.168.30.12")); err != nil {
		t.Fatalf("handlePunchIntent: %v", err)
	}
	if srv.punchTable().count() != 1 {
		t.Fatalf("应建立 1 条协调记录，实际 %d", srv.punchTable().count())
	}

	// B 收到的 invite 字段必须完整（A 的 punch 地址 / seed / 指纹 / 窗口）
	msgs := bobSink.all()
	if len(msgs) != 1 {
		t.Fatalf("B 应收到 1 条邀请，实际 %d", len(msgs))
	}
	inv := msgs[0]
	if inv.Type != signalMsgTypePunchInvite || inv.PeerVIP != "192.168.30.11" ||
		inv.PunchAddr != testPunchAddr || inv.DirectFingerprint != testFP ||
		inv.WindowMs != 10000 || inv.Metadata == "" || inv.AttemptID != testAttemptID {
		t.Fatalf("邀请内容不对: %+v", inv)
	}

	// A 的应答（fakeSink 只计数；这里用 signalReply 的返回值单独验证语义）
	resp := srv.signalReply(alice, testIntent("192.168.30.12"))
	if resp.Type != signalMsgTypePeer || !resp.PeerOnline || !resp.PeerSignalReady {
		t.Fatalf("A 应拿到 peer 应答且 signalReady=true，实际 %+v", resp)
	}
}

// TestHandlePunchIntentRejects 各种拒绝路径，且不得留下协调记录
func TestHandlePunchIntentRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*signalMessage)
		offline bool
		wantErr string
	}{
		{"peerVIP 为空", func(m *signalMessage) { m.PeerVIP = "" }, false, "peerVIP required"},
		{"打自己", func(m *signalMessage) { m.PeerVIP = "192.168.30.11" }, false, "cannot punch self"},
		{"attemptId 非法", func(m *signalMessage) { m.AttemptID = "xyz" }, false, "attemptId"},
		{"punchAddr 为空", func(m *signalMessage) { m.PunchAddr = "" }, false, "punchAddr 不能为空"},
		{"punchAddr 是私网", func(m *signalMessage) { m.PunchAddr = "10.0.0.5:40001" }, false, "私网"},
		{"punchAddr 是环回", func(m *signalMessage) { m.PunchAddr = "127.0.0.1:40001" }, false, "私网/环回"},
		{"指纹非法", func(m *signalMessage) { m.DirectFingerprint = "zz" }, false, "directFingerprint"},
		{"publicAddr 非法", func(m *signalMessage) { m.PublicAddr = "" }, false, "publicAddr"},
		{"对端不在线", func(m *signalMessage) { m.PeerVIP = "192.168.30.199" }, true, "peer-unreachable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, reg := newSignalTestServer(t, true)
			alice := registerStream(srv, "192.168.30.11", "alice")
			if !tc.offline {
				registerStream(srv, "192.168.30.12", "bob")
				_ = reg.Update("192.168.30.12", "5.6.7.8:40002", "symmetric", "")
				reg.AttachSink("192.168.30.12", &recordingSink{})
			}
			msg := testIntent("192.168.30.12")
			tc.mutate(msg)
			sink := &recordingSink{}
			if err := srv.handlePunchIntent(sink, alice, msg); err != nil {
				t.Fatalf("handler 不应返回错误，应回 error 消息: %v", err)
			}
			msgs := sink.all()
			if len(msgs) != 1 || msgs[0].Type != signalMsgTypeError {
				t.Fatalf("应回一条 error 应答，实际 %+v", msgs)
			}
			if !strings.Contains(msgs[0].Error, tc.wantErr) {
				t.Fatalf("错误信息应含 %q，实际 %q", tc.wantErr, msgs[0].Error)
			}
			if srv.punchTable().count() != 0 {
				t.Fatalf("被拒的请求不得留下协调记录，实际 %d", srv.punchTable().count())
			}
		})
	}
}

// TestHandlePunchIntentPeerNoSink 对端在线但没有信令通道 → peer-not-ready 且回滚
func TestHandlePunchIntentPeerNoSink(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	registerStream(srv, "192.168.30.12", "bob")
	_ = reg.Update("192.168.30.12", "5.6.7.8:40002", "symmetric", "")
	// 故意不挂 sink

	sink := &recordingSink{}
	if err := srv.handlePunchIntent(sink, alice, testIntent("192.168.30.12")); err != nil {
		t.Fatalf("handler: %v", err)
	}
	msgs := sink.all()
	if len(msgs) != 1 || msgs[0].Type != signalMsgTypeError ||
		!strings.Contains(msgs[0].Error, "peer-not-ready") {
		t.Fatalf("应回 peer-not-ready，实际 %+v", msgs)
	}
	if srv.punchTable().count() != 0 {
		t.Fatalf("推送失败必须回滚协调记录，实际 %d", srv.punchTable().count())
	}
}

// TestHandlePunchReadyPushesPeerOnce 就绪回报：首次推 punch-peer，重复幂等；空 punchAddr 也转达
func TestHandlePunchReadyPushesPeerOnce(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	_ = reg.Update("192.168.30.12", "5.6.7.8:40002", "symmetric", "")
	aliceSink := &recordingSink{}
	bobSink := &recordingSink{}
	reg.AttachSink("192.168.30.11", aliceSink)
	reg.AttachSink("192.168.30.12", bobSink)

	// 先建立协调
	if err := srv.handlePunchIntent(&recordingSink{}, alice, testIntent("192.168.30.12")); err != nil {
		t.Fatalf("intent: %v", err)
	}
	if aliceSink.count() != 0 {
		t.Fatalf("建立协调时不应给 A 推 punch-peer，实际 %d", aliceSink.count())
	}

	ready := &signalMessage{
		Type:       signalMsgTypePunchReady,
		AttemptID:  testAttemptID,
		PeerVIP:    "192.168.30.11",
		PublicAddr: "5.6.7.8:40002",
		NATType:    "symmetric",
		PunchAddr:  "203.0.113.9:40002",
	}
	out := &recordingSink{}
	if err := srv.handlePunchReady(out, bob, ready); err != nil {
		t.Fatalf("ready: %v", err)
	}
	if msgs := out.all(); len(msgs) != 1 || msgs[0].Type != signalMsgTypePeer {
		t.Fatalf("B 应收到 peer 应答，实际 %+v", msgs)
	}
	msgs := aliceSink.all()
	if len(msgs) != 1 {
		t.Fatalf("A 应收到 1 条 punch-peer，实际 %d", len(msgs))
	}
	if msgs[0].Type != signalMsgTypePunchPeer || msgs[0].PunchAddr != "203.0.113.9:40002" ||
		msgs[0].PeerVIP != "192.168.30.12" || msgs[0].AttemptID != testAttemptID {
		t.Fatalf("punch-peer 内容不对: %+v", msgs[0])
	}

	// 重复 ready：不再推（幂等），但仍回 peer
	if err := srv.handlePunchReady(out, bob, ready); err != nil {
		t.Fatalf("重复 ready: %v", err)
	}
	if aliceSink.count() != 1 {
		t.Fatalf("重复 ready 不应重复推送，实际 %d", aliceSink.count())
	}
	if got := out.count(); got != 2 {
		t.Fatalf("每次 ready 都应回 peer 应答，实际 %d 条", got)
	}

	// 未知 attemptId → unknown-attempt
	bad := &recordingSink{}
	ready2 := *ready
	ready2.AttemptID = "ffffffffffffffff"
	if err := srv.handlePunchReady(bad, bob, &ready2); err != nil {
		t.Fatalf("ready: %v", err)
	}
	if msgs := bad.all(); len(msgs) != 1 || !strings.Contains(msgs[0].Error, "unknown-attempt") {
		t.Fatalf("未知 attempt 应回 unknown-attempt，实际 %+v", msgs)
	}

	// 空 punchAddr（B 无法广告地址）必须被接受并原样转达。
	// 注意：这里必须换一对（alice←carol）—— 同一对 10s 内会被 pair-cooldown 挡住，
	// 那正是上一条测试在验证的行为。
	carolVIP := "192.168.30.13"
	carol := registerStream(srv, carolVIP, "carol")
	_ = reg.Update(carolVIP, "203.0.113.20:40003", "full-cone", "")
	reg.AttachSink(carolVIP, &recordingSink{})
	a2, _, err := srv.punchTable().start("192.168.30.11", carolVIP, nextID(), 10000)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	emptyReady := &signalMessage{
		Type: signalMsgTypePunchReady, AttemptID: a2.id,
		PeerVIP: "192.168.30.11", PublicAddr: "203.0.113.20:40003", NATType: "full-cone",
		PunchAddr: "",
	}
	if err := srv.handlePunchReady(&recordingSink{}, carol, emptyReady); err != nil {
		t.Fatalf("空 punchAddr 的 ready: %v", err)
	}
	last := aliceSink.all()
	if n := len(last); n != 2 || last[n-1].PunchAddr != "" || last[n-1].PeerVIP != carolVIP {
		t.Fatalf("空 punchAddr 应被原样转达，实际 %+v", last)
	}
}

// TestPunchHandlersFailClosedWhenDisabled P2P 关闭时两个请求都必须被拒
func TestPunchHandlersFailClosedWhenDisabled(t *testing.T) {
	srv, _ := newSignalTestServer(t, false)
	alice := registerStream(srv, "192.168.30.11", "alice")

	out := &recordingSink{}
	if err := srv.handlePunchIntent(out, alice, testIntent("192.168.30.12")); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if msgs := out.all(); len(msgs) != 1 || msgs[0].Type != signalMsgTypeError {
		t.Fatalf("P2P 关闭时应回 error，实际 %+v", msgs)
	}
	out2 := &recordingSink{}
	if err := srv.handlePunchReady(out2, alice, &signalMessage{
		Type: signalMsgTypePunchReady, AttemptID: testAttemptID, PeerVIP: "192.168.30.12",
	}); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if msgs := out2.all(); len(msgs) != 1 || msgs[0].Type != signalMsgTypeError {
		t.Fatalf("P2P 关闭时应回 error，实际 %+v", msgs)
	}
}

// TestEnableP2PSignalClosesPunchTable 关掉 P2P 必须把协调表连同 ticker 一起停掉
func TestEnableP2PSignalClosesPunchTable(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	if srv.punchTable() == nil {
		t.Fatal("启用时应创建协调表")
	}
	old := srv.punchTable()
	srv.EnableP2PSignal(false, reg)
	if srv.punchTable() != nil {
		t.Fatal("关闭时协调表应为 nil")
	}
	select {
	case <-old.stop:
	case <-time.After(time.Second):
		t.Fatal("关闭时协调表的清理 goroutine 应被停止")
	}
	// 再打开 → 新表（干净）
	srv.EnableP2PSignal(true, reg)
	if srv.punchTable() == nil || srv.punchTable() == old {
		t.Fatal("重新启用应换一张新表")
	}
	srv.punchTable().close()
}
