package quic

// vpn-tool/backend/quic/d1a_peers_test.go
//
// ⭐ D1-a 测试：**枚举在线对端**（`peers` / `peers-list`）。
//
// 覆盖方案 §10.2（客户端侧）与端到端：
//   - 正常解析 peers-list
//   - 旧服务端（unknown message type）⇒ ErrPeersUnsupported + **静默降级** + **只探测一次**（缓存）
//   - 服务端**连 error 都不回** ⇒ 超时后**不缓存**（下次仍会尝试）
//   - 集合约束（三集合两两不相交 + 新类型各归其集合）已由 TestClientSignalTypeSetsAreDisjoint 覆盖
//
// ⚠️ 与「预打洞」的关系：本切片**只做协议与查询**，不做预打洞策略（那是第 2 步-B）。

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestResponseDispatchMirrorsCollection ⭐⭐ review 追问 1：**防「双清单漂移」的通用武器**。
//
// 背景：客户端有**两个运行时分派点**（`isResponseType` + `dispatchSignalMessage`）。
// D1-a 实测踩过：只给 `isResponseType` 加了 `peers-list`、漏了分派处 ⇒
//
//	应答落到 `default` 被当成推送丢弃 ⇒ 请求一直等到 5s 超时。
//
// 现在两个分派点都**只引用集合变量** `signalResponseTypes`。本用例把这条不变式钉住：
//
//	① 集合里**每一个**应答类型，两个分派点都必须判为「应答」；
//	② 集合**之外**的每个已知类型（请求/推送常量），两个分派点都**不得**判为应答；
//	③ 用**真的投递**验证：集合里的类型必须能填进等待槽（不是只看谓词返回值）。
//
// ⚠️ 有牙：把任一分派点改回硬编码且漏掉某个新类型 ⇒ 本用例立刻红。
func TestResponseDispatchMirrorsCollection(t *testing.T) {
	// 收集「已知但不属于应答集合」的类型（请求 ∪ 推送）
	allOthers := map[string]bool{}
	for _, v := range signalRequestTypes {
		allOthers[v] = true
	}
	for _, v := range signalPushTypes {
		allOthers[v] = true
	}

	for _, resp := range signalResponseTypes {
		// ① 谓词必须认它是应答
		if !(&Hysteria2Client{}).isResponseType(resp) {
			t.Fatalf("应答集合成员 %q 未被 isResponseType 认作应答", resp)
		}
		// ③ 真投递：装好等待槽后喂进去，必须**填进槽**（而不是走推送分支丢弃）
		c := &Hysteria2Client{}
		ch := make(chan signalMessage, 1)
		c.signalPending = ch
		c.dispatchSignalMessage(signalMessage{Type: resp})
		select {
		case got := <-ch:
			if got.Type != resp {
				t.Fatalf("槽里应收到 %q，实际 %q", resp, got.Type)
			}
		default:
			t.Fatalf("应答 %q 没有投进等待槽 —— 分派点与集合漂移了"+
				"（这正是 D1-a 踩过的「只加一处漏另一处」）", resp)
		}
		delete(allOthers, resp) // 若某类型同时出现在两个集合，这里会暴露
	}

	// ② 反向：非应答类型**不得**被判为应答（否则会被投进等待槽，约束 1 被破坏）
	for other := range allOthers {
		if (&Hysteria2Client{}).isResponseType(other) {
			t.Fatalf("非应答类型 %q 被判为应答（会被投进等待槽 ⇒ 约束 1 被破坏）", other)
		}
	}
}

// TestUnknownTypeStillGoesToPushHook ⭐ review 追问 1 + 方案 §2.3 的**硬断言**：
//
//	「未知 type ⇒ 一律走 push 钩子」——**绝不能**静默丢弃。
//
// 为什么必须有这条：`dispatchSignalMessage` 去掉 `default:` 改成 if/else 后，
// 很容易被后人误写成 `else { return }`（静默丢弃）⇒ 将来新增的推送类型"看起来没生效"。
// 本用例把该契约钉死：非应答类型（含完全未知的字符串）必须送达 push 钩子。
func TestUnknownTypeStillGoesToPushHook(t *testing.T) {
	for _, typ := range []string{
		"totally-unknown-type",   // 完全未知（模拟旧客户端的未知新推送）
		"punch-invite-future-v2", // 未来可能新增的推送命名风格
		signalMsgTypePunchInvite, // 已知推送类型
	} {
		c := &Hysteria2Client{}
		var got []string
		c.signalPush = func(p SignalPush) { got = append(got, p.Type) }

		// 不装等待槽：若被误判为应答，会走「无主应答」分支 ⇒ got 为空（被丢弃）
		c.dispatchSignalMessage(signalMessage{Type: typ})

		if len(got) != 1 || got[0] != typ {
			t.Fatalf("非应答类型 %q 必须送达 push 钩子（方案 §2.3），实际送达 %v"+
				" —— 若为空说明被静默丢弃了", typ, got)
		}
	}
}

// TestPeersQueryRateLimitedIsDistinct ⭐ review 追问 4：三类错误必须**可区分**。
//
// 调用方若把「太频繁」误判为「不支持」并缓存 ⇒ 本连接内再也不试 ⇒ 功能永久失效。
func TestPeersQueryRateLimitedIsDistinct(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()
	c := d1aClient(t, srv, "192.168.30.11")
	defer func() { _ = c.Close() }()

	srv.mu.Lock()
	srv.peersRateLimited = true
	srv.mu.Unlock()

	_, _, err := c.PeersQuery(context.Background())
	if !errors.Is(err, ErrPeersRateLimited) {
		t.Fatalf("限流应返回 ErrPeersRateLimited，实际 %v", err)
	}
	// 必须与「不支持」互不混淆
	if errors.Is(err, ErrPeersUnsupported) {
		t.Fatal("限流**绝不能**被当成「不支持」（否则调用方会缓存并永久放弃）")
	}
	if c.PeersUnsupportedCached() {
		t.Fatal("限流**不得**污染「不支持」缓存")
	}
	// 限流后仍应继续探测（下一轮/稍后）
	srv.mu.Lock()
	srv.peersRateLimited = false
	srv.peersOnline = []string{"192.168.30.12"}
	srv.mu.Unlock()
	peers, _, err2 := c.PeersQuery(context.Background())
	if err2 != nil {
		t.Fatalf("限流解除后应能正常查询，实际 %v", err2)
	}
	if len(peers) != 1 || peers[0].VIP != "192.168.30.12" {
		t.Fatalf("限流解除后应拿到列表，实际 %+v", peers)
	}
}

// TestPeersUnsupportedCacheScopeIsConnection ⭐ review 追问 2：缓存**作用域是一次连接**。
//
// 为什么必须这样（功能性 bug）：同一个 `Hysteria2Client` 实例可以连**不同服务端**
// （用户切节点）；若把「旧服务端不支持 peers」的结论带过去 ⇒ 新服务端明明支持也永不尝试。
//
// ⚠️ 测试设计说明：本用例**不**做「同实例真重连」——`cleanupPartial()` 会取消客户端的
// `ctx`（`c.ctx`），同实例二次 `Connect()` 必然拿到 `context canceled`（生命周期设计）。
// 所以要分两段验证，合起来覆盖完整链条：
//
//	① **清除点的不变式**：`cleanupPartial()`（走生产的收尾链路 `closeSignalStream`）必须清零；
//	② **端到端**：一个**干净客户端**连上「支持 peers」的服务端 ⇒ 能正常枚举
//	   （若缓存真被跨连接带过去，第 ① 步的断言就会失败）。
func TestPeersUnsupportedCacheScopeIsConnection(t *testing.T) {
	// ① 旧服务端（不认识 peers）⇒ 缓存置位
	srvOld := newFakeSignalServer(t)
	defer srvOld.close()
	srvOld.mu.Lock()
	srvOld.peersUnknownType = true
	srvOld.mu.Unlock()

	c := d1aClient(t, srvOld, "192.168.30.11")
	defer func() { _ = c.Close() }()

	if _, _, err := c.PeersQuery(context.Background()); !errors.Is(err, ErrPeersUnsupported) {
		t.Fatalf("旧服务端应报不支持，实际 %v", err)
	}
	if !c.PeersUnsupportedCached() {
		t.Fatal("前置：应已缓存「不支持」")
	}

	// ① 收尾链路（换服务端/断连都会走这条）必须清零缓存
	c.cleanupPartial()
	if c.PeersUnsupportedCached() {
		t.Fatal("收尾后「不支持」缓存必须清零 —— 否则切到新服务端会永久不试 peers（功能性 bug）")
	}

	// ① 另一条清除点：换流/重连（closeSignalStream）
	c.peersUnsupported.Store(true)
	c.closeSignalStream()
	if c.PeersUnsupportedCached() {
		t.Fatal("换流（closeSignalStream）后也必须清零")
	}

	// ② 端到端：干净客户端 + 支持 peers 的服务端 ⇒ 能枚举
	srvNew := newFakeSignalServer(t)
	defer srvNew.close()
	srvNew.setPeersOnline("192.168.30.12")
	cNew := d1aClient(t, srvNew, "192.168.30.11")
	defer func() { _ = cNew.Close() }()

	if cNew.PeersUnsupportedCached() {
		t.Fatal("新连接不得带任何旧缓存")
	}
	peers, _, err := cNew.PeersQuery(context.Background())
	if err != nil {
		t.Fatalf("支持 peers 的服务端应能枚举，实际 %v", err)
	}
	if len(peers) != 1 || peers[0].VIP != "192.168.30.12" {
		t.Fatalf("应拿到列表，实际 %+v", peers)
	}
}

// TestPeersConcurrentClientsEachExcludeSelf ⭐ review 追问 3：**多客户端并发**时
// 假服务端必须**按连接**跟踪身份（每条流各排除自己），不能全局一份。
func TestPeersConcurrentClientsEachExcludeSelf(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	// 两个客户端，各自不同 VIP，各自一条信令流
	cA := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	cA.noteAssignedIP("192.168.30.11")
	dialFakeSignal(t, cA, srv)
	if err := cA.ensureSignalStream(); err != nil {
		t.Fatalf("A 建流失败: %v", err)
	}
	defer func() { _ = cA.Close() }()

	cB := newSignalTestClientWithNAT("5.6.7.8:40002", string(NATFullCone))
	cB.noteAssignedIP("192.168.30.12")
	dialFakeSignal(t, cB, srv)
	if err := cB.ensureSignalStream(); err != nil {
		t.Fatalf("B 建流失败: %v", err)
	}
	defer func() { _ = cB.Close() }()

	// 假服务端按**流序号**记录身份 ⇒ 需要知道哪条流是谁的。
	// `setDeclaredVIP` 只声明一个全局值；并发场景改用 `declareStreamVIPs` 显式绑定。
	srv.declareStreamVIPs("192.168.30.11", "192.168.30.12")
	// 触发身份记录（各写一帧 register）
	for _, c := range []*Hysteria2Client{cA, cB} {
		c.signalMu.Lock()
		st := c.signalStream
		c.signalMu.Unlock()
		if st == nil {
			t.Fatal("前置：信令流应已建立")
		}
		if err := c.writeSignalMessage(st, signalMessage{Type: signalMsgTypeRegister}); err != nil {
			t.Fatalf("写 register 失败: %v", err)
		}
	}
	waitUntil(t, "两个客户端身份都记录", func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return srv.streamVIPs[0] == "192.168.30.11" && srv.streamVIPs[1] == "192.168.30.12"
	})

	srv.setPeersOnline("192.168.30.11", "192.168.30.12")

	// A 枚举：应只见 B；B 枚举：应只见 A
	peersA, _, err := cA.PeersQuery(context.Background())
	if err != nil {
		t.Fatalf("A PeersQuery: %v", err)
	}
	if len(peersA) != 1 || peersA[0].VIP != "192.168.30.12" {
		t.Fatalf("A 应只见 .12（排除自己），实际 %+v", peersA)
	}
	peersB, _, err := cB.PeersQuery(context.Background())
	if err != nil {
		t.Fatalf("B PeersQuery: %v", err)
	}
	if len(peersB) != 1 || peersB[0].VIP != "192.168.30.11" {
		t.Fatalf("B 应只见 .11（排除自己），实际 %+v", peersB)
	}
}

// waitUntil 简易轮询等待
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待「%s」超时", what)
}

// d1aClient 造一个「P2P 生效 + 已拨上假服务端」的客户端（带本机 VIP）。
//
// ⚠️ 容器同时向假服务端声明「本连接的身份 = vip」：真服务端的身份来自
// 已授权的 ctrl 连接（客户端不声明），单测里没有授权流程 ⇒ 由测试显式声明，语义等价。
func d1aClient(t *testing.T, srv *fakeSignalServer, vip string) *Hysteria2Client {
	t.Helper()
	srv.setDeclaredVIP(vip)
	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	c.noteAssignedIP(vip) // 走生产入口（DHCP 拿到地址时就是调它）
	dialFakeSignal(t, c, srv)
	if err := c.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	return c
}

// TestPeersQueryParsesList 正常应答：拿到 VIP 列表 + signalReady 标志。
func TestPeersQueryParsesList(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()
	c := d1aClient(t, srv, "192.168.30.11")
	defer func() { _ = c.Close() }()

	srv.setPeersOnline("192.168.30.12", "192.168.30.13")
	srv.setPeersNotReady(map[string]bool{"192.168.30.13": true})

	peers, truncated, err := c.PeersQuery(context.Background())
	if err != nil {
		t.Fatalf("PeersQuery: %v", err)
	}
	if truncated {
		t.Fatal("未设截断时不应报告截断")
	}
	if len(peers) != 2 {
		t.Fatalf("应返回 2 个对端，实际 %d：%+v", len(peers), peers)
	}
	// 排序契约：signalReady=true 优先，组内按 VIP
	if peers[0].VIP != "192.168.30.12" || !peers[0].SignalReady {
		t.Fatalf("第 1 个应是 signalReady=true 的 .12，实际 %+v", peers[0])
	}
	if peers[1].VIP != "192.168.30.13" || peers[1].SignalReady {
		t.Fatalf("第 2 个应是 signalReady=false 的 .13，实际 %+v", peers[1])
	}
}

// TestPeersQueryTruncatedFlag peers-list 的 truncated 标志必须透传。
func TestPeersQueryTruncatedFlag(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()
	c := d1aClient(t, srv, "192.168.30.11")
	defer func() { _ = c.Close() }()

	srv.setPeersOnline("192.168.30.12")
	srv.mu.Lock()
	srv.peersTruncated = true
	srv.mu.Unlock()

	_, truncated, err := c.PeersQuery(context.Background())
	if err != nil {
		t.Fatalf("PeersQuery: %v", err)
	}
	if !truncated {
		t.Fatal("服务端报截断时客户端必须知道「列表不全」")
	}
}

// TestPeersQueryOldServerDegradesSilently ⭐ 有牙：旧服务端 ⇒ ErrPeersUnsupported，
// **静默**（不 panic、不重试）、且**只探测一次**（第二次直接用缓存，不再打往返）。
func TestPeersQueryOldServerDegradesSilently(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()
	c := d1aClient(t, srv, "192.168.30.11")
	defer func() { _ = c.Close() }()

	srv.mu.Lock()
	srv.peersUnknownType = true
	srv.mu.Unlock()

	// 第 1 次：真的发了一次请求，拿到明确的「unknown message type」
	_, _, err := c.PeersQuery(context.Background())
	if !errors.Is(err, ErrPeersUnsupported) {
		t.Fatalf("旧服务端应返回 ErrPeersUnsupported，实际 %v", err)
	}
	if !c.PeersUnsupportedCached() {
		t.Fatal("已知不支持后应缓存该结论（否则每次预打洞都去打一个不支持的服务端）")
	}
	before := srv.peersQueryCount()

	// 第 2 次：必须**不再发请求**（走缓存）
	_, _, err2 := c.PeersQuery(context.Background())
	if !errors.Is(err2, ErrPeersUnsupported) {
		t.Fatalf("第 2 次仍应返回 ErrPeersUnsupported，实际 %v", err2)
	}
	if after := srv.peersQueryCount(); after != before {
		t.Fatalf("已缓存「不支持」后不得再发请求：前 %d 后 %d", before, after)
	}
}

// TestPeersQueryTimeoutIsNotCached ⭐ 有牙：服务端**连 error 都不回** ⇒ 超时；
// **超时绝不能被当成「不支持」而缓存**（那会把「服务端忙/网络慢」永久判死）。
func TestPeersQueryTimeoutIsNotCached(t *testing.T) {
	if testing.Short() {
		t.Skip("需要等一个信令超时")
	}
	srv := newFakeSignalServer(t)
	defer srv.close()
	c := d1aClient(t, srv, "192.168.30.11")
	defer func() { _ = c.Close() }()

	srv.mu.Lock()
	srv.peersSilent = true // 收到了但不回
	srv.mu.Unlock()

	_, _, err := c.PeersQuery(context.Background())
	if err == nil {
		t.Fatal("服务端不回时应报错（超时）")
	}
	if errors.Is(err, ErrPeersUnsupported) {
		t.Fatal("超时不得被判为「服务端不支持」（那会永久放弃）")
	}
	if c.PeersUnsupportedCached() {
		t.Fatal("超时**不得**缓存「不支持」结论（下次重连/再次调用仍应尝试）")
	}
}

// TestPeersQueryRequiresP2P P2P 未启用时给出清晰错误（不 panic）。
func TestPeersQueryRequiresP2P(t *testing.T) {
	c := newSignalTestClient()
	if _, _, err := c.PeersQuery(context.Background()); err == nil {
		t.Fatal("P2P 未启用时应报错")
	}
}

// TestPeersQueryExcludesSelf 端到端：请求方**自己不出现在列表里**（与真服务端
// `enumerableVIPs` 的 `vip == cs.vip ⇒ skip` 一致）。
//
// 前置：先让服务端知道这条流的身份 —— 真服务端从 ctrl 连接推导，
// 假服务端从 register 帧推导。这里直接写一帧 register（不需要它的应答，
// 所以不走 `SignalQuery`：本单测里假服务端没有配 register 的应答逻辑）。
func TestPeersQueryExcludesSelf(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()
	c := d1aClient(t, srv, "192.168.30.11")
	defer func() { _ = c.Close() }()

	c.signalMu.Lock()
	stream := c.signalStream
	c.signalMu.Unlock()
	if stream == nil {
		t.Fatal("前置：信令流应已建立")
	}
	// 唤醒帧（建流时已发）就带身份；这里再等假服务端记下来即可。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		got := srv.streamVIPs[0]
		srv.mu.Unlock()
		if got == "192.168.30.11" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	srv.mu.Lock()
	self := srv.streamVIPs[0]
	srv.mu.Unlock()
	if self != "192.168.30.11" {
		t.Fatalf("前置：假服务端应已记录请求方 VIP，实际 %q", self)
	}

	srv.setPeersOnline("192.168.30.11", "192.168.30.12") // 含自己

	peers, _, err := c.PeersQuery(context.Background())
	if err != nil {
		t.Fatalf("PeersQuery: %v", err)
	}
	if len(peers) != 1 || peers[0].VIP != "192.168.30.12" {
		t.Fatalf("必须排除请求方自己，应恰好返回 .12，实际 %+v", peers)
	}
}

// ---------- review 追问 3：PeersQuery 必须接受 ctx（取消立即返回） ----------

// TestPeersQueryAbortsOnContextCancel ⭐⭐ review 追问 3 的**有牙**用例：
//
//	服务端**连 error 都不回**（最坏情况）时，`PeersQuery(ctx)` 必须在 ctx 取消后
//	**立即**返回，而不是白等到 `signalTimeout`。
//
// 手法：把「等信令应答」的上限故意拉长到 60s（远超用例超时），这样「等到超时」与
// 「立即返回」在时间尺度上**差 300 倍**，用例不可能把前者误判成通过。
//
// ⚠️ 有牙：把 `signalExchange` 里的 `case <-ctxDone(ctx)` 删掉 ⇒ 本用例在 2s 上限处红
// （实际要等 60s）。
//
// ⚠️ A3a（2026-09-28）**迁入本文件**（原在 `prepunch_test.go`，原位留指针注释）：
//
//	它测的是信令层公共 API `PeersQuery` 的 **ctx 契约**（`signal.go`），属 **D1-a 面**，
//	与预打洞发起侧无关 ⇒ 预打洞整体删除时**保留**，并移到与其余 `PeersQuery` 用例同处。
//	📌 记账：A3a 之后 `PeersQuery` 的**生产过程调用者归零**（唯一调用者是已删除的预打洞调度器）；
//	本用例继续守它的 API 契约，等 D1-a 落地或由 A3b/独立切片评估其去留。
//	📎 原代码：`A2-干净点快照-2026-09-28\quic\prepunch_test.go:257-296`。
func TestPeersQueryAbortsOnContextCancel(t *testing.T) {
	overrideSignalExchangeWait(t, 60*time.Second)

	srv := newFakeSignalServer(t)
	defer srv.close()
	srv.mu.Lock()
	srv.peersSilent = true // 收到 peers 请求后**什么都不回**
	srv.mu.Unlock()

	c := d1aClient(t, srv, "192.168.30.11")
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, err := c.PeersQuery(ctx)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("PeersQuery 未随 ctx 取消立即返回：耗时 %v（等待上限=%v）", elapsed, signalExchangeWait)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ctx 取消应返回 context.DeadlineExceeded，实际 %v", err)
	}
	// 取消 ≠ 「服务端不支持」：绝不能污染缓存（否则一次收尾会让本连接内永久不试）
	if c.PeersUnsupportedCached() {
		t.Fatal("ctx 取消**不得**污染「不支持」缓存")
	}
}
