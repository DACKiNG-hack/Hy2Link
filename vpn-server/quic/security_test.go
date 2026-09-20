package quic

import (
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"vpn-server/admin"
	"vpn-server/store"
)

func newTestAuth(t *testing.T) (*CustomAuthenticator, *IPAllocator) {
	t.Helper()
	st, err := store.NewStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	alloc := NewIPAllocator()
	auth := NewCustomAuthenticatorWithAllocator(st, alloc, "", "")
	return auth, alloc
}

// TestAuthorizeDataPlane 验证安全审计 S1 的核心修复。
//
// 修复前：数据面注册帧里的 mode/username/vip 全部由客户端自报，
// 而 h3-data / h3-ctrl 从不经过认证器，服务端直接采信 ——
// 于是「无口令即可入网」「注册别人的 VIP 即可劫持」都成立。
func TestAuthorizeDataPlane(t *testing.T) {
	auth, alloc := newTestAuth(t)

	const peer = "203.0.113.9"
	const user = "alice"

	// 1) 没有任何认证记录 → 拒绝（这正是修复前的 Critical 场景）
	if _, ok := auth.AuthorizeDataPlane(peer, user, "10.0.0.100"); ok {
		t.Fatal("未认证的对端不应通过数据面校验")
	}

	auth.registerSession(peer, user)

	// 2) VIP 未租出（客户端凭空捏造）→ 拒绝
	if _, ok := auth.AuthorizeDataPlane(peer, user, "10.0.0.150"); ok {
		t.Fatal("未被 DHCP 租出的 VIP 不应通过校验")
	}

	vip := alloc.AllocateByDeviceID("some-uuid")
	if vip == "" {
		t.Fatal("DHCP 分配失败")
	}

	// 3) 正常注册 → 通过，且 mode 由服务端决定
	mode, ok := auth.AuthorizeDataPlane(peer, user, vip)
	if !ok {
		t.Fatal("合法注册应当通过")
	}
	if mode != "multi" {
		t.Fatalf("mode 必须由服务端决定为 multi，得到 %q", mode)
	}

	// 4) 另一个用户名想抢占已被占用的 VIP → 拒绝
	auth.registerSession(peer, "bob")
	if _, ok := auth.AuthorizeDataPlane(peer, "bob", vip); ok {
		t.Fatal("已被 alice 占用的 VIP 不应被 bob 抢占")
	}
	bobVIP := alloc.AllocateByDeviceID("bob-uuid")
	if _, ok := auth.AuthorizeDataPlane(peer, "bob", bobVIP); !ok {
		t.Fatal("bob 使用自己租到的 VIP 应当通过")
	}

	// 5) 从别的 peerIP 冒充 alice → 拒绝
	if _, ok := auth.AuthorizeDataPlane("198.51.100.7", user, vip); ok {
		t.Fatal("不同 peerIP 不应通过校验（这是跨网络劫持的主要防线）")
	}

	// 6) 断开后该 VIP 变成「空闲且已租出」的地址，
	//    此时别的已认证身份可以正常使用它（它已经不属于任何人了）。
	//
	//    真正要防的是「别人正在用的 VIP」被抢走 —— 见第 4 步。
	//    这里也说明为什么不能用「一个 key 只能绑一个 VIP」来限制：
	//    同一账号多客户端共用时，每个客户端都需要自己的 VIP。
	auth.releaseSession(peer, user, vip)
	if _, ok := auth.AuthorizeDataPlane(peer, "bob", vip); !ok {
		t.Fatal("原占用者释放后，空闲的 VIP 应可被其他已认证身份使用")
	}
}

// TestSharedAccountMultipleClientsSamePeerIP 是本轮新增需求的核心测试：
// **同一个用户名 + 密码允许被多个客户端共用**，包括
// 「同一路由器后面（同一出口 IP）的多台设备」这种最容易被忽略的情况。
func TestSharedAccountMultipleClientsSamePeerIP(t *testing.T) {
	auth, alloc := newTestAuth(t)

	const peer = "203.0.113.30" // 同一个出口 IP（例如同一个家里的路由器）
	const user = "shared-account"

	// 客户端 A：认证 → DHCP → 注册
	auth.registerSession(peer, user)
	vipA := alloc.AllocateByDeviceID("device-A")
	if vipA == "" {
		t.Fatal("device-A 分配失败")
	}
	if _, ok := auth.AuthorizeDataPlane(peer, user, vipA); !ok {
		t.Fatal("第一个客户端应当通过")
	}

	// 客户端 B：同样是同一出口 IP、同一账号
	auth.registerSession(peer, user)
	vipB := alloc.AllocateByDeviceID("device-B")
	if vipB == "" {
		t.Fatal("device-B 分配失败")
	}
	if vipA == vipB {
		t.Fatal("两个设备应当拿到不同的 VIP")
	}
	if _, ok := auth.AuthorizeDataPlane(peer, user, vipB); !ok {
		t.Fatal("同一出口 IP、同一用户名的第二个客户端也必须通过（共用账号）")
	}

	// 第三个设备（模拟更多客户端共用）
	auth.registerSession(peer, user)
	vipC := alloc.AllocateByDeviceID("device-C")
	if _, ok := auth.AuthorizeDataPlane(peer, user, vipC); !ok {
		t.Fatal("第三个共用客户端也必须通过")
	}
	if got := auth.BoundVIPCount(); got != 3 {
		t.Fatalf("应绑定 3 个 VIP，实际 %d", got)
	}

	// 断开其中一个只释放它自己的 VIP
	auth.releaseSession(peer, user, vipB)
	if got := auth.BoundVIPCount(); got != 2 {
		t.Fatalf("释放一个后应剩 2 个绑定，实际 %d", got)
	}
	// 其余两个仍然可用（重新注册同一 VIP 仍通过）
	if _, ok := auth.AuthorizeDataPlane(peer, user, vipA); !ok {
		t.Fatal("释放 vipB 不应影响 vipA")
	}
	if _, ok := auth.AuthorizeDataPlane(peer, user, vipC); !ok {
		t.Fatal("释放 vipB 不应影响 vipC")
	}

	// 四个数据面连接（bulk/match/game/ctrl）用**同一个** VIP 反复注册
	// 也必须都通过（多面连接共享一个 clientStream）
	for i := 0; i < 4; i++ {
		if _, ok := auth.AuthorizeDataPlane(peer, user, vipA); !ok {
			t.Fatalf("同一 VIP 的第 %d 次注册（其它数据面）应当通过", i+2)
		}
	}
}

// TestSharedAccountDifferentPeerIP 不同公网 IP 的多个客户端共用账号
func TestSharedAccountDifferentPeerIP(t *testing.T) {
	auth, alloc := newTestAuth(t)
	const user = "roaming"

	peers := []string{"198.51.100.10", "198.51.100.20", "2001:db8::1"}
	for i, p := range peers {
		auth.registerSession(p, user)
		vip := alloc.AllocateByDeviceID(fmt.Sprintf("dev-%d", i))
		if vip == "" {
			t.Fatalf("第 %d 个客户端分配失败", i)
		}
		if _, ok := auth.AuthorizeDataPlane(p, user, vip); !ok {
			t.Fatalf("来自 %s 的共用客户端应当通过", p)
		}
	}
	if got := auth.BoundVIPCount(); got != len(peers) {
		t.Fatalf("应绑定 %d 个 VIP，实际 %d", len(peers), got)
	}

	// 一个 IP 的授权不能用于另一个 IP
	if _, ok := auth.AuthorizeDataPlane("203.0.113.99", user, "10.0.0.100"); ok {
		t.Fatal("未认证过的 peerIP 不应通过")
	}
}

// TestAuthorizeDataPlaneRejectsExpiredSession 授权过期后必须拒绝
func TestAuthorizeDataPlaneRejectsExpiredSession(t *testing.T) {
	auth, alloc := newTestAuth(t)

	const peer = "203.0.113.10"
	auth.registerSession(peer, "carol")

	auth.mu.Lock()
	auth.authorizedKeys[sessionKey(peer, "carol")] = time.Now().Add(-time.Second)
	auth.mu.Unlock()

	vip := alloc.AllocateByDeviceID("carol-dev")
	if _, ok := auth.AuthorizeDataPlane(peer, "carol", vip); ok {
		t.Fatal("过期授权不应通过校验")
	}
}

// TestAuthorizeDataPlaneRejectsEmptyClaim 空用户名/VIP 必须拒绝
func TestAuthorizeDataPlaneRejectsEmptyClaim(t *testing.T) {
	auth, _ := newTestAuth(t)
	auth.registerSession("203.0.113.11", "dave")

	if _, ok := auth.AuthorizeDataPlane("203.0.113.11", "", "10.0.0.100"); ok {
		t.Fatal("空用户名应被拒绝")
	}
	if _, ok := auth.AuthorizeDataPlane("203.0.113.11", "dave", ""); ok {
		t.Fatal("空 VIP 应被拒绝")
	}
}

// TestAdminStateSupportsSharedAccount 在线列表必须按**每连接唯一**的键记录，
// 否则同一账号的多个客户端会互相覆盖，且断开一个会把另一个也删掉。
func TestAdminStateSupportsSharedAccount(t *testing.T) {
	st := admin.NewAdminState("test")

	// 两个客户端用同一账号、同一出口 IP，但 VIP 不同
	st.OnConnect("10.0.0.11", "shared", "multi", "10.0.0.11", "203.0.113.1:1111")
	st.OnConnect("10.0.0.12", "shared", "multi", "10.0.0.12", "203.0.113.1:2222")

	snap := st.Snapshot()
	if snap.ClientCount != 2 {
		t.Fatalf("同一账号的 2 个客户端都应出现在在线列表，实际 %d", snap.ClientCount)
	}

	// 各自记流量与延迟，互不干扰
	st.AddTraffic("10.0.0.11", 100, 0)
	st.AddTraffic("10.0.0.12", 500, 0)
	st.SetClientLatency("10.0.0.11", 33)
	st.SetClientLatency("10.0.0.12", 77)

	snap = st.Snapshot()
	byVIP := map[string]*admin.ClientInfo{}
	for _, c := range snap.Clients {
		byVIP[c.VirtualIP] = c
	}
	if byVIP["10.0.0.11"].BytesIn != 100 || byVIP["10.0.0.12"].BytesIn != 500 {
		t.Fatalf("两个客户端的流量应分别统计: %+v", byVIP)
	}
	if byVIP["10.0.0.11"].LatencyMs != 33 || byVIP["10.0.0.12"].LatencyMs != 77 {
		t.Fatalf("两个客户端的延迟应分别统计: %+v", byVIP)
	}

	// 断开其中一个，另一个必须还在
	st.OnDisconnect("10.0.0.11")
	snap = st.Snapshot()
	if snap.ClientCount != 1 {
		t.Fatalf("断开一个后应剩 1 个，实际 %d", snap.ClientCount)
	}
	if snap.Clients[0].VirtualIP != "10.0.0.12" || snap.Clients[0].Username != "shared" {
		t.Fatalf("剩下的应当是 10.0.0.12/shared，实际 %+v", snap.Clients[0])
	}
}

// TestKickAllSharedAccount 「踢出」必须踢掉该用户名的**全部**连接。
// 修复前只踢第一个匹配的，共用账号时踢人会失效。
func TestKickAllSharedAccount(t *testing.T) {
	auth, alloc := newTestAuth(t)

	s := NewDataChannelServer(alloc, nil, nil, auth, nil, [4]byte{}, nil, nil, nil)

	mk := func(vip string, last byte, user string) *clientStream {
		var b [4]byte
		copy(b[:], net.ParseIP(vip).To4())
		return &clientStream{vip: vip, vipBytes: b, username: user, mode: "multi"}
	}

	csA := mk("10.0.0.11", 11, "shared")
	csB := mk("10.0.0.12", 12, "shared")
	csOther := mk("10.0.0.13", 13, "other")
	s.register([4]byte{10, 0, 0, 11}, csA)
	s.register([4]byte{10, 0, 0, 12}, csB)
	s.register([4]byte{10, 0, 0, 13}, csOther)

	if got := s.kickAll("shared"); got != 2 {
		t.Fatalf("应踢掉 2 个同账号连接，实际 %d", got)
	}
	if got := s.kickAll("other"); got != 1 {
		t.Fatalf("应踢掉 1 个 other 连接，实际 %d", got)
	}
	if got := s.kickAll("nobody"); got != 0 {
		t.Fatalf("不存在的用户应踢 0 个，实际 %d", got)
	}
	if err := s.Kick("nobody"); err == nil {
		t.Fatal("不存在的用户 Kick 应返回错误")
	}

	// 连接真正断开后（handler 的 defer 会调用 unregisterData）才彻底下线
	s.unregisterData([4]byte{10, 0, 0, 11}, csA)
	s.unregisterData([4]byte{10, 0, 0, 12}, csB)
	if got := s.kickAll("shared"); got != 0 {
		t.Fatalf("下线后应踢 0 个，实际 %d", got)
	}
	if err := s.Kick("shared"); err == nil {
		t.Fatal("全部下线后 Kick 应返回错误")
	}
}

// TestIPLeaseLifecycle 验证安全审计 S7 的租约生命周期。
//
// 修复前：DHCP 用客户端自报的 deviceID 作为身份键，且
// dhcpConn.Close() 从不释放租约 —— 一个已认证用户不断用新的 deviceID
// 申请即可占满整个地址池，让所有正常用户都无法认证。
func TestIPLeaseLifecycle(t *testing.T) {
	alloc := NewIPAllocator()
	alloc.leaseTTL = 20 * time.Millisecond

	// ① 未被数据面认领的租约 → 到期被回收
	vip := alloc.AllocateByDeviceID("dev-1")
	if vip == "" {
		t.Fatal("分配失败")
	}
	if !alloc.IsLeased(vip) {
		t.Fatal("刚分配的 VIP 应处于租用中")
	}
	if alloc.LeaseCount() != 1 {
		t.Fatalf("租约数应为 1，实际 %d", alloc.LeaseCount())
	}

	time.Sleep(40 * time.Millisecond)
	alloc.reapExpiredLeases()
	if alloc.IsLeased(vip) {
		t.Fatalf("过期租约 %s 应被回收（否则地址池会被打空）", vip)
	}
	if alloc.LeaseCount() != 0 {
		t.Fatalf("回收后租约表应清空，实际 %d", alloc.LeaseCount())
	}

	// ② 已绑定活跃数据面的租约 → 永不过期
	vip2 := alloc.AllocateByDeviceID("dev-2")
	if vip2 == "" {
		t.Fatal("分配失败")
	}
	alloc.MarkLeaseActive(vip2)
	time.Sleep(40 * time.Millisecond)
	alloc.reapExpiredLeases()
	if !alloc.IsLeased(vip2) {
		t.Fatal("已绑定活跃会话的租约不应被回收")
	}

	// ③ 显式释放
	alloc.ReleaseByVirtualIP(vip2)
	if alloc.IsLeased(vip2) {
		t.Fatal("释放后不应再是租用中")
	}
	if alloc.LeaseCount() != 0 {
		t.Fatalf("释放后租约表应清空，实际 %d", alloc.LeaseCount())
	}

	// ④ 反复「申请 + 释放」不应泄漏地址，也不应撑爆租约表
	for i := 0; i < 80; i++ {
		v := alloc.AllocateByDeviceID(fmt.Sprintf("loop-%d", i))
		if v == "" {
			t.Fatalf("第 %d 次分配失败（地址泄漏或池耗尽）", i)
		}
		alloc.ReleaseByVirtualIP(v)
	}
	if alloc.LeaseCount() != 0 {
		t.Fatalf("循环结束后租约表应清空，实际 %d", alloc.LeaseCount())
	}

	// ⑤ 模拟攻击：申请大量租约但不建立数据面，回收后池应完全恢复可用
	for i := 0; i < 200; i++ {
		alloc.AllocateByDeviceID(fmt.Sprintf("flood-%d", i))
	}
	time.Sleep(40 * time.Millisecond)
	alloc.reapExpiredLeases()
	if n := alloc.LeaseCount(); n != 0 {
		t.Fatalf("洪水申请后租约应全部回收，实际剩余 %d", n)
	}
	if v := alloc.AllocateByDeviceID("after-flood"); v == "" {
		t.Fatal("回收后仍应能正常分配地址（池未被永久占用）")
	}
}
