package quic

import (
	"path/filepath"
	"testing"

	"vpn-server/store"
)

// TestAuthorizePlaneCoversCtrl 验证 S1 的身份校验对**所有面**生效。
//
// ⚠️ 回归背景：S1 最初只在 handleDataConn 里校验（h3-data 的 4 个面），
// 漏掉了走 HandleCtrlConn 的 h3-ctrl。那意味着一个**未认证**的连接
// 只要猜到一个在线 VIP，就能注册控制面，覆盖对方的
// cs.ctrlConn / icmpStream / hbStream，从而：
//   - 以对方身份向其他客户端注入任意 IP 包（readICMPStream 只按目的地址转发）；
//   - 窃取对方的 ICMP 回复；
//   - 伪造对方的心跳与 RTT。
//
// 现在两个入口共用 authorizePlane，本测试锁住该行为。
func TestAuthorizePlaneCoversCtrl(t *testing.T) {
	st, err := store.NewStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	alloc := NewIPAllocator()
	auth := NewCustomAuthenticatorWithAllocator(st, alloc, "", "")
	srv := NewDataChannelServer(alloc, nil, nil, auth, nil, [4]byte{}, nil, nil, nil)

	const peer = "203.0.113.50"
	const user = "alice"

	// 所有面在「还没有任何认证记录」时都必须被拒绝
	for _, plane := range []string{"data", "data-match", "data-game-tcp", "data-game", "ctrl"} {
		if _, ok := srv.authorizePlane(plane, peer, user, "10.0.0.100"); ok {
			t.Fatalf("未认证时 %s 面必须被拒绝", plane)
		}
	}

	// 认证成功后（等价于 hysteria 认证通过）再走一遍
	auth.registerSession(peer, user)
	vip := alloc.AllocateByDeviceID("uuid-1")
	if vip == "" {
		t.Fatal("分配 VIP 失败")
	}

	for _, plane := range []string{"data", "data-match", "data-game-tcp", "data-game", "ctrl"} {
		mode, ok := srv.authorizePlane(plane, peer, user, vip)
		if !ok {
			t.Fatalf("已认证 + 合法 VIP 时 %s 面应当通过", plane)
		}
		if mode != "multi" {
			t.Fatalf("%s 面返回的 mode 应为服务端认定的 multi，实际 %q", plane, mode)
		}
	}

	// 控制面同样受「VIP 未被别的身份占用」约束：
	// 另一个用户（同一出口 IP）不能拿这个 VIP 注册控制面
	auth.registerSession(peer, "bob")
	if _, ok := srv.authorizePlane("ctrl", peer, "bob", vip); ok {
		t.Fatal("已被 alice 占用的 VIP 不应允许 bob 注册控制面")
	}

	// 换一个出口 IP 冒充 alice 也不行
	if _, ok := srv.authorizePlane("ctrl", "198.51.100.7", user, vip); ok {
		t.Fatal("不同 peerIP 不应允许注册控制面")
	}

	// 凭空捏造的 VIP 也不行
	if _, ok := srv.authorizePlane("ctrl", peer, user, "10.0.0.199"); ok {
		t.Fatal("未被 DHCP 租出的 VIP 不应允许注册控制面")
	}

	// 认证器缺失时必须 fail-closed（而不是放行）
	bare := NewDataChannelServer(alloc, nil, nil, nil, nil, [4]byte{}, nil, nil, nil)
	if _, ok := bare.authorizePlane("ctrl", peer, user, vip); ok {
		t.Fatal("认证器缺失时必须拒绝，不能放行")
	}
}

// TestOldClientCtrlRegistrationStillPasses 锁定「旧客户端不受 S1 补丁影响」。
//
// 结论：不受影响。authorizePlane 依赖的两样东西都不是数据面注册产生的：
//   - authorizedKeys[peerIP\x00用户名]：**hy-core 认证成功**时就写好了
//     （CustomAuthenticator.authMultiUser → registerSession，TTL 10 分钟）；
//   - IsLeased(vip)：**DHCP 分配**时就写好了（dhcpLeaseTTL 5 分钟，
//     一旦有任何一个面注册成功就 MarkLeaseActive 永不过期）。
//
// 旧客户端（vpn-tool 当前版本）的传参路径：
//
//	hy-core 认证(username:password) → DHCP 拿到 VIP → h3-data 注册帧
//	"data\nmulti\n<user>\n<vip>" → h3-ctrl 注册帧 "ctrl\nmulti\n<user>\n<vip>"
//	（client.go: connectDataConn 1197 → connectCtrlConn 1246，
//	 注册帧构造见 client.go:1415 与 1678；两条连接来自同一个 UDP 出口 IP）
//
// 也就是说：用户名和 VIP 都是**服务端自己在前面给的**，peerIP 由 QUIC 连接
// 决定且同机不变 —— 全部满足 authorizePlane 的条件。
func TestOldClientCtrlRegistrationStillPasses(t *testing.T) {
	st, err := store.NewStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	alloc := NewIPAllocator()
	auth := NewCustomAuthenticatorWithAllocator(st, alloc, "", "")
	srv := NewDataChannelServer(alloc, nil, nil, auth, nil, [4]byte{}, nil, nil, nil)

	const peer, user, device = "203.0.113.50", "alice", "device-uuid-1"

	// ① hy-core 认证通过（旧客户端连接 h3 时发生）
	auth.registerSession(peer, user)
	// ② DHCP 分配 VIP（旧客户端把它写进后面所有面的注册帧）
	vip := alloc.AllocateByDeviceID(device)
	if vip == "" {
		t.Fatal("分配 VIP 失败")
	}

	// ③ 旧客户端顺序：先数据面、后控制面（同一个出口 IP）
	if _, ok := srv.authorizePlane("data", peer, user, vip); !ok {
		t.Fatal("数据面注册被拒，旧客户端会直接连不上")
	}
	if _, ok := srv.authorizePlane("ctrl", peer, user, vip); !ok {
		t.Fatal("控制面注册被拒 —— S1 补丁破坏了旧客户端")
	}

	// ④ 反过来（先控制面、后数据面）也必须通过：
	//    authorizePlane 不要求数据面先注册，它只看认证记录 + 租约。
	//    这样万一将来客户端调整了建连顺序，也不会被这条校验误伤。
	st2, _ := store.NewStore(filepath.Join(t.TempDir(), "users2.json"))
	alloc2 := NewIPAllocator()
	auth2 := NewCustomAuthenticatorWithAllocator(st2, alloc2, "", "")
	srv2 := NewDataChannelServer(alloc2, nil, nil, auth2, nil, [4]byte{}, nil, nil, nil)
	auth2.registerSession(peer, user)
	vip2 := alloc2.AllocateByDeviceID(device)
	if _, ok := srv2.authorizePlane("ctrl", peer, user, vip2); !ok {
		t.Fatal("只注册控制面（没有先注册数据面）也应当通过")
	}
	// 控制面注册本身会把租约标记为活跃，所以控制面也能独立维持租约
	if !alloc2.IsLeased(vip2) {
		t.Fatal("控制面注册后租约应仍然有效")
	}

	// ⑤ 唯一会让旧客户端失败的时序：DHCP 租约被回收（5 分钟）
	//    或者认证记录过期（10 分钟）—— 都远大于旧客户端的建连间隔（秒级）。
}

// BenchmarkAuthorizePlane 量化 authorizePlane 的成本 ——
// 它现在多跑在每一次 h3-ctrl 注册上，必须确认不会拖慢正常连接。
//
// 它只做「两把锁 + 两次 map 查找」，没有任何 I/O 与分配。
//
//	go test -bench BenchmarkAuthorizePlane -benchtime 200000x -run XXX ./quic/
func BenchmarkAuthorizePlane(b *testing.B) {
	st, err := store.NewStore(filepath.Join(b.TempDir(), "users.json"))
	if err != nil {
		b.Fatalf("NewStore: %v", err)
	}
	alloc := NewIPAllocator()
	auth := NewCustomAuthenticatorWithAllocator(st, alloc, "", "")
	srv := NewDataChannelServer(alloc, nil, nil, auth, nil, [4]byte{}, nil, nil, nil)

	const peer, user = "203.0.113.50", "alice"
	auth.registerSession(peer, user)
	vip := alloc.AllocateByDeviceID("uuid-1")
	if vip == "" {
		b.Fatal("分配 VIP 失败")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := srv.authorizePlane("ctrl", peer, user, vip); !ok {
			b.Fatal("合法注册应当通过")
		}
	}
}
