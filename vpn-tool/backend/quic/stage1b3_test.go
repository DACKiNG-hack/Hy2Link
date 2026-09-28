package quic

// vpn-tool/backend/quic/stage1b3_test.go
//
// ⭐ 1b-3（A1 + 2.3）客户端侧测试：
//   A1  —— punch socket 的**全部**观测值不再被丢弃（只留第一个是 2.2 永不生效的根因），
//          以及候选列表 `punchAddrs` 的组装/下发/接收/最终交给 realm.Punch。
//   2.3 —— 双向指纹固定：A 作为 listener 也固定 B（1b-1 是单向）。
//
// 重点：这些用例尽量有「牙」——不是断言「字段存在」，而是断言
// 「少了这条链路就会失败」（例如只发单地址时打洞必然不通）。

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- 纯函数：候选列表归一化 ----------

// TestNormalizePunchAddrsKeepsAllObservations ⭐ A1 的核心：
//
//	realm.Discover 返回多个观测值时**不能只留第一个**（原来就是只留第一个 ⇒
//	同 IP 的候选永远只有 1 个 ⇒ realm 的 predictatblePortGroup 永不触发）。
func TestNormalizePunchAddrsKeepsAllObservations(t *testing.T) {
	in := []netip.AddrPort{
		netip.MustParseAddrPort("1.2.3.4:50002"),
		netip.MustParseAddrPort("1.2.3.4:50001"),
		netip.MustParseAddrPort("1.2.3.4:50001"), // 重复 → 去重
		netip.MustParseAddrPort("[2001:db8::1]:50003"),
		netip.AddrPort{}, // 零值 → 丢弃
		netip.MustParseAddrPort("1.2.3.4:50003"),
	}
	got := normalizePunchAddrs(in)
	if len(got) != 3 {
		t.Fatalf("应保留 3 个 IPv4 候选（去重 + 丢 IPv6/零值），实际 %d: %v", len(got), got)
	}
	want := []string{"1.2.3.4:50001", "1.2.3.4:50002", "1.2.3.4:50003"}
	for i, w := range want {
		if got[i].String() != w {
			t.Fatalf("第 %d 个候选应为 %s（按端口升序），实际 %s（全量 %v）", i, w, got[i], got)
		}
	}
	// 上限截断
	many := make([]netip.AddrPort, 0, 64)
	for p := 10000; p < 10064; p++ {
		many = append(many, netip.AddrPortFrom(netip.MustParseAddr("1.2.3.4"), uint16(p)))
	}
	if n := len(normalizePunchAddrs(many)); n != maxPunchAddrs {
		t.Fatalf("候选数应截断到 %d，实际 %d", maxPunchAddrs, n)
	}
}

// TestPeerAddrsForKeepsSingleAddr 单地址必须始终在列表里（旧对端只有 punchAddr）
func TestPeerAddrsForKeepsSingleAddr(t *testing.T) {
	single := netip.MustParseAddrPort("5.6.7.8:40002")
	// ① 列表为空（旧对端）→ 只剩单地址
	if got := peerAddrsFor(nil, single); len(got) != 1 || got[0] != single {
		t.Fatalf("空列表时应回退到单地址，实际 %v", got)
	}
	// ② 列表里没有单地址 → 也要把它并进去（不能漏掉主目标）
	list := []netip.AddrPort{netip.MustParseAddrPort("5.6.7.8:40003")}
	got := peerAddrsFor(list, single)
	if len(got) != 2 {
		t.Fatalf("应并入单地址，实际 %v", got)
	}
	found := false
	for _, a := range got {
		if a == single {
			found = true
		}
	}
	if !found {
		t.Fatalf("单地址必须保留在列表里，实际 %v", got)
	}
	// ③ 空单地址 + 列表 → 用列表
	got = peerAddrsFor(list, netip.AddrPort{})
	if len(got) != 1 || got[0] != list[0] {
		t.Fatalf("无单地址时应使用列表，实际 %v", got)
	}
}

// ---------- 线协议：punch-intent / punch-ready 携带全部候选 ----------

// TestPunchIntentCarriesAllObservedPunchAddrs ⭐ A1：把观测到的多个映射都广告出去
func TestPunchIntentCarriesAllObservedPunchAddrs(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	a := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, a, srv)
	if err := a.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)

	srv.setOnReg(func(idx int, msg signalMessage) {
		switch msg.Type {
		case signalMsgTypeRegister, signalMsgTypePunchIntent:
			// ⚠️ 必须带上 peerNATType：A 侧流程会校验「对端 NAT 类型已知」，
			//    否则会在发 intent 之前就以 nat-unknown 收工（本测试就抓不到 intent 了）
			_ = srv.writeTo(idx, signalMessage{
				Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true,
				PeerPublicAddr: "5.6.7.8:40002", PeerNATType: string(NATFullCone),
			})
		}
	})

	attachLoopbackManager(t, a, newStatusRecorder())
	// 覆盖发现函数：模拟「服务端内置 STUN + 公共 STUN」观测到两个相邻端口
	mgr := punchMgrOf(t, a)
	mgr.discoverPunchAddr = func(context.Context, net.PacketConn) ([]netip.AddrPort, error) {
		return []netip.AddrPort{
			netip.MustParseAddrPort("1.2.3.4:30001"),
			netip.MustParseAddrPort("1.2.3.4:30002"),
		}, nil
	}

	if _, err := a.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}

	intent := waitForIntent(t, srv)
	// ⭐ 2.2 起：广告的是「观测值 + 预测值」，所以数量不再等于观测数（上限 32）
	if len(intent.PunchAddrs) < 2 || len(intent.PunchAddrs) > maxPunchAddrs {
		t.Fatalf("候选数应在 [2,%d]，实际 %d: %v", maxPunchAddrs, len(intent.PunchAddrs), intent.PunchAddrs)
	}
	if intent.PunchAddr != "1.2.3.4:30001" {
		t.Fatalf("punchAddr 应 = 候选中的第一个（最小端口），实际 %q", intent.PunchAddr)
	}
	joined := strings.Join(intent.PunchAddrs, ",")
	for _, want := range []string{"1.2.3.4:30001", "1.2.3.4:30002"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("观测值 %s 必须保留在候选里，实际 %v", want, intent.PunchAddrs)
		}
	}
}

// TestCandidatesForNATTypeGatesPredictionByNATType ⭐ 1b-4 第 2 步-A（**bug #3 防回归**，纯函数级）。
//
// bug #3 的实质：`predictSymmetricCandidates` 原先被**无条件**调用，
// 于是 cone NAT 用户也广告 32 个候选（全是噪声：cone 的观测值本身就是对端可达地址）。
// 修复 = 加一道**NAT 类型门**，且**两侧共用同一判据**（`candidatesForNATType`）。
func TestCandidatesForNATTypeGatesPredictionByNATType(t *testing.T) {
	obs := func(ss ...string) []netip.AddrPort {
		out := make([]netip.AddrPort, 0, len(ss))
		for _, s := range ss {
			out = append(out, netip.MustParseAddrPort(s))
		}
		return out
	}
	two := obs("1.2.3.4:30001", "1.2.3.4:30002")

	cases := []struct {
		nat  NATType
		want int
	}{
		{NATSymmetric, maxPunchAddrs}, // 对称 NAT：预测到上限（32）
		{NATFullCone, 2},              // ★ bug #3 的核心：cone 只广告观测值
		{NATRestrictedCone, 2},
		{NATPortRestricted, 2},
		{NATUnknown, 2},
	}
	for _, tc := range cases {
		got := candidatesForNATType(tc.nat, two)
		if len(got) != tc.want {
			t.Fatalf("NAT=%s 时候选数应为 %d，实际 %d: %v", tc.nat, tc.want, len(got), got)
		}
		// 观测值在任何 NAT 类型下都不得丢（协议锚点）
		for _, want := range []string{"1.2.3.4:30001", "1.2.3.4:30002"} {
			found := false
			for _, a := range got {
				if a.String() == want {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("NAT=%s 时观测值 %s 不得丢，实际 %v", tc.nat, want, got)
			}
		}
	}

	// 边界：空观测 ⇒ 不得 panic，且返回空
	if got := candidatesForNATType(NATSymmetric, nil); len(got) != 0 {
		t.Fatalf("空观测应返回空，实际 %v", got)
	}
	// 全局禁用开关仍优先（真机 A/B 用）：对称 NAT 也只广告观测值
	t.Run("HY2_NO_PORT_PREDICT=1 仍然全局禁用", func(t *testing.T) {
		t.Setenv("HY2_NO_PORT_PREDICT", "1")
		if got := candidatesForNATType(NATSymmetric, two); len(got) != 2 {
			t.Fatalf("全局禁用时对称 NAT 也只广告观测值（2 个），实际 %d", len(got))
		}
	})
}

// TestPunchReadyAdvertisesOnlyObservedForCone ⭐ bug #3 防回归（**响应方**侧，端到端）。
//
// 响应方的候选列表走 `punch-ready`（与发起方的 `punch-intent` 对称）⇒ 只有改了这一侧，
// 「两侧判据一致」才算成立（B1' 不可切片点）。
func TestPunchReadyAdvertisesOnlyObservedForCone(t *testing.T) {
	for _, tc := range []struct {
		nat  NATType
		want int
	}{
		{NATFullCone, 2},              // cone：只广告观测值
		{NATSymmetric, maxPunchAddrs}, // 对称：预测到上限
	} {
		t.Run(string(tc.nat), func(t *testing.T) {
			srv := newFakeSignalServer(t)
			defer srv.close()

			b := newSignalTestClientWithNAT("5.6.7.8:40002", string(tc.nat))
			dialFakeSignal(t, b, srv)
			if err := b.ensureSignalStream(); err != nil {
				t.Fatalf("建流失败: %v", err)
			}
			waitStreamCount(t, srv, 1)
			srv.setOnReg(func(idx int, msg signalMessage) {
				_ = srv.writeTo(idx, signalMessage{Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true})
			})

			mgr := attachLoopbackManager(t, b, newStatusRecorder())
			// 两个相邻观测值（与 A 侧用例同形）
			mgr.discoverPunchAddr = func(context.Context, net.PacketConn) ([]netip.AddrPort, error) {
				return []netip.AddrPort{
					netip.MustParseAddrPort("5.6.7.8:40002"),
					netip.MustParseAddrPort("5.6.7.8:40003"),
				}, nil
			}
			// 直接造响应方会话并走 punch-ready 发送路径（不跑整轮打洞）
			s := mgr.newSession("0123456789abcdef", "192.168.30.11", pathRoleResponder,
				3000, strings.Repeat("ab", 32), "", netip.MustParseAddrPort("1.2.3.4:30001"))
			if _, fp, err := b.ensureDirectCert(); err == nil {
				s.myFP = fp
			}
			if !s.openSocket() {
				t.Fatal("开 punch socket 失败")
			}
			addrs, err := s.discover()
			if err != nil || len(addrs) == 0 {
				t.Fatalf("发现地址失败: %v", err)
			}
			// 与 runResponder 同一判据（这就是被考察的那一行）
			s.myPunchAddrs = candidatesForNATType(s.mgr.c.NATType(), addrs)
			s.myPunchAddr = s.myPunchAddrs[0]
			s.sendReadyWithRetry()

			var ready *signalMessage
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) && ready == nil {
				for _, m := range srv.allRegs() {
					if m.Type == signalMsgTypePunchReady {
						mm := m
						ready = &mm
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if ready == nil {
				t.Fatal("没有捕获到 punch-ready")
			}
			if len(ready.PunchAddrs) != tc.want {
				t.Fatalf("NAT=%s 时 punch-ready 候选数应为 %d，实际 %d: %v",
					tc.nat, tc.want, len(ready.PunchAddrs), ready.PunchAddrs)
			}
		})
	}
}

// TestPredictSymmetricCandidates ⭐ 2.2：候选预测的规则与开关
func TestPredictSymmetricCandidates(t *testing.T) {
	p := func(ss ...string) []netip.AddrPort {
		out := make([]netip.AddrPort, 0, len(ss))
		for _, s := range ss {
			out = append(out, netip.MustParseAddrPort(s))
		}
		return out
	}
	has := func(list []netip.AddrPort, want string) bool {
		for _, a := range list {
			if a.String() == want {
				return true
			}
		}
		return false
	}

	t.Run("两观测用最小步长向上扩", func(t *testing.T) {
		got := predictSymmetricCandidates(p("1.2.3.4:50000", "1.2.3.4:50002"))
		if len(got) < 3 || len(got) > maxPunchAddrs {
			t.Fatalf("候选数应 >2 且 ≤%d，实际 %d", maxPunchAddrs, len(got))
		}
		// step=2：50002 之后应出现 50004（保守起见只断言「向上扩了」）
		if !has(got, "1.2.3.4:50004") && !has(got, "1.2.3.4:50006") {
			t.Fatalf("应按观测步长向上预测，实际 %v", got)
		}
		for _, want := range []string{"1.2.3.4:50000", "1.2.3.4:50002"} {
			if !has(got, want) {
				t.Fatalf("观测值 %s 必须保留，实际 %v", want, got)
			}
		}
	})

	t.Run("单观测假设连续分配并向上补", func(t *testing.T) {
		got := predictSymmetricCandidates(p("1.2.3.4:50000"))
		if len(got) != maxPunchAddrs {
			t.Fatalf("单观测应补到上限 %d，实际 %d", maxPunchAddrs, len(got))
		}
		if got[0].String() != "1.2.3.4:50000" || got[1].String() != "1.2.3.4:50001" {
			t.Fatalf("应从观测值起连续向上，实际 %v", got[:3])
		}
	})

	t.Run("超大间隔仍补满上限且保留观测", func(t *testing.T) {
		got := predictSymmetricCandidates(p("1.2.3.4:1000", "1.2.3.4:60000"))
		if len(got) != maxPunchAddrs {
			t.Fatalf("应补满上限，实际 %d", len(got))
		}
		if !has(got, "1.2.3.4:60000") {
			t.Fatalf("远端观测值不能丢，实际 %v", got)
		}
	})

	t.Run("混 IP 不做预测", func(t *testing.T) {
		got := predictSymmetricCandidates(p("1.2.3.4:50000", "5.6.7.8:50002"))
		if len(got) != 2 {
			t.Fatalf("混 IP 时应原样返回，实际 %v", got)
		}
	})

	t.Run("HY2_NO_PORT_PREDICT=1 只广告观测值", func(t *testing.T) {
		t.Setenv("HY2_NO_PORT_PREDICT", "1")
		got := predictSymmetricCandidates(p("1.2.3.4:50000", "1.2.3.4:50002"))
		if len(got) != 2 {
			t.Fatalf("开关打开时不得预测，实际 %v", got)
		}
	})
}

// TestPunchReadyCarriesAddrsAndFingerprint ⭐ A1 + 2.3（响应方一侧）
func TestPunchReadyCarriesAddrsAndFingerprint(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	b := newSignalTestClientWithNAT("5.6.7.8:40002", string(NATFullCone))
	dialFakeSignal(t, b, srv)
	if err := b.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)

	// punch-ready 要等应答（signalRoundTrip），否则会走 3 次重试
	srv.setOnReg(func(idx int, msg signalMessage) {
		_ = srv.writeTo(idx, signalMessage{Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true})
	})

	mgr := attachLoopbackManager(t, b, newStatusRecorder())
	// 直接造一个「响应方会话」并调用 punch-ready 发送路径（不跑打洞）
	s := mgr.newSession("0123456789abcdef", "192.168.30.11", pathRoleResponder,
		3000, strings.Repeat("ab", 32), "", netip.MustParseAddrPort("1.2.3.4:30001"))
	if _, fp, err := b.ensureDirectCert(); err == nil {
		s.myFP = fp
	} else {
		t.Fatalf("生成直连证书失败: %v", err)
	}
	s.myPunchAddrs = []netip.AddrPort{
		netip.MustParseAddrPort("5.6.7.8:40002"),
		netip.MustParseAddrPort("5.6.7.8:40003"),
	}
	s.myPunchAddr = s.myPunchAddrs[0]
	s.sendReadyWithRetry()

	var ready *signalMessage
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && ready == nil {
		for _, m := range srv.allRegs() {
			if m.Type == signalMsgTypePunchReady {
				mm := m
				ready = &mm
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ready == nil {
		t.Fatal("没有捕获到 punch-ready")
	}
	if len(ready.PunchAddrs) != 2 {
		t.Fatalf("punch-ready 必须携带候选列表，实际 %v", ready.PunchAddrs)
	}
	if len(ready.DirectFingerprint) != 64 {
		t.Fatalf("punch-ready 必须携带自己的指纹（2.3 双向固定），实际 %q", ready.DirectFingerprint)
	}
	if s.myFP != ready.DirectFingerprint {
		t.Fatalf("指纹应与本机证书一致：%q vs %q", s.myFP, ready.DirectFingerprint)
	}
}

// ---------- 2.3：A 作为 listener 固定 B ----------

// TestListenerTLSConfigPinsPeerFingerprint ⭐ 2.3：
//
//	1b-1 是单向固定（B 固定 A）；A 作为 listener 只要求「出示任意证书」。
//	现在 A 拿到 B 的指纹后必须**同时**固定 B；拿不到（旧对端）则保持单向语义。
func TestListenerTLSConfigPinsPeerFingerprint(t *testing.T) {
	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	mgr := attachLoopbackManager(t, c, newStatusRecorder())
	cert, fp, err := c.ensureDirectCert()
	if err != nil {
		t.Fatalf("生成直连证书失败: %v", err)
	}
	s := mgr.newSession("0123456789abcdef", "192.168.30.12", pathRoleInitiator,
		3000, strings.Repeat("ab", 32), "", netip.AddrPort{})

	// ① 旧对端（没给指纹）→ 不固定，行为等价 1b-1（但仍要求出示证书）
	conf := s.listenerTLSConfig(cert)
	if conf.VerifyPeerCertificate != nil {
		t.Fatal("没有对端指纹时不应固定（否则旧对端会连不上）")
	}
	if conf.ClientAuth != tls.RequireAnyClientCert {
		t.Fatal("仍必须要求对端出示证书（RequireAnyClientCert）")
	}

	// ② 新对端给了指纹 → 必须固定，且校验真的生效
	s.mu.Lock()
	s.peerFP = fp
	s.mu.Unlock()
	conf = s.listenerTLSConfig(cert)
	if conf.VerifyPeerCertificate == nil {
		t.Fatal("有对端指纹时必须固定对端（2.3 双向固定）")
	}
	if err := conf.VerifyPeerCertificate([][]byte{cert.Certificate[0]}, nil); err != nil {
		t.Fatalf("指纹匹配时应通过校验，实际 %v", err)
	}

	// ③ 指纹不匹配 → 必须拒绝（这是「失败则断开」的牙齿）
	s.mu.Lock()
	s.peerFP = strings.Repeat("cd", 32)
	s.mu.Unlock()
	conf = s.listenerTLSConfig(cert)
	if err := conf.VerifyPeerCertificate([][]byte{cert.Certificate[0]}, nil); err == nil {
		t.Fatal("指纹不匹配时必须校验失败（否则双向固定没有意义）")
	}
}

// ---------- 端到端：候选列表真的被用上（少了它必然打不通） ----------

// TestLoopbackPunchUsesFullCandidateList ⭐ A1 端到端（有牙）：
//
//	给两侧的发现函数各追加一个「端口更小的**死地址**」（127.0.0.1:1）：
//	normalize 按端口升序 ⇒ 它成为 `punchAddr`，而真实 punch socket 地址排在它后面。
//	  - 若候选列表没有被转发（旧行为：只用 punchAddr）⇒ 对端只朝死地址发包 ⇒ 打不通；
//	  - 只有「列表被完整转发 + realm 向每个候选发包」才会成功。
//
//	因此本用例通过 = 候选列表真的在链路上生效（不是「字段存在」这种弱断言）。
func TestLoopbackPunchUsesFullCandidateList(t *testing.T) {
	a, b, recA, recB, srv, cleanup := newLoopbackPairFull(t)
	defer cleanup()

	deadAddr := netip.MustParseAddrPort("127.0.0.1:1")
	// ⚠️ `realAddrs` 会被**双方各自的**打洞 goroutine 写（A 侧 runInitiator、B 侧 runResponder
	// 都会调用被替换的 `discoverPunchAddr`），而测试 goroutine 随后会读它。
	// `-race -count=50` 实测报出 DATA RACE（`stage1b3_test.go` 的 map 读写）——**是测试自身的
	// 同步缺口，不是产品代码问题**。用一个 mutex 把两侧的写与主 goroutine 的读串起来。
	var realAddrsMu sync.Mutex
	realAddrs := map[*Hysteria2Client]netip.AddrPort{}
	for _, c := range []*Hysteria2Client{a, b} {
		c := c
		mgr := punchMgrOf(t, c)
		inner := mgr.discoverPunchAddr
		mgr.discoverPunchAddr = func(ctx context.Context, sock net.PacketConn) ([]netip.AddrPort, error) {
			out, err := inner(ctx, sock)
			if err != nil {
				return nil, err
			}
			if len(out) > 0 {
				realAddrsMu.Lock()
				realAddrs[c] = out[0]
				realAddrsMu.Unlock()
			}
			return append(out, deadAddr), nil
		}
	}

	if _, err := a.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}

	// 先确认前置条件：广告出去的 punchAddr 就是那个死地址（端口最小）
	intent := waitForMsg(t, srv, signalMsgTypePunchIntent)
	if intent.PunchAddr != deadAddr.String() {
		t.Fatalf("前置条件不成立：punchAddr 应是端口更小的死地址 %s，实际 %q —— "+
			"否则本用例无法证明「成功来自候选列表」", deadAddr, intent.PunchAddr)
	}
	// ⭐ 牙齿：真实的 punch socket 地址必须出现在候选列表里（1b-3 之前这里只有 punchAddr 一个）
	realAddrsMu.Lock()
	realA, ok := realAddrs[a]
	realAddrsMu.Unlock()
	if !ok {
		t.Fatal("没有捕获到真实 punch socket 地址")
	}
	foundReal := false
	for _, s := range intent.PunchAddrs {
		if s == realA.String() {
			foundReal = true
			break
		}
	}
	if !foundReal {
		t.Fatalf("候选列表必须包含真实 punch socket 地址 %s，实际 %v", realA, intent.PunchAddrs)
	}

	// 能打通 ⇒ 对端确实按候选列表向「真实地址」发了包
	waitDirect(t, recA, "192.168.30.12", 10*time.Second)
	waitDirect(t, recB, "192.168.30.11", 10*time.Second)

	// ⭐ 2.3：响应方的 punch-ready 必须带自己的指纹（否则 A 只能单向固定）
	ready := waitForMsg(t, srv, signalMsgTypePunchReady)
	if len(ready.DirectFingerprint) != 64 {
		t.Fatalf("punch-ready 必须携带响应方指纹（2.3 双向固定），实际 %q", ready.DirectFingerprint)
	}
}

// ---------- 测试辅助 ----------

// punchMgrOf 取客户端的打洞管理器
func punchMgrOf(t *testing.T, c *Hysteria2Client) *punchManager {
	t.Helper()
	c.punchMu.Lock()
	mgr := c.punchMgr
	c.punchMu.Unlock()
	if mgr == nil {
		t.Fatal("打洞管理器未启动")
	}
	return mgr
}

// waitForIntent 等在假信令服务端上出现 punch-intent，并返回它
func waitForIntent(t *testing.T, srv *fakeSignalServer) signalMessage {
	t.Helper()
	return waitForMsg(t, srv, signalMsgTypePunchIntent)
}

// waitForMsg 等在假信令服务端上出现指定类型的消息（失败时 dump 收到的全部类型）
func waitForMsg(t *testing.T, srv *fakeSignalServer, msgType string) signalMessage {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range srv.allRegs() {
			if m.Type == msgType {
				return m
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	var got []string
	for _, m := range srv.allRegs() {
		got = append(got, m.Type+"(peer="+m.PeerVIP+",addrs="+itoa(len(m.PunchAddrs))+")")
	}
	t.Fatalf("没有捕获到 %s；服务端收到的消息: %v", msgType, got)
	return signalMessage{}
}

// itoa 极简十进制转换（避免为一个断言引入 strconv 的额外 import）
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
