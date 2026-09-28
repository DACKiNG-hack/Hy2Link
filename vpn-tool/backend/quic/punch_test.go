package quic

// vpn-tool/backend/quic/punch_test.go
//
// 阶段 1b-1 客户端侧测试。§7.2 要求的 9 条并发/回归测试都在本文件：
//  1 TestPunchSessionStateMachineConcurrent
//  2 TestPunchPushHandlerDoesNotBlockReadLoop
//  3 （服务端侧：TestServerPunchAttemptTableConcurrent，见 vpn-server/quic/punch_test.go）
//  4 TestPunchSocketHandoverRace
//  5 TestDirectHandshakeFallbackOnFingerprintMismatch
//  6 TestPunchBudgetGateAbortsEarly
//  7 TestPeerFilterConnRejectsStranger（+ StrangerDialFails 集成版）
//  8 TestPunchProbeMeasuresRTT
//  9 TestPeerFilterConnUnmapsIPv4InIPv6
//
// 另加：E2E（loopback 真打洞）、metadata 派生、三集合不相交、原因码表完整性。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/extras/v2/realm"
)

// ---------- 基础工具 ----------

// TestPunchMetadataFromSeed realm 需要 (nonce16, obfs32)，我们只有 32 字节 seed
func TestPunchMetadataFromSeed(t *testing.T) {
	seed := strings.Repeat("ab", 32) // 32 字节 hex
	meta, err := punchMetadataFromSeed(seed)
	if err != nil {
		t.Fatalf("派生失败: %v", err)
	}
	if len(meta.Nonce) != realm.PunchNonceSize*2 {
		t.Fatalf("nonce 应为 %d 个 hex，实际 %d", realm.PunchNonceSize*2, len(meta.Nonce))
	}
	if len(meta.Obfs) != realm.PunchObfsKeySize*2 {
		t.Fatalf("obfs 应为 %d 个 hex，实际 %d", realm.PunchObfsKeySize*2, len(meta.Obfs))
	}
	// 确定性：同一 seed 必须得到同一组值（两端各自派生）
	again, err := punchMetadataFromSeed(seed)
	if err != nil || again != meta {
		t.Fatalf("派生必须确定性，got=%+v want=%+v", again, meta)
	}
	// nonce 必须是 seed 的前 16 字节（线上只暴露半个 seed）
	if meta.Nonce != seed[:32] {
		t.Fatalf("nonce 应等于 seed[0:16]，实际 %s", meta.Nonce)
	}
	// 不同 seed → 不同 obfs（不会退化成常量）
	other, _ := punchMetadataFromSeed(strings.Repeat("cd", 32))
	if other.Obfs == meta.Obfs {
		t.Fatal("不同 seed 必须派生出不同 obfs 密钥")
	}
	// 非法输入
	for _, bad := range []string{"", "zz", strings.Repeat("ab", 16)} {
		if _, err := punchMetadataFromSeed(bad); err == nil {
			t.Fatalf("非法 seed %q 应当报错", bad)
		}
	}
	// realm 必须接受我们派生的 metadata（最终判据）
	if _, err := realm.EncodePunchPacket(realm.PunchPacketHello, meta); err != nil {
		t.Fatalf("realm 不接受派生的 metadata: %v", err)
	}
}

// TestClientSignalTypeSetsAreDisjoint 约束 1（客户端侧）：三集合两两不相交
func TestClientSignalTypeSetsAreDisjoint(t *testing.T) {
	sets := map[string][]string{
		"request":  signalRequestTypes,
		"response": signalResponseTypes,
		"push":     signalPushTypes,
	}
	seen := map[string]string{}
	for name, list := range sets {
		for _, v := range list {
			if prev, dup := seen[v]; dup {
				t.Fatalf("类型 %q 同时属于 %s 与 %s（约束 1 被破坏）", v, prev, name)
			}
			seen[v] = name
		}
	}
	// ⭐ D1-a：应答集合 3 → 4（新增 peers-list）
	if len(signalResponseTypes) != 4 {
		t.Fatal("应答类型集合变了，必须重新评估约束 1")
	}
	// push 类型绝不能被 isResponseType 认作应答（否则会被投进等待槽）
	for _, v := range signalPushTypes {
		if (&Hysteria2Client{}).isResponseType(v) {
			t.Fatalf("推送类型 %q 被当成应答类型（约束 1 被破坏）", v)
		}
	}
	// ⭐ D1-a：新应答类型必须**能**被认作应答（否则应答进不了等待槽、请求必然超时）
	if !(&Hysteria2Client{}).isResponseType(signalMsgTypePeersList) {
		t.Fatalf("%q 必须是应答类型（isResponseType 漏登记 ⇒ 请求会一直等到超时）", signalMsgTypePeersList)
	}
	// 新增的 4 个常量都要登记
	for _, v := range []string{
		signalMsgTypePunchIntent, signalMsgTypePunchReady,
		signalMsgTypePunchInvite, signalMsgTypePunchPeer,
		// ⭐ D1-a：两个新常量必须各归其集合
		signalMsgTypePeers, signalMsgTypePeersList,
	} {
		if _, ok := seen[v]; !ok {
			t.Fatalf("类型常量 %q 未登记", v)
		}
	}
}

// TestP2PReasonTableComplete 原因码表必须完整（UI 契约）
func TestP2PReasonTableComplete(t *testing.T) {
	codes := []string{
		P2PReasonOKDirect, P2PReasonNATSymmetric, P2PReasonNATUnknown,
		P2PReasonPeerUnreachable, P2PReasonPeerNotReady, P2PReasonLocalNoPunchAddr,
		P2PReasonPeerNoPunchAddr, P2PReasonPunchTimeout, P2PReasonDirectHandshakeFailed,
		P2PReasonFingerprintMismatch, P2PReasonProbeTimeout, P2PReasonRateLimited,
		P2PReasonPeerBusy, P2PReasonAttemptTimeout, P2PReasonSessionExpired,
		P2PReasonServerP2PDisabled, P2PReasonCancelled, P2PReasonDirectLost,
		P2PReasonQualityDegraded,
		P2PReasonQualityPoor,  // ⭐ 1b-4 第一步：试用期质量不达标
		P2PReasonTrialProbing, // ⭐ 1b-4 第一步：进入试用期（正常状态，非失败）
		// ⭐ 2026-09-27（真机 Bug 3）：对端主动关闭（非本机链路问题）
		P2PReasonPeerClosed,
	}
	for _, c := range codes {
		txt, ok := p2pReasonText[c]
		if !ok || txt == "" {
			t.Fatalf("原因码 %q 缺少中文文案", c)
		}
		if strings.Contains(txt, "⚠️") {
			t.Fatalf("原因码 %q 的文案必须中性（不得带告警符号）: %q", c, txt)
		}
	}
	if len(p2pReasonText) != len(codes) {
		t.Fatalf("文案表项数(%d) 与原因码数(%d) 不一致", len(p2pReasonText), len(codes))
	}
	// 指纹不匹配必须是中性文案 + 不可重试
	if p2pRetryable(P2PReasonFingerprintMismatch) {
		t.Fatal("fingerprint-mismatch 不应标记为可重试")
	}
	if strings.Contains(p2pReasonText[P2PReasonFingerprintMismatch], "攻击") {
		t.Fatal("指纹不匹配文案不应制造恐慌")
	}
}

// ---------- 9. TestPeerFilterConnUnmapsIPv4InIPv6 ----------

func TestPeerFilterConnUnmapsIPv4InIPv6(t *testing.T) {
	// 期望地址写成 IPv4-in-IPv6 形式，实际包来自 4 字节形式（反之亦然）
	v4 := netip.MustParseAddrPort("1.2.3.4:5000")
	v6mapped := netip.AddrPortFrom(netip.MustParseAddr("::ffff:1.2.3.4"), 5000)

	if !sameAddrPort(v4, v6mapped) || !sameAddrPort(v6mapped, v4) {
		t.Fatal("IPv4-in-IPv6 与 4 字节 IPv4 必须视为同一地址（否则会误杀对端包）")
	}
	if sameAddrPort(v4, netip.MustParseAddrPort("1.2.3.4:5001")) {
		t.Fatal("端口不同不应相等")
	}
	if sameAddrPort(v4, netip.MustParseAddrPort("1.2.3.5:5000")) {
		t.Fatal("IP 不同不应相等")
	}

	// 端到端：ReadFrom 收到的是 *net.UDPAddr（4 字节形式），期望值用 mapped 形式写
	pc := newFakePacketConn()
	pc.push([]byte("hello"), &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000})
	filter := newPeerFilterConn(pc, v6mapped)
	buf := make([]byte, 64)
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := filter.ReadFrom(buf)
	if err != nil {
		t.Fatalf("对端包被误杀了（Unmap 归一化失效）: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("内容不对: %q", buf[:n])
	}
	if filter.dropCount() != 0 {
		t.Fatalf("不应有丢弃，实际 %d", filter.dropCount())
	}
}

// ---------- 7. TestPeerFilterConnRejectsStranger ----------

func TestPeerFilterConnRejectsStranger(t *testing.T) {
	pc := newFakePacketConn()
	filter := newPeerFilterConn(pc, netip.MustParseAddrPort("1.2.3.4:5000"))

	pc.push([]byte("stranger"), &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 6000})
	pc.push([]byte("peer"), &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000})

	buf := make([]byte, 64)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := filter.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "peer" {
		t.Fatalf("只应读到对端的包，实际 %q", buf[:n])
	}
	if filter.dropCount() != 1 {
		t.Fatalf("应丢弃 1 个陌生包，实际 %d", filter.dropCount())
	}

	// WriteTo 只允许写对端
	if _, err := filter.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 6000}); err == nil {
		t.Fatal("向非对端地址写必须报错")
	}
	if _, err := filter.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000}); err != nil {
		t.Fatalf("写对端不应报错: %v", err)
	}
}

// TestPeerFilterConnDropLoggingBounded 洪泛陌生包：不 panic、丢弃计数有界、仍能收到对端包
func TestPeerFilterConnDropLoggingBounded(t *testing.T) {
	pc := newFakePacketConn()
	filter := newPeerFilterConn(pc, netip.MustParseAddrPort("1.2.3.4:5000"))
	for i := 0; i < 10000; i++ {
		pc.push([]byte("junk"), &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 6000 + i%100})
	}
	pc.push([]byte("peer"), &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000})
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, _, err := filter.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "peer" {
		t.Fatalf("洪泛后仍应能读到对端包（err=%v n=%d）", err, n)
	}
	if got := filter.dropCount(); got != 10000 {
		t.Fatalf("丢弃计数应为 10000，实际 %d", got)
	}
}

// ---------- 1. TestPunchSessionStateMachineConcurrent ----------

func TestPunchSessionStateMachineConcurrent(t *testing.T) {
	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	mgr := newPunchManager(c)
	defer mgr.close()

	s := mgr.newSession("attempt-1", "192.168.30.12", "initiator", 10000, strings.Repeat("ab", 32), "", netip.AddrPort{})
	sock, err := mgr.openPunchSocket()
	if err != nil {
		t.Fatalf("open socket: %v", err)
	}
	s.sock = sock
	defer sock.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 4 {
			case 0:
				s.fail(P2PReasonPunchTimeout)
			case 1:
				s.succeed()
			case 2:
				s.closeAll() // 幂等
			case 3:
				s.cancel() // 超时/取消
			}
		}(i)
	}
	wg.Wait()

	// 只能「结束」一次（finishOnce），不能 panic
	select {
	case <-s.doneCh:
	default:
		t.Fatal("会话应已结束")
	}
	s.fail(P2PReasonCancelled) // 再调一次也不能 panic
	// socket 只能关一次（sync.Once）→ 再关一次不报错
	s.closeAll()
	if v, ok := s.state.Load().(string); !ok || v == "" {
		t.Fatal("状态必须已被设置")
	}
}

// ---------- 6. TestPunchBudgetGateAbortsEarly ----------

func TestPunchBudgetGateAbortsEarly(t *testing.T) {
	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	mgr := newPunchManager(c)
	defer mgr.close()
	mgr.budget = 2 * time.Second // 极小预算
	mgr.tuning = punchTuning{handshake: 200 * time.Millisecond, probe: 200 * time.Millisecond,
		stun: 200 * time.Millisecond, readyWait: 200 * time.Millisecond}
	// 让发现必然失败，从而快速走到失败出口
	mgr.discoverPunchAddr = func(context.Context, net.PacketConn) ([]netip.AddrPort, error) {
		return nil, fmt.Errorf("stun 不可达")
	}
	if err := c.ensureSignalStreamForTest(); err != nil {
		t.Skipf("跳过：无法建立信令流（%v）", err)
	}

	s := mgr.newSession("attempt-budget", "192.168.30.12", "initiator", 10000, strings.Repeat("ab", 32), "", netip.AddrPort{})
	start := time.Now()
	// 直接跑「共同尾段」：剩余预算(2s) < window(10s)+握手 → 必须立刻 attempt-timeout
	s.runCommonTail(true)
	elapsed := time.Since(start)
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("预算门应提前收工，实际耗时 %v", elapsed)
	}
	if r, _ := s.reason.Load().(string); r != P2PReasonAttemptTimeout {
		t.Fatalf("原因码应为 %s，实际 %q", P2PReasonAttemptTimeout, r)
	}
}

// ---------- 2. TestPunchPushHandlerDoesNotBlockReadLoop ----------

// TestPunchPushHandlerDoesNotBlockReadLoop push 处理绝不能阻塞信令读协程（1a 的钩子约束）
func TestPunchPushHandlerDoesNotBlockReadLoop(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c, srv)
	if err := c.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)

	// 管理器 + 一个**故意很慢**的状态回调
	mgr := newPunchManager(c)
	mgr.start()
	defer mgr.close()
	blocking := make(chan struct{})
	go func() {
		// 回调阻塞 400ms（模拟 UI 卡顿）
		mgr.setStatusHandler(func(P2PStatus) {
			select {
			case <-blocking:
			case <-time.After(400 * time.Millisecond):
			}
		})
	}()

	c.punchMu.Lock()
	c.punchMgr = mgr
	c.punchMu.Unlock()
	defer func() {
		c.punchMu.Lock()
		c.punchMgr = nil
		c.punchMu.Unlock()
		close(blocking)
	}()

	// 服务端推一条 punch-invite（会被 punchManager 处理 → 触发会话 → 触发慢回调）
	srv.setOnReg(func(idx int, msg signalMessage) {
		_ = srv.writeTo(idx, signalMessage{Type: signalMsgTypeRegistered})
	})
	_ = srv.writeTo(0, signalMessage{
		Type: signalMsgTypePunchInvite, AttemptID: "0123456789abcdef",
		PeerVIP: "192.168.30.12", PunchAddr: "203.0.113.9:40001",
		Metadata: strings.Repeat("ab", 32), DirectFingerprint: strings.Repeat("a", 64), WindowMs: 3000,
	})

	// 等慢回调确实开始（会话已建立）
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mgr.mu.Lock()
		n := len(mgr.sessions)
		mgr.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 关键断言：回调阻塞期间，信令读协程仍能完成一次往返
	start := time.Now()
	if _, err := c.signalRoundTrip(signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	}); err != nil {
		t.Fatalf("往返失败: %v", err)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("push 处理阻塞了信令读协程：往返耗时 %v", d)
	}
}

// ---------- 4. TestPunchSocketHandoverRace ----------

// TestPunchSocketHandoverRace 打洞与 QUIC 不能同时读同一条 socket
//
// 用一个「并发读探针」PacketConn：Punch 期间它被 Punch 读，
// 交付 QUIC 后只允许 QUIC 读 —— 任何重叠都会被记录下来。
func TestPunchSocketHandoverRace(t *testing.T) {
	c1, _, rec1, _, cleanup := newLoopbackPair(t)
	defer cleanup()

	if _, err := c1.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("A 发起失败: %v", err)
	}
	waitDirect(t, rec1, "192.168.30.12", 8*time.Second)

	// 探针（concurrentReadProbe）若发现「打洞与 QUIC 同时读」会置位；
	// 会话内的交接不变量也会把状态判成失败（那样 waitDirect 就已经失败了）。
	if overlappingReads.Load() {
		t.Fatal("检测到 socket 被并发读取（打洞与 QUIC 重叠）")
	}
}

// ---------- 5. TestDirectHandshakeFallbackOnFingerprintMismatch ----------

func TestDirectHandshakeFallbackOnFingerprintMismatch(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	a := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	b := newSignalTestClientWithNAT("5.6.7.8:40002", string(NATFullCone))
	for _, c := range []*Hysteria2Client{a, b} {
		dialFakeSignal(t, c, srv)
		if err := c.ensureSignalStream(); err != nil {
			t.Fatalf("建流失败: %v", err)
		}
	}
	waitStreamCount(t, srv, 2)

	// 假服务端：协调 A→B，但**故意把指纹改错**（模拟冒充/中间人）
	otherIdx := func(i int) int {
		if i == 0 {
			return 1
		}
		return 0
	}
	srv.setOnReg(func(idx int, msg signalMessage) {
		switch msg.Type {
		case signalMsgTypeRegister:
			_ = srv.writeTo(idx, signalMessage{
				Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true,
				PeerPublicAddr: "5.6.7.8:40002", PeerNATType: string(NATFullCone),
			})
		case signalMsgTypePunchIntent:
			_ = srv.writeTo(idx, signalMessage{Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true})
			_ = srv.writeTo(otherIdx(idx), signalMessage{
				Type: signalMsgTypePunchInvite, AttemptID: msg.AttemptID,
				PeerVIP: "192.168.30.11", PunchAddr: msg.PunchAddr,
				Metadata: msg.Metadata, DirectFingerprint: strings.Repeat("f", 64), // ← 错的
				WindowMs: msg.WindowMs,
			})
		case signalMsgTypePunchReady:
			_ = srv.writeTo(idx, signalMessage{Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true})
			_ = srv.writeTo(otherIdx(idx), signalMessage{
				Type: signalMsgTypePunchPeer, AttemptID: msg.AttemptID,
				PeerVIP: "192.168.30.12", PunchAddr: msg.PunchAddr, WindowMs: msg.WindowMs,
			})
		}
	})

	// 两端都启动管理器（loopback 化：STUN 打桩、socket 绑回环）
	recs := map[*Hysteria2Client]*statusRecorder{}
	for _, c := range []*Hysteria2Client{a, b} {
		rec := newStatusRecorder()
		recs[c] = rec
		attachLoopbackManager(t, c, rec)
	}

	if _, err := a.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}

	// B 必须因指纹不匹配而失败（中性原因码），绝不建立直连
	waitReason(t, recs[b], "192.168.30.11", P2PReasonFingerprintMismatch, 8*time.Second)
	if _, ok := recs[b].directStatus("192.168.30.11"); ok {
		t.Fatal("指纹不匹配时绝不能进入 direct")
	}
}

// ---------- 8. TestPunchProbeMeasuresRTT ----------

// TestPunchProbeMeasuresRTT 端到端：打洞 → 握手 → 探针测出 RTT
func TestPunchProbeMeasuresRTT(t *testing.T) {
	c1, _, rec1, rec2, cleanup := newLoopbackPair(t)
	defer cleanup()

	if _, err := c1.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}
	stA := waitDirect(t, rec1, "192.168.30.12", 8*time.Second)
	stB := waitDirect(t, rec2, "192.168.30.11", 8*time.Second)

	// UI 契约：direct 状态必须带 path=direct 与 RTT
	if stA.Path != "direct" || stB.Path != "direct" {
		t.Fatalf("direct 状态的 path 应为 direct: A=%+v B=%+v", stA, stB)
	}
	if stA.RTTDirectMs <= 0 || stB.RTTDirectMs <= 0 {
		t.Fatalf("两端都应测出 RTT：A=%dms B=%dms", stA.RTTDirectMs, stB.RTTDirectMs)
	}
	if stA.RTTDirectMs > 500 || stB.RTTDirectMs > 500 {
		t.Fatalf("loopback RTT 过大：A=%dms B=%dms", stA.RTTDirectMs, stB.RTTDirectMs)
	}
	if stA.ReasonCode != P2PReasonOKDirect || stA.Retryable {
		t.Fatalf("成功状态的原因码/可重试标记不对: %+v", stA)
	}
}

// ---------- E2E 辅助：loopback 双端 + 假信令服务端 ----------

var (
	overlappingReads atomic.Bool
	loopSeq          atomic.Int64
)

// concurrentReadProbe 检测「同一条 socket 被两个读者同时读」
type concurrentReadProbe struct {
	net.PacketConn
	reading atomic.Int32
}

func (p *concurrentReadProbe) ReadFrom(b []byte) (int, net.Addr, error) {
	if p.reading.Add(1) > 1 {
		overlappingReads.Store(true)
	}
	defer p.reading.Add(-1)
	return p.PacketConn.ReadFrom(b)
}

// fastTuning 缩短各阶段超时（测试用；生产用默认值）
//
// ⚠️ handshake 不能压得太狠：打洞刚结束时对端的首个 Initial 仍可能落在
// 「QUIC 还没开始读 socket」的窗口里，要靠 QUIC 的 RTO 重传（~1s）补回来。
// 生产是 5s，测试给 3s 既快又不会误报。
func fastTuning() punchTuning {
	return punchTuning{
		handshake: 3 * time.Second,
		probe:     3 * time.Second,
		stun:      500 * time.Millisecond,
		readyWait: 3 * time.Second,
	}
}

// newLoopbackPair 造一对已连上同一个假信令服务端的客户端，并让它们能互相打洞。
//
// STUN 被替换成「直接返回本机 punch socket 的地址」（loopback），
// 打洞/握手/探针全部走**真实**代码路径。
func newLoopbackPair(t *testing.T) (*Hysteria2Client, *Hysteria2Client, *statusRecorder, *statusRecorder, func()) {
	t.Helper()
	a, b, recA, recB, _, cleanup := newLoopbackPairFull(t)
	return a, b, recA, recB, cleanup
}

// newLoopbackPairFull 同 newLoopbackPair，但把假信令服务端也返回（1b-3 测试要断言转发的字段）
func newLoopbackPairFull(t *testing.T) (*Hysteria2Client, *Hysteria2Client, *statusRecorder, *statusRecorder, *fakeSignalServer, func()) {
	t.Helper()
	srv := newFakeSignalServer(t)

	a := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	b := newSignalTestClientWithNAT("5.6.7.8:40002", string(NATFullCone))
	// ⭐ 第 3 步-C：本机 VIP（隧道地址）必须落地，否则直连无法移交给路径管理器。
	//
	// 为什么（实证）：夹具原来从不设 `assignedIP` ⇒ `myVIP4()` 返回 false ⇒
	// `punchSession.handoverToPath()` 第一道前置就 return ⇒ 打洞成功后的连接
	// **交不出去**（既无路径持有、也无路径会关）⇒ 每轮泄漏 2 个 transport 协程。
	// 走生产同一个入口 `noteAssignedIP`（DHCP 拿到地址时就是调它），**不是**直接写字段。
	a.noteAssignedIP("192.168.30.11")
	b.noteAssignedIP("192.168.30.12")
	for _, c := range []*Hysteria2Client{a, b} {
		dialFakeSignal(t, c, srv)
		if err := c.ensureSignalStream(); err != nil {
			t.Fatalf("建流失败: %v", err)
		}
	}
	waitStreamCount(t, srv, 2)

	// 假服务端的协调逻辑（与真服务端 handlePunchIntent/handlePunchReady 同形）
	//
	// ⚠️ 必须用「另一个 stream」而不是写死 idx=1：两条信令流谁先到是**竞态**
	// （客户端开流后立刻写第一帧，到达顺序不定），写死 idx 会把邀请投给发起方自己，
	// 制造出「双向同时发起」的假象。
	windowFromIntent := 3000
	otherIdx := func(i int) int {
		if i == 0 {
			return 1
		}
		return 0
	}
	srv.setOnReg(func(idx int, msg signalMessage) {
		switch msg.Type {
		case signalMsgTypeRegister:
			// 1a 的查询/登记：回一条 peer（对端在线且信令就绪）
			_ = srv.writeTo(idx, signalMessage{
				Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true,
				PeerPublicAddr: "5.6.7.8:40002", PeerNATType: string(NATFullCone),
			})
		case signalMsgTypePunchIntent:
			windowFromIntent = clampPunchWindow(msg.WindowMs)
			_ = srv.writeTo(idx, signalMessage{Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true})
			_ = srv.writeTo(otherIdx(idx), signalMessage{
				Type: signalMsgTypePunchInvite, AttemptID: msg.AttemptID,
				PeerVIP: "192.168.30.11", PunchAddr: msg.PunchAddr, NATType: msg.NATType,
				Metadata: msg.Metadata, DirectFingerprint: msg.DirectFingerprint,
				PunchAddrs: msg.PunchAddrs, // ⭐ 1b-3：与真服务端同形（转发候选列表）
				WindowMs:   windowFromIntent,
			})
		case signalMsgTypePunchReady:
			_ = srv.writeTo(idx, signalMessage{Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true})
			_ = srv.writeTo(otherIdx(idx), signalMessage{
				Type: signalMsgTypePunchPeer, AttemptID: msg.AttemptID,
				PeerVIP: "192.168.30.12", PunchAddr: msg.PunchAddr,
				PunchAddrs: msg.PunchAddrs, // ⭐ 1b-3
				// ⭐ 1b-3（2.3）：与真服务端同形 —— 把 B 的指纹转给 A，A 才能双向固定
				DirectFingerprint: msg.DirectFingerprint,
				NATType:           msg.NATType, WindowMs: windowFromIntent,
			})
		}
	})

	// ⭐ 第 3 步-C：必须**关掉两个客户端**，不能只关假服务端。
	//
	// 为什么（实测，`TestLoopbackPunchRoundsNoGoroutineLeak`）：只 `srv.close()` 时，
	// 每个打洞会话的 `serveProbe` 会一直卡在 `readFrame`（读对端探针流），
	// 连带真实 QUIC 传输一起滞留 —— **每轮泄漏 ≈13 个 goroutine**，
	// 在 `-count=50` 全包长跑里累积到 1139 个、最终拖到超时。
	//
	// 客户端 `Close()` 会走生产的 `stopPunchManager()`（先 `pathMgr.close()` 再 `mgr.close()`），
	// 即与生产同一条收尾链路；`Close()` 本身幂等（`closeOnce`）。
	//
	// ⚠️ 用 `t.Cleanup` 注册而**不是**只放进返回的 `cleanup`：这样即使调用方忘了调，
	//    收尾也一定会发生（本夹具的泄漏正是「忘了调」造成的）。
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			srv.close()
			_ = a.Close()
			_ = b.Close()
		})
	}
	t.Cleanup(cleanup)
	recA := newStatusRecorder()
	recB := newStatusRecorder()
	attachLoopbackManager(t, a, recA)
	attachLoopbackManager(t, b, recB)
	return a, b, recA, recB, srv, cleanup
}

// attachLoopbackManager 给客户端挂一个「loopback 化」的打洞管理器。
//
// ⚠️ A3a（2026-09-28）**删除了本文件的两个预打洞入口**
// （`attachLoopbackManagerPrePunch` / `attachLoopbackManagerPrePunchTuned`）：
// 预打洞发起侧已整体删除（`prepunch.go` 桩化、`prePunchCfg` 字段从 `punch.go` 移除）
// ⇒ 11 处调用者**全部随 `prepunch_test.go` 桩化消失**，这两个入口成为死函数。
// 📎 原代码：`A2-干净点快照-2026-09-28\quic\punch_test.go:655-676`。
func attachLoopbackManager(t *testing.T, c *Hysteria2Client, rec *statusRecorder) *punchManager {
	t.Helper()
	return attachLoopbackManagerCfg(t, c, rec)
}

// loopback 夹具的试用期注入常量（产品**本来就有的**注入口；生产恒 0 ⇒ 走真实参数）。
const (
	// loopbackTrialWindow 试用期窗口。
	// ⚠️ 必须**大于「检查间隔 + 探针间隔」**：窗口太短会在第一个样本采到之前就过期，
	//    试用期必然失败（实测踩过：窗口 400ms + 默认 checkInterval 2s ⇒ 直接过期）。
	loopbackTrialWindow = 3 * time.Second
	// loopbackTrialProbeEvery 探针间隔（< 窗口，且让首个回显尽早到达）。
	// ⚠️ **不能调得太小**：实测 50ms 会让「无回显」判定抢先触发（L2 探针丢失）
	//    ⇒ 路径直接 `direct-lost` 降级，试用期根本没机会判定。
	//    250ms 是实测稳定值（试过 50ms 会红）。
	loopbackTrialProbeEvery = 250 * time.Millisecond
	// loopbackTrialCheckEvery 看门狗检查间隔 —— **决定试用期判定多久跑一次**（生产 2s）。
	// 必须 ≪ 窗口：否则「好样本够了」这件事要等到窗口都快过才被发现。
	loopbackTrialCheckEvery = 50 * time.Millisecond
	// loopbackTrialRelaySeed 中继 RTT 基准种子：
	// 不种的话 `relay <= 0 ⇒ 样本不好`，试用期会必然失败（见 noteTrialRelayRtt 的说明）。
	// ⚠️ 必须给**足够余量**：判据是 `direct < 0.8×relay`，而 loopback 的直连 RTT 并不总是
	//   亚毫秒（实测出现过 150ms —— 探针回显与看门狗同拍时的调度抖动）。
	//   取 1s ⇒ `0.8×1s = 800ms` 远大于该抖动，判据稳定成立。
	loopbackTrialRelaySeed = 1 * time.Second
)

// attachLoopbackManagerCfg 夹具实现
//
// 试用期注入（**产品本来就有的注入口**，口径同 `trial_integration_test.go` 的 harness）：
// 1b-4「先验后切」之后，打洞成功只进**试用期**，要走完才装表变成 direct。
// loopback 用例关心的是「打洞/候选列表/探针」而不是试用期时长，所以窗口压短 ——
// 但**仍然真实走试用期**（不跳过、不旁路）。
//
// ⚠️ A3a（2026-09-28）：签名由 5 参（`prePunch bool` + `tune ...func(*prePunchConfig, *punchManager)`）
// **收成 3 参** —— `prePunchConfig` 类型随预打洞发起侧删除 ⇒ 无对象可注入。
func attachLoopbackManagerCfg(t *testing.T, c *Hysteria2Client, rec *statusRecorder) *punchManager {
	t.Helper()
	mgr := newPunchManager(c)
	// ⚠️ loopback 用例关掉「对称 NAT 端口预测」：这些用例把发现函数替换成
	//    「返回本机 punch socket 地址」，预测会把 1 个地址扩成 32 个候选，
	//    对端就会朝进程内别的 socket 端口喷包，破坏用例时序（实测 3 个用例超时）。
	//    产品路径默认开启预测。
	mgr.noPredict = true
	mgr.tuning = fastTuning()
	mgr.budget = 12 * time.Second
	mgr.windowDefault = 3000
	if rec != nil {
		mgr.setStatusHandler(rec.handle)
	}
	mgr.discoverPunchAddr = func(_ context.Context, sock net.PacketConn) ([]netip.AddrPort, error) {
		ua, ok := sock.LocalAddr().(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("非 UDP socket")
		}
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(ua.Port))}, nil
	}
	mgr.openPunchSocket = func() (net.PacketConn, error) {
		ua, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			return nil, err
		}
		return &concurrentReadProbe{PacketConn: ua}, nil
	}
	// ⚠️ A3a（2026-09-28）**删除了这里的「预打洞调度器注入」块**
	// （原 `:735-755`：`mgr.prePunchCfg = defaultPrePunchConfig()` + `enabled` +
	//	紧凑节奏 + 调用方 `tune` 回调）。发起侧整体删除后 `prePunchCfg` 字段与
	//	`prePunchConfig` 类型都不复存在 ⇒ 无对象可注入；夹具所用的
	//	`newPunchManager(c)` 本就是生产构造器（**不存在「夹具默认关、夹具才开」的差别**）。
	// 📎 原代码：`A2-干净点快照-2026-09-28\quic\punch_test.go:735-755`。
	// ⭐ 第 3 步-C 泄漏收敛：**按生产的方式**建并绑定直连路径管理器。
	//
	// 为什么必须有（实证判定见交付说明 §9.2.3）：
	//   夹具原来只设 `c.punchMgr`，**从不建 `c.pathMgr`**，而生产是
	//   `pm := newPathManager(c); c.pathMgr = pm; pm.start(); mgr.setPathManager(pm)`。
	//   后果：`stopPunchManager()` 的 `if pm != nil { pm.close() }` 永不执行，
	//   `mgr.pathMgrRef()` 为 nil ⇒ `handleEstablished` 里**直连路径从未被登记**、
	//   因而**没有任何人持有它、也没有任何人会关它** ⇒ 其 QUIC transport 协程永久滞留
	//   （实测 +2/轮 线性累积；补上绑定后用例立刻进入 `state=probing`，证明此前路径「无主」）。
	//
	// ⚠️ 这里是**照生产建**，不是加测试旁路：唯一差别是下面那几个**产品本来就有的**
	//    试用期注入点（`trialWindowOverride` / `trialNeedOverride` / `trialRelayRttSeed`），
	//    口径与 `trial_integration_test.go` 的 harness 完全一致 —— 路径**真的走试用期**，
	//    只是窗口短。**绝不**引入「跳过试用期」之类的旁路。
	pm := newPathManager(c)
	// 时序契约：这些值由看门狗 goroutine 读，必须在 pm.start() 之前写好。
	pm.probeInterval = loopbackTrialProbeEvery
	pm.checkInterval = loopbackTrialCheckEvery
	pm.trialWindowOverride = loopbackTrialWindow
	pm.trialNeedOverride = 1
	pm.trialRelayRttSeed = int64(loopbackTrialRelaySeed)
	c.punchMu.Lock()
	c.pathMgr = pm
	c.punchMu.Unlock()
	pm.start()
	mgr.setPathManager(pm)
	t.Cleanup(pm.close)

	// ⭐ **最后才 start**：路径管理器已 `start()` 并完成 `setPathManager` 绑定
	// （A3a 之前的「等 `prePunchCfg` 注入完毕」这一前提已随预打洞发起侧删除，
	//	原因见上方 ⚠️ 块；现在是**生产同款**的启动顺序：先绑 pathManager、再 start 打洞管理器）。
	mgr.start()

	c.punchMu.Lock()
	c.punchMgr = mgr
	c.punchMu.Unlock()
	t.Cleanup(mgr.close)
	return mgr
}

// statusRecorder 记录状态回调（模拟 UI）：E2E 断言走**对外契约**（事件），
// 而不是偷看活的会话（会话结束就会被移出表）。
type statusRecorder struct {
	mu     sync.Mutex
	last   map[string]P2PStatus
	direct []P2PStatus
}

func newStatusRecorder() *statusRecorder {
	return &statusRecorder{last: map[string]P2PStatus{}}
}

func (r *statusRecorder) handle(st P2PStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last[st.PeerVIP] = st
	if st.State == P2PStateDirect {
		r.direct = append(r.direct, st)
	}
}

func (r *statusRecorder) directStatus(peerVIP string) (P2PStatus, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, st := range r.direct {
		if st.PeerVIP == peerVIP {
			return st, true
		}
	}
	return P2PStatus{}, false
}

func (r *statusRecorder) lastReason(peerVIP string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last[peerVIP].ReasonCode
}

func (r *statusRecorder) snapshot(peerVIP string) P2PStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last[peerVIP]
}

// waitDirect 等某个对端进入 direct（走状态回调，即 UI 契约）
func waitDirect(t *testing.T, rec *statusRecorder, peerVIP string, within time.Duration) P2PStatus {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if st, ok := rec.directStatus(peerVIP); ok {
			return st
		}
		if st := rec.snapshot(peerVIP); st.State == P2PStateFailed {
			t.Fatalf("直连失败：%s（%s）", st.ReasonCode, st.ReasonText)
		}
		time.Sleep(20 * time.Millisecond)
	}
	st := rec.snapshot(peerVIP)
	t.Fatalf("等待直连超时（peer=%s state=%s reason=%s）", peerVIP, st.State, st.ReasonCode)
	return P2PStatus{}
}

// waitReason 等某个原因码出现
func waitReason(t *testing.T, rec *statusRecorder, peerVIP, want string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if rec.lastReason(peerVIP) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("应报 %s，实际 %q（state=%s）",
		want, rec.lastReason(peerVIP), rec.snapshot(peerVIP).State)
}

// ---------- review 补充：RDY1 时序 / 字段超集 / 重复邀请 ----------

// TestPunchReadyDatagramTimingOnPunchSocket（review 问题 1）
//
//	P2SP-RDY1（「我已开始监听」通知）**走打洞那条 socket**，时序必须满足：
//	  - A 侧：在 `realm.Punch` **返回之后**发出（打洞期间绝不发）；
//	  - B 侧：在创建 QUIC transport（开始读同一 socket）**之前**收到 ——
//	    B 的 waitListening 用裸 ReadFrom，之后才把 socket 交给 QUIC。
//	（属于 BUG-B「同一 socket 不能有两个读者」约束的一部分。）
func TestPunchReadyDatagramTimingOnPunchSocket(t *testing.T) {
	c1, c2, rec1, rec2, cleanup := newLoopbackPair(t)
	defer cleanup()

	if _, err := c1.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}
	waitDirect(t, rec1, "192.168.30.12", 8*time.Second)
	waitDirect(t, rec2, "192.168.30.11", 8*time.Second)

	// ① A 侧：通知在打洞返回之后才发（rdySentSeen 置位 → notifyListening 的
	//    punchActive 断言没有拦住它，说明打洞确实已结束）；
	// ② B 侧：在**拨号之前**就收到了通知（rdyReceived）；
	// ③ 整轮没有出现「同一 socket 被并发读」（打洞与 QUIC 重叠）。
	if !rdySeenOf(c1, true) {
		t.Fatal("A 侧应在打洞返回之后发送监听就绪通知")
	}
	if !rdySeenOf(c2, false) {
		t.Fatal("B 侧应在拨号之前收到监听就绪通知（rdyReceived 未置位）")
	}
	if overlappingReads.Load() {
		t.Fatal("检测到 socket 被并发读取（打洞与 QUIC 重叠）")
	}
}

// rdySeenOf 查询该客户端是否出现过「打洞后发通知」(sent=true) / 「拨号前收到通知」(sent=false)
func rdySeenOf(c *Hysteria2Client, sent bool) bool {
	c.punchMu.Lock()
	mgr := c.punchMgr
	c.punchMu.Unlock()
	if mgr == nil {
		return false
	}
	if sent {
		return mgr.rdySentSeen.Load()
	}
	return mgr.rdyRecvSeen.Load()
}

// TestPunchIntentCarriesRegisterSuperset（review 问题 3，客户端侧）
//
//	punch-intent 必须是 register 的**超集**：服务端复用 signalReply，
//	而后者依赖 publicAddr / natType / metadata。这条测试直接检查客户端**实际发出**
//	的那条消息（由假信令服务端记录），把两侧的字段耦合钉死。
func TestPunchIntentCarriesRegisterSuperset(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	a := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	b := newSignalTestClientWithNAT("5.6.7.8:40002", string(NATFullCone))
	for _, c := range []*Hysteria2Client{a, b} {
		dialFakeSignal(t, c, srv)
		if err := c.ensureSignalStream(); err != nil {
			t.Fatalf("建流失败: %v", err)
		}
	}
	waitStreamCount(t, srv, 2)

	srv.setOnReg(func(idx int, msg signalMessage) {
		switch msg.Type {
		case signalMsgTypeRegister:
			_ = srv.writeTo(idx, signalMessage{
				Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true,
				PeerPublicAddr: "5.6.7.8:40002", PeerNATType: string(NATFullCone),
			})
		case signalMsgTypePunchIntent:
			// 不回 punch-peer：本测试只关心客户端发出的字段
			_ = srv.writeTo(idx, signalMessage{Type: signalMsgTypePeer, PeerOnline: true, PeerSignalReady: true})
		}
	})

	attachLoopbackManager(t, a, newStatusRecorder())
	if _, err := a.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}

	var intent *signalMessage
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && intent == nil {
		for _, m := range srv.allRegs() {
			if m.Type == signalMsgTypePunchIntent {
				mm := m
				intent = &mm
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if intent == nil {
		t.Fatal("没有捕获到 punch-intent")
	}

	// register 字段（signalReply 依赖这三项，缺一项服务端就会拒绝）
	if intent.PublicAddr == "" {
		t.Error("punch-intent 必须携带 publicAddr（signalReply 依赖）")
	}
	if !isValidNATTypeForTest(intent.NATType) {
		t.Errorf("punch-intent 必须携带合法 natType，实际 %q", intent.NATType)
	}
	if len(intent.Metadata) != 64 {
		t.Errorf("punch-intent 必须携带 32 字节 seed（64 hex），实际 %d 字符", len(intent.Metadata))
	}
	// 打洞字段
	if len(intent.AttemptID) != 16 {
		t.Errorf("attemptId 应为 16 hex，实际 %q", intent.AttemptID)
	}
	if intent.PunchAddr == "" {
		t.Error("punchAddr 不应为空")
	} else if _, ok := parsePunchAddr(intent.PunchAddr); !ok {
		t.Errorf("punchAddr 非法: %q", intent.PunchAddr)
	}
	if len(intent.DirectFingerprint) != 64 {
		t.Errorf("directFingerprint 应为 64 hex，实际 %d 字符", len(intent.DirectFingerprint))
	}
	if intent.WindowMs < punchWindowMin || intent.WindowMs > punchWindowMax {
		t.Errorf("windowMs 应在 [%d,%d]，实际 %d", punchWindowMin, punchWindowMax, intent.WindowMs)
	}
}

// isValidNATTypeForTest 与 nat.go 的白名单一致（客户端不引 admin 包）
func isValidNATTypeForTest(s string) bool {
	switch s {
	case "full-cone", "restricted-cone", "port-restricted", "symmetric", "unknown":
		return true
	}
	return false
}

// TestDuplicateInviteIgnored（review 问题 2 的客户端侧配套）
//
//	服务端在「重复 punch-intent」时会重推 invite；B 侧必须按 attemptId 去重，
//	否则同一次打洞会起两个会话（两条 socket、翻倍发包、重复占配额）。
func TestDuplicateInviteIgnored(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	b := newSignalTestClientWithNAT("5.6.7.8:40002", string(NATFullCone))
	dialFakeSignal(t, b, srv)
	if err := b.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)

	mgr := newPunchManager(b)
	mgr.tuning = fastTuning()
	mgr.windowDefault = 3000
	mgr.discoverPunchAddr = func(_ context.Context, sock net.PacketConn) ([]netip.AddrPort, error) {
		ua, ok := sock.LocalAddr().(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("非 UDP socket")
		}
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(ua.Port))}, nil
	}
	mgr.start()
	defer mgr.close()
	b.punchMu.Lock()
	b.punchMgr = mgr
	b.punchMu.Unlock()

	invite := signalMessage{
		Type: signalMsgTypePunchInvite, AttemptID: "0123456789abcdef",
		PeerVIP: "192.168.30.11", PunchAddr: "127.0.0.1:48099",
		Metadata: strings.Repeat("ab", 32), DirectFingerprint: strings.Repeat("a", 64), WindowMs: 3000,
	}
	mgr.onPush(invite)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mgr.mu.Lock()
		n := len(mgr.sessions)
		mgr.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mgr.mu.Lock()
	first := len(mgr.sessions)
	mgr.mu.Unlock()
	if first != 1 {
		t.Fatalf("第一条邀请应建立 1 个会话，实际 %d", first)
	}

	// 同 attemptId 再来一条 → 必须被忽略
	mgr.onPush(invite)
	time.Sleep(150 * time.Millisecond)
	mgr.mu.Lock()
	after := len(mgr.sessions)
	responders := mgr.responders
	mgr.mu.Unlock()
	if after > 1 {
		t.Fatalf("重复邀请不得新建会话，实际 %d 个", after)
	}
	if responders > 1 {
		t.Fatalf("重复邀请不得重复占用响应方配额，实际 %d", responders)
	}
}

// ---------- 假 PacketConn ----------

type fakePacketConn struct {
	mu     sync.Mutex
	queue  []fakePacket
	closed bool
	deadl  time.Time
	cond   *sync.Cond
}

type fakePacket struct {
	data []byte
	addr net.Addr
}

func newFakePacketConn() *fakePacketConn {
	f := &fakePacketConn{}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *fakePacketConn) push(data []byte, addr net.Addr) {
	f.mu.Lock()
	f.queue = append(f.queue, fakePacket{data: data, addr: addr})
	f.mu.Unlock()
	f.cond.Broadcast()
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for len(f.queue) == 0 {
		if f.closed {
			return 0, nil, net.ErrClosed
		}
		f.cond.Wait()
	}
	pkt := f.queue[0]
	f.queue = f.queue[1:]
	n := copy(p, pkt.data)
	return n, pkt.addr, nil
}

func (f *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (f *fakePacketConn) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.cond.Broadcast()
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000}
}

func (f *fakePacketConn) SetDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadl = t
	f.mu.Unlock()
	f.cond.Broadcast()
	return nil
}

func (f *fakePacketConn) SetReadDeadline(t time.Time) error  { return f.SetDeadline(t) }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error { return f.SetDeadline(t) }

// TestTrafficDrivenBlockedWhileSessionInFlight ⭐ ⑤ 的主语义（**选 A**）：
//
//	**同一个对端已有会话在跑**时，流量驱动的这次打洞**被挡回**（不走并列会话），
//	⇒ 用户本次继续走中继，**下一次**（占位会话结束后）受益。
//
// ⚠️ A3a（2026-09-28）**改写 + 迁入本文件**：原名 `TestTrafficDrivenStillWorksWhenPrePunchInFlight`
//
//	（在 `prepunch_test.go`，原位留指针注释），用**预打洞会话**占位。预打洞发起侧已整体删除
//	⇒ 占位者改为**对端发起的会话**（`P2PTriggerRemote`）。**被测主体不变**（`byPeer` 忙门），
//	只是不再依赖预打洞。⚠️ 这道门**只此一处**从 punchManager 侧覆盖
//	（`TestPathManagerTrafficAttemptBacksOffWhenPrePunchBusy` 走 `fakeHost` 注入同一文案，
//	测的是 pathManager 的反应，不是这道门本身）⇒ **因此改写而非删除**。
//	📎 原代码：`A2-干净点快照-2026-09-28\quic\prepunch_test.go:1108-1175`。
//
// 具体断言（这是「用户可见行为」的唯一落点）：
//   - `PunchWithTrigger(..., traffic)` 返回**含「已在向该对端发起打洞」的错误**
//     （不是静默成功、也不是 panic）；
//   - 该错误**不含** `errPunchCooldown` 哨兵 ⇒ `pathManager.attemptFor` 走的是
//     「短延迟重试」分支（`backoffBusy = 30s`，见 `setBackoffTransient`），
//     **不会**推进退避台阶、也不写用户可见的失败事件；
//   - 占位会话结束后 `byPeer` 释放 ⇒ 流量驱动立刻可以发起（「下次受益」）。
//
// ⚠️ 有牙：去掉 `PunchWithTrigger` 里的 `byPeer` 判断 ⇒ 第二次调用会「成功」并新建会话
//
//	（同一对端两个并列会话）⇒ 第一条断言红。
func TestTrafficDrivenBlockedWhileSessionInFlight(t *testing.T) {
	m := newBusyTestManager()
	const vip = "192.168.30.12"

	// ① 已有会话在跑（占住 `byPeer` 槽位）——A3a：占位者由「预打洞会话」改为「对端发起的会话」。
	// ⚠️ `newSession` **不接收 trigger**（签名为 id/peerVIP/role/windowMs/seed/peerFP/peerPunchAddr）
	//	⇒ `trigger` 的零值是空串，**必须显式覆盖**（生产的两条路径也都在 newSession 之后单独赋值）。
	pre := m.newSession("0123456789abcdef", vip, pathRoleInitiator,
		3000, "seed", "", netip.MustParseAddrPort("1.2.3.4:30001"))
	pre.trigger = P2PTriggerRemote
	m.mu.Lock()
	m.sessions[pre.id] = pre
	m.byPeer[vip] = pre
	m.mu.Unlock()
	pre.cancel()
	defer func() {
		m.mu.Lock()
		delete(m.sessions, pre.id)
		delete(m.byPeer, vip)
		m.mu.Unlock()
	}()

	// ② 流量驱动的本次打洞被挡回（选 A：不排队、不并列）
	_, err := m.PunchWithTrigger(vip, P2PTriggerTraffic)
	if err == nil {
		t.Fatal("已有会话在跑时，流量驱动的本次打洞必须被挡回（否则同一对端出现两个并列会话）")
	}
	if !strings.Contains(err.Error(), "已在向该对端发起打洞") {
		t.Fatalf("错误文案应是「已在向该对端发起打洞」（attemptFor 按它记日志），实际 %v", err)
	}
	if errors.Is(err, errPunchCooldown) {
		t.Fatal("这是「忙」不是「冷却」：**不得**带 errPunchCooldown 哨兵" +
			"（否则 pathManager 会误判成冷却期、跳过短延迟重试）")
	}

	// ③ 占位会话结束后 ⇒ 流量驱动立刻能发起（「下次受益」）
	m.mu.Lock()
	delete(m.sessions, pre.id)
	delete(m.byPeer, vip)
	m.mu.Unlock()
	if _, err := m.PunchWithTrigger(vip, P2PTriggerTraffic); err != nil {
		t.Fatalf("占位会话结束后流量驱动应能正常发起，实际 %v", err)
	}
	// 收尾：把刚发起的那个会话清掉（它会在后台跑，用例不等它）
	m.mu.Lock()
	for id, s := range m.sessions {
		if s.trigger == P2PTriggerTraffic {
			delete(m.sessions, id)
			delete(m.byPeer, s.peerVIP)
			// ⚠️ **锁内调 `cancel()` 安全的前提：`session.ctx` 上没有任何 `AfterFunc` 回调。**
			//	`cancel` 是结构体字段（`context.CancelFunc`，由 `newSession` 从
			//	`context.WithTimeout` 赋值）⇒ 只取消 context，**不取 `m.mu`**；
			//	但 `CancelFunc` 会**同步执行**注册在该 ctx 上的回调
			//	⇒ **若将来给 `session.ctx` 加 `AfterFunc`，回调内不得取 `m.mu`**（否则自死锁）。
			//	（全仓当前唯一 `AfterFunc` 在 `path.go:3237`，挂在 `conn.Context()` 上，与本 ctx 无关。）
			s.cancel()
		}
	}
	m.mu.Unlock()
}

// ---------- 其它小工具 ----------

// ensureSignalStreamForTest 在测试里建流（没有 ctrlConn 时返回错误，调用方自行 skip）
func (c *Hysteria2Client) ensureSignalStreamForTest() error {
	if c.ctrlConn == nil {
		return fmt.Errorf("测试客户端没有 ctrlConn")
	}
	return c.ensureSignalStream()
}

var _ = json.Marshal
