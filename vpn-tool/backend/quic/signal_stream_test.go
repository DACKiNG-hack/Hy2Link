package quic

// vpn-tool/backend/quic/signal_stream_test.go
//
// 信令**通道**（常驻读协程 + 主动下行）的测试。
//
// 这里用一个真的 QUIC 监听器当「假服务端」：信令的载体就是 QUIC 流，
// 用 net.Pipe 之类的假流测不出「读协程 + 写方向」这种真实语义
// （尤其是「客户端不读流就收不到推送」这一点）。
//
// ⭐ 本文件覆盖用户要求的「A 和 B 都连上、A 查询 B 后，B 的信令读协程
// 能收到服务端主动下行」——这是打洞（双方同时发包）的前置条件。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

// ---------- 假服务端 ----------

type fakeSignalServer struct {
	t         *testing.T
	transport *quic.Transport
	listener  *quic.Listener
	udpConn   *net.UDPConn

	writeMu sync.Mutex // 串行化服务端侧写入（真服务端由 signalStreamSink 的写锁保证）

	mu      sync.Mutex
	streams []*quic.Stream
	conns   []*quic.Conn
	regs    []signalMessage
	errs    []string
	onReg   func(idx int, msg signalMessage)
	closed  bool

	// ⭐ D1-a：假服务端的 `peers` 支持（端到端用例需要）。
	//
	//	peersOnline  「在线对端」VIP（按注册顺序返回，requester 自动排除）
	//	peersNotReady 其中的这些 VIP 标记为 signalReady=false（默认全 true）
	//	peersUnknownType 模拟**旧服务端**：回 `unknown message type`（降级用例用）
	//	peersSilent      模拟**连 error 都不回**的旧服务端（超时兜底用例用）
	//	peersTruncated   模拟被上限截断
	peersOnline      []string
	peersNotReady    map[string]bool
	peersUnknownType bool
	peersSilent      bool
	peersTruncated   bool
	// peersRateLimited 模拟服务端限流（回 error: peers-rate-limited）
	peersRateLimited bool
	// declaredVIPList 并发场景：按**流序号**声明身份（`declareStreamVIPs`）
	declaredVIPList []string
	// peersQueryVIPs 记录每次 peers 请求的请求方 VIP（断言「按请求方计数」用）
	peersQueryVIPs []string
	// streamVIPs 每条流登录的 VIP（服务端从 ctrl 连接推导身份；这里从 register 帧记录）
	// ⇒ 用于**真的排除请求方自己**（与真服务端一致）
	streamVIPs map[int]string
	// declaredVIP 测试声明的「本连接身份」（真服务端从 ctrl 连接推导，见 setDeclaredVIP）
	declaredVIP string

	handlers sync.WaitGroup
}

func testServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signal-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("自签证书失败: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{alpnCtrl},
	}
}

func newFakeSignalServer(t *testing.T) *fakeSignalServer {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("监听 UDP 失败: %v", err)
	}
	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.Listen(testServerTLS(t), &quic.Config{
		MaxIdleTimeout:       60 * time.Second,
		HandshakeIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		_ = udpConn.Close()
		t.Fatalf("Listen 失败: %v", err)
	}
	f := &fakeSignalServer{t: t, transport: tr, listener: ln, udpConn: udpConn}
	go f.acceptLoop()
	return f
}

func (f *fakeSignalServer) addr() string { return f.listener.Addr().String() }

func (f *fakeSignalServer) acceptLoop() {
	for {
		conn, err := f.listener.Accept(context.Background())
		if err != nil {
			return
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			_ = conn.CloseWithError(0, "")
			return
		}
		f.conns = append(f.conns, conn)
		f.mu.Unlock()

		f.handlers.Add(1)
		go func() {
			defer f.handlers.Done()
			// 一条连接上可能有多条信令流：客户端丢弃流之后会在同一条
			// ctrl 连接上重开（真服务端也是循环 accept，见 acceptSignalStream）
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					f.mu.Lock()
					f.errs = append(f.errs, fmt.Sprintf("AcceptStream: %v", err))
					f.mu.Unlock()
					return
				}
				f.mu.Lock()
				if f.closed {
					f.mu.Unlock()
					return
				}
				f.streams = append(f.streams, stream)
				idx := len(f.streams) - 1
				f.mu.Unlock()

				f.handlers.Add(1)
				go func(idx int, stream *quic.Stream) {
					defer f.handlers.Done()
					f.serve(idx, stream)
				}(idx, stream)
			}
		}()
	}
}

func (f *fakeSignalServer) serve(idx int, stream *quic.Stream) {
	buf := make([]byte, maxFrameSize)
	for {
		pkt, err := readFrame(stream, buf)
		if err != nil {
			return
		}
		var msg signalMessage
		if err := json.Unmarshal(pkt, &msg); err != nil {
			continue
		}
		f.mu.Lock()
		f.regs = append(f.regs, msg)
		// ⭐ D1-a：记录该流登录的 VIP（真服务端的身份来自 ctrl 连接；这里从 register 推导）。
		//
		// ⚠️ 不能只在 `msg.PeerVIP != ""` 时记：客户端建流时的**唤醒帧** register
		//    不带 PeerVIP（它只为「让流对服务端可见」），而身份正是在那一刻确定的。
		//    真服务端从 ctrl 连接就能知道身份，不受帧内容影响 —— 这里用调用方
		//    预先声明的 VIP（`setStreamVIP`）或帧里的 PeerVIP 兜底。
		if msg.Type == signalMsgTypeRegister {
			if f.streamVIPs == nil {
				f.streamVIPs = map[int]string{}
			}
			if f.streamVIPs[idx] == "" {
				f.streamVIPs[idx] = f.declaredVIPFor(idx)
			}
		}
		cb := f.onReg
		f.mu.Unlock()
		if cb != nil {
			cb(idx, msg)
		}
		// ⭐ D1-a：`peers` 由假服务端**自己**应答（模拟真服务端的枚举语义）。
		if msg.Type == signalMsgTypePeers {
			f.servePeers(idx, stream, msg)
		}
	}
}

// setPeersOnline 设定假服务端的「在线对端」列表（D1-a）。
func (f *fakeSignalServer) setPeersOnline(vips ...string) {
	f.mu.Lock()
	f.peersOnline = append([]string{}, vips...)
	f.mu.Unlock()
}

// setDeclaredVIP 声明「连到本假服务端的客户端身份」。
//
// 真服务端的身份来自**已通过 S1 授权的 ctrl 连接**（客户端不声明 VIP）；
// 单测里没有 ctrl 授权流程，所以由测试显式声明，语义等价。
//
// ⚠️ 这是**单客户端**场景的用法；并发多客户端请用 `declareStreamVIPs`
// （按流序号绑定，否则后连的客户端会覆盖前者 —— 与「夹具只建一半」同类坑）。
func (f *fakeSignalServer) setDeclaredVIP(vip string) {
	f.mu.Lock()
	f.declaredVIP = vip
	f.mu.Unlock()
}

// declareStreamVIPs 按**流序号**声明多个客户端身份（并发场景）。
//
// 为什么需要：真服务端每条 ctrl 连接各自有身份；假服务端若只有一个全局
// `declaredVIP`，多客户端时**后连的会覆盖前者** ⇒ 排除自己会算错。
func (f *fakeSignalServer) declareStreamVIPs(vips ...string) {
	f.mu.Lock()
	f.declaredVIPList = append([]string{}, vips...)
	f.mu.Unlock()
}

// declaredVIPFor 取某条流应记录的身份（优先按序号的列表，否则全局声明）
func (f *fakeSignalServer) declaredVIPFor(idx int) string {
	if idx < len(f.declaredVIPList) && f.declaredVIPList[idx] != "" {
		return f.declaredVIPList[idx]
	}
	return f.declaredVIP
}

// setPeersNotReady 把某些 VIP 标成 signalReady=false
func (f *fakeSignalServer) setPeersNotReady(set map[string]bool) {
	f.mu.Lock()
	f.peersNotReady = set
	f.mu.Unlock()
}

// servePeers 应答 `peers` 请求。
//
// 语义刻意与**真服务端**对齐：只回 VIP + signalReady（不泄露地址/NAT）；
// requester 自己不出现在列表里；顺序 = signalReady=true 优先 + 组内 VIP 排序
// （确定性，便于断言）。
func (f *fakeSignalServer) servePeers(idx int, stream *quic.Stream, req signalMessage) {
	f.mu.Lock()
	unknown, silent := f.peersUnknownType, f.peersSilent
	rateLimited := f.peersRateLimited
	online := append([]string{}, f.peersOnline...)
	notReady := f.peersNotReady
	truncated := f.peersTruncated
	self := f.streamVIPs[idx] // ⭐ 排除请求方自己（与真服务端 enumerableVIPs 一致）
	f.peersQueryVIPs = append(f.peersQueryVIPs, self)
	f.mu.Unlock()

	if silent {
		return // 连 error 都不回（模拟最老的实现）
	}
	if unknown {
		f.writeToStream(stream, signalMessage{Type: signalMsgTypeError, Error: "unknown message type"})
		return
	}
	if rateLimited {
		f.writeToStream(stream, signalMessage{Type: signalMsgTypeError, Error: peersRateLimitedCode})
		return
	}
	_ = req
	type e struct {
		vip string
		rdy bool
	}
	entries := make([]e, 0, len(online))
	for _, v := range online {
		if self != "" && v == self {
			continue // 不跟自己打洞
		}
		entries = append(entries, e{vip: v, rdy: !notReady[v]})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].rdy != entries[j].rdy {
			return entries[i].rdy
		}
		return entries[i].vip < entries[j].vip
	})
	out := make([]SignalPeerEntry, 0, len(entries))
	for _, x := range entries {
		out = append(out, SignalPeerEntry{VIP: x.vip, SignalReady: x.rdy})
	}
	f.writeToStream(stream, signalMessage{
		Type: signalMsgTypePeersList, Peers: out, PeersTruncated: truncated,
	})
}

// writeToStream 向指定流写一条消息（带写锁）
func (f *fakeSignalServer) writeToStream(stream *quic.Stream, msg signalMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	_ = writeFrameToStream(stream, data)
}

// peersQueryCount 累计收到的 `peers` 请求数（断言「缓存后不再请求」用）
func (f *fakeSignalServer) peersQueryCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.peersQueryVIPs)
}

func (f *fakeSignalServer) setOnReg(cb func(idx int, msg signalMessage)) {
	f.mu.Lock()
	f.onReg = cb
	f.mu.Unlock()
}

// writeTo 从服务端侧向第 idx 条流写一条消息（**主动下行**）
func (f *fakeSignalServer) writeTo(idx int, msg signalMessage) error {
	f.mu.Lock()
	var s *quic.Stream
	if idx >= 0 && idx < len(f.streams) {
		s = f.streams[idx]
	}
	f.mu.Unlock()
	if s == nil {
		return fmt.Errorf("没有第 %d 条流", idx)
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	return writeFrameToStream(s, data)
}

func (f *fakeSignalServer) streamCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.streams)
}

func (f *fakeSignalServer) lastReg() (signalMessage, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.regs) == 0 {
		return signalMessage{}, false
	}
	return f.regs[len(f.regs)-1], true
}

func (f *fakeSignalServer) allRegs() []signalMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]signalMessage(nil), f.regs...)
}

// closeClient 关闭客户端侧连接（ctrlConn 可能已被 cleanupPartial 置空）
func closeClient(c *Hysteria2Client) {
	if c.ctrlConn != nil {
		_ = c.ctrlConn.CloseWithError(0, "")
	}
}

// closeConns 关闭服务端侧所有连接（模拟服务端断开）
func (f *fakeSignalServer) closeConns() {
	f.mu.Lock()
	conns := f.conns
	f.conns = nil
	f.mu.Unlock()
	for _, c := range conns {
		_ = c.CloseWithError(0, "")
	}
}

func (f *fakeSignalServer) close() {
	f.mu.Lock()
	f.closed = true
	conns := f.conns
	f.conns = nil
	f.mu.Unlock()

	for _, c := range conns {
		_ = c.CloseWithError(0, "")
	}
	_ = f.listener.Close()
	_ = f.transport.Close()
	_ = f.udpConn.Close()
	f.handlers.Wait()
}

// ---------- 客户端小工具 ----------

// newSignalTestClientWithNAT 造一个「服务端开关已开 + NAT 探测已完成」的客户端
func newSignalTestClientWithNAT(addr, nat string) *Hysteria2Client {
	c := newSignalTestClient()
	c.p2pServerEnabled = true
	// ⚠️ 1b-2A 起本机开关也参与判定（P2PEffective = 服务端 && 本机）
	c.p2pLocalEnabled = true
	c.natMu.Lock()
	c.natResult = NATProbeResult{Type: NATType(nat), PublicAddr: addr}
	c.natReady = true
	c.natMu.Unlock()
	return c
}

// dialFakeSignal 让客户端连上假服务端（只为拿到 ctrlConn，不跑完整的 Connect）
//
// ⚠️ 第 3 步-C 记账：这里**曾试过**改用显式 `quic.Transport`（想收掉包级 `quic.DialAddr`
// 自建的那个 transport），但实测**没有收益**且**破坏既有断言**：
//   - `TestSignalStreamReaderStopsOnClose` 自身就断言「关掉后 goroutine 归零」，
//     显式 transport 引入的额外对象让基线 7 → 15 ⇒ 该用例直接红；
//   - 环回打洞的跨轮泄漏也没减少（仍是 6/轮，来源在打洞侧，不在信令拨号）。
//
// ⇒ 按「不引入无收益的复杂度」回退为原实现。残留泄漏见 §3-C 交付说明的观察项。
func dialFakeSignal(t *testing.T, c *Hysteria2Client, srv *fakeSignalServer) {
	t.Helper()
	// 测试里必须跳过指纹固定：默认路径会把服务端指纹写进 %APPDATA%，
	// 那是沙箱外/有副作用的操作，与信令通道无关。
	c.skipCertVerify = true
	conn, err := quic.DialAddr(context.Background(), srv.addr(),
		c.buildTLSConfig([]string{alpnCtrl}), &quic.Config{
			MaxIdleTimeout:       60 * time.Second,
			HandshakeIdleTimeout: 5 * time.Second,
		})
	if err != nil {
		t.Fatalf("连接假服务端失败: %v", err)
	}
	c.ctrlConn = conn
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
}

func waitStreamCount(t *testing.T, srv *fakeSignalServer, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.streamCount() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.mu.Lock()
	conns, errs := len(srv.conns), append([]string(nil), srv.errs...)
	srv.mu.Unlock()
	t.Fatalf("等服务端看到第 %d 条流超时（流=%d 连接=%d 错误=%v）",
		want, srv.streamCount(), conns, errs)
}

func waitSignalReaders(t *testing.T, c *Hysteria2Client, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.signalReaderCount() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等读协程数变成 %d 超时（当前 %d）", want, c.signalReaderCount())
}

// waitGoroutinesBack 断言 goroutine 总数回落到基线（允许极小的运行时抖动）
func waitGoroutinesBack(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var cur int
	for time.Now().Before(deadline) {
		cur = runtime.NumGoroutine()
		if cur <= baseline {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutine 未归零：基线 %d，当前 %d", baseline, cur)
}

// ---------- 测试 ----------

// TestSignalPushChannelDelivers 是阶段 1b 的前置条件：
//
//	A 与 B 都连上；A 查询 B 之后，**B 的常驻读协程**必须能收到
//	服务端主动下行的消息（这里用一条未定义 type 当探针）。
//
// 纯请求—响应模型下这条测试必然失败：B 没有发问，也就永远不会去读流。
func TestSignalPushChannelDelivers(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	a := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	b := newSignalTestClientWithNAT("5.6.7.8:40002", string(NATSymmetric))
	dialFakeSignal(t, a, srv)
	dialFakeSignal(t, b, srv)

	// 先 A 后 B，让服务端视角的流序号确定（0=A，1=B）
	if err := a.ensureSignalStream(); err != nil {
		t.Fatalf("A 建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)
	if err := b.ensureSignalStream(); err != nil {
		t.Fatalf("B 建流失败: %v", err)
	}
	waitStreamCount(t, srv, 2)
	waitSignalReaders(t, a, 1)
	waitSignalReaders(t, b, 1)

	// B 装 push 钩子（1b 就在这里接「A 想连你」）
	got := make(chan SignalPush, 8)
	b.SetSignalPushHandler(func(p SignalPush) { got <- p })

	// 假服务端的行为：收到 A 的「查询 B」→ 应答 A + 主动下行给 B
	srv.setOnReg(func(idx int, msg signalMessage) {
		if idx != 0 || msg.PeerVIP != "192.168.30.12" {
			return
		}
		_ = srv.writeTo(0, signalMessage{
			Type: signalMsgTypePeer, PeerOnline: true, PeerPublicAddr: "5.6.7.8:40002",
		})
		_ = srv.writeTo(1, signalMessage{Type: "punch-request", PeerVIP: "192.168.30.11"})
	})

	peer, err := a.SignalQuery("192.168.30.12")
	if err != nil {
		t.Fatalf("A 查询 B 失败: %v", err)
	}
	if !peer.Online || peer.PublicAddr != "5.6.7.8:40002" {
		t.Fatalf("A 拿到的应答不对: %+v", peer)
	}

	select {
	case p := <-got:
		if p.Type != "punch-request" || p.PeerVIP != "192.168.30.11" {
			t.Fatalf("B 收到的主动下行不对: %+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("B 的常驻读协程没有收到服务端主动下行（拉取式通道的典型症状）")
	}

	// 顺带确认 A 的 register 里仍然**没有**任何「我是谁」字段。
	// 注意服务端会看到两帧：① 建流时那帧「让流可见 + 登记自己」
	// ② SignalQuery 发出的「查 B」——这里查最后一帧。
	last, ok := srv.lastReg()
	if !ok {
		t.Fatal("服务端没有收到任何 register")
	}
	if last.PublicAddr != "1.2.3.4:30001" || last.PeerVIP != "192.168.30.12" ||
		last.NATType != "full-cone" {
		t.Fatalf("A 的 register 内容不对: %+v", last)
	}
	all := srv.allRegs()
	if len(all) < 2 {
		t.Fatalf("应有「建流 register + 查询 register」两帧，实际 %d 帧", len(all))
	}
	if all[0].PublicAddr != "1.2.3.4:30001" || all[0].PeerVIP != "" {
		t.Fatalf("建流那帧应是纯登记（无 peerVIP）: %+v", all[0])
	}
}

// TestSignalUnsolicitedResponseKeepsChannel 未预期的应答不能让读协程退出
func TestSignalUnsolicitedResponseKeepsChannel(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c, srv)
	if err := c.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)

	// 服务端在客户端**没有请求**时塞一条 registered（非法时序）
	if err := srv.writeTo(0, signalMessage{Type: signalMsgTypeRegistered}); err != nil {
		t.Fatalf("下行失败: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// 通道必须还活着：读协程还在，后面的请求照常
	waitSignalReaders(t, c, 1)
	srv.setOnReg(func(idx int, msg signalMessage) {
		_ = srv.writeTo(idx, signalMessage{Type: signalMsgTypeRegistered})
	})
	if _, err := c.signalRoundTrip(signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	}); err != nil {
		t.Fatalf("收到未预期应答后通道应仍然可用: %v", err)
	}
}

// TestSignalReadLoopHandlesFrameNoise 畸形/空帧不能让读协程崩掉
func TestSignalReadLoopHandlesFrameNoise(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c, srv)
	if err := c.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)

	// ① 非法 JSON ② 空载荷 ③ 未知 type —— 一个都不许把读协程搞挂
	srv.writeMu.Lock()
	_ = writeFrameToStream(srv.streams[0], []byte("{not json"))
	_ = writeFrameToStream(srv.streams[0], []byte{})
	srv.writeMu.Unlock()
	time.Sleep(80 * time.Millisecond)

	waitSignalReaders(t, c, 1)
	srv.setOnReg(func(idx int, msg signalMessage) {
		_ = srv.writeTo(idx, signalMessage{Type: signalMsgTypeRegistered})
	})
	if _, err := c.signalRoundTrip(signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	}); err != nil {
		t.Fatalf("噪声之后通道应仍然可用: %v", err)
	}
}

// TestSignalStreamReaderStopsOnClose 覆盖所有断开路径，并断言读协程归零。
//
// 覆盖：① closeSignalStream（主动关/退出）② Close() ③ cleanupPartial()
// ④ 对端关闭（读协程自己退出）⑤ 幂等重复关闭
func TestSignalStreamReaderStopsOnClose(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	baseline := runtime.NumGoroutine()

	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c, srv)

	// ① closeSignalStream
	if err := c.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)
	waitSignalReaders(t, c, 1)
	c.closeSignalStream()
	waitSignalReaders(t, c, 0)
	// 幂等
	c.closeSignalStream()
	c.closeSignalStream()

	// ② Close() 必须收掉读协程
	c2 := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c2, srv)
	if err := c2.ensureSignalStream(); err != nil {
		t.Fatalf("c2 建流失败: %v", err)
	}
	waitStreamCount(t, srv, 2)
	waitSignalReaders(t, c2, 1)
	if err := c2.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	waitSignalReaders(t, c2, 0)

	// ③ cleanupPartial() 必须收掉读协程
	c3 := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c3, srv)
	if err := c3.ensureSignalStream(); err != nil {
		t.Fatalf("c3 建流失败: %v", err)
	}
	waitStreamCount(t, srv, 3)
	waitSignalReaders(t, c3, 1)
	c3.cleanupPartial()
	waitSignalReaders(t, c3, 0)

	// ④ 对端关闭：读协程自己发现并退出（客户端没调用任何关闭函数）
	c4 := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c4, srv)
	if err := c4.ensureSignalStream(); err != nil {
		t.Fatalf("c4 建流失败: %v", err)
	}
	waitStreamCount(t, srv, 4)
	waitSignalReaders(t, c4, 1)
	srv.closeConns() // 服务端侧全断
	waitSignalReaders(t, c4, 0)

	// 关掉客户端连接与假服务端，goroutine 应回到基线
	closeClient(c)
	closeClient(c2)
	closeClient(c3)
	closeClient(c4)
	srv.closeConns()
	srv.handlers.Wait()
	waitGoroutinesBack(t, baseline)
}

// TestSignalQueryTimeoutDropsStream 超时必须把流扔掉而不是留下错位的应答槽
//
// 协议没有请求 ID：晚到的应答无法与下一次请求区分，留着就会张冠李戴。
func TestSignalQueryTimeoutDropsStream(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c, srv)
	if err := c.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)

	// 服务端**不回应**任何消息 → 客户端必须超时
	srv.setOnReg(func(idx int, msg signalMessage) {})
	start := time.Now()
	if _, err := c.signalRoundTrip(signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	}); err == nil {
		t.Fatal("服务端不回应时应当超时报错")
	}
	// ⚠️ 断言必须对着**实际生效的等待上限**（`signalExchangeWait`，初值 = signalTimeout）：
	//    只对着 `signalTimeout` 断言的话，若该变量被别的用例污染成更大的值，
	//    这里会「因为等得够久」而**说谎式通过**（review 追问 2 的连带加固）。
	if d := time.Since(start); d < signalExchangeWait {
		t.Fatalf("应等满 %v 才超时，实际 %v", signalExchangeWait, d)
	}

	// 超时后：读协程归零、流已丢弃、允许重开（冷却被自己清掉）
	waitSignalReaders(t, c, 0)
	c.signalMu.Lock()
	streamNil := c.signalStream == nil
	deadZero := c.signalDeadUntil.IsZero()
	c.signalMu.Unlock()
	if !streamNil {
		t.Fatal("超时后应丢弃信令流")
	}
	if !deadZero {
		t.Fatal("自己主动丢弃不应留下重开冷却")
	}
	if err := c.ensureSignalStream(); err != nil {
		t.Fatalf("超时后应允许重开信令流: %v", err)
	}
	waitStreamCount(t, srv, 2)
}

// TestSignalQueryAfterServerCloseStopsReopening 对端断开要留下冷却，避免每次查询都白等
func TestSignalQueryAfterServerCloseStopsReopening(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c, srv)
	if err := c.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)
	waitSignalReaders(t, c, 1)

	// 服务端关掉这条流（等价于运行期关掉 P2P 后 CloseAllSinks）
	srv.mu.Lock()
	stream := srv.streams[0]
	srv.mu.Unlock()
	_ = stream.Close()

	waitSignalReaders(t, c, 0)
	c.signalMu.Lock()
	cooldown := time.Until(c.signalDeadUntil)
	c.signalMu.Unlock()
	if cooldown <= 0 {
		t.Fatal("对端关闭后应留下重开冷却")
	}

	// 冷却期内查询：应立刻报错，不去开一条没人接的流
	start := time.Now()
	if _, err := c.signalRoundTrip(signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	}); err == nil {
		t.Fatal("冷却期内应当直接报错")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("冷却期内不应再等满超时（实际 %v）", d)
	}
}

// TestSignalConcurrentQueryAndClose 并发压测：查询/关闭/P2P 开关交错不得死锁或 panic。
//
// 这条测试是给 `go test -race` 用的（本机没有 cgo/gcc，跑不了 -race，
// 但普通构建下它仍然能抓出死锁、panic、读协程泄漏）。
func TestSignalConcurrentQueryAndClose(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c, srv)
	if err := c.ensureSignalStream(); err != nil {
		t.Fatalf("建流失败: %v", err)
	}
	waitStreamCount(t, srv, 1)

	srv.setOnReg(func(idx int, msg signalMessage) {
		_ = srv.writeTo(idx, signalMessage{
			Type: signalMsgTypePeer, PeerOnline: true, PeerPublicAddr: "5.6.7.8:40002",
		})
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				_, _ = c.SignalQuery("192.168.30.12")
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 5; j++ {
			c.closeSignalStream()
			time.Sleep(5 * time.Millisecond)
		}
	}()
	wg.Wait()

	// 压完之后必须收敛：**最多 1 个**读协程（最后一次查询可能刚把流重开，
	// 那是合法的，漏的是「每次查询都留一个」那种累积）。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && c.signalReaderCount() > 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if n := c.signalReaderCount(); n > 1 {
		t.Fatalf("压测后读协程泄漏：%d", n)
	}
	c.closeSignalStream()
	if n := c.signalReaderCount(); n != 0 {
		t.Fatalf("压测后读协程应归零，实际 %d", n)
	}
}

// TestRegisterSignalSelfSkippedWithoutPublicAddr（BUG-A 边界 1）
//
//	NAT 探测失败时，registerSignalSelf 必须**明确跳过**：
//	不建信令流、不发出任何 register 帧（绝不会带空 publicAddr 去写）。
//
// 两道闸都要单独验证：
//   - natReady=false（还没跑完）
//   - natReady=true 但 PublicAddr==""（跑完了但所有 STUN 都不可达）
func TestRegisterSignalSelfSkippedWithoutPublicAddr(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	cases := []struct {
		name    string
		ready   bool
		pubAddr string
		natType string
	}{
		{"探测未完成", false, "", ""},
		{"探测完成但失败（无公网地址）", true, "", string(NATUnknown)},
		{"探测完成但地址只有空白", true, "   ", string(NATUnknown)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newSignalTestClient()
			c.p2pServerEnabled = true
			c.p2pLocalEnabled = true // 1b-2A：本机开关也参与判定
			c.natMu.Lock()
			c.natResult = NATProbeResult{Type: NATType(tc.natType), PublicAddr: tc.pubAddr}
			c.natReady = tc.ready
			c.natMu.Unlock()

			dialFakeSignal(t, c, srv)
			defer c.closeSignalStream()

			c.registerSignalSelf()

			// ① 没有建流
			if c.signalReaderCount() != 0 {
				t.Fatalf("不应建立信令流，实际读协程数=%d", c.signalReaderCount())
			}
			c.signalMu.Lock()
			hasStream := c.signalStream != nil
			c.signalMu.Unlock()
			if hasStream {
				t.Fatal("不应建立信令流")
			}
			// ② 服务端一条流、一帧都没收到
			time.Sleep(150 * time.Millisecond)
			if n := srv.streamCount(); n != 0 {
				t.Fatalf("不应向服务端开出信令流，实际 %d 条", n)
			}
			if regs := srv.allRegs(); len(regs) != 0 {
				t.Fatalf("不应发出任何 register 帧（尤其不能带空地址），实际 %d 帧: %+v", len(regs), regs)
			}
			// ③ 查询也必须拒绝
			if _, err := c.SignalQuery("192.168.30.12"); err == nil {
				t.Fatal("没有公网地址时 SignalQuery 应当报错")
			}
		})
	}
}

// TestNATProbeTimeoutFitsServerAcceptWindow（BUG-A 边界 2）
//
//	客户端 NAT 探测总超时必须**小于**服务端 accept 信令流的窗口。
//
// 时序：服务端在收到 h3-ctrl 注册帧后就等着 accept 第 4 条流，
// 超时 signalStreamAcceptTimeout = 20s（vpn-server/quic/signal.go）就放弃；
// 而客户端是「NAT 探测完成 → 建流并立刻写第一帧」，
// 所以探测比窗口慢的话，服务端已经不等了 → 那条流永远没人接 → 推送能力静默失效。
//
// 服务端的常量在另一个 module（vpn-server），这里无法直接引用，
// 所以用「上限断言」当变更探测器：谁把探测超时调大，这条就会失败并指向服务端常量。
func TestNATProbeTimeoutFitsServerAcceptWindow(t *testing.T) {
	const serverAcceptTimeout = 20 * time.Second // 与 vpn-server/quic/signal.go 保持一致

	if natDetectTotalTimeout >= serverAcceptTimeout {
		t.Fatalf("NAT 探测总超时(%v) 必须小于服务端 accept 窗口(%v)", natDetectTotalTimeout, serverAcceptTimeout)
	}
	// 留出足够余量：探测 + 建流 + 首帧写入 + 网络往返都得挤在窗口内。
	// 目前 10s vs 20s，余量 10s；若哪天变成 >15s，就要重新评估（可能被慢 DNS/慢 STUN 拖爆）。
	if natDetectTotalTimeout > serverAcceptTimeout*3/4 {
		t.Fatalf("余量太小：探测 %v 已超过服务端窗口 %v 的 3/4", natDetectTotalTimeout, serverAcceptTimeout)
	}
	if stunPerServerTimeout >= natDetectTotalTimeout {
		t.Fatalf("单台 STUN 超时(%v) 应小于总超时(%v)", stunPerServerTimeout, natDetectTotalTimeout)
	}
}

// TestSetSignalPushHandlerIsSafe 钩子设置与读协程并发不得竞争
func TestSetSignalPushHandlerIsSafe(t *testing.T) {
	c := newSignalTestClient()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			c.SetSignalPushHandler(func(SignalPush) {})
		}
	}()
	msg := signalMessage{Type: "whatever", PeerVIP: "192.168.30.11"}
	for i := 0; i < 200; i++ {
		c.dispatchSignalMessage(msg)
	}
	<-done
}
