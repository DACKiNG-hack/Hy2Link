package quic

// vpn-server/quic/signal_stream_test.go
//
// 服务端侧信令**通道**测试：下行通道（VIP → 信令流）的挂载/注销，
// 以及「服务端主动推送」这条打洞必需的能力。
//
// 这里用一个真的 QUIC 监听器 + 原始客户端，走的是**真正的**
// signalStreamSink（写锁 + 分帧）与 serveSignalStream（应答 + 推送并发写），
// 而不是假 sink —— 推送写路径必须被真的跑一遍。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"

	"vpn-server/admin"
)

// ---------- 真 QUIC 监听器 ----------

func signalTestTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signal-server-test"},
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
		NextProtos:   []string{alpnCtrlTest},
	}
}

// alpnCtrlTest 必须与 manager 里的 alpnCtrl（"h3-ctrl"）一致；
// 那个常量在 manager 包，quic 包测试里不能引用，所以在这里复写一份。
const alpnCtrlTest = "h3-ctrl"

type signalTestListener struct {
	transport *quic.Transport
	listener  *quic.Listener
	udpConn   *net.UDPConn
}

func newSignalTestListener(t *testing.T) *signalTestListener {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("监听 UDP 失败: %v", err)
	}
	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.Listen(signalTestTLS(t), &quic.Config{
		MaxIdleTimeout:       60 * time.Second,
		HandshakeIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		_ = udpConn.Close()
		t.Fatalf("Listen 失败: %v", err)
	}
	return &signalTestListener{transport: tr, listener: ln, udpConn: udpConn}
}

func (l *signalTestListener) close() {
	_ = l.listener.Close()
	_ = l.transport.Close()
	_ = l.udpConn.Close()
}

// dialSignalClient 用原始 QUIC 客户端连上监听器并开一条流（模拟 h3-ctrl 的第 4 条流）
func dialSignalClient(t *testing.T, l *signalTestListener) (*quic.Conn, *quic.Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, l.listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, // 测试自签证书
		NextProtos:         []string{alpnCtrlTest},
	}, &quic.Config{MaxIdleTimeout: 60 * time.Second, HandshakeIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Dial 失败: %v", err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		t.Fatalf("OpenStreamSync 失败: %v", err)
	}
	return conn, stream
}

// sendSignalMsg 客户端侧写一帧（并保证流对服务端可见）
func sendSignalMsg(t *testing.T, stream *quic.Stream, msg signalMessage) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := writeFrameToStream(stream, data); err != nil {
		t.Fatalf("写入信令失败: %v", err)
	}
}

// recvSignalMsg 客户端侧读一帧（带超时，避免测试挂死）
func recvSignalMsg(t *testing.T, stream *quic.Stream, timeout time.Duration) signalMessage {
	t.Helper()
	_ = stream.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, maxFrameSize)
	pkt, err := readFrame(stream, buf)
	if err != nil {
		t.Fatalf("读取信令失败: %v", err)
	}
	var msg signalMessage
	if err := json.Unmarshal(pkt, &msg); err != nil {
		t.Fatalf("解析信令失败: %v (raw=%s)", err, pkt)
	}
	_ = stream.SetReadDeadline(time.Time{})
	return msg
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待「%s」超时", what)
}

// TestServeSignalStreamAttachPushDetach 服务端侧完整走一遍：
//
//	挂载下行通道 → 应答 register → **主动推送** → 客户端断开 → 注销
func TestServeSignalStreamAttachPushDetach(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")

	l := newSignalTestListener(t)
	defer l.close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		srv.serveSignalStream(conn, alice, stream, reg)
	}()

	conn, stream := dialSignalClient(t, l)
	defer conn.CloseWithError(0, "")

	// ① 客户端第一帧（真实客户端开完流立刻写：让流对服务端可见 + 登记自己）
	sendSignalMsg(t, stream, signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	})
	if resp := recvSignalMsg(t, stream, 3*time.Second); resp.Type != signalMsgTypeRegistered {
		t.Fatalf("期望 registered，实际 %+v", resp)
	}

	// ② 下行通道必须已经挂在这个 VIP 上
	waitFor(t, "挂载下行通道", func() bool { return reg.HasSink("192.168.30.11") })

	// ③ ⭐ 服务端**主动**推送（1b 的「A 想连你」）
	if err := srv.PushSignal("192.168.30.11", signalMessage{
		Type: "punch-request", PeerVIP: "192.168.30.12",
	}); err != nil {
		t.Fatalf("主动推送失败: %v", err)
	}
	push := recvSignalMsg(t, stream, 3*time.Second)
	if push.Type != "punch-request" || push.PeerVIP != "192.168.30.12" {
		t.Fatalf("客户端收到的推送不对: %+v", push)
	}

	// ④ 推送与应答并发时写入不得交错（同一时刻打多个推送 + 一个查询）
	bob := registerStream(srv, "192.168.30.12", "bob")
	if err := reg.Update("192.168.30.12", "5.6.7.8:40002", "symmetric", ""); err != nil {
		t.Fatalf("登记 bob 失败: %v", err)
	}
	_ = bob
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			_ = srv.PushSignal("192.168.30.11", signalMessage{Type: "push", Metadata: "ab"})
		}
	}()
	sendSignalMsg(t, stream, signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
		PeerVIP: "192.168.30.12",
	})
	// 收到的每一帧都必须是完整可解析的 JSON（交错就会解析失败）
	sawPeer := false
	for i := 0; i < 21; i++ {
		msg := recvSignalMsg(t, stream, 5*time.Second)
		if msg.Type == signalMsgTypePeer {
			sawPeer = true
			if !msg.PeerOnline || msg.PeerPublicAddr != "5.6.7.8:40002" {
				t.Fatalf("peer 应答不对: %+v", msg)
			}
		} else if msg.Type != "push" {
			t.Fatalf("收到意料之外的消息: %+v", msg)
		}
	}
	<-done
	if !sawPeer {
		t.Fatal("并发推送下没有收到 peer 应答")
	}

	// ⑤ 客户端断开 → 注销下行通道
	_ = stream.Close()
	_ = conn.CloseWithError(0, "")
	waitFor(t, "注销下行通道", func() bool { return !reg.HasSink("192.168.30.11") })
	if err := srv.PushSignal("192.168.30.11", signalMessage{Type: "push"}); err == nil {
		t.Fatal("注销之后推送应该报错")
	}
	<-served
}

// TestPushSignalFailClosed P2P 关闭 / 没有下行通道时必须报错而不是静默丢弃
func TestPushSignalFailClosed(t *testing.T) {
	srv, _ := newSignalTestServer(t, false)
	registerStream(srv, "192.168.30.11", "alice")
	if err := srv.PushSignal("192.168.30.11", signalMessage{Type: "push"}); err == nil {
		t.Fatal("P2P 关闭时推送应报错")
	}

	srvOn, _ := newSignalTestServer(t, true)
	registerStream(srvOn, "192.168.30.11", "alice")
	if err := srvOn.PushSignal("192.168.30.11", signalMessage{Type: "push"}); err == nil {
		t.Fatal("没有下行通道时推送应报错")
	}
}

// TestEnableP2PSignalDisableClosesSinks 运行期关掉 P2P：已建的下行通道必须立刻关闭
func TestEnableP2PSignalDisableClosesSinks(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	registerStream(srv, "192.168.30.11", "alice")

	fake := &fakeSink{}
	reg.AttachSink("192.168.30.11", fake)
	if !reg.HasSink("192.168.30.11") {
		t.Fatal("挂载失败")
	}

	// 关掉（保留同一个登记表实例，只把开关置 false）
	srv.EnableP2PSignal(false, reg)

	if !fake.closed.Load() {
		t.Fatal("关闭 P2P 时必须关闭已建立的下行通道")
	}
	if reg.HasSink("192.168.30.11") {
		t.Fatal("关闭 P2P 时下行通道必须被注销")
	}
	if srv.p2pOn() {
		t.Fatal("开关应为 false")
	}
	// 关掉之后连应答都要拒绝（fail-closed）
	alice := mkStream("192.168.30.11", "alice")
	if resp := srv.signalReply(alice, &signalMessage{
		PublicAddr: "1.2.3.4:1", NATType: "unknown",
	}); resp.Type != signalMsgTypeError || !strings.Contains(resp.Error, "disabled") {
		t.Fatalf("关闭后应答应为 signaling disabled，实际 %+v", resp)
	}
}

// TestSignalMessageJSONFieldNamesExact（服务端侧）锁定全部线上字段名。
//
// 服务端与客户端各有一份 signalMessage，靠字段名对齐；
// 任何一边改名/加字段都会在两边各自的测试里暴露。
//
// ⭐ 用反射做第一重锁：结构体字段数必须等于名单长度、每个字段的 json tag
// 都必须在名单里 —— 否则「新增一个带 omitempty 的字段」会悄无声息地漏过
// （只比较「我设了值的字段」是抓不到的）。
//
// ⭐ 1b-2B：新增 `relayRttMs`（中继 RTT 估计，随 peer 应答返回）→ 名单 15 → 16。
// ⭐ 1b-3（A1）：新增 `punchAddrs`（同 socket 的候选地址列表）→ 16 → 17。
// ⭐ D1-a：新增 `peers`（在线对端列表）+ `peersTruncated`（是否被上限截断）→ 17 → 19。
func TestSignalMessageJSONFieldNamesExact(t *testing.T) {
	want := []string{
		"type",
		"peerVIP", "publicAddr", "natType", "metadata",
		"attemptId", "punchAddr", "directFingerprint", "windowMs",
		"punchAddrs",
		"peerOnline", "peerPublicAddr", "peerNATType", "peerMetadata", "peerSignalReady",
		"relayRttMs",
		// ⭐ D1-a
		"peers", "peersTruncated",
		"error",
	}

	typ := reflect.TypeOf(signalMessage{})
	if typ.NumField() != len(want) {
		t.Fatalf("结构体字段数(%d) ≠ 锁死的线上字段数(%d)：加了字段就必须同步更新这份名单",
			typ.NumField(), len(want))
	}
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			t.Fatalf("字段 %s 缺少可用的 json tag", typ.Field(i).Name)
		}
		found := false
		for _, w := range want {
			if w == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("字段 %s 的线上名 %q 没有登记（新增字段必须登记）", typ.Field(i).Name, name)
		}
	}

	full := signalMessage{
		Type:              "t",
		PeerVIP:           "vip",
		PublicAddr:        "1.2.3.4:1",
		NATType:           "full-cone",
		Metadata:          "ab",
		AttemptID:         "0123456789abcdef",
		PunchAddr:         "198.51.100.7:40001",
		DirectFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		WindowMs:          10000,
		PunchAddrs:        []string{"198.51.100.7:40001", "198.51.100.7:40002"},
		PeerOnline:        true,
		PeerPublicAddr:    "5.6.7.8:2",
		PeerNATType:       "symmetric",
		PeerMetadata:      "cd",
		PeerSignalReady:   true,
		RelayRttMs:        25, // ⭐ 1b-2B
		// ⭐ D1-a
		Peers: []SignalPeerEntry{
			{VIP: "192.168.30.12", SignalReady: true},
			{VIP: "192.168.30.13"},
		},
		PeersTruncated: true,
		Error:          "boom",
	}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("字段数不对：got=%d want=%d\n实际 JSON=%s", len(got), len(want), raw)
	}
	for _, name := range want {
		if _, ok := got[name]; !ok {
			t.Fatalf("缺少线上字段 %q\n实际 JSON=%s", name, raw)
		}
	}
	wantJSON := `{"type":"t","peerVIP":"vip","publicAddr":"1.2.3.4:1","natType":"full-cone",` +
		`"metadata":"ab","attemptId":"0123456789abcdef","punchAddr":"198.51.100.7:40001",` +
		`"directFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",` +
		`"windowMs":10000,"punchAddrs":["198.51.100.7:40001","198.51.100.7:40002"],` +
		`"peerOnline":true,"peerPublicAddr":"5.6.7.8:2",` +
		`"peerNATType":"symmetric","peerMetadata":"cd","peerSignalReady":true,"relayRttMs":25,` +
		`"peers":[{"vip":"192.168.30.12","signalReady":true},{"vip":"192.168.30.13"}],` +
		`"peersTruncated":true,"error":"boom"}`
	if string(raw) != wantJSON {
		t.Fatalf("字段顺序/名字变了：\n got=%s\nwant=%s", raw, wantJSON)
	}
}

// TestPeerSignalReadyReflectsSink（协议约束 2 的服务端侧锁：定稿选 B）
//
//	peerOnline      = 1a 原语义：数据面在线 **且** 信令表里有登记（查得到地址）
//	peerSignalReady = 服务端能主动推给它（sink 存在）
//
// 三种可区分的组合都要能分出来 —— 这正是选 B 而不是改 peerOnline 含义的原因。
func TestPeerSignalReadyReflectsSink(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")
	bob := registerStream(srv, "192.168.30.12", "bob")
	_ = bob

	query := func(peerVIP string) signalMessage {
		return srv.signalReply(alice, &signalMessage{
			Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
			PeerVIP: peerVIP,
		})
	}

	// ① 对端数据面不在线 → online=false，signalReady=false
	if r := query("192.168.30.199"); r.PeerOnline || r.PeerSignalReady {
		t.Fatalf("离线对端应为 online=false signalReady=false，实际 %+v", r)
	}

	// ② 对端数据面在线，但信令表里还没登记（拿不到地址）
	//    → online=false（1a 语义就是「数据面在线**且**有登记」），signalReady=false
	if r := query("192.168.30.12"); r.PeerOnline || r.PeerSignalReady {
		t.Fatalf("只有数据面在线、没有登记时应为 online=false signalReady=false，实际 %+v", r)
	}

	// ③ 有登记（能查到地址），但信令流没建立 → online=true，signalReady=false
	if err := reg.Update("192.168.30.12", "5.6.7.8:40002", "symmetric", ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if r := query("192.168.30.12"); !r.PeerOnline || r.PeerSignalReady {
		t.Fatalf("有地址但未就绪应为 online=true signalReady=false，实际 %+v", r)
	}

	// ④ 挂上下行通道 → 两个都为 true（1b 要求的「地址 + 推得过去」齐了）
	sink := &fakeSink{}
	reg.AttachSink("192.168.30.12", sink)
	r := query("192.168.30.12")
	if !r.PeerOnline || !r.PeerSignalReady {
		t.Fatalf("就绪后应为 online=true signalReady=true，实际 %+v", r)
	}
	// ⭐ 结构性推论：sink 存在 ⟹ 数据面在线（信令流挂在 ctrl 面上，
	//    而 ctrl 面必须等数据面注册完成才会关联）。这里断言方向性，
	//    免得将来有人把 peerOnline 改成「只看数据面」而悄悄破坏它。
	if r.PeerSignalReady && !r.PeerOnline {
		t.Fatal("signalReady=true 时 online 必须也为 true")
	}

	// ⑤ 注销 sink（登记还在）→ 回到 online=true / signalReady=false
	if !reg.DetachSink("192.168.30.12", sink) {
		t.Fatal("注销失败")
	}
	if r := query("192.168.30.12"); !r.PeerOnline || r.PeerSignalReady {
		t.Fatalf("注销后应为 online=true signalReady=false，实际 %+v", r)
	}
}

// TestPushSignalRejectsResponseTypes（协议约束 1 的服务端侧运行时兜底）
//
//	推送 type 与应答类型 {registered, peer, error} 不相交。
func TestPushSignalRejectsResponseTypes(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	registerStream(srv, "192.168.30.11", "alice")
	reg.AttachSink("192.168.30.11", &fakeSink{}) // 通道是通的，只是 type 非法

	for _, bad := range []string{signalMsgTypeRegistered, signalMsgTypePeer, signalMsgTypeError} {
		if err := srv.PushSignal("192.168.30.11", signalMessage{Type: bad}); err == nil {
			t.Fatalf("推送 type=%q 与应答类型冲突，必须被拒绝（协议约束 1）", bad)
		}
	}
	// 合法的推送类型照常放行
	if err := srv.PushSignal("192.168.30.11", signalMessage{Type: "punch-request"}); err != nil {
		t.Fatalf("合法推送不应被拒: %v", err)
	}
}

// TestServeSignalStreamServesOneAtATime 每条 ctrl 连接**同时只服务 1 条**信令流。
//
// 循环 accept 的意义只是「客户端丢弃流之后能在同一条连接上重开」，
// 不是并发服务多条：serveSignalStream 会阻塞到当前流结束。
// 断言方式：A 流还活着时，推送必须走 A 的 sink；A 结束后服务端才去服务 B，
// 推送随之转到 B。
func TestServeSignalStreamServesOneAtATime(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")

	l := newSignalTestListener(t)
	defer l.close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			return
		}
		srv.acceptSignalStream(conn, alice) // 走真正的循环 accept
	}()

	conn, streamA := dialSignalClient(t, l)
	defer conn.CloseWithError(0, "")

	// 第 1 条流：写一帧让它可见（BUG-A），登记并挂上 sink
	sendSignalMsg(t, streamA, signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	})
	if resp := recvSignalMsg(t, streamA, 3*time.Second); resp.Type != signalMsgTypeRegistered {
		t.Fatalf("期望 registered，实际 %+v", resp)
	}
	waitFor(t, "第 1 条流挂载", func() bool { return reg.HasSink("192.168.30.11") })

	// 第 2 条流也开出来并写入（对服务端可见）
	streamB, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("开第 2 条流失败: %v", err)
	}
	sendSignalMsg(t, streamB, signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	})

	// A 还活着：推送必须走 A，B 收不到
	if err := srv.PushSignal("192.168.30.11", signalMessage{Type: "push-a"}); err != nil {
		t.Fatalf("推送失败: %v", err)
	}
	if got := recvSignalMsg(t, streamA, 3*time.Second); got.Type != "push-a" {
		t.Fatalf("A 应收到推送，实际 %+v", got)
	}
	_ = streamB.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if pkt, err := readFrame(streamB, make([]byte, maxFrameSize)); err == nil {
		var unexpected signalMessage
		_ = json.Unmarshal(pkt, &unexpected)
		t.Fatalf("A 还活着时 B 不应该被服务（也不该收到推送），实际收到 %+v", unexpected)
	}
	_ = streamB.SetReadDeadline(time.Time{})

	// A 结束 → 服务端才服务 B，推送转到 B
	_ = streamA.Close()
	waitFor(t, "第 2 条流接管", func() bool {
		// 轮询：等推送能打到 B（sink 已被新流替换）
		if err := srv.PushSignal("192.168.30.11", signalMessage{Type: "push-b"}); err != nil {
			return false
		}
		_ = streamB.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		pkt, err := readFrame(streamB, make([]byte, maxFrameSize))
		_ = streamB.SetReadDeadline(time.Time{})
		if err != nil {
			return false
		}
		var msg signalMessage
		return json.Unmarshal(pkt, &msg) == nil && msg.Type == "push-b"
	})

	_ = streamB.Close()
	srv.EnableP2PSignal(false, reg) // 收尾：让 accept 循环退出
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("收尾后 acceptSignalStream 未退出")
	}
}

// TestRuntimeDisableStopsServerStreamGoroutine 运行期关掉 P2P 后，
// 正在跑的信令流 goroutine 必须真的退出。
//
// ⚠️ 这条测试盯的是一个很容易漏的点：QUIC 的 Stream.Close() **只关写方向**，
// 不加 CancelRead 的话服务端的读循环会永远卡在 readFrame 上 ——
// 通道看起来关了、sink 也注销了，但每条流的 goroutine 都留了下来（泄漏）。
func TestRuntimeDisableStopsServerStreamGoroutine(t *testing.T) {
	srv, reg := newSignalTestServer(t, true)
	alice := registerStream(srv, "192.168.30.11", "alice")

	l := newSignalTestListener(t)
	defer l.close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		srv.serveSignalStream(conn, alice, stream, reg)
	}()

	conn, stream := dialSignalClient(t, l)
	defer conn.CloseWithError(0, "")

	sendSignalMsg(t, stream, signalMessage{
		Type: signalMsgTypeRegister, PublicAddr: "1.2.3.4:30001", NATType: "full-cone",
	})
	if resp := recvSignalMsg(t, stream, 3*time.Second); resp.Type != signalMsgTypeRegistered {
		t.Fatalf("期望 registered，实际 %+v", resp)
	}
	waitFor(t, "挂载下行通道", func() bool { return reg.HasSink("192.168.30.11") })

	// 运行期关闭 P2P（面板路径）
	srv.EnableP2PSignal(false, reg)

	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("关闭 P2P 后 serveSignalStream 仍未退出（读方向没被取消 → goroutine 泄漏）")
	}
	if reg.HasSink("192.168.30.11") {
		t.Fatal("关闭 P2P 后下行通道应已注销")
	}
	// 关闭之后不得再处理信令（fail-closed）
	if err := srv.PushSignal("192.168.30.11", signalMessage{Type: "push"}); err == nil {
		t.Fatal("关闭 P2P 后推送应报错")
	}
}

// ---------- 假 sink ----------

type fakeSink struct {
	closed atomic.Bool
	sent   atomic.Int32
}

func (f *fakeSink) SendSignal([]byte) error {
	f.sent.Add(1)
	return nil
}

func (f *fakeSink) CloseSignal() error {
	f.closed.Store(true)
	return nil
}

var _ admin.SignalSink = (*fakeSink)(nil)
