package quic

// vpn-tool/backend/quic/path_test.go
//
// ⭐ P2SP 阶段 1b-2A 的测试。
//
// 三条硬验收项（review 指定）在本文件里的落点：
//   1. `TestDirectWriteDoesNotBlockOtherPath` + `TestDirectWriteTimeoutDemotes`：
//      一条直连流**永久阻塞**时，别的路径不受影响、调用方永不阻塞、该路径被判死降级；
//   2. `BenchmarkRouteLookupCOW`：断言读路径 **0 allocs/op**；
//   3. `TestDemoteOrderStrict`（4 个 L1 入口）：四条链路都进同一个 demote()，
//      且顺序严格「先摘路由 → 再关路径 → 最后排退避」。
//
// 全部用窄接口假实现（fakeHost/fakeConn/fakeStream），**不需要 TUN、不需要真实 socket**。

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- 测试替身 ----------

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

type fakeStream struct {
	mu         sync.Mutex
	wrote      bytes.Buffer
	reads      chan []byte
	rdl, wdl   time.Time
	closed     bool
	closedCh   chan struct{}
	blockWrite bool  // 永久阻塞（写截止到了才返回超时）
	writeErr   error // 固定写错误
	readErr    error // 固定读错误
	failCh     chan struct{}
	pending    []byte // 上次 Read 没读完的残留（模拟字节流）
	closeCount atomic.Int32
}

func newFakeStream() *fakeStream {
	return &fakeStream{reads: make(chan []byte, 64), closedCh: make(chan struct{}), failCh: make(chan struct{})}
}

// fail 让阻塞中的 Read 立刻返回读错误（模拟 L1-d）
func (s *fakeStream) fail(err error) {
	s.mu.Lock()
	s.readErr = err
	s.mu.Unlock()
	close(s.failCh)
}

func (s *fakeStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	block, wdl, werr, closed := s.blockWrite, s.wdl, s.writeErr, s.closed
	s.mu.Unlock()
	if closed {
		return 0, errors.New("stream closed")
	}
	if werr != nil {
		return 0, werr
	}
	if block {
		if !wdl.IsZero() {
			select {
			case <-time.After(time.Until(wdl)):
				return 0, timeoutErr{}
			case <-s.closedCh:
				return 0, errors.New("stream closed")
			}
		}
		<-s.closedCh
		return 0, errors.New("stream closed")
	}
	s.mu.Lock()
	s.wrote.Write(p)
	s.mu.Unlock()
	return len(p), nil
}

func (s *fakeStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	readErr := s.readErr
	// ⚠️ 必须保留上一次没读完的残留：真实 QUIC 流是字节流，
	//    readFrame 会「先读 4 字节长度、再读正文」两次 Read，截断会丢掉正文（踩过）。
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()
	if readErr != nil {
		return 0, readErr
	}
	// ⚠️ 必须实现**读截止**：真实 QUIC 流会在截止到点时让 Read 返回超时错误，
	//    而生产代码依赖它给「对端只开流不写声明」兜底（否则 setup 永久卡住、测试挂死）。
	s.mu.Lock()
	rdl := s.rdl
	s.mu.Unlock()
	var deadlineCh <-chan time.Time
	if !rdl.IsZero() {
		wait := time.Until(rdl)
		if wait <= 0 {
			return 0, timeoutErr{}
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		deadlineCh = t.C
	}
	select {
	case b := <-s.reads:
		n := copy(p, b)
		if n < len(b) {
			s.mu.Lock()
			s.pending = append(s.pending, b[n:]...)
			s.mu.Unlock()
		}
		return n, nil
	case <-s.closedCh:
		return 0, errors.New("stream closed")
	case <-s.failCh:
		s.mu.Lock()
		e := s.readErr
		s.mu.Unlock()
		if e == nil {
			e = errors.New("read failed")
		}
		return 0, e
	case <-deadlineCh:
		return 0, timeoutErr{}
	}
}

func (s *fakeStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.wdl = t
	s.mu.Unlock()
	return nil
}

func (s *fakeStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.rdl = t
	s.mu.Unlock()
	return nil
}

func (s *fakeStream) Close() error {
	if s.closeCount.Add(1) == 1 {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		close(s.closedCh)
	}
	return nil
}

// frames 取已写入的帧
func (s *fakeStream) frames() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw := s.wrote.Bytes()
	var out [][]byte
	for len(raw) >= 4 {
		n := int(binary.BigEndian.Uint32(raw[:4]))
		if len(raw) < 4+n {
			break
		}
		out = append(out, append([]byte(nil), raw[4:4+n]...))
		raw = raw[4+n:]
	}
	return out
}

// dataFrames 只看**数据**帧：跳过流用途声明帧（`{"t":"stream",...}`，每条流的首帧）
func (s *fakeStream) dataFrames() [][]byte {
	var out [][]byte
	for _, f := range s.frames() {
		if len(f) > 0 && f[0] == '{' {
			continue // 声明帧
		}
		out = append(out, f)
	}
	return out
}

type fakeConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	opened []*fakeStream
	closed atomic.Bool
	// datagrams 收到的不可靠包
	datagrams chan []byte
	// sendErr 模拟 SendDatagram 失败
	sendErr error
	// accepted 对端发起的流（AcceptStream）
	accepted chan directStream
}

func newFakeConn() *fakeConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeConn{ctx: ctx, cancel: cancel, datagrams: make(chan []byte, 16),
		accepted: make(chan directStream, 8)}
}

func (c *fakeConn) OpenStreamSync(ctx context.Context) (directStream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := newFakeStream()
	c.opened = append(c.opened, s)
	return s, nil
}

func (c *fakeConn) AcceptStream(ctx context.Context) (directStream, error) {
	select {
	case s := <-c.accepted:
		return s, nil
	// ⭐ 与真实 QUIC 对齐：连接关闭后 AcceptStream 立即返回错误。
	// 若只看传入的 ctx，close() 就无法唤醒卡在 setup 里的响应方路径，
	// 调用方（仲裁丢弃旧路径时的 close+wait）得白等整个 setup 超时（默认 5s）。
	case <-c.ctx.Done():
		return nil, errors.New("fakeConn 已关闭")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *fakeConn) SendDatagram(p []byte) error {
	if c.sendErr != nil {
		return c.sendErr
	}
	if len(p) > directMaxDatagram {
		return errors.New("datagram too large")
	}
	return nil
}

func (c *fakeConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.datagrams:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *fakeConn) Context() context.Context { return c.ctx }

func (c *fakeConn) CloseWithError(code uint64, msg string) error {
	if c.closed.CompareAndSwap(false, true) {
		c.cancel()
	}
	return nil
}

// bulkStream 发起方第 1 条开的流（bulk）；crit = 第 2 条；ctrl = 第 3 条
func (c *fakeConn) bulkStream() *fakeStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.opened) > 0 {
		return c.opened[0]
	}
	return nil
}

func (c *fakeConn) critStream() *fakeStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.opened) > 1 {
		return c.opened[1]
	}
	return nil
}

func (c *fakeConn) ctrlStream() *fakeStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.opened) > 2 {
		return c.opened[2]
	}
	return nil
}

// fakeHost 实现 pathHost
type fakeHost struct {
	mu        sync.Mutex
	vip       [4]byte
	vipOK     bool
	natOK     bool
	p2p       bool
	peers     map[string]SignalPeer
	queryErr  map[string]error
	queries   []string
	punches   []string
	triggers  []string
	punchErr  error
	refreshes int
	// refreshErr 让 refreshNAT 失败（⭐1b-4：验「重探测失败不清退避」）
	refreshErr error
	// natReprobes 「NAT 重探测成功」回调次数（⭐1b-4 第 2 条重置）
	natReprobes int
	delivered   [][]byte
	events      []P2PStatus
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		vip: [4]byte{192, 168, 30, 11}, vipOK: true, natOK: true, p2p: true,
		peers: map[string]SignalPeer{}, queryErr: map[string]error{},
	}
}

func (h *fakeHost) myVIP4() ([4]byte, bool) { return h.vip, h.vipOK }
func (h *fakeHost) natProbeReady() bool     { return h.natOK }
func (h *fakeHost) p2pEnabled() bool        { return h.p2p }

func (h *fakeHost) signalQuery(vip string) (SignalPeer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.queries = append(h.queries, vip)
	if err := h.queryErr[vip]; err != nil {
		return SignalPeer{}, err
	}
	if p, ok := h.peers[vip]; ok {
		return p, nil
	}
	return SignalPeer{VIP: vip, Online: false, SignalReady: false}, nil
}

func (h *fakeHost) punchWithTrigger(vip, trigger string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.punchErr != nil {
		return "", h.punchErr
	}
	h.punches = append(h.punches, vip)
	h.triggers = append(h.triggers, trigger)
	return "attempt-" + vip, nil
}

func (h *fakeHost) refreshNAT(ctx context.Context) error {
	h.mu.Lock()
	h.refreshes++
	err := h.refreshErr
	h.mu.Unlock()
	return err
}

// notifyNATReprobed ⭐ 1b-4 第 2 条重置的宿主钩子：记一次「重探测成功」
func (h *fakeHost) notifyNATReprobed() {
	h.mu.Lock()
	h.natReprobes++
	h.mu.Unlock()
}

// natReprobeCount 重探测成功回调的次数（用例用它断言「成功才重置」）
func (h *fakeHost) natReprobeCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.natReprobes
}

func (h *fakeHost) deliverToTun(pkt []byte) {
	h.mu.Lock()
	h.delivered = append(h.delivered, append([]byte(nil), pkt...))
	h.mu.Unlock()
}

func (h *fakeHost) onPathEvent(st P2PStatus) {
	h.mu.Lock()
	h.events = append(h.events, st)
	h.mu.Unlock()
}

func (h *fakeHost) queryCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.queries)
}

func (h *fakeHost) punchCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.punches)
}

func (h *fakeHost) deliveredCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.delivered)
}

func (h *fakeHost) addPeer(vip string) {
	h.mu.Lock()
	h.peers[vip] = SignalPeer{VIP: vip, Online: true, SignalReady: true}
	h.mu.Unlock()
}

// ---------- 小工具 ----------

func ip4(s string) [4]byte {
	var out [4]byte
	copy(out[:], net.ParseIP(s).To4())
	return out
}

// newTestPath 建一条「已建立」的路径（不经过打洞）
//
// ⭐ 1b-4：`newDirectPath` 现在把新路径放进 **trial**（先验后切），而绝大多数既有用例关心的是
// 「有一条 Up 的、正在承载流量的路径」⇒ 这里用 `passTrialForTest` 把试用期按「通过」结算掉。
// 它走的是与生产**完全相同**的两道取消门 + 同一个装表仲裁临界区，只把「判定」换成直接通过。
// 试用期本身的用例（trial_integration_test.go）**不**用这个助手，自己控制窗口与样本。
func newTestPath(pm *pathManager, host *fakeHost, peerVIP, role string) (*directPath, *fakeConn) {
	conn := newFakeConn()
	req := establishedReq{
		peerVIP: peerVIP,
		peer:    ip4(peerVIP),
		role:    role,
		conn:    conn,
		closers: []func() error{func() error { return nil }},
		myVIP:   host.vip,
	}
	p, err := newDirectPath(pm, req)
	if err != nil {
		panic(err) // 假实现不会失败
	}
	pm.installRoute(req.peer, p) // 与 handleEstablished 一致：trial 也登记在表里（面板要看得见）
	p.passTrialForTest()
	p.run()
	return p, conn
}

// newTestPathNoPass ⭐⭐ A2 形态 A：建一条**停留在试用期**的路径（**不**走装表流程）。
//
// 与 `newTestPath` 的唯一区别：**不调 `passTrialForTest()`**。这一处差异是**为正确性**，不是风格：
//
//	`passTrialForTest → installAfterTrial → p.untrack()` 会**烧掉** `detachTrialPath` 的
//	**一次性闭包**（`sync.Once`）⇒ 之后再 `addTrialPath` 补登记的路径，**永远摘不掉**
//	（`releaseRejected → untrack()` 成 no-op）⇒ 登记残留 = 泄漏。
//
// ⚠️ **与生产逐字同形**（`handleEstablished`）：`newDirectPath` 之后**锁内** `addTrialPath` + `run()`。
//
//	为什么必须同临界区：否则出现「已登记但 `wg.Add` 未发生」的窗口 ⇒ `close()` 的 `wait()` 与
//	`Add` 并发 = **WaitGroup 误用**（见 `run()` 头注释的锁内契约）。
//
// ⚠️ **不等待数据面/控制流建立**：`run()` 只启动协程（`setup()` 在独立协程里建流）
// —— 与生产一致。需要 ctrl 流的用例**自己** `waitFor`（见 `TestTrialRejectedStillEchoes`）。
func newTestPathNoPass(t *testing.T, pm *pathManager, host *fakeHost, peerVIP, role string) (*directPath, *fakeConn) {
	t.Helper()
	conn := newFakeConn()
	p, err := newDirectPath(pm, establishedReq{
		peerVIP: peerVIP,
		peer:    ip4(peerVIP),
		role:    role,
		conn:    conn,
		closers: []func() error{func() error { return nil }},
		myVIP:   host.vip,
	})
	if err != nil {
		t.Fatal(err)
	}
	// ⚠️ 登记 + run() 必须在**同一** `routeMu` 临界区（生产契约，见函数头注释）
	pm.routeMu.Lock()
	pm.addTrialPath(p)
	p.run()
	pm.routeMu.Unlock()
	t.Cleanup(p.close)
	return p, conn
}

// newTestPathOwned ⭐ 第 3 步-D：`newTestPath` + **注册显式关闭**。
//
// 为什么需要：有些用例建完路径后会把管理器与路径**解绑**（典型是
// `pm.replaceRoutes(nil)` —— 为了考察「没有路由时」的行为），此后
// `pm.close()` 遍历路由表就**看不见这条路径** ⇒ 路径永不关闭 ⇒
// 它的读协程永久阻塞在 `fakeStream.Read`（实测每迭代泄漏 ≈12 个协程）。
//
// `t.Cleanup` 保证无论用例怎么改路由表、无论中途 t.Fatal，这条路径都会被关。
func newTestPathOwned(t *testing.T, pm *pathManager, host *fakeHost, peerVIP, role string) (*directPath, *fakeConn) {
	t.Helper()
	p, conn := newTestPath(pm, host, peerVIP, role)
	t.Cleanup(p.close)
	return p, conn
}

// newTestPathOwnedB 同上，供 Benchmark 使用（`b.Cleanup` 是 Go 1.24+ 的 API）。
func newTestPathOwnedB(b *testing.B, pm *pathManager, host *fakeHost, peerVIP, role string) (*directPath, *fakeConn) {
	b.Helper()
	p, conn := newTestPath(pm, host, peerVIP, role)
	b.Cleanup(p.close)
	return p, conn
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

// pathFor ⭐ 1b-4 测试助手：取某对端当前的路径 —— 先看路由表（已装表 / standby），
// 再看**试用表**（trial 期间不在路由表里）。这是「这个对端现在有没有路径」的唯一口径。
//
// ⚠️ 它**不适合**用来抓「同一对端的两条 trial」：一旦结算了一条（进了路由表），
// 后续调用就会优先返回那条。要按序号取试用路径请用 trialPathsFor。
func pathFor(pm *pathManager, peerVIP string) *directPath {
	dst := ip4(peerVIP)
	pm.routeMu.Lock()
	defer pm.routeMu.Unlock()
	if p := (*pm.routes.Load())[dst]; p != nil {
		return p
	}
	if list := pm.trialPaths[dst]; len(list) > 0 {
		return list[0]
	}
	return nil
}

// trialPathsFor 某对端当前**试用表中**的路径快照（顺序 = 进入 trial 的顺序）。
func trialPathsFor(pm *pathManager, peerVIP string) []*directPath {
	pm.routeMu.Lock()
	defer pm.routeMu.Unlock()
	return append([]*directPath(nil), pm.trialPaths[ip4(peerVIP)]...)
}

// forceTrialPass ⭐ 1b-4 测试助手：把某对端**最新进入 trial 的那条**路径按「通过」结算掉，
// 返回那条路径（没有在试用期的路径则返回 nil）。
//
// 为什么需要它：`handleEstablished` 现在只把路径放进 trial（先验后切），而大量既有用例
// （仲裁 / 上限淘汰 / 本机开关）关心的是「有一条已经在用的直连」。让它们各等 15 秒
// 试用期没有意义，所以统一用这个助手结算 —— 走的是**真实**的取消门 + 装表仲裁临界区。
//
// ⚠️ 必须取**试用表**里的路径，不能用 pathFor：对端已经有一条装表成功的路径时，
// pathFor 会返回那一条，于是「让新来的第二条通过试用期」会静默失效（本助手踩过）。
func forceTrialPass(t *testing.T, pm *pathManager, peerVIP string) *directPath {
	t.Helper()
	list := trialPathsFor(pm, peerVIP)
	if len(list) == 0 {
		return nil
	}
	p := list[len(list)-1]
	p.passTrialForTest()
	return p
}

// wireFrame 造一个「4 字节长度 + 1 字节平面标签 + 载荷」的线帧（模拟对端发来的帧）
func wireFrame(tag byte, pkt []byte) []byte {
	body := append([]byte{tag}, pkt...)
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

// 造一个 IP 包（20 字节头 + 载荷），目的地址可指定
func ipPacket(src, dst [4]byte, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	pkt[9] = 6 // TCP
	copy(pkt[20:], payload)
	return pkt
}

// ---------- 硬验收项 2：COW 查表 0 allocs/op ----------

func BenchmarkRouteLookupCOW(b *testing.B) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()
	p, _ := newTestPathOwnedB(b, pm, host, "192.168.30.12", pathRoleInitiator)
	_ = p
	dst := ip4("192.168.30.12")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ch := pm.sinkFor(dst, planeTCP); ch == nil {
			b.Fatal("应有直连")
		}
	}
}

// TestRouteTableCOWNeverMutatesPublishedMap 并发读 + 反复切换写：
// 发布后的表绝不被修改（-race 下也必须干净）
func TestRouteTableCOWNeverMutatesPublishedMap(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dst := ip4("192.168.30.12")
			for {
				select {
				case <-stop:
					return
				default:
					_ = pm.sinkFor(dst, planeTCP)
					_, _ = pm.routeVIP(dst)
				}
			}
		}()
	}

	for i := 0; i < 200; i++ {
		// 此处**显式** close（循环内自行清理），不需要 Owned 版本
		p, _ := newTestPath(pm, host, "192.168.30.12", pathRoleInitiator)
		pm.removeRoute(p.peer, p)
		p.close()
	}
	close(stop)
	wg.Wait()
}

// ---------- 触发（热路径） ----------

// TestObserveDedupeAndNonBlocking 同一地址只入队一次；队列满时 Observe 立即返回
func TestObserveDedupeAndNonBlocking(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	dst := ip4("192.168.30.12")
	pm.Observe(dst)
	pm.Observe(dst)
	pm.Observe(dst)
	if n := len(pm.triggerCh); n != 1 {
		t.Fatalf("同一地址应只入队一次，实际队列长度 %d", n)
	}
	// 队列打满后继续调用必须立即返回（不阻塞）
	for i := 0; i < triggerQueueLen+10; i++ {
		pm.Observe(ip4(fmt.Sprintf("192.168.30.%d", 100+i)))
	}
	done := make(chan struct{})
	go func() { pm.Observe(ip4("10.0.0.1")); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Observe 在队列满时必须立即返回（不能阻塞 TUN 读循环）")
	}
}

// TestSignalGateCachesAndBudget 信号门：正/负缓存生效，且全局预算封顶
func TestSignalGateCachesAndBudget(t *testing.T) {
	host := newFakeHost()
	host.addPeer("192.168.30.12")
	pm := newPathManager(host)
	defer pm.close()

	dst := ip4("192.168.30.12")
	for i := 0; i < 5; i++ {
		if pass, err := pm.gateCheck(dst, "192.168.30.12"); !pass || err != nil {
			t.Fatalf("在线对端应通过信号门：pass=%v err=%v", pass, err)
		}
	}
	if n := host.queryCount(); n != 1 {
		t.Fatalf("正缓存应让 5 次判断只查 1 次，实际 %d 次", n)
	}

	// 未知地址：负缓存（多次仍只查 1 次）
	unknown := ip4("192.168.30.99")
	for i := 0; i < 5; i++ {
		if pass, _ := pm.gateCheck(unknown, "192.168.30.99"); pass {
			t.Fatal("不在线地址不应通过信号门")
		}
	}
	if n := host.queryCount(); n != 2 {
		t.Fatalf("负缓存应让重复判断不再查询，实际共 %d 次", n)
	}
}

// TestBackoffLadderBusyAndPermanent 失败分类：可重试走台阶、忙走短延迟、永久走长冷却
func TestBackoffLadderBusyAndPermanent(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	retry := ip4("192.168.30.12")
	for i, want := range backoffLadder {
		pm.onPunchFailed("192.168.30.12", P2PReasonPunchTimeout)
		pm.mu.Lock()
		got := time.Until(pm.backoff[retry].until)
		step := pm.backoff[retry].step
		pm.mu.Unlock()
		if step != i+1 {
			t.Fatalf("第 %d 次失败后台阶应为 %d，实际 %d", i+1, i+1, step)
		}
		if got < want-time.Second || got > want+time.Second {
			t.Fatalf("第 %d 次失败退避应约 %v，实际 %v", i+1, want, got)
		}
	}

	busy := ip4("192.168.30.13")
	pm.onPunchFailed("192.168.30.13", P2PReasonRateLimited)
	pm.mu.Lock()
	st := pm.backoff[busy]
	pm.mu.Unlock()
	if st.step != 0 {
		t.Fatalf("「忙」不应推进台阶，实际 step=%d", st.step)
	}
	if d := time.Until(st.until); d > backoffBusy+time.Second {
		t.Fatalf("「忙」应为短延迟 %v，实际 %v", backoffBusy, d)
	}

	// ⭐ 1b-4 第一步改法（保留牙）：不再断言「冷却 ≥ 10min」，而是断言
	//   ① 它进入了**确定性台阶表**的第 0 档（5min）——验「分类正确」而不是「冷却够长」；
	//   ② 它**推进了打洞 streak**（下一次会到第 1 档 15min）；
	//   ③ 它**没有**污染质量差 streak（两套 streak 必须独立）。
	perm := ip4("192.168.30.14")
	pm.onPunchFailed("192.168.30.14", P2PReasonNATSymmetric)
	pm.mu.Lock()
	st = pm.backoff[perm]
	pm.mu.Unlock()
	if want := backoffLadderDeterministic[0]; time.Until(st.until) < want-time.Second ||
		time.Until(st.until) > want+time.Second {
		t.Fatalf("确定性失败应走确定性台阶第 0 档 %v，实际 %v", want, time.Until(st.until))
	}
	if st.step != 1 {
		t.Fatalf("确定性失败应推进打洞 streak（期望 1），实际 %d", st.step)
	}
	if st.qualityStep != 0 {
		t.Fatalf("确定性失败不得推进质量差 streak，实际 %d", st.qualityStep)
	}
	// 再失败一次 ⇒ 第 1 档（15min）：证明台阶真的在递增（而不只是「有个冷却」）
	pm.onPunchFailed("192.168.30.14", P2PReasonNATSymmetric)
	pm.mu.Lock()
	st = pm.backoff[perm]
	pm.mu.Unlock()
	if want := backoffLadderDeterministic[1]; time.Until(st.until) < want-time.Second ||
		time.Until(st.until) > want+time.Second {
		t.Fatalf("确定性失败第 2 次应走第 1 档 %v，实际 %v", want, time.Until(st.until))
	}

	// 成功清退避
	pm.onPunchSucceeded("192.168.30.12")
	pm.mu.Lock()
	_, ok := pm.backoff[retry]
	pm.mu.Unlock()
	if ok {
		t.Fatal("成功后应清除退避")
	}
}

// TestTiebreakYieldOnInboundInvite 让路：VIP 较大的一侧收到邀请就放弃自己发起
func TestTiebreakYieldOnInboundInvite(t *testing.T) {
	host := newFakeHost()
	host.vip = ip4("192.168.30.20") // 比对端大 → 需要让路
	host.addPeer("192.168.30.12")
	pm := newPathManager(host)
	pm.tiebreakDelay = 300 * time.Millisecond // 缩短等待（改实例字段，不动全局）
	pm.start()
	defer pm.close()

	dst := ip4("192.168.30.12")
	pm.handleTrigger(dst)
	time.Sleep(50 * time.Millisecond) // 让它进入让路等待
	pm.notifyInboundInvite("192.168.30.12")

	time.Sleep(200 * time.Millisecond)
	if n := host.punchCount(); n != 0 {
		t.Fatalf("收到邀请后不应再自己发起，实际发起 %d 次", n)
	}
}

// TestTiebreakSmallerVIPInitiatesImmediately VIP 较小的一侧立即发起
func TestTiebreakSmallerVIPInitiatesImmediately(t *testing.T) {
	host := newFakeHost()
	host.vip = ip4("192.168.30.11") // 比对端小
	host.addPeer("192.168.30.12")
	pm := newPathManager(host)
	pm.start()
	defer pm.close()

	pm.handleTrigger(ip4("192.168.30.12"))
	waitFor(t, "小 VIP 立即发起打洞", func() bool { return host.punchCount() == 1 })
	host.mu.Lock()
	trig := host.triggers[0]
	host.mu.Unlock()
	if trig != P2PTriggerTraffic {
		t.Fatalf("触发来源应为 traffic，实际 %q", trig)
	}
}

// TestLocalNotReadyDelaysWithoutNegativeCache 本机 NAT 未就绪：只延迟，不写负缓存
func TestLocalNotReadyDelaysWithoutNegativeCache(t *testing.T) {
	host := newFakeHost()
	host.natOK = false
	host.addPeer("192.168.30.12")
	pm := newPathManager(host)
	pm.start()
	defer pm.close()

	pm.handleTrigger(ip4("192.168.30.12"))
	time.Sleep(100 * time.Millisecond)
	if host.queryCount() != 0 {
		t.Fatal("本机没就绪时不应查询信号门")
	}
	if host.punchCount() != 0 {
		t.Fatal("本机没就绪时不应发起打洞")
	}
	pm.mu.Lock()
	_, cached := pm.gate[ip4("192.168.30.12")]
	pm.mu.Unlock()
	if cached {
		t.Fatal("本机没就绪**不应**写负缓存（那不是对端的问题）")
	}
}

// ---------- 仲裁与归属（Q15 / P0） ----------

// TestEstablishedArbitrationKeepsSmallerVIPListener 两条直连时保留「小 VIP 当 listener」那条
func TestEstablishedArbitrationKeepsSmallerVIPListener(t *testing.T) {
	host := newFakeHost()
	host.vip = ip4("192.168.30.20") // 我大 → 胜者应是「小 VIP（对端）当 listener」= 我作为 responder
	pm := newPathManager(host)
	defer pm.close()

	// 先装一条「我当前 listener（initiator）」= 败者
	loserConn := newFakeConn()
	loserClosed := atomic.Bool{}
	pm.handleEstablished(establishedReq{
		peerVIP: "192.168.30.11", peer: ip4("192.168.30.11"), role: pathRoleInitiator,
		conn: loserConn, closers: []func() error{func() error { loserClosed.Store(true); return nil }}, myVIP: host.vip,
	})
	// ⭐ 1b-4：先验后切 —— 第一条必须**通过试用期**才谈得上「已有直连」
	forceTrialPass(t, pm, "192.168.30.11")
	if _, ok := pm.routeVIP(ip4("192.168.30.11")); !ok {
		t.Fatal("第一条应已装表")
	}

	// 再来一条「我是 responder」= 胜者（小 VIP 当 listener）
	winnerConn := newFakeConn()
	pm.handleEstablished(establishedReq{
		peerVIP: "192.168.30.11", peer: ip4("192.168.30.11"), role: pathRoleResponder,
		conn: winnerConn, myVIP: host.vip,
	})
	// ⭐ 1b-4：仲裁现在发生在**装表点** —— 第二条也要通过试用期，才能触发「AI 判负 / 胜者换表」
	forceTrialPass(t, pm, "192.168.30.11")

	waitFor(t, "旧路径被关闭", func() bool { return loserClosed.Load() })
	pm.routeMu.Lock()
	cur := (*pm.routes.Load())[ip4("192.168.30.11")]
	pm.routeMu.Unlock()
	if cur == nil || cur.role != pathRoleResponder {
		t.Fatalf("应保留 responder（小 VIP 当 listener）那条，实际 %+v", cur)
	}
}

// TestArbitrationBothSidesChooseSamePath ⭐ 真机 bug 回归（双向同时发起）。
//
// 场景：A=192.168.30.11（VIP 小）、B=192.168.30.12（VIP 大），双方**同时**发起打洞：
//
//	attempt X：A 发起 → A 是 QUIC listener（A 侧 role=initiator，B 侧 role=responder）
//	attempt Y：B 发起 → B 是 QUIC listener（B 侧 role=initiator，A 侧 role=responder）
//
// 正确结果：两侧都必须保留 **X**（「小 VIP 当 listener」的那条物理连接），
// 并各自关掉 Y。若两侧结论相反（一侧留 X、一侧留 Y），就会出现
// 「各自关掉对方保留的那条」→ 两条连接全死 → 直连中断回退中继。
//
// 真机现象（.12 侧）：`连接已关闭：Application error 0x0 (remote): path closed`
// —— 这个错误串正是 path.close() 发出的，说明对端关掉了一条本侧仍在用的连接。
func TestArbitrationBothSidesChooseSamePath(t *testing.T) {
	const vipA, vipB = "192.168.30.11", "192.168.30.12" // A 小、B 大

	// ① 纯判据：同一对端的两条连接，「谁合法」在两侧必须一致，且胜者是 X。
	//    （这是本 bug 的核心不变量：两侧对同一物理连接的结论相同。）
	if !arbitrationKeeps(ip4(vipB), ip4(vipA), pathRoleInitiator) {
		t.Fatal("A（小 VIP）侧：X（我自己监听）必须判为胜者")
	}
	if arbitrationKeeps(ip4(vipB), ip4(vipA), pathRoleResponder) {
		t.Fatal("A（小 VIP）侧：Y（我拨号、对方监听）不得判为胜者")
	}
	if !arbitrationKeeps(ip4(vipA), ip4(vipB), pathRoleResponder) {
		t.Fatal("B（大 VIP）侧：X（对方监听）必须判为胜者")
	}
	if arbitrationKeeps(ip4(vipA), ip4(vipB), pathRoleInitiator) {
		t.Fatal("B（大 VIP）侧：Y（我自己监听）不得判为胜者")
	}

	// ② 端到端：两侧各自独立仲裁后，路由表里留下的必须是**同一条**物理连接（X）。
	type ev struct {
		attempt    string
		amListener bool // 本侧是否为该连接的 QUIC listener（role=initiator）
	}
	xA, yA := ev{"X", true}, ev{"Y", false} // A 侧：X 是我监听、Y 是我拨号
	xB, yB := ev{"X", false}, ev{"Y", true} // B 侧：X 是我拨号、Y 是我监听

	cases := []struct {
		name           string
		orderA, orderB []ev
	}{
		{"两侧同序 X→Y", []ev{xA, yA}, []ev{xB, yB}},
		{"两侧反序 Y→X", []ev{yA, xA}, []ev{yB, xB}},
		{"A 正序 / B 反序", []ev{xA, yA}, []ev{yB, xB}},
		{"A 反序 / B 正序", []ev{yA, xA}, []ev{xB, yB}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hostA, hostB := newFakeHost(), newFakeHost()
			hostA.vip, hostB.vip = ip4(vipA), ip4(vipB)
			pmA, pmB := newPathManager(hostA), newPathManager(hostB)
			defer pmA.close()
			defer pmB.close()
			// ⚠️ 仲裁失败的一侧会 close+wait 败者路径（setup 的写握手最多 2s），
			//    所以这里把 L2 判死阈值放得很宽：结论不受影响，用例不白等、也不会
			//    被看门狗的「探针无回显」抢先降级（本用例不模拟对端回显）。
			for _, pm := range []*pathManager{pmA, pmB} {
				pm.probeInterval = 100 * time.Millisecond
				pm.checkInterval = 50 * time.Millisecond
				pm.probeMissLimit = 1000
			}

			connsA := map[string]*fakeConn{"X": newFakeConn(), "Y": newFakeConn()}
			connsB := map[string]*fakeConn{"X": newFakeConn(), "Y": newFakeConn()}
			closedA := map[string]*atomic.Bool{"X": {}, "Y": {}}
			closedB := map[string]*atomic.Bool{"X": {}, "Y": {}}

			// ⭐ 1b-4：仲裁现在发生在**装表点**（试用期结算），不再在 handleEstablished 里。
			//    所以本用例的时间线改成：两条 attempt 都先各进 trial（**互不裁决**），
			//    再**按到达顺序逐个结算试用期** —— 与真机上「两条通道先后通过试用期」同形。
			//
			//    关键不变量：无论两条试用期的结算顺序如何，最终必须**两侧都留下同一条物理连接 X**
			//    （VIP 规则：小 VIP 当 listener 的那条）。若装表点不是原子的、或退化成先到先得，
			//    就会出现一侧留 X、另一侧留 Y ⇒ 互相关掉对方保留的那条。
			//
			//    ⚠️ 实现细节：**不能**在 feed 里立刻用 pathFor 取路径 —— 同一对端两条 trial 都在
			//    试用表里，而 pathFor 会优先返回**路由表**里的那条；一旦先结算了一条，后续解析
			//    就会指回它，本用例会静默退化成「只结算一条」。所以这里存序号，全部建好后统一解析。
			type attempt struct {
				name string
				idx  int
			}
			feed := func(pm *pathManager, myVIP, peerVIP string,
				conns map[string]*fakeConn, closed map[string]*atomic.Bool,
				idx int, e ev) attempt {
				role := pathRoleResponder
				if e.amListener {
					role = pathRoleInitiator
				}
				c := closed[e.attempt]
				pm.handleEstablished(establishedReq{
					peerVIP: peerVIP, peer: ip4(peerVIP), role: role,
					conn: conns[e.attempt], myVIP: ip4(myVIP),
					closers: []func() error{func() error { c.Store(true); return nil }},
				})
				return attempt{name: e.attempt, idx: idx}
			}
			var orderA, orderB []attempt
			for i, e := range tc.orderA {
				orderA = append(orderA, feed(pmA, vipA, vipB, connsA, closedA, i, e))
			}
			for i, e := range tc.orderB {
				orderB = append(orderB, feed(pmB, vipB, vipA, connsB, closedB, i, e))
			}
			// 前置条件：两条 attempt 都真的进了 trial（试用表里各 2 条）
			for tag, pm := range map[string]*pathManager{"A": pmA, "B": pmB} {
				if n := pm.trialPathCount(); n != 2 {
					t.Fatalf("前置条件：%s 侧同一对端两条 attempt 都应在 trial 里，实际 %d 条", tag, n)
				}
			}
			// 全部建好后按序号解析各自的 trial 路径，再**按到达顺序逐个结算**
			resolve := func(pm *pathManager, peerVIP string, idx int) *directPath {
				list := trialPathsFor(pm, peerVIP)
				if idx < 0 || idx >= len(list) {
					t.Fatalf("trial 路径序号越界：idx=%d len=%d", idx, len(list))
				}
				return list[idx]
			}
			// ⚠️ 必须先**全部解析**再结算：结算一条会把它从试用表里摘掉（换表/关闭），
			//    之后再按序号解析就会错位。
			var toSettle []*directPath
			for _, a := range orderA {
				toSettle = append(toSettle, resolve(pmA, vipB, a.idx))
			}
			for _, a := range orderB {
				toSettle = append(toSettle, resolve(pmB, vipA, a.idx))
			}
			for _, p := range toSettle {
				p.passTrialForTest()
			}

			// 用 conn 指针反查「本侧存活的是哪一个 attempt」
			attemptOf := func(cur *directPath, conns map[string]*fakeConn) string {
				if cur == nil {
					return "<无>"
				}
				for name, c := range conns {
					if cur.conn == c {
						return name
					}
				}
				return "<未知>"
			}
			keptA := (*pmA.routes.Load())[ip4(vipB)]
			keptB := (*pmB.routes.Load())[ip4(vipA)]
			gotA, gotB := attemptOf(keptA, connsA), attemptOf(keptB, connsB)

			if gotA != "X" {
				t.Fatalf("A（小 VIP）应保留 X（自己监听的那条），实际保留 %s", gotA)
			}
			if gotB != "X" {
				t.Fatalf("B（大 VIP）应保留 X（对方监听的那条），实际保留 %s", gotB)
			}
			if gotA != gotB {
				t.Fatalf("两侧必须保留同一条物理连接：A 保留 %s、B 保留 %s（不一致 ⇒ 互相关掉对方保留的那条）",
					gotA, gotB)
			}
			// 活下来的那条必须是**在用**（装表后转 Up）—— 否则 UI 面板会显示「测试中」而实际不通
			if keptA == nil || keptA.state.Load() != pathStateUp {
				t.Fatalf("A 侧存活路径必须已转 Up，实际 %v", keptA)
			}
			if keptB == nil || keptB.state.Load() != pathStateUp {
				t.Fatalf("B 侧存活路径必须已转 Up，实际 %v", keptB)
			}
			// 败者必须被关掉（否则泄漏一条连接），胜者不得被关
			if !closedA["Y"].Load() || !closedB["Y"].Load() {
				t.Fatalf("两侧都应关掉败者 Y（A=%v B=%v）", closedA["Y"].Load(), closedB["Y"].Load())
			}
			if closedA["X"].Load() || closedB["X"].Load() {
				t.Fatalf("胜者 X 不得被关闭（A=%v B=%v）", closedA["X"].Load(), closedB["X"].Load())
			}
		})
	}
}

// TestArbitrationInstallPointIsSerialized ⭐ 真机 bug 回归（1b-4 形态）。
//
// 背景：仲裁从 `handleEstablished` 搬到了**装表点**（试用期结算）。竞争形态随之变化：
// 两条 attempt 各自进 trial（**不裁决**），等到各自试用期通过时才在 `installAfterTrial` 里
// 抢装表。若那个临界区不是原子的（读 existing → 仲裁 → 装表），两次结算就会双双装表：
// 败者既不关闭也不摘除（泄漏一条连接），且最终路由取决于谁最后装。
//
// 本用例用「同一对端两条路径，在两次结算之间**重复触发**第二条的结算」来放大这个窗口：
// 无论哪条先结算、结算多少次，最终必须只留下 responder（VIP 规则）那条，且只留一条。
func TestArbitrationInstallPointIsSerialized(t *testing.T) {
	host := newFakeHost()
	host.vip = ip4("192.168.30.20") // 我大 → 应保留「小 VIP（对端）当 listener」= 我作为 responder
	pm := newPathManager(host)
	defer pm.close()
	dst := ip4("192.168.30.11")

	for round := 0; round < 50; round++ {
		// 两条连接都保持可用：本用例只考察仲裁，不希望任一条因 setup/探针失败被降级
		initConn, respConn := newFakeConn(), newFakeConn()
		initClosed, respClosed := &atomic.Bool{}, &atomic.Bool{}
		closer := func(b *atomic.Bool) []func() error {
			return []func() error{func() error { b.Store(true); return nil }}
		}

		pm.handleEstablished(establishedReq{
			peerVIP: "192.168.30.11", peer: dst, role: pathRoleInitiator,
			conn: initConn, myVIP: host.vip, closers: closer(initClosed),
		})
		pm.handleEstablished(establishedReq{
			peerVIP: "192.168.30.11", peer: dst, role: pathRoleResponder,
			conn: respConn, myVIP: host.vip, closers: closer(respClosed),
		})
		// ⚠️ 用 trialPathsFor 按序号取（不能用 pathFor：结算过一条之后它会优先返回路由表那条）
		trials := trialPathsFor(pm, "192.168.30.11")
		if len(trials) != 2 {
			t.Fatalf("第 %d 轮：两条 attempt 都应各自进入 trial，实际 %d 条", round, len(trials))
		}
		initPath, respPath := trials[0], trials[1]
		if initPath.role != pathRoleInitiator || respPath.role != pathRoleResponder {
			t.Fatalf("第 %d 轮：试用表顺序应与到达顺序一致，实际 %s / %s", round, initPath.role, respPath.role)
		}
		// trial 期间**不进路由表**（设计 §9 Q1）⇒ sinkFor 必须看不到任何一条
		if ch := pm.sinkFor(dst, planeTCP); ch != nil {
			t.Fatalf("第 %d 轮：trial 期间不得承载流量（sinkFor 必须为 nil）", round)
		}
		// 同一对端的两条 attempt 必须**都在试用表里**（互不裁决，等装表点再比）
		if got := pm.pathCount(); got != 2 {
			t.Fatalf("第 %d 轮：两条 attempt 都应在 trial 里，实际共 %d 条", round, got)
		}

		// 并发结算两条（= 两条通道的试用期同时到点），并各重复结算一次：
		// 取消门保证每条只结算一次，临界区保证只有一条能装表。
		var wg sync.WaitGroup
		for _, p := range []*directPath{initPath, respPath} {
			p := p
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.passTrialForTest()
				p.passTrialForTest() // 重复结算：必须被取消门挡住（不双写）
			}()
		}
		wg.Wait()

		cur := (*pm.routes.Load())[dst]
		if cur == nil || cur.role != pathRoleResponder {
			t.Fatalf("第 %d 轮：结算后应只保留 responder（VIP 规则胜者），实际 %+v", round, cur)
		}
		if got := pm.pathCount(); got != 1 {
			t.Fatalf("第 %d 轮：结算后应只剩 1 条路径（路由表 + 试用表），实际 %d", round, got)
		}
		// 败者（initiator）必须被关闭：它的结算在装表点判负，走的是「直接关路径、不排退避」。
		// 只有胜者（responder）不得被关 —— 这一条与结算顺序无关（VIP 规则是确定的）。
		if !initClosed.Load() {
			t.Fatalf("第 %d 轮：败者（initiator）必须被关闭/释放（漏关 = 泄漏一条连接）", round)
		}
		if respClosed.Load() {
			t.Fatalf("第 %d 轮：胜者（responder）不得被关闭", round)
		}
		// 清场，避免影响下一轮
		pm.removeRoute(dst, cur)
		cur.close()
		cur.wait()
	}
}

// TestManagerCloseClosesAllPaths（P0 验收）：Close 必须关掉每一条直连与其资源
func TestManagerCloseClosesAllPaths(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.start()

	var closedCount atomic.Int32
	var conns []*fakeConn
	for i := 10; i <= 12; i++ {
		conn := newFakeConn()
		vip := fmt.Sprintf("192.168.30.%d", i)
		pm.handleEstablished(establishedReq{
			peerVIP: vip, peer: ip4(vip), role: pathRoleInitiator, conn: conn,
			closers: []func() error{func() error { closedCount.Add(1); return nil }}, myVIP: host.vip,
		})
		conns = append(conns, conn)
	}
	if n := pm.pathCount(); n != 3 {
		t.Fatalf("应有 3 条路径（试用表 + 路由表），实际 %d", n)
	}

	pm.close()

	if closedCount.Load() != 3 {
		t.Fatalf("Close 后应有 3 个资源被释放，实际 %d", closedCount.Load())
	}
	if n := pm.pathCount(); n != 0 {
		t.Fatalf("Close 后路由表与试用表都应为空，实际 %d", n)
	}
	for i, conn := range conns {
		if conn.Context().Err() == nil {
			t.Fatalf("Close 后第 %d 条直连连接必须已关闭", i)
		}
	}
}

// TestDetachedSessionCloseAllIsNoop（P0 的另一面）：资源已移交时 closeAll 不得关连接
func TestDetachedSessionCloseAllIsNoop(t *testing.T) {
	sock, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("建 socket: %v", err)
	}
	defer sock.Close()

	s := &punchSession{sock: sock}
	s.detached.Store(true)
	s.closeAll() // 必须什么都不做

	if _, err := sock.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}); err != nil {
		t.Fatalf("移交后 closeAll 不应关闭 socket：%v", err)
	}

	// 未移交时应当真的释放
	s2 := &punchSession{sock: sock}
	s2.releaseAll()
	if _, err := sock.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}); err == nil {
		t.Fatal("releaseAll 之后 socket 必须已关闭")
	}
}

// ---------- 硬验收项 1：写隔离 ----------

// TestDirectWriteDoesNotBlockOtherPath 一条直连流永久阻塞：
//   - 调用方（写协程）永不阻塞：入队立即返回，即使队列已满；
//   - 别的路径照常收发（互不影响）。
func TestDirectWriteDoesNotBlockOtherPath(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	// ⚠️ 数据流写截止默认是 10s（防「拥塞被误判成路径死」），测试里在**这个实例**上缩短它
	pm.dataWriteDeadline = 300 * time.Millisecond

	// 路径 A：写永久阻塞
	stuck, stuckConn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	// ⚠️ setup() 是异步的（不能在探针回调里同步建流），所以要等流建好再操作
	waitFor(t, "A 的数据流建立", func() bool { return stuckConn.bulkStream() != nil })
	stuckConn.bulkStream().mu.Lock()
	stuckConn.bulkStream().blockWrite = true
	stuckConn.bulkStream().mu.Unlock()

	// 路径 B：正常
	_, okConn := newTestPathOwned(t, pm, host, "192.168.30.13", pathRoleInitiator)
	waitFor(t, "B 的数据流建立", func() bool { return okConn.bulkStream() != nil })

	// ① 调用方永不阻塞：把 A 的队列灌满（写协程一包都写不出去）
	dstA := ip4("192.168.30.12")
	chA := pm.sinkFor(dstA, planeTCP)
	if chA == nil {
		t.Fatal("A 应有直连队列")
	}
	start := time.Now()
	for i := 0; i < pathTxQueue*3; i++ {
		select {
		case chA <- pathPkt{plane: planeTCP, data: ipPacket(host.vip, dstA, []byte("x"))}:
		default: // 满 → 丢弃，与设计一致
		}
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("入队耗时 %v：调用方不该被阻塞", elapsed)
	}

	// ② 别的路径照常把包写出去
	dstB := ip4("192.168.30.13")
	chB := pm.sinkFor(dstB, planeTCP)
	if chB == nil {
		t.Fatal("B 应有直连队列")
	}
	payload := []byte("hello-B")
	chB <- pathPkt{plane: planeTCP, data: ipPacket(host.vip, dstB, payload)}
	waitFor(t, "B 路径写出数据帧", func() bool { return len(okConn.bulkStream().dataFrames()) >= 1 })

	frames := okConn.bulkStream().dataFrames()
	if len(frames) == 0 || frames[0][0] != byte(planeTCP) {
		t.Fatalf("B 的第一帧应带 TCP 平面标签，实际 %v", frames)
	}
	if !bytes.Equal(frames[0][1:], ipPacket(host.vip, dstB, payload)) {
		t.Fatal("B 的帧载荷应与原包一致")
	}

	// ③ 卡住的那条最终被判死（写截止 + 看门狗/写错误），路由被摘掉
	waitFor(t, "A 路径被降级", func() bool {
		_, ok := pm.routeVIP(dstA)
		return !ok
	})
	_ = stuck
}

// TestDirectWriteTimeoutDemotes 写超时 → L1-b：摘路由 + 关路径 + 排退避
func TestDirectWriteTimeoutDemotes(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.dataWriteDeadline = 300 * time.Millisecond // 本实例缩短（不动全局）
	defer pm.close()

	p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	waitFor(t, "数据流建立", func() bool { return conn.bulkStream() != nil })
	conn.bulkStream().mu.Lock()
	conn.bulkStream().blockWrite = true
	conn.bulkStream().mu.Unlock()

	dst := ip4("192.168.30.12")
	pm.sinkFor(dst, planeTCP) <- pathPkt{plane: planeTCP, data: ipPacket(host.vip, dst, []byte("y"))}

	// ⚠️ 等待条件必须是**降级全流程的终态**，不能只等「路由被摘掉」。
	//
	// `demote()` 的顺序契约是 ① 摘路由 → ② close → ③ 排退避；
	// 只等 ①（`routeVIP` 为 nil）就断言 ③ 的 backoff，存在真实窗口
	// （`-race -count=20` 负载下实测偶发：`path_test.go:1232 降级后必须排退避`）。
	// 这不是产品缺陷，是本用例的等待条件不充分。
	waitFor(t, "写超时后降级完成（摘路由 + Down + 已排退避）", func() bool {
		if _, ok := pm.routeVIP(dst); ok {
			return false
		}
		if p.state.Load() != pathStateDown {
			return false
		}
		pm.mu.Lock()
		_, backed := pm.backoff[dst]
		pm.mu.Unlock()
		return backed
	})
	if p.state.Load() != pathStateDown {
		t.Fatal("降级后状态应为 Down")
	}
	pm.mu.Lock()
	_, backed := pm.backoff[dst]
	pm.mu.Unlock()
	if !backed {
		t.Fatal("降级后必须排退避")
	}
}

// ---------- 硬验收项 3：demote 顺序 ----------

// TestDemoteOrderStrict 四条 L1 链路都进同一个 demote()，且顺序严格不可颠倒
func TestDemoteOrderStrict(t *testing.T) {
	cases := []struct {
		name    string
		trigger func(t *testing.T, p *directPath, c *fakeConn, host *fakeHost)
	}{
		{"L1-a 写返回错误", func(t *testing.T, p *directPath, c *fakeConn, host *fakeHost) {
			c.bulkStream().mu.Lock()
			c.bulkStream().writeErr = errors.New("stream reset")
			c.bulkStream().mu.Unlock()
			p.mgr.sinkFor(p.peer, planeTCP) <- pathPkt{plane: planeTCP, data: ipPacket(host.vip, p.peer, []byte("z"))}
		}},
		{"L1-b 写超时", func(t *testing.T, p *directPath, c *fakeConn, host *fakeHost) {
			c.bulkStream().mu.Lock()
			c.bulkStream().blockWrite = true
			c.bulkStream().mu.Unlock()
			p.mgr.sinkFor(p.peer, planeTCP) <- pathPkt{plane: planeTCP, data: ipPacket(host.vip, p.peer, []byte("z"))}
		}},
		{"L1-c 连接关闭", func(t *testing.T, p *directPath, c *fakeConn, host *fakeHost) {
			_ = c.CloseWithError(0, "test close")
		}},
		{"L1-d 读返回错误", func(t *testing.T, p *directPath, c *fakeConn, host *fakeHost) {
			c.bulkStream().fail(errors.New("read failed"))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := newFakeHost()
			pm := newPathManager(host)
			// 写超时用例要跨过数据写截止；默认 10s 太慢，本实例缩短
			pm.dataWriteDeadline = 300 * time.Millisecond
			defer pm.close()

			var order []string
			routeGoneAtClose := false
			pm.hooks = &pathHooks{
				RouteRemoved: func(vip string) { order = append(order, "route-removed") },
				PathClosed: func(vip string) {
					order = append(order, "path-closed")
					// 「先摘路由」的最强证据：关路径时表里已经没有它了
					_, ok := pm.routeVIP(ip4(vip))
					routeGoneAtClose = !ok
				},
				BackoffSet: func(vip string, d time.Duration) { order = append(order, "backoff-set") },
			}

			p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
			// setup() 是异步的：先等两条流建好，再注入故障
			waitFor(t, "数据流建立", func() bool { return conn.bulkStream() != nil })
			tc.trigger(t, p, conn, host)

			waitFor(t, "路径降级", func() bool {
				select {
				case <-p.demoted():
					return true
				default:
					return false
				}
			})

			want := []string{"route-removed", "path-closed", "backoff-set"}
			if !reflect.DeepEqual(order, want) {
				t.Fatalf("demote 顺序必须严格为 %v，实际 %v", want, order)
			}
			if !routeGoneAtClose {
				t.Fatal("关路径时路由必须已经摘掉（先 Store 新表 → 再关路径）")
			}
		})
	}
}

// ---------- 平面标签与投递 ----------

// TestPlaneTagRoundTripAndDelivery 平面标签：写出带标签、读入按标签投递到 TUN
func TestPlaneTagRoundTripAndDelivery(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	waitFor(t, "数据流建立", func() bool { return conn.bulkStream() != nil })

	// 出方向：中继写协程入队 → 路径写协程写帧
	pkt := ipPacket(host.vip, ip4("192.168.30.12"), []byte("payload"))
	pm.sinkFor(p.peer, planeUDP) <- pathPkt{plane: planeUDP, data: pkt}
	waitFor(t, "写出 UDP 平面帧", func() bool { return len(conn.bulkStream().dataFrames()) >= 1 })
	frame := conn.bulkStream().dataFrames()[0]
	if frame[0] != byte(planeUDP) {
		t.Fatalf("标签应为 UDP(%d)，实际 %d", planeUDP, frame[0])
	}
	if !bytes.Equal(frame[1:], pkt) {
		t.Fatal("载荷应原样")
	}

	// 入方向：把一帧塞进数据流的读队列 → 应投递到 TUN
	down := ipPacket(ip4("192.168.30.12"), host.vip, []byte("down"))
	conn.bulkStream().reads <- wireFrame(byte(planeTCP), down)
	waitFor(t, "下行投递到 TUN", func() bool { return host.deliveredCount() >= 1 })
	host.mu.Lock()
	got := host.delivered[0]
	host.mu.Unlock()
	if !bytes.Equal(got, ipPacket(ip4("192.168.30.12"), host.vip, []byte("down"))) {
		t.Fatal("投递内容应为去掉标签后的原始 IP 包")
	}

	// 未知标签：丢弃（fail-closed）
	conn.bulkStream().reads <- wireFrame(99, []byte("junk"))
	time.Sleep(100 * time.Millisecond)
	if n := host.deliveredCount(); n != 1 {
		t.Fatalf("未知平面标签应被丢弃，实际投递 %d 个", n)
	}
}

// TestIdleEvictDefaultsAreUserFriendly ⭐ review 追问 3 的守卫：
//   - 空闲淘汰必须**足够长**（短暂停不该被淘汰 → 否则用户看到「回中继又切直连」的抖动）；
//   - keepalive 不算活跃（否则这个机制永不触发）；
//   - 重建延迟要短（淘汰后的第一批流量不该等太久）。
//
// ⚠️ 这条测的是**默认值本身**（常量 + 新建实例的字段），与注入短门槛的机制测试分工明确。
func TestIdleEvictDefaultsAreUserFriendly(t *testing.T) {
	if defaultIdleEvict < 30*time.Minute {
		t.Fatalf("空闲淘汰默认门槛 %v 太短：正常使用里暂停几分钟就会被淘汰并重新打洞", defaultIdleEvict)
	}
	if defaultRecreateDelay > 5*time.Second {
		t.Fatalf("重建延迟默认值 %v 太长：淘汰后的第一批流量会明显感到卡顿", defaultRecreateDelay)
	}
	if pathMaxPaths <= 0 {
		t.Fatal("路径上限必须为正")
	}
	// 新建实例必须**采用**这些默认值（防「常量改了但忘了在 newPathManager 里接上」）
	pm := newPathManager(newFakeHost())
	defer pm.close()
	if pm.idleEvict != defaultIdleEvict || pm.recreateDelay != defaultRecreateDelay {
		t.Fatalf("新建管理器未采用默认门槛：idle=%v recreate=%v", pm.idleEvict, pm.recreateDelay)
	}
}

// TestIdleEvictionClosesPath 空闲淘汰真的会执行，并且**真的用注入的门槛变量**。
//
// ⭐ review 追问 4：这个测试必须能发现「代码里把门槛写死/改回去了」。
// 做法不是「让 lastUse 老到任何门槛都能过」（那样硬编码也绿），而是**两个方向都钉**：
//   - 空闲 5 分钟 + 门槛 50ms  → 必须淘汰（写死 ≥5min 的门槛就会失败）；
//   - 空闲 5 分钟 + 门槛 1 小时 → 必须**不**淘汰（写死「一律淘汰」也会失败）。
func TestIdleEvictionClosesPath(t *testing.T) {
	// ① 门槛远小于空闲时长 → 淘汰
	host := newFakeHost()
	pm := newPathManager(host)
	pm.idleEvict = 50 * time.Millisecond // 本实例短门槛（不动全局）
	p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	p.lastUse.Store(time.Now().Add(-5 * time.Minute).UnixMilli())
	pm.evictIdle()

	if _, ok := pm.routeVIP(p.peer); ok {
		t.Fatal("空闲 5 分钟 > 门槛 50ms 时必须淘汰（若失败，说明 evictIdle 没用 idleEvict 字段）")
	}
	if conn.Context().Err() == nil {
		t.Fatal("淘汰必须真的关闭连接")
	}
	pm.mu.Lock()
	until, ok := pm.evictAfter[p.peer]
	pm.mu.Unlock()
	if !ok || time.Until(until) > pm.recreateDelay+time.Second {
		t.Fatalf("淘汰后应记录较短的重建延迟，实际 %v ok=%v", time.Until(until), ok)
	}
	pm.close()

	// ② 门槛远大于空闲时长 → 必须保留（防「无条件淘汰一切」这类反向 bug）
	host2 := newFakeHost()
	pm2 := newPathManager(host2)
	pm2.idleEvict = time.Hour
	defer pm2.close()
	p2, _ := newTestPathOwned(t, pm2, host2, "192.168.30.13", pathRoleInitiator)
	p2.lastUse.Store(time.Now().Add(-5 * time.Minute).UnixMilli())
	pm2.evictIdle()
	if _, ok := pm2.routeVIP(p2.peer); !ok {
		t.Fatal("空闲 5 分钟 < 门槛 1 小时时不得淘汰（否则短暂停也会被清掉）")
	}
}

// TestResponderFailsWhenStreamCountInsufficient ⭐ review 追问 1：
// 声明都合法、但**数量不够**（发起方只开了 2 条）→ 必须在有限时间内失败并降级，
// 不能无限等（否则就是「direct 但不通、还不回落」的 limbo）。
func TestResponderFailsWhenStreamCountInsufficient(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	conn := newFakeConn()
	// 只送两条合法声明（bulk + crit），第三条永远不来
	for _, kind := range []streamKind{streamBulk, streamCrit} {
		s := newFakeStream()
		decl, _ := json.Marshal(streamDecl{Type: "stream", Kind: kind})
		s.reads <- append([]byte{0, 0, 0, byte(len(decl))}, decl...)
		conn.accepted <- s
	}

	p, _ := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleResponder,
		conn: conn, myVIP: host.vip,
	})
	p.setupTimeout = 300 * time.Millisecond // 注入短超时（默认 5s）
	pm.installRoute(p.peer, p)
	p.passTrialForTest() // ⭐ 1b-4：先验后切 ⇒ 这里显式让它通过（语义 = 「在用」）
	p.run()

	select {
	case <-p.demoted():
	case <-time.After(5 * time.Second):
		t.Fatal("流数量不足必须在 setup 超时后降级，不能无限等")
	}
	if _, ok := pm.routeVIP(p.peer); ok {
		t.Fatal("降级后路由必须已摘除（流量回落中继）")
	}
}

// TestResponderFailsWhenDeclarationNeverArrives ⭐ review 追问 1：
// 对端**开了流但不写声明** → 声明读必须有截止时间，不能永久卡住
func TestResponderFailsWhenDeclarationNeverArrives(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	conn := newFakeConn()
	conn.accepted <- newFakeStream() // 一条流，永远不写声明

	p, _ := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleResponder,
		conn: conn, myVIP: host.vip,
	})
	p.setupTimeout = 300 * time.Millisecond
	pm.installRoute(p.peer, p)
	p.passTrialForTest() // ⭐ 1b-4：同上（本用例只关心「声明读超时 ⇒ 降级」）
	p.run()

	select {
	case <-p.demoted():
	case <-time.After(5 * time.Second):
		t.Fatal("声明读必须带截止时间：对端只开流不写声明时必须超时降级")
	}
}

// TestStreamKindsIsTheSingleSourceOfTruth 流的数量与种类只有一处权威清单
func TestStreamKindsIsTheSingleSourceOfTruth(t *testing.T) {
	kinds := streamKinds()
	if len(kinds) != 3 {
		t.Fatalf("数据面流数应为 3（bulk/crit/ctrl），实际 %d", len(kinds))
	}
	seen := map[streamKind]bool{}
	for _, k := range kinds {
		if seen[k] {
			t.Fatalf("streamKinds() 里有重复项 %q", k)
		}
		seen[k] = true
	}
	for _, want := range []streamKind{streamBulk, streamCrit, streamCtrl} {
		if !seen[want] {
			t.Fatalf("streamKinds() 缺少 %q", want)
		}
	}
	// 每个流平面都必须能映射到这两种数据流之一（datagram 平面除外）
	for _, pl := range []pathPlaneIndex{planeTCP, planeUDP, planeMatch, planeGameTCP, planeICMP} {
		k := planeStream(pl)
		if k != streamBulk && k != streamCrit {
			t.Fatalf("平面 %s 映射到了非数据流 %q", planeName(pl), k)
		}
	}
	if planeStream(planeTCP) == planeStream(planeICMP) {
		t.Fatal("bulk TCP 与 ICMP 必须在不同流上（Q1：关键小包不被批量流量拖住）")
	}
}

// TestSilentPathWarnsButIsNotDemoted ⭐ review 追问 3：
// 「有包要发却上行 0 字节」必须显式告警，且**不能**降级（降级交给探针/写错误），
// 这样既不会把数据面 bug 掩盖成「正常空闲淘汰」，也不会误杀正常路径。
func TestSilentPathWarnsButIsNotDemoted(t *testing.T) {
	// 注入 0 门槛（改**本实例**字段，不动包级变量）。
	// ⚠️ 必须是 **0** 而不是 1ns：Windows 上 `time.Since()` 对极短间隔可能返回**正好 0**
	//    （1b-1 的 BUG-C 就是这个时钟粒度问题），那样 `up >= 1ns` 会是 false → 测试假失败。
	//    「默认门槛是否合理」由 TestHealthWarnDefaultsAreSane 单独守（review 追问 4 的同一套做法）。
	host := newFakeHost()
	pm := newPathManager(host)
	pm.silentWarn = 0
	defer pm.close()

	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	// ⚠️ 直接构造判据的输入（原子量），**不依赖写协程的时序**：
	//    这条测试要验的是「判据 + 不降级 + 面板暴露」，不是「写线程调度」；
	//    「写真的被阻塞后会怎样」由 TestDirectWriteTimeoutDemotes / TestBulkBlockedDoesNotDelayCritical 覆盖。
	p.enqueued.Store(1) // 有包要发给这条路径
	// bytesUp 保持 0（一个字节都没发出去）
	p.checkDataPlaneHealth() // 看门狗每秒调它一次；直接调用把时机变确定
	if !p.silentWarned.Load() {
		t.Fatalf("有包要发却上行 0 字节时必须告警（enqueued=%d upBytes=%d）",
			p.enqueued.Load(), p.bytesUp.Load())
	}
	infos := pm.Paths()
	if len(infos) != 1 || infos[0].Warn == "" {
		t.Fatalf("面板快照必须带上告警，实际 %+v", infos)
	}
	if p.state.Load() != pathStateUp {
		t.Fatal("告警不应该降级路径（降级交给探针/写错误）")
	}
}

// TestIdlePathDoesNotWarn 「用户真没用」不得告警（与数据面坏了区分开）
func TestIdlePathDoesNotWarn(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.silentWarn = 10 * time.Millisecond
	defer pm.close()

	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	time.Sleep(80 * time.Millisecond)
	p.checkDataPlaneHealth()
	if p.silentWarned.Load() || p.oneWayWarned.Load() {
		t.Fatal("没有任何包要发时不应告警（那只是用户没用流量）")
	}
}

// TestOneWayPathWarns 只出不进也要告警（对端可能没在读我们的流）
func TestOneWayPathWarns(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.oneWayWarn = 0 // 同上：0 而不是 1ns（Windows 上 time.Since 可能是正好 0）
	defer pm.close()

	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	p.bytesUp.Store(4096) // 发出了，但对端一个字节都没回
	time.Sleep(50 * time.Millisecond)
	p.checkDataPlaneHealth()
	if !p.oneWayWarned.Load() {
		t.Fatal("上行有量、下行恒 0 时必须告警")
	}
}

// TestHealthWarnDefaultsAreSane 告警门槛的守卫（防止被改到「几乎不可能触发」或「秒级误报」）
func TestHealthWarnDefaultsAreSane(t *testing.T) {
	if defaultSilentWarn < 5*time.Second || defaultSilentWarn > time.Minute {
		t.Fatalf("「数据面疑似未生效」默认门槛 %v 不合理（应在 5s~1m）", defaultSilentWarn)
	}
	if defaultOneWayWarn < defaultSilentWarn || defaultOneWayWarn > 5*time.Minute {
		t.Fatalf("「数据面疑似单向」默认门槛 %v 不合理（应 ≥ 前者且 ≤5m）", defaultOneWayWarn)
	}
	// 新建实例必须采用这些默认值
	pm := newPathManager(newFakeHost())
	defer pm.close()
	if pm.silentWarn != defaultSilentWarn || pm.oneWayWarn != defaultOneWayWarn {
		t.Fatalf("新建管理器未采用默认告警门槛：silent=%v oneWay=%v", pm.silentWarn, pm.oneWayWarn)
	}
}

// ---------- RTT 回归（真机「直连 RTT 恒 0ms」的三条根因） ----------

// TestRTTTextNeverShowsZero 显示层规则：测到了至少显示 1ms，没测到显示「待测」而不是 0s
func TestRTTTextNeverShowsZero(t *testing.T) {
	if got := rttText(0); got != "待测" {
		t.Fatalf("未测到时应显示「待测」，实际 %q", got)
	}
	if got := rttText(int64(500 * time.Microsecond)); got != "1ms" {
		t.Fatalf("亚毫秒 RTT 应折算成 1ms（1b-1 BUG-C 规则），实际 %q", got)
	}
	if got := rttText(int64(5 * time.Millisecond)); got != "5ms" {
		t.Fatalf("5ms 应显示 5ms，实际 %q", got)
	}
}

// TestPathSeedsRTTFromHandover 根因①：打洞阶段测到的 RTT 必须**继承**到路径上，
// 否则路径初始 RTT=0，而发起方永远测不到自己的值（见下一条测试）。
func TestPathSeedsRTTFromHandover(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	conn := newFakeConn()
	p, err := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleInitiator,
		conn: conn, myVIP: host.vip,
		rttDirect: 7 * time.Millisecond,
		rttQuic:   9 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("newDirectPath: %v", err)
	}
	// ⚠️ 第 3 步-D：直建的路径**不归管理器管**（没走 installRoute），
	//    所以 `defer pm.close()` 关不到它 ⇒ 必须显式注册关闭，否则其读协程永久滞留。
	t.Cleanup(p.close)
	if got := p.rttValue(); got != 7*time.Millisecond {
		t.Fatalf("应继承打洞测到的 rttDirect(7ms)，实际 %v", got)
	}
	// 只给 QUIC stats 时用它兜底
	conn2 := newFakeConn()
	p2, _ := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.13", peer: ip4("192.168.30.13"), role: pathRoleInitiator,
		conn: conn2, myVIP: host.vip, rttQuic: 4 * time.Millisecond,
	})
	t.Cleanup(p2.close) // 同上：直建路径不归管理器管
	if got := p2.rttValue(); got != 4*time.Millisecond {
		t.Fatalf("没有 rttDirect 时应回退 rttQuic(4ms)，实际 %v", got)
	}
}

// TestProbeEchoSetsRTT 根因④的一半：收到**自己那发探测**的回显 → 更新 RTT 并清失败计数
func TestProbeEchoSetsRTT(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	waitFor(t, "控制流建立", func() bool { return conn.ctrlStream() != nil })
	p.probeMiss.Store(1)

	// 造一条「5ms 前的探测」的回显（对端会把我的 TS 原样带回来）
	echo, _ := json.Marshal(pathCtrlMsg{Type: ctrlProbeEcho, Seq: 1, TS: time.Now().Add(-5 * time.Millisecond).UnixNano()})
	conn.ctrlStream().reads <- append([]byte{0, 0, 0, byte(len(echo))}, echo...)

	waitFor(t, "RTT 被回显更新", func() bool { return p.rttValue() > 0 })
	if got := p.rttValue(); got < 3*time.Millisecond || got > 200*time.Millisecond {
		t.Fatalf("RTT 应约为 5ms，实际 %v", got)
	}
	if p.probeMiss.Load() != 0 {
		t.Fatal("收到回显必须清失败计数")
	}
}

// TestBothSidesSendProbes 根因④：**发起方也必须自己发探测**
// （早期实现只有响应方发，导致发起方 RTT 恒 0、且只能靠「收不到探测」猜死活）
func TestBothSidesSendProbes(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.probeInterval = 20 * time.Millisecond
	defer pm.close()

	p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator) // 注意：发起方
	waitFor(t, "控制流建立", func() bool { return conn.ctrlStream() != nil })

	waitFor(t, "发起方自己发出探测帧", func() bool {
		for _, f := range conn.ctrlStream().frames() {
			var m pathCtrlMsg
			if json.Unmarshal(f, &m) == nil && m.Type == ctrlProbe {
				return true
			}
		}
		return false
	})
	_ = p
}

// TestNoEchoDemotesPath 根因④的判活：两侧对称探测后，「自己一直收不到回显」= 路径失效
// （单向黑洞/对端不读控制流，都能在 ~2 个探测周期内被发现并回落中继）
func TestNoEchoDemotesPath(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.probeInterval = 30 * time.Millisecond
	pm.probeMissLimit = 2
	defer pm.close()

	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)

	select {
	case <-p.demoted():
	case <-time.After(10 * time.Second):
		t.Fatal("一直收不到自己的探测回显时必须判路径失效（不能无限留在 direct）")
	}
	if _, ok := pm.routeVIP(p.peer); ok {
		t.Fatal("降级后路由必须已摘除")
	}
}

// TestPathInfoCountsBytesCarried ⭐ 字节数统计链路的守卫（用户建议的断言）：
// 直连路径承载 N 字节后，`Paths()` 必须报出 ≥N —— 把
// writeData/readStreamLoop 的计数 → pathEntry 原子量 → PathInfo 快照 这条链钉死。
//
// 背景：真机上「流量确实走直连（对端 HTTP 日志来源 IP 是 B 的 VIP、服务端流量 0），
// 但面板 ↑/↓ 恒为 0」。根因是**前端只在状态变化时拉取**（已单独修复），
// 这条测试保证后端这一段没有一起漏。
func TestPathInfoCountsBytesCarried(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	waitFor(t, "bulk 流建立", func() bool { return conn.bulkStream() != nil })

	// ① 上行：交给路径去发 → 写出后应计入 BytesUp
	up := ipPacket(host.vip, p.peer, []byte("hello-up"))
	pm.sinkFor(p.peer, planeTCP) <- pathPkt{plane: planeTCP, data: up}
	waitFor(t, "上行字节被统计", func() bool {
		infos := pm.Paths()
		return len(infos) == 1 && infos[0].BytesUp >= uint64(len(up))
	})

	// ② 下行：从直连流读到包 → 应计入 BytesDown
	down := ipPacket(p.peer, host.vip, []byte("hello-down"))
	conn.bulkStream().reads <- wireFrame(byte(planeTCP), down)
	waitFor(t, "下行字节被统计", func() bool {
		infos := pm.Paths()
		return len(infos) == 1 && infos[0].BytesDown >= uint64(len(down))
	})

	infos := pm.Paths()
	if infos[0].BytesUp != uint64(len(up)) {
		t.Fatalf("BytesUp 应为 %d（一个包），实际 %d", len(up), infos[0].BytesUp)
	}
	if infos[0].BytesDown != uint64(len(down)) {
		t.Fatalf("BytesDown 应为 %d（一个包），实际 %d", len(down), infos[0].BytesDown)
	}
	// ③ 事件里的统计也要带上（UI 的另一种入口）
	st := p.status(P2PStateDirect, P2PReasonOKDirect)
	if st.BytesUp != infos[0].BytesUp || st.BytesDown != infos[0].BytesDown {
		t.Fatalf("状态事件里的字节数应与快照一致：event=%d/%d snapshot=%d/%d",
			st.BytesUp, st.BytesDown, infos[0].BytesUp, infos[0].BytesDown)
	}
}

// TestPathInfoCountsDatagramBytes 不可靠 UDP 平面的字节数也要统计（走 datagram 不走流）
func TestPathInfoCountsDatagramBytes(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	waitFor(t, "bulk 流建立", func() bool { return conn.bulkStream() != nil })

	pkt := make([]byte, 300)
	p.writeDatagram(pkt)
	conn.datagrams <- pkt

	waitFor(t, "datagram 上下行都被统计", func() bool {
		infos := pm.Paths()
		return len(infos) == 1 && infos[0].BytesUp >= uint64(len(pkt)) && infos[0].BytesDown >= uint64(len(pkt))
	})
}

// TestBulkBlockedDoesNotDelayCritical ⭐ Q1 的核心验收：
// bulk 流被大批量数据堵死时，关键小包（ICMP/match/游戏 TCP）走**另一条流**照常发出，
// 而且不会因为 bulk 写超时被提前判死（数据写截止默认给得很宽松 = 10s）。
func TestBulkBlockedDoesNotDelayCritical(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	waitFor(t, "bulk 流建立", func() bool { return conn.bulkStream() != nil })
	waitFor(t, "crit 流建立", func() bool { return conn.critStream() != nil })

	// 把 bulk 流变成「写就永久阻塞」；crit 流保持正常
	conn.bulkStream().mu.Lock()
	conn.bulkStream().blockWrite = true
	conn.bulkStream().mu.Unlock()

	// 灌满 bulk 队列（模拟大批量 TCP）
	bulkCh := pm.sinkFor(p.peer, planeTCP)
	if bulkCh == nil {
		t.Fatal("TCP 平面应映射到 bulk 流")
	}
	for i := 0; i < pathTxQueue*2; i++ {
		select {
		case bulkCh <- pathPkt{plane: planeTCP, data: ipPacket(host.vip, p.peer, []byte("bulk"))}:
		default:
		}
	}

	// 关键小包：ICMP 与 match 都应立刻出现在 **crit 流**上
	critCh := pm.sinkFor(p.peer, planeICMP)
	if critCh == nil {
		t.Fatal("ICMP 平面应映射到 crit 流")
	}
	if pm.sinkFor(p.peer, planeICMP) != pm.sinkFor(p.peer, planeMatch) {
		t.Fatal("ICMP 与 match 应共用同一条 crit 流")
	}
	critCh <- pathPkt{plane: planeICMP, data: ipPacket(host.vip, p.peer, []byte("ping"))}

	waitFor(t, "ICMP 帧出现在 crit 流上", func() bool { return len(conn.critStream().dataFrames()) >= 1 })
	frame := conn.critStream().dataFrames()[0]
	if frame[0] != byte(planeICMP) {
		t.Fatalf("crit 流首帧标签应为 ICMP(%d)，实际 %d", planeICMP, frame[0])
	}

	// bulk 仍然堵着（一帧都没出去），且路径**没有被**提前判死
	if n := len(conn.bulkStream().dataFrames()); n != 0 {
		t.Fatalf("bulk 流被阻塞时不应有数据帧写出，实际 %d", n)
	}
	time.Sleep(400 * time.Millisecond) // 跨过「如果误用 1s 截止就会降级」的时间窗
	if _, ok := pm.routeVIP(p.peer); !ok {
		t.Fatal("bulk 写阻塞不应把整条路径判死（数据写截止默认 10s，拥塞是正常背压）")
	}
	if p.state.Load() != pathStateUp {
		t.Fatal("路径应仍在 direct 状态")
	}

	// 关键小包在 bulk 持续阻塞期间还能继续发（隔离是持续的，不是一次性的）
	critCh <- pathPkt{plane: planeMatch, data: ipPacket(host.vip, p.peer, []byte("match"))}
	waitFor(t, "crit 流第二条帧", func() bool { return len(conn.critStream().dataFrames()) >= 2 })
}

// TestResponderAcceptsAndClassifiesStreams ⭐ 修正「双方各读各开的流」那个真错：
// 响应方必须 Accept 对端开的流，并按**首帧声明**归类（bulk/crit/ctrl）。
func TestResponderAcceptsAndClassifiesStreams(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	conn := newFakeConn()
	// 模拟对端（发起方）开三条流并各写一个声明帧
	for _, kind := range []streamKind{streamCtrl, streamBulk, streamCrit} { // 故意乱序：不能靠顺序猜
		s := newFakeStream()
		decl, _ := json.Marshal(streamDecl{Type: "stream", Kind: kind})
		s.reads <- append([]byte{0, 0, 0, byte(len(decl))}, decl...)
		conn.accepted <- s
	}

	p, err := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleResponder,
		conn: conn, myVIP: host.vip,
	})
	if err != nil {
		t.Fatalf("newDirectPath: %v", err)
	}
	pm.installRoute(p.peer, p)
	p.passTrialForTest() // ⭐ 1b-4：先验后切 ⇒ 这里显式让它通过（sinkFor 只认 Up）
	p.run()

	waitFor(t, "响应方三条流归类完成", func() bool {
		bulk, crit, ctrl := p.streams()
		return bulk != nil && crit != nil && ctrl != nil
	})

	// 归类必须正确：走 crit 队列的包出现在 crit 那条被 accept 的流上
	critCh := pm.sinkFor(p.peer, planeICMP)
	critCh <- pathPkt{plane: planeICMP, data: ipPacket(host.vip, p.peer, []byte("ping"))}
	_, crit, _ := p.streams()
	fs, ok := crit.(*fakeStream)
	if !ok {
		t.Fatalf("crit 流类型不对: %T", crit)
	}
	waitFor(t, "响应方在 crit 流上写出", func() bool { return len(fs.frames()) >= 1 })
	if fs.frames()[0][0] != byte(planeICMP) {
		t.Fatal("响应方写出的帧应带 ICMP 标签")
	}
	// 而且它用的是**对端开的那条流**（不是自己新开的）
	conn.mu.Lock()
	openedByUs := len(conn.opened)
	conn.mu.Unlock()
	if openedByUs != 0 {
		t.Fatalf("响应方不应自己开流（应由发起方开、响应方 accept），实际开了 %d 条", openedByUs)
	}
}

// TestResponderRejectsBadStreamDeclaration 声明非法/重复 → 建流失败并降级（fail-closed）
func TestResponderRejectsBadStreamDeclaration(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	conn := newFakeConn()
	// 第一条声明非法（不是 stream 声明）
	junk := []byte(`{"t":"nope"}`)
	bad := newFakeStream()
	bad.reads <- append([]byte{0, 0, 0, byte(len(junk))}, junk...)
	conn.accepted <- bad

	p, _ := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleResponder,
		conn: conn, myVIP: host.vip,
	})
	pm.installRoute(p.peer, p)
	p.passTrialForTest() // ⭐ 1b-4：先验后切 ⇒ 这里显式让它通过
	p.run()

	select {
	case <-p.demoted():
	case <-time.After(5 * time.Second):
		t.Fatal("声明非法时必须降级（fail-closed）")
	}
	if _, ok := pm.routeVIP(p.peer); ok {
		t.Fatal("降级后路由必须已摘除")
	}
}

// TestCtrlLoopNilStreamNoPanic ⭐ 回归（1b-4 收尾期 `-race -count=20` 实测 panic）：
//
//	控制流还没建立时（setup 失败 / 路径正在关停）调 `ctrlLoop` 必须**直接退出**，
//	绝不能把 nil 交给 `readFrame`。
//
// 现场（完整 goroutine dump 摘录）：
//
//	panic: runtime error: invalid memory address or nil pointer dereference
//	io.ReadAtLeast({0x0, 0x0}, {0xc00054841c, 0x4, 0x4}, 0x4)
//	vpn-tool/backend/quic.readFrame({0x0, 0x0}, {0xc0010c0000, 0xffff, 0xffff})  client.go:2591
//	vpn-tool/backend/quic.(*directPath).ctrlLoop(...)                             path.go:2709
//
// 可达窗口（为什么不是「只在测试里」）：
//   - `run()` 的启动门只查 `alive()`，而 1b-4 让 **trial 也算活着**（试用期要跑探针）；
//   - `setup()` 失败时是「先 `close(ready)`、**再** `demote()`（=setState(Down)）」；
//   - 七条数据面 goroutine 等在 `ready` 上，`close` 一到就醒 ⇒ 存在真实窗口：
//     醒来时 state 仍是 trial（alive=true）但三条流还是 nil。
func TestCtrlLoopNilStreamNoPanic(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	p, _ := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleResponder,
		conn: newFakeConn(), myVIP: host.vip,
	})
	// ⚠️ 第 3 步-D：直建的路径不归管理器管（未走 installRoute）⇒ 显式注册关闭
	t.Cleanup(p.close)
	p.setState(pathStateTrial) // 关键前置：alive()==true 且三条流都还是 nil

	done := make(chan struct{})
	go func() { defer close(done); p.ctrlLoop() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ctrlLoop 在控制流缺失时必须立即退出（不能阻塞、更不能 panic）")
	}
}

// TestCtrlLoopReadsCtrlStreamUnderLock 回归（`-race` 有牙）：
//
//	`ctrlLoop` 必须走 `streams()`（锁下读）。若改回直读 `p.ctrlStream`，
//	本用例会在**未加锁的读**与 `setStreams()` 的**锁下写**之间形成数据竞争，
//	`-race` 直接报红（这正是 panic 的同源缺陷：读写既不同步、也可能读到 nil）。
func TestCtrlLoopReadsCtrlStreamUnderLock(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host) // checkInterval 默认 0 ⇒ 看门狗不跑，避免无关竞争
	defer pm.close()

	p, _ := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleResponder,
		conn: newFakeConn(), myVIP: host.vip,
	})
	// ⚠️ 第 3 步-D：直建的路径不归管理器管（未走 installRoute）⇒ 显式注册关闭
	t.Cleanup(p.close)
	p.setState(pathStateTrial)

	// 立刻可读失败的流：让 ctrlLoop 的 `readFrame` 快速返回（不阻塞用例）
	s := newFakeStream()
	s.mu.Lock()
	s.readErr = errors.New("fake read error")
	s.mu.Unlock()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			p.setStreams(nil, nil, s) // 与 ctrlLoop 的读并发
		}
	}()

	done := make(chan struct{})
	go func() { defer close(done); p.ctrlLoop() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	close(stop)
	wg.Wait()
}

// TestPathWaitTimeoutIsBounded ⭐ 第 3 步-B 回归（**有牙**）：
//
//	`setup()` 卡住（响应方等不到流）⇒ `waitTimeout()` 必须**在界内返回 true**，
//	而不是像裸 `p.wait()` 那样永久挂住调用方。
//
// 现场（`-race -count=20` 全包长跑实测，完整 goroutine dump 摘录）：
//
//	用例主 goroutine      : sync.(*WaitGroup).Wait   path_test.go:1053
//	结算 goroutine        : (*pathManager).installAfterTrial → (*directPath).wait   path.go:2161/2179
//	被等的那条路径        : (*directPath).setup → acceptStreams → AcceptStream（永不返回）
//
// ⚠️ 必须先关掉自动关停协程（`idleEvict=0` 会被看门狗当成「立刻空闲淘汰」），
// 否则淘汰逻辑会先把这条路径关掉，卡住的 setup 被放行 ⇒ 测不到超时分支。
func TestPathWaitTimeoutIsBounded(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.idleEvict = time.Hour     // 不要被空闲淘汰抢先关掉
	pm.checkInterval = time.Hour // 看门狗不跑，排除干扰
	defer pm.close()

	p, _ := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleResponder,
		conn: newFakeConn(), myVIP: host.vip,
	})
	// 让 setup 一直卡在 AcceptStream：fakeConn 的 accepted 里没有任何流，
	// 而 setup 超时被放宽到 1h ⇒ 三条流永远建不起来，数据面协程永不退出。
	p.setupTimeout = time.Hour
	p.run()

	old := pathWaitTimeout
	pathWaitTimeout = 300 * time.Millisecond
	defer func() { pathWaitTimeout = old }()

	done := make(chan bool, 1)
	go func() { done <- p.waitTimeout() }()
	select {
	case timedOut := <-done:
		if !timedOut {
			t.Fatal("setup 仍卡住时 waitTimeout 必须报超时（返回 true）")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waitTimeout 没有在界内返回 —— 无界等待（第 3 步-B 修的正是这个）")
	}

	// 收尾：close() 会取消 conn ⇒ 卡住的 setup 立刻退出（用例不留悬挂协程）
	p.close()
}

// TestPathWaitTimeoutFastPath 快速通道：协程能正常退出时**不白等**，返回 false。
func TestPathWaitTimeoutFastPath(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.idleEvict = time.Hour
	pm.checkInterval = time.Hour
	defer pm.close()

	p, _ := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleResponder,
		conn: newFakeConn(), myVIP: host.vip,
	})
	// setup 超时 200ms：responder 拿不到流 ⇒ setup 快速失败 ⇒ 全部协程退出
	p.setupTimeout = 200 * time.Millisecond
	p.run()

	old := pathWaitTimeout
	pathWaitTimeout = 5 * time.Second
	defer func() { pathWaitTimeout = old }()

	start := time.Now()
	if p.waitTimeout() {
		t.Fatal("协程已能正常退出时不应报超时")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("快速通道应远早于上界返回，实际 %v", elapsed)
	}
	p.close()
}

// TestWriteLoopExitsOnPathClose 写协程在路径关闭后必须退出（第 3 步-B）。
//
// ⚠️ 诚实标注（**这条用例的边界**）：它只能断言「关闭后 wait 能在界内返回」，
// **无法**区分「事件驱动退出」与「200ms 轮询 `alive()` 退出」—— 实测：
// `newTestPath` 造出来的路径在 `close()` 之前写协程就已因 `alive()==false` 退出了
// （`elapsed≈520µs`、`alive=false`），把界收紧到 20ms 也照样通过，属**弱用例**。
//
// 该修复的**主证据是端到端长跑**：`-race -count=20`（隔离用例从「90s 超时」→ `ok 3.6s`）。
func TestWriteLoopExitsOnPathClose(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.idleEvict = time.Hour
	pm.checkInterval = time.Hour
	defer pm.close()

	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)

	old := pathWaitTimeout
	pathWaitTimeout = 2 * time.Second
	defer func() { pathWaitTimeout = old }()

	p.close()
	if p.waitTimeout() {
		t.Fatalf("写协程必须在路径关闭后退出（实测等满了上界 %v）", pathWaitTimeout)
	}
}

// TestDatagramOversizeDropped 直连 datagram 超限丢弃（与中继语义一致）
func TestDatagramOversizeDropped(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	p, conn := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	waitFor(t, "数据流建立", func() bool { return conn.bulkStream() != nil })

	big := make([]byte, directMaxDatagram+1)
	p.writeDatagram(big)
	if p.bytesUp.Load() != 0 {
		t.Fatal("超限 datagram 不应计入上行字节（应该被丢弃）")
	}
	small := make([]byte, 100)
	p.writeDatagram(small)
	if p.bytesUp.Load() != uint64(len(small)) {
		t.Fatalf("正常 datagram 应计入上行，实际 %d", p.bytesUp.Load())
	}

	// 入方向
	conn.datagrams <- []byte("dgram-down")
	waitFor(t, "datagram 投递", func() bool { return host.deliveredCount() >= 1 })
}

// ---------- 上限、淘汰、快照 ----------

// TestPathCapEvictsLRU 路径数达上限时淘汰最久未使用者
func TestPathCapEvictsLRU(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	// ⚠️ 必须走 handleEstablished：上限与淘汰是在那里执行的（newTestPath 会绕过它）
	for i := 0; i < pathMaxPaths; i++ {
		vip := fmt.Sprintf("192.168.30.%d", 20+i)
		pm.handleEstablished(establishedReq{
			peerVIP: vip, peer: ip4(vip), role: pathRoleInitiator,
			conn: newFakeConn(), myVIP: host.vip,
		})
		// ⭐ 1b-4：先验后切 ⇒ 逐条结算试用期，本用例才有「8 条在用路径」的前置条件
		forceTrialPass(t, pm, vip)
	}
	if n := pm.pathCount(); n != pathMaxPaths {
		t.Fatalf("应有 %d 条路径（试用表 + 路由表），实际 %d", pathMaxPaths, n)
	}
	// 让第一条成为「最久未使用」
	oldest := ip4("192.168.30.20")
	pm.routeMu.Lock()
	(*pm.routes.Load())[oldest].lastUse.Store(time.Now().Add(-time.Hour).UnixMilli())
	pm.routeMu.Unlock()

	// 再加一条 → 触发淘汰
	pm.handleEstablished(establishedReq{
		peerVIP: "192.168.30.99", peer: ip4("192.168.30.99"), role: pathRoleInitiator,
		conn: newFakeConn(), myVIP: host.vip,
	})
	// ⭐ 1b-4：新路径要先通过试用期才会被装表（淘汰在 handleEstablished 入口就已发生）
	forceTrialPass(t, pm, "192.168.30.99")
	if _, ok := pm.routeVIP(oldest); ok {
		t.Fatal("最久未使用的路径应被淘汰")
	}
	if n := len(pm.snapshotPaths()); n != pathMaxPaths {
		t.Fatalf("淘汰后仍应保持 %d 条，实际 %d", pathMaxPaths, n)
	}
}

// TestPathsSnapshotForUI 快照字段（UI 面板用）
func TestPathsSnapshotForUI(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()

	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	p.bytesUp.Store(1000)
	p.bytesDown.Store(2000)
	p.rtt.Store(int64(5 * time.Millisecond))

	infos := pm.Paths()
	if len(infos) != 1 {
		t.Fatalf("应有 1 条，实际 %d", len(infos))
	}
	got := infos[0]
	if got.PeerVIP != "192.168.30.12" || got.State != "direct" || got.Role != pathRoleInitiator {
		t.Fatalf("快照基本字段不对: %+v", got)
	}
	if got.BytesUp != 1000 || got.BytesDown != 2000 || got.RTTMs != 5 || got.DirectSince == 0 {
		t.Fatalf("快照统计字段不对: %+v", got)
	}
}

// ---------- 事件字段锁 ----------

// TestP2PStatusJSONFieldLock P2PStatus 的线上字段名必须逐一登记（防止改字段忘了同步前端）
func TestP2PStatusJSONFieldLock(t *testing.T) {
	want := []string{
		"peerVip", "state", "reasonCode", "reasonText", "path",
		"rttDirectMs", "rttQuicMs", "at", "retryable",
		"trigger", "pathState", "bytesUp", "bytesDown", "directSince",
	}
	typ := reflect.TypeOf(P2PStatus{})
	if typ.NumField() != len(want) {
		t.Fatalf("P2PStatus 字段数 %d != 名单 %d（新增字段必须同时更新本测试与前端）",
			typ.NumField(), len(want))
	}
	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		seen[name] = true
		if !contains(want, name) {
			t.Fatalf("字段 %s 的线上名 %q 没有登记", typ.Field(i).Name, name)
		}
	}
	for _, w := range want {
		if !seen[w] {
			t.Fatalf("名单里的 %q 在结构体里找不到", w)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
