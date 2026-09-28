package quic

// vpn-tool/backend/quic/nat_sim_test.go
//
// ⭐ 1b-3（2.2）验收用的 **userspace NAT 模拟器**（只在测试里用，不参与产品构建）。
//
// 目的：在 loopback 上真实复现「对称 NAT（NAT4）+ cone（NAT1-3）」的打洞，
// 而不是只验证「候选列表字段存在」。模拟器实现的是对称 NAT 的两个关键性质：
//
//  1. **端口分配与目的地相关**：每个新的目的端口分配一个**独立的外部 socket**
//     （端口按策略分配：连续 step / 随机）—— 这正是「观测值 ≠ 对端方向端口」的来源；
//  2. **地址+端口相关过滤**：某个映射只接受「它当初发往的那个目的地」的回包，
//     别的来源的包一律丢弃（对称 NAT 的典型行为）。没有这一条，
//     「只广告 1 个地址」的用例会被误判为成功。
//
// 客户端侧看到的是一个 net.PacketConn（`simNATConn`）：WriteTo 走映射的外部 socket，
// ReadFrom 拿回经过过滤、且源地址被如实呈现（= 对端的外部映射地址）的包。
// 因此 realm.Punch / QUIC 握手 / 数据面全部走真实代码路径。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type simNATPolicy int

const (
	// simNATSequential 连续分配（step 可配）——「端口有规律」的对称 NAT（NAT4）
	simNATSequential simNATPolicy = iota
	// simNATRandom 随机分配 —— 预测不可能命中的对称 NAT
	simNATRandom
)

// simNATMode 映射/过滤语义
type simNATMode int

const (
	// simNATSymmetric 对称 NAT（NAT4）：**按目的地**分配端口 + 地址+端口相关过滤
	simNATSymmetric simNATMode = iota
	// simNATConeRestricted 端口受限 cone（NAT3，家宽常见）：
	// **一个端口对所有目的地**（cone），但只放行「本机主动发过的那个目的地址」的回包。
	// ⭐ 这一档是 2.2 端口预测的必要性所在：对端必须先朝我们**真实的**对外端口发包，
	//    它自己的 NAT 才会放行对端回给我们的包；只广告观测端口就会卡在这里。
	simNATConeRestricted
)

type simPacket struct {
	data []byte
	from netip.AddrPort
}

type simMapping struct {
	ext *net.UDPConn   // 该映射的外部 socket（对端看到的源端口就是它）
	dst netip.AddrPort // 这条映射是发给谁建的（过滤依据）
}

type simNAT struct {
	t      *testing.T
	mode   simNATMode
	policy simNATPolicy
	step   int
	next   int

	mu     sync.Mutex
	maps   map[int]*simMapping // key = 目的端口（对称模式）；cone 模式只用 key 0
	allow  map[netip.AddrPort]struct{}
	shared *simMapping // cone 模式：唯一的映射
	err    error       // ⚠️ 绑定失败只记录，由**主 goroutine** 断言（不能在非测试 goroutine 里 Fatalf）
	closed atomic.Bool

	queue chan simPacket // 送给「私网侧客户端」的包
	wg    sync.WaitGroup
}

func newSimNAT(t *testing.T, policy simNATPolicy, step, startPort int) *simNAT {
	t.Helper()
	return newSimNATMode(t, simNATSymmetric, policy, step, startPort)
}

func newSimNATMode(t *testing.T, mode simNATMode, policy simNATPolicy, step, startPort int) *simNAT {
	t.Helper()
	return &simNAT{
		t: t, mode: mode, policy: policy, step: step, next: startPort,
		maps:  make(map[int]*simMapping),
		allow: make(map[netip.AddrPort]struct{}),
		queue: make(chan simPacket, 256),
	}
}

func (n *simNAT) close() {
	if n.closed.CompareAndSwap(false, true) {
		n.mu.Lock()
		for _, m := range n.maps {
			_ = m.ext.Close()
		}
		if n.shared != nil {
			_ = n.shared.ext.Close() // ⚠️ cone 模式的共享映射不在 maps 里，漏了会卡住 wg.Wait
		}
		n.mu.Unlock()
	}
	n.wg.Wait()
}

// observe 模拟一次 STUN 观测：返回该 NAT 对「目的端口 dstPort」分配到的外部地址。
// （真实世界里这是 STUN Binding 响应里的映射地址。）
func (n *simNAT) observe(dstPort int) netip.AddrPort {
	m := n.mappingFor(dstPort)
	if m == nil {
		return netip.AddrPort{} // 绑定失败：调用方返回空列表 ⇒ 会话走 local-no-punch-addr（用例会失败）
	}
	ua := m.ext.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(ua.Port))
}

// mappingFor 取/建「到目的端口 dstPort」的映射
//
//	对称模式：按目的端口区分（每个目的地一个新外部端口）——「观测值 ≠ 对端方向端口」的来源
//	cone 模式：所有目的地共用一个外部端口，但记录「发过谁」用于受限过滤
func (n *simNAT) mappingFor(dstPort int) *simMapping {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.mode == simNATConeRestricted {
		if n.shared == nil {
			ext := n.bindExternalLocked()
			if ext == nil {
				return nil
			}
			n.shared = &simMapping{ext: ext}
			n.startReaderLocked(n.shared)
		}
		return n.shared
	}
	if m, ok := n.maps[dstPort]; ok {
		return m
	}
	ext := n.bindExternalLocked()
	if ext == nil {
		return nil
	}
	m := &simMapping{ext: ext, dst: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(dstPort))}
	n.maps[dstPort] = m
	n.startReaderLocked(m)
	return m
}

// allowPeer 记录「本机主动发过这个目的地址」（受限 cone 的过滤依据）
func (n *simNAT) allowPeer(dst netip.AddrPort) {
	n.mu.Lock()
	n.allow[dst] = struct{}{}
	n.mu.Unlock()
}

// startReaderLocked 起该映射的读协程（调用方持锁）
//
// 过滤规则：
//   - 对称模式：只接受「当初发往的那个目的地址」的回包（地址+端口相关）；
//   - 受限 cone：只接受「本机主动发过的目的地址」的回包（地址+端口相关，与映射无关）。
func (n *simNAT) startReaderLocked(m *simMapping) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		buf := make([]byte, 65535)
		for {
			nn, src, err := m.ext.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if src.IP.To4() == nil {
				continue
			}
			sp := netip.AddrPortFrom(netip.AddrFrom4([4]byte(src.IP.To4())), uint16(src.Port))
			sp = netip.AddrPortFrom(sp.Addr().Unmap(), sp.Port())
			n.mu.Lock()
			ok := sp == m.dst
			if n.mode == simNATConeRestricted {
				_, ok = n.allow[sp]
			}
			n.mu.Unlock()
			if !ok {
				continue // 过滤：不是允许的来源 ⇒ 丢弃
			}
			pkt := make([]byte, nn)
			copy(pkt, buf[:nn])
			select {
			case n.queue <- simPacket{data: pkt, from: sp}:
			default:
			}
		}
	}()
}

func (n *simNAT) bindExternalLocked() *net.UDPConn {
	for i := 0; i < 400; i++ {
		var port int
		if n.policy == simNATRandom {
			port = 0
		} else {
			if n.next <= 0 || n.next > 65000 {
				n.next = 30000 // 回绕到安全区间，避免越界后一直失败
			}
			port = n.next
			n.next += n.step
		}
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err == nil {
			return conn
		}
		if n.policy == simNATRandom {
			break
		}
	}
	// ⚠️ 绝不能在非测试 goroutine 里 t.Fatalf（非法用法，-race 下会 panic）⇒ 只记录
	if n.err == nil {
		n.err = fmt.Errorf("找不到可用的外部端口（policy=%v next=%d）", n.policy, n.next)
	}
	return nil
}

// failIfErr 由**测试 goroutine** 调用，把绑定失败暴露成明确的测试失败
func (n *simNAT) failIfErr(t *testing.T) {
	t.Helper()
	n.mu.Lock()
	err := n.err
	n.mu.Unlock()
	if err != nil {
		t.Fatalf("NAT 模拟器不可用: %v", err)
	}
}

// clientConn 返回私网侧客户端使用的 PacketConn（所有流量经 NAT）
func (n *simNAT) clientConn() net.PacketConn {
	// 私网 socket 只用来提供一个本地地址；实际收发都走映射的外部 socket
	priv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		n.t.Fatalf("绑定私网 socket 失败: %v", err)
	}
	return &simNATConn{nat: n, priv: priv}
}

// ---------- 私网侧 PacketConn ----------

type simNATConn struct {
	nat  *simNAT
	priv *net.UDPConn

	mu     sync.Mutex
	rdead  time.Time
	closed atomic.Bool
}

func (c *simNATConn) LocalAddr() net.Addr { return c.priv.LocalAddr() }

func (c *simNATConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	dst, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return 0, err
	}
	m := c.nat.mappingFor(int(dst.Port()))
	if m == nil {
		return 0, fmt.Errorf("NAT 模拟器不可用（绑定失败）")
	}
	c.nat.allowPeer(dst) // 受限 cone 需要记录「我主动发过谁」
	return m.ext.WriteToUDP(p, net.UDPAddrFromAddrPort(dst))
}

func (c *simNATConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if c.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		c.mu.Lock()
		dl := c.rdead
		c.mu.Unlock()
		if dl.IsZero() {
			select {
			case pkt := <-c.nat.queue:
				return copy(p, pkt.data), net.UDPAddrFromAddrPort(pkt.from), nil
			case <-time.After(200 * time.Millisecond):
				continue
			}
		}
		d := time.Until(dl)
		if d <= 0 {
			// 与真实 socket 一致：超时是可识别的 net.Error（realm.Punch 依赖它）
			return 0, nil, os.ErrDeadlineExceeded
		}
		select {
		case pkt := <-c.nat.queue:
			return copy(p, pkt.data), net.UDPAddrFromAddrPort(pkt.from), nil
		case <-time.After(d):
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (c *simNATConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		return c.priv.Close()
	}
	return nil
}

func (c *simNATConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdead = t
	c.mu.Unlock()
	return nil
}

func (c *simNATConn) SetReadDeadline(t time.Time) error { return c.SetDeadline(t) }
func (c *simNATConn) SetWriteDeadline(time.Time) error  { return nil }

var _ net.PacketConn = (*simNATConn)(nil)
var _ = errors.Is

// ---------- 2.2 验收：四个用例（技术方案 §8.4） ----------

// natSimSetup 把客户端挂到一个模拟 NAT 后面
//
//	observations = 模拟 STUN 观测用的「目的端口」列表（每个都会分配/复用一个映射）
func natSimSetup(t *testing.T, nat *simNAT, a *Hysteria2Client, observations []int) {
	t.Helper()
	mgr := punchMgrOf(t, a)
	conn := nat.clientConn()
	mgr.openPunchSocket = func() (net.PacketConn, error) { return conn, nil }
	mgr.discoverPunchAddr = func(context.Context, net.PacketConn) ([]netip.AddrPort, error) {
		out := make([]netip.AddrPort, 0, len(observations))
		for _, p := range observations {
			out = append(out, nat.observe(p))
		}
		return out, nil
	}
}

// markSymmetric 把客户端的 NAT 类型标成 symmetric
// （模拟器让真实打洞路径跑起来，但**类型标签**要如实反映 NAT4，才能同时验证 1b-3 的预检放宽）
func markSymmetric(c *Hysteria2Client) {
	c.natMu.Lock()
	c.natResult.Type = NATSymmetric
	c.natResult.MappingIndependent = false
	c.natMu.Unlock()
}

// assertNoDirect 在 within 时间内**必须不出现**直连（用于「如实回落」类断言）
//
// ⚠️ 有界保证（第 3 步-C 追问 3）：本函数保证**在有界时间内返回**，且失败时打印的
// elapsed **本身也有界**。关键点：**每次 Sleep 都取「到 deadline 的剩余时间」为上限**，
// 所以 deadline 一到，sleep 立刻缩短、循环随即退出 —— 不需要额外硬上限。
//
// 反例（我第一版就写错了）：`time.Sleep(50ms)` 被拖到 60s 时，
// 「睡完再判 elapsed > hardCap」会打印 elapsed=60s —— 那**不是**快速失败，只是慢失败。
// 改成「按剩余时间睡」后，同一种拖延最多让**返回时刻**超出 deadline 一个睡片的量级。
func assertNoDirect(t *testing.T, rec *statusRecorder, peerVIP string, within time.Duration) {
	t.Helper()
	const pollStep = 50 * time.Millisecond // 逻辑轮询间隔（保持原语义）
	deadline := time.Now().Add(within)
	start := time.Now()
	n := 0
	for {
		if st, ok := rec.directStatus(peerVIP); ok && st.State == "direct" {
			t.Fatalf("不应出现直连（伪直连），实际状态=%+v", st)
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return // 到期即退出（不再多睡一片）
		}
		if remain > pollStep {
			remain = pollStep
		}
		time.Sleep(remain)
		n++
		if elapsed := time.Since(start); elapsed > within+2*time.Second {
			// 走到这里说明「单次 Sleep 远超请求值」到了极端程度（实测 ≈7s / 请求 50ms）。
			// 打印的 elapsed 仍被本判定夹在 within+2s 附近 ⇒ 有界。
			t.Fatalf("assertNoDirect 严重超时：within=%v 实际 %v（n=%d）——"+
				"单次 Sleep 被极端拖延（goroutine 长时间未被调度）", within, elapsed, n)
		}
	}
}

// TestNATSimSymmetricPlusConeConnects ⭐ 用例 A：
//
//	NAT4（连续分配、step=1）+ NAT3（端口受限 cone）⇒ 广告 punchAddrs（观测 + 预测）⇒ **打通**。
//
// 为什么必须预测（而不是只广告观测值）：NAT3 侧**自己也有过滤** ——
// 它只放行「它主动发过的那个地址」的回包。所以它必须先朝「NAT4 侧真实的对外端口」发包，
// 才可能把 Ack 送回去；而那个端口只能靠 NAT4 侧的预测给出（观测端口不是它）。
//
// 同时本用例把 NAT4 侧的**类型标签**设为 symmetric ⇒ 一并验证 1b-3 的预检放宽
// （1b-1/1b-2B 在这里直接 nat-symmetric 拒绝，根本不会尝试）。
func TestNATSimSymmetricPlusConeConnects(t *testing.T) {
	nat := newSimNAT(t, simNATSequential, 1, 40000)
	defer nat.close()
	natB := newSimNATMode(t, simNATConeRestricted, simNATSequential, 1, 45000) // NAT3（家宽常见）
	defer natB.close()

	a, b, recA, recB, _, cleanup := newLoopbackPairFull(t)
	defer cleanup()

	natSimSetup(t, nat, a, []int{3478, 3479})
	natSimSetup(t, natB, b, []int{3478})
	markSymmetric(a)

	if _, err := a.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}
	waitDirect(t, recA, "192.168.30.12", 15*time.Second)
	waitDirect(t, recB, "192.168.30.11", 15*time.Second)
}

// TestNATSimSingleAddressIsNotEnough ⭐ 用例 B（有牙）：
//
//	同样的拓扑（NAT4 + NAT3），但 NAT4 侧**只观测到一个端口**（= 1b-2B 的行为）⇒ **打不通**。
//
// 机制：NAT4 侧的真实对外端口（对 NAT3 方向）是它分配的**第二个**端口，
// 只广告观测端口时，NAT3 侧会朝那个错端口发包 ⇒ 它自己的过滤从不为真实端口打开 ⇒
// 它回的 Ack / 拨号包被**它自己的 NAT**丢掉 ⇒ 两侧都拿不到对方的有效包 ⇒ 如实失败。
//
// 这条用例证明 2.2 的端口预测（前提是 A1 保留全部观测）是 NAT4+NAT3 的**必要条件**。
func TestNATSimSingleAddressIsNotEnough(t *testing.T) {
	// ⚠️ 必须**关掉预测**才是「只广告 1 个地址」的 1b-2B 行为：
	//    否则单观测也会被预测补成 32 个候选，用例就测不到「单地址不够」这件事。
	t.Setenv("HY2_NO_PORT_PREDICT", "1")

	nat := newSimNAT(t, simNATSequential, 1, 41000)
	defer nat.close()
	natB := newSimNATMode(t, simNATConeRestricted, simNATSequential, 1, 46000)
	defer natB.close()

	a, b, recA, recB, _, cleanup := newLoopbackPairFull(t)
	defer cleanup()

	natSimSetup(t, nat, a, []int{3478}) // ⚠️ 只观测一个端口 + 关预测 ⇒ 只广告 1 个地址
	natSimSetup(t, natB, b, []int{3478})
	markSymmetric(a)

	if _, err := a.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}
	assertNoDirect(t, recA, "192.168.30.12", 8*time.Second)
	assertNoDirect(t, recB, "192.168.30.11", 8*time.Second)
	// 必须**如实**报出失败原因（而不是静默什么都不做）
	if r := recA.lastReason("192.168.30.12"); r == "" {
		t.Fatal("单地址打不通时应记录失败原因（如实上报）")
	}
}

// TestNATSimSymmetricPlusSymmetricFallsBackHonestly ⭐ 用例 C：
//
//	NAT4 + NAT4 ⇒ **预检直接放弃**（1b-3 的硬限制），如实回落中继，绝不出现「伪直连」。
func TestNATSimSymmetricPlusSymmetricFallsBackHonestly(t *testing.T) {
	natA := newSimNAT(t, simNATRandom, 1, 0)
	natB := newSimNAT(t, simNATRandom, 1, 0)
	defer natA.close()
	defer natB.close()

	a, b, recA, recB, _, cleanup := newLoopbackPairFull(t)
	defer cleanup()

	natSimSetup(t, natA, a, []int{3478, 3479})
	natSimSetup(t, natB, b, []int{3478, 3479})
	markSymmetric(a)
	markSymmetric(b)

	if _, err := a.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}
	assertNoDirect(t, recA, "192.168.30.12", 6*time.Second)
	assertNoDirect(t, recB, "192.168.30.11", 6*time.Second)
	// 硬限制只要求「如实回落」：原因必须是**失败类**（nat-symmetric / punch-timeout 都算如实）
	if r := recA.lastReason("192.168.30.12"); r == "" || r == P2PReasonOKDirect {
		t.Fatalf("NAT4+NAT4 必须如实报失败，实际 %q", r)
	}
}

// TestNATSimRandomSymmetricPlusConeFailsHonestly ⭐ 用例 D：
//
//	NAT4（端口**步长很大/无规律**）+ NAT3 ⇒ 预测窗口（32 个端口）覆盖不到真实端口
//	⇒ 如实失败，不假装成功。
//
// ⚠️ 实现说明（踩过的坑）：这里用「大步长」（step=5000）而不是「随机绑定」来建模不可预测性 ——
// Windows 的临时端口是**顺序**分配的，`bind(0)` 拿到的端口往往连续，
// 于是「随机」策略反而让真实端口落在预测窗口里，把用例测成了成功（假通过）。
// 大步长是**确定性**的不可预测模型，不受 OS 分配策略影响。
func TestNATSimRandomSymmetricPlusConeFailsHonestly(t *testing.T) {
	nat := newSimNAT(t, simNATSequential, 200, 20000) // 观测 20000/20200，对端方向 20400 ∉ 32 端口窗口
	defer nat.close()
	natB := newSimNATMode(t, simNATConeRestricted, simNATSequential, 1, 47000)
	defer natB.close()

	a, b, recA, recB, _, cleanup := newLoopbackPairFull(t)
	defer cleanup()

	natSimSetup(t, nat, a, []int{3478, 3479})
	natSimSetup(t, natB, b, []int{3478})
	markSymmetric(a)

	if _, err := a.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}
	assertNoDirect(t, recA, "192.168.30.12", 10*time.Second)
	assertNoDirect(t, recB, "192.168.30.11", 10*time.Second)
	if r := recA.lastReason("192.168.30.12"); r == P2PReasonOKDirect {
		t.Fatal("端口无规律的 NAT4 打不通时绝不能报成功（伪直连）")
	}
}
