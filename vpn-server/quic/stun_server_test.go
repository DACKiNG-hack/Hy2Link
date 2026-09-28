package quic

// vpn-server/quic/stun_server_test.go
//
// 内置 STUN 端点的测试：能正确应答 Binding 请求、只应答 Binding 请求、
// 限流生效、端口为 0 时**不监听**（P2P 关闭时也不启动 —— 由 manager 的
// TestBuiltinSTUNGatingOnP2P 覆盖）。

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/stun"
)

func TestBuiltinSTUNRespondsBindingRequest(t *testing.T) {
	// 用 0 作为基准端口无法预知端口，这里显式挑一个高位端口避免冲突
	base := 48010
	b := StartBuiltinSTUN(base)
	if b == nil {
		t.Fatal("应启动成功")
	}
	defer b.Close()
	if len(b.Ports()) != builtinSTUNMaxPorts {
		t.Skipf("端口 %d/%d 被占用，跳过（本机环境限制）", base, base+1)
	}

	// 客户端：普通 UDP socket（模拟 realm.Discover）
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("客户端 socket: %v", err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)

	req, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: b.Ports()[0]}
	if _, err := conn.WriteToUDP(req.Raw, target); err != nil {
		t.Fatalf("发送请求: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("未收到响应: %v", err)
	}

	res := &stun.Message{Raw: buf[:n]}
	if err := res.Decode(); err != nil {
		t.Fatalf("响应解码失败: %v", err)
	}
	if res.Type != stun.BindingSuccess {
		t.Fatalf("类型应为 BindingSuccess，实际 %v", res.Type)
	}
	// ⭐ 事务 ID 必须原样回填（否则客户端无法把响应与请求对上）
	if res.TransactionID != req.TransactionID {
		t.Fatal("Transaction ID 必须与请求一致")
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(res); err != nil {
		t.Fatalf("缺少 XOR-MAPPED-ADDRESS: %v", err)
	}
	if !xor.IP.Equal(local.IP) || xor.Port != local.Port {
		t.Fatalf("观测地址应为 %v，实际 %v:%d", local, xor.IP, xor.Port)
	}
	// 两个端点的观测结果必须一致（同一 socket → 端点无关映射）
	// 统计是异步累加的，轮询一下再断言
	var served, dropped uint64
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		served, dropped = b.Stats()
		if served > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if served != 1 || dropped != 0 {
		t.Fatalf("统计应为 served=1 dropped=0，实际 served=%d dropped=%d", served, dropped)
	}
}

func TestBuiltinSTUNIgnoresNonBindingRequest(t *testing.T) {
	base := 48020
	b := StartBuiltinSTUN(base)
	if b == nil {
		t.Fatal("应启动成功")
	}
	defer b.Close()
	if len(b.Ports()) != builtinSTUNMaxPorts {
		t.Skipf("端口 %d/%d 被占用，跳过", base, base+1)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("客户端 socket: %v", err)
	}
	defer conn.Close()
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: b.Ports()[0]}

	// ① 一个 Binding Success（响应，不是请求）② 垃圾字节 ③ 空包
	success, err := stun.Build(stun.TransactionID, stun.BindingSuccess)
	if err != nil {
		t.Fatalf("构造: %v", err)
	}
	if _, err := conn.WriteToUDP(success.Raw, target); err != nil {
		t.Fatalf("发送: %v", err)
	}
	if _, err := conn.WriteToUDP([]byte("not-a-stun-packet-at-all"), target); err != nil {
		t.Fatalf("发送: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	if _, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Fatal("非 Binding 请求不应得到任何响应（防反射/防回环）")
	}
	if _, dropped := b.Stats(); dropped == 0 {
		t.Fatal("应记录丢弃计数")
	}
}

func TestBuiltinSTUNRateLimit(t *testing.T) {
	base := 48030
	b := StartBuiltinSTUN(base)
	if b == nil {
		t.Fatal("应启动成功")
	}
	defer b.Close()
	if len(b.Ports()) != builtinSTUNMaxPorts {
		t.Skipf("端口 %d/%d 被占用，跳过", base, base+1)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("客户端 socket: %v", err)
	}
	defer conn.Close()
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: b.Ports()[0]}

	const burst = builtinSTUNRatePerIP + 20
	for i := 0; i < burst; i++ {
		req, err := stun.Build(stun.TransactionID, stun.BindingRequest)
		if err != nil {
			t.Fatalf("构造: %v", err)
		}
		if _, err := conn.WriteToUDP(req.Raw, target); err != nil {
			t.Fatalf("发送: %v", err)
		}
	}
	// 给服务端一点处理时间
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		served, dropped := b.Stats()
		if served+dropped >= uint64(burst) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	served, dropped := b.Stats()
	if served == 0 {
		t.Fatal("至少应服务一部分请求")
	}
	if dropped == 0 {
		t.Fatalf("超过 %d/s 的部分应被限流丢弃（served=%d dropped=%d）",
			builtinSTUNRatePerIP, served, dropped)
	}
}

// TestBuiltinSTUNDisabledWhenPortZero 端口 0 = 显式关闭 → 不监听任何端口
func TestBuiltinSTUNDisabledWhenPortZero(t *testing.T) {
	if b := StartBuiltinSTUN(0); b != nil {
		b.Close()
		t.Fatal("stunPort=0 时应返回 nil（不启动）")
	}
	if b := StartBuiltinSTUN(-1); b != nil {
		b.Close()
		t.Fatal("负数端口应视同关闭")
	}
	// nil 接收者也要安全
	var nilResp *BuiltinSTUN
	if nilResp.Announce() != "off" {
		t.Fatal("nil 的 Announce 应为 off")
	}
	nilResp.Close()
	if len(nilResp.Ports()) != 0 {
		t.Fatal("nil 的 Ports 应为空")
	}
}

// TestBuiltinSTUNAnnounceFormats 公告格式（写进 DHCP 第 12 段）
func TestBuiltinSTUNAnnounceFormats(t *testing.T) {
	b := &BuiltinSTUN{ports: []int{3478, 3479}}
	if got := b.Announce(); got != "3478|3479" {
		t.Fatalf("公告应为 3478|3479，实际 %q", got)
	}
	if got := (&BuiltinSTUN{ports: []int{3479}}).Announce(); got != "3479" {
		t.Fatalf("单端点公告应为 3479，实际 %q", got)
	}
	if got := (&BuiltinSTUN{}).Announce(); got != "off" {
		t.Fatalf("没有端点应为 off，实际 %q", got)
	}
}

// TestBuiltinSTUNGatingOnP2P（验收要求之一）
//
//	P2P 关闭（或端口为 0）时内置 STUN 端点**不启动** —— 连 socket 都不建。
//
// 判定点就是 manager.Start 用的那个 ShouldStartBuiltinSTUN，所以这里断言的是
// 真实代码路径；再用 socket 层面确认「没启动 = 端口空闲 / 启动了 = 端口被占」。
func TestBuiltinSTUNGatingOnP2P(t *testing.T) {
	const port = 48080

	if ShouldStartBuiltinSTUN(false, port) {
		t.Fatal("P2P 关闭时不应启动内置 STUN")
	}
	if ShouldStartBuiltinSTUN(true, 0) {
		t.Fatal("stunPort=0 视为显式关闭")
	}
	if ShouldStartBuiltinSTUN(false, 0) {
		t.Fatal("两个条件都不满足时不应启动")
	}
	if !ShouldStartBuiltinSTUN(true, port) {
		t.Fatal("P2P 打开且端口 >0 时应启动")
	}

	// P2P 关闭 → 端口必须空闲（证明没有残留监听）
	free, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		t.Fatalf("P2P 关闭时端口 %d 应空闲，实际被占用: %v", port, err)
	}
	_ = free.Close()

	// 启动后 → 端口被占（说明确实在监听）
	b := StartBuiltinSTUN(port)
	defer b.Close()
	if len(b.Ports()) == 0 {
		t.Skipf("端口 %d 起不来，跳过占用断言", port)
	}
	if c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: b.Ports()[0]}); err == nil {
		_ = c.Close()
		t.Fatalf("启动后端口 %d 应被内置 STUN 占用", b.Ports()[0])
	}
	// 关闭后应重新空闲（Stop() 会调用它）
	b.Close()
	after, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: b.Ports()[0]})
	if err != nil {
		t.Fatalf("关闭后端口 %d 应空闲: %v", b.Ports()[0], err)
	}
	_ = after.Close()
}

// TestBuiltinSTUNWarningWhenSingleEndpoint（体验要求）
//
//	只绑上一个端点时，面板/状态接口必须给出**带后果**的提示，
//	不能只写一行 port occupied —— 因为只绑一个 = 国内打洞照样打不通。
func TestBuiltinSTUNWarningWhenSingleEndpoint(t *testing.T) {
	full := &BuiltinSTUN{ports: []int{3478, 3479}}
	if w := full.Warning(true, 3478); w != "" {
		t.Fatalf("两个端点都在时不应有警告，实际 %q", w)
	}

	one := &BuiltinSTUN{ports: []int{3479}}
	w := one.Warning(true, 3478)
	if w == "" {
		t.Fatal("只有一个端点时必须给出警告")
	}
	for _, want := range []string{"仅启动 1/2", "P2P 直连可能不可用", "两个端点", "国内"} {
		if !strings.Contains(w, want) {
			t.Fatalf("警告文案应包含 %q，实际 %q", want, w)
		}
	}

	none := &BuiltinSTUN{}
	if w := none.Warning(true, 3478); !strings.Contains(w, "未启动") {
		t.Fatalf("一个都没起来时应说明未启动，实际 %q", w)
	}
	// P2P 关闭 / 端口 0 → 不是问题，不该报警
	if w := one.Warning(false, 3478); w != "" {
		t.Fatalf("P2P 关闭时不应警告，实际 %q", w)
	}
	if w := one.Warning(true, 0); w != "" {
		t.Fatalf("stunPort=0（显式关闭）时不应警告，实际 %q", w)
	}
}

// TestBuiltinSTUNTwoPortsGiveConsistentObservation 两个端点必须给出相同观测端口
//
// 这正是「客户端只靠内置端点也能判定非对称 NAT」的前提。
func TestBuiltinSTUNTwoPortsGiveConsistentObservation(t *testing.T) {
	base := 48040
	b := StartBuiltinSTUN(base)
	if b == nil {
		t.Fatal("应启动成功")
	}
	defer b.Close()
	if len(b.Ports()) != builtinSTUNMaxPorts {
		t.Skipf("端口 %d/%d 被占用，跳过", base, base+1)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("客户端 socket: %v", err)
	}
	defer conn.Close()

	var ports []int
	for _, p := range b.Ports() {
		req, _ := stun.Build(stun.TransactionID, stun.BindingRequest)
		if _, err := conn.WriteToUDP(req.Raw, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p}); err != nil {
			t.Fatalf("发送: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1500)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("端点 %d 未响应: %v", p, err)
		}
		res := &stun.Message{Raw: buf[:n]}
		if err := res.Decode(); err != nil {
			t.Fatalf("解码: %v", err)
		}
		var xor stun.XORMappedAddress
		if err := xor.GetFrom(res); err != nil {
			t.Fatalf("缺少 XOR-MAPPED-ADDRESS: %v", err)
		}
		ports = append(ports, xor.Port)
	}
	if len(ports) != 2 || ports[0] != ports[1] {
		t.Fatalf("同一条客户端 socket 问两个端点应观测到同一端口，实际 %v", ports)
	}
}
