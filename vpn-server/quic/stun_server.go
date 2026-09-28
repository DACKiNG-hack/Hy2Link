package quic

// vpn-server/quic/stun_server.go
//
// P2SP 阶段 1b-1 补丁：**服务端内置 STUN 端点**。
//
// 为什么需要它：国内公共 STUN 经常不可达/被限速，客户端 `realm.Discover` 拿不到
// 自己的公网映射 → `local-no-punch-addr` → 打洞根本没开始（是常态，不是边缘情况）。
//
// ⭐ 硬约束（评估结论）：**完全不动 QUIC 监听路径**。
//   - 另开**独立的 UDP socket**（不是包 QUIC socket，不用 PunchPacketConn）；
//   - 不碰 Salamander/obfs 包装，不进 quic-go 的 Transport；
//   - 与 6 条连接架构、信令流、数据面**零交互**。
//
// ⭐ 为什么要开**两个**端口（这个结论是评估里最关键的一条）：
// 客户端的 `classifyNAT` 需要**至少两台 STUN 响应者**才能对比映射端口，
// 只有一台时它会返回 NATUnknown（nat.go:205-208「只有 1 台 STUN 服务器响应，
// 无法对比映射端口」）→ 1b-1 的预检又把 NATUnknown 判成「不打洞」，
// 于是国内环境下打洞**照样不会开始**。所以内置端点必须是相邻的两个 UDP 端口。
//
// ⚠️ 精度说明（准确表述，勿写成「等价于两台公共 STUN」）：
// **同一 IP 的两个端口只能判定「映射是否与目标端口有关」**。
//   - 对 full-cone 与 symmetric（address-and-port-dependent）足以区分；
//   - 对 address-dependent（只看目标 IP）会**误判为 full-cone** ——
//     因为两个端点是同一个 IP，该类 NAT 在它们上面映射一致；
//     但这类 NAT 相对少见，误判后果是**打洞失败、回落中继**，不是安全问题；
//   - 真正的「映射是否与目标 IP 无关」需要**两台不同 IP** 的 STUN：
//     公共 STUN 可达时客户端列表里本来就有（精度更高）；
//     完全依赖内置端点时只得到端口维度，IP 维度留给 1b-3 或按需补充。
//
// ⚠️ 精度说明（写进设计文档）：这里观测的是「客户端 ↔ 服务端 STUN 端口」的映射。
// 非对称 NAT 下端口不影响映射，而 1b-1 只支持非对称（设计 §0.5），所以够用；
// 将来 1b-3 处理对称 NAT 时再上「服务端观测 QUIC 端口」的完整版。

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/pion/stun"
)

const (
	// builtinSTUNMaxPorts 内置端点数（必须 ≥2，理由见文件头）
	builtinSTUNMaxPorts = 2

	// 反滥用：每源 IP 的请求速率上限（固定窗口 1s）。
	// 正常客户端只在连接时问 2~4 个包；30/s 对真实用户绰绰有余。
	builtinSTUNRatePerIP  = 30
	builtinSTUNRateWindow = time.Second
	// 限流表上限（超过就整体清理一次，避免内存被刷爆）
	builtinSTUNMaxTrackedIPs = 4096
)

// BuiltinSTUN 服务端内置 STUN 端点（1~2 条独立 UDP socket）
type BuiltinSTUN struct {
	conns []*net.UDPConn
	ports []int

	closeOnce sync.Once
	wg        sync.WaitGroup

	mu      sync.Mutex
	rate    map[string]*stunIPBucket
	served  uint64
	dropped uint64
}

type stunIPBucket struct {
	windowStart time.Time
	count       int
}

// ShouldStartBuiltinSTUN 内置 STUN 是否应当启动（导出：manager 用它，测试也用它）。
//
// P2P 关闭、或端口为 0（显式关闭）→ 不启动，连 socket 都不建。
func ShouldStartBuiltinSTUN(p2pEnabled bool, stunPort int) bool {
	return p2pEnabled && stunPort > 0
}

// StartBuiltinSTUN 在 basePort、basePort+1 上启动内置 STUN 端点。
//
// basePort <= 0 表示显式关闭（返回 nil，不监听任何端口）。
// 某个端口绑定失败只记日志并跳过（例如被别的程序占用），不影响服务端启动；
// 实际生效的端口由 Ports() 给出，并据此写进 DHCP 应答（**announce 反映现实**，
// 而不是反映配置意图 —— 否则客户端会把 3 秒浪费在一个没开的端口上）。
func StartBuiltinSTUN(basePort int) *BuiltinSTUN {
	if basePort <= 0 {
		return nil
	}
	b := &BuiltinSTUN{rate: make(map[string]*stunIPBucket)}

	for i := 0; i < builtinSTUNMaxPorts; i++ {
		port := basePort + i
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
		if err != nil {
			log.Printf("⚠️ [内置STUN] 监听 UDP %d 失败（跳过该端点）: %v", port, err)
			continue
		}
		b.conns = append(b.conns, conn)
		b.ports = append(b.ports, port)
		b.wg.Add(1)
		go b.serve(conn)
	}

	if len(b.conns) == 0 {
		log.Printf("❌ [内置STUN] 没能监听任何端口（基准端口 %d）——客户端将退回公共 STUN", basePort)
		return b
	}
	log.Printf("📡 [内置STUN] 已启动 %d 个端点: %v（独立 UDP socket，不影响 QUIC 监听）",
		len(b.ports), b.ports)
	if len(b.ports) < builtinSTUNMaxPorts {
		// ⭐ 只起来一个端点时必须把后果说清楚，不能只写一行「端口被占用」：
		//    只绑一个 = 客户端判不出「映射是否与目标端口有关」= 国内打洞照样打不通。
		log.Printf("❌ [内置STUN] STUN 端点仅启动 %d/%d，P2P 直连可能不可用！"+
			"客户端需要两个端点才能判定映射是否与目标端口有关；"+
			"只启动一个时，国内环境（公共 STUN 不可达）将无法打洞。"+
			"请检查 %d/%d 端口是否被占用，或改用其它 stunPort",
			len(b.ports), builtinSTUNMaxPorts, basePort, basePort+1)
	}
	return b
}

// Warning 返回需要提示管理员的问题（空串 = 正常）。
//
// 用途：服务端状态接口 / 面板 —— 面板上必须能明确看到
// 「STUN 端点仅启动 1/2，P2P 直连可能不可用」，而不只是日志里一行 port occupied。
func (b *BuiltinSTUN) Warning(p2pEnabled bool, stunPort int) string {
	if !p2pEnabled || stunPort <= 0 {
		return ""
	}
	need := builtinSTUNMaxPorts
	if b == nil || len(b.ports) == 0 {
		return fmt.Sprintf("内置 STUN 端点未启动（UDP %d/%d 被占用或无法绑定）："+
			"国内公共 STUN 不可达时 P2P 直连将不可用，请更换 stunPort 或在防火墙放行", stunPort, stunPort+1)
	}
	if len(b.ports) < need {
		return fmt.Sprintf("STUN 端点仅启动 %d/%d，P2P 直连可能不可用："+
			"客户端需要两个端点才能判定映射是否与目标端口有关，只启动一个时国内打洞无法开始",
			len(b.ports), need)
	}
	return ""
}

// Ports 实际生效的端口（可能为空）
func (b *BuiltinSTUN) Ports() []int {
	if b == nil {
		return nil
	}
	return append([]int(nil), b.ports...)
}

// Announce 返回写进 DHCP 应答的形式（"3478|3479" 或 "off"）
func (b *BuiltinSTUN) Announce() string {
	if b == nil || len(b.ports) == 0 {
		return "off"
	}
	s := ""
	for i, p := range b.ports {
		if i > 0 {
			s += "|"
		}
		s += fmt.Sprintf("%d", p)
	}
	return s
}

// Close 关闭所有端点（幂等）
func (b *BuiltinSTUN) Close() {
	if b == nil {
		return
	}
	b.closeOnce.Do(func() {
		for _, c := range b.conns {
			_ = c.Close()
		}
		b.wg.Wait()
		log.Printf("📴 [内置STUN] 已关闭（服务 %d 个请求，限流丢弃 %d 个）", b.served, b.dropped)
	})
}

// Stats 服务/丢弃计数（监控/测试用）
func (b *BuiltinSTUN) Stats() (served, dropped uint64) {
	if b == nil {
		return 0, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.served, b.dropped
}

func (b *BuiltinSTUN) serve(conn *net.UDPConn) {
	defer b.wg.Done()
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // socket 被关闭
		}
		if from == nil || n <= 0 {
			continue
		}
		if !b.allow(from.IP) {
			b.mu.Lock()
			b.dropped++
			b.mu.Unlock()
			continue
		}
		resp := buildSTUNBindingResponse(buf[:n], from)
		if resp == nil {
			b.mu.Lock()
			b.dropped++
			b.mu.Unlock()
			continue
		}
		if _, err := conn.WriteToUDP(resp, from); err != nil {
			continue
		}
		b.mu.Lock()
		b.served++
		b.mu.Unlock()
	}
}

// allow 每源 IP 的固定窗口限流
func (b *BuiltinSTUN) allow(ip net.IP) bool {
	key := ip.String()
	now := time.Now()

	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.rate) > builtinSTUNMaxTrackedIPs {
		for k, v := range b.rate {
			if now.Sub(v.windowStart) > builtinSTUNRateWindow {
				delete(b.rate, k)
			}
		}
	}
	bucket, ok := b.rate[key]
	if !ok || now.Sub(bucket.windowStart) > builtinSTUNRateWindow {
		b.rate[key] = &stunIPBucket{windowStart: now, count: 1}
		return true
	}
	if bucket.count >= builtinSTUNRatePerIP {
		return false
	}
	bucket.count++
	return true
}

// buildSTUNBindingResponse 解析并构造 Binding Success 响应。
//
// 只应答 `Binding Request`：
//   - 不应答 Binding Success/Error（避免与别的 STUN 服务器形成回环/互放大）；
//   - 不支持 CHANGE-REQUEST / OTHER-ADDRESS / TURN（那些才是反射放大的放大器）；
//   - 响应固定为 20 字节头 + 12 字节 XOR-MAPPED-ADDRESS（IPv4）≈ 32 字节，
//     请求本身 20 字节 → 放大倍数 ≈1.6，低于公共 STUN 服务的常见水平；
//   - **必须原样回填 Transaction ID**，否则客户端（realm）无法把响应与请求对上。
func buildSTUNBindingResponse(packet []byte, from *net.UDPAddr) []byte {
	req := &stun.Message{Raw: append([]byte(nil), packet...)}
	if err := req.Decode(); err != nil {
		return nil
	}
	if req.Type != stun.BindingRequest {
		return nil
	}
	ip4 := from.IP.To4()
	if ip4 == nil {
		return nil // 只服务 IPv4（客户端栈也是 IPv4-only）
	}

	resp, err := stun.Build(
		stun.BindingSuccess,
		stun.NewTransactionIDSetter(req.TransactionID),
		&stun.XORMappedAddress{IP: ip4, Port: from.Port},
	)
	if err != nil {
		return nil
	}
	return resp.Raw
}
