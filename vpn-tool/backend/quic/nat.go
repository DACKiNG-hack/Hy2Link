package quic

// vpn-tool/backend/quic/nat.go
//
// P2SP 阶段 0：NAT 类型探测。
//
// 做法（对应任务书 0.1）：
//  1. 新建一个**临时** UDP socket（绝不复用 sharedUDPConn —— 那条 socket
//     被 6 条 QUIC 连接共享，拿它发 STUN 会污染 QUIC 的数据流）；
//  2. 依次向两个不同厂商的公共 STUN 服务器各发一次 Binding 请求；
//  3. 比较两次观测到的**映射端口**：
//     - 相同 → 端点无关映射（cone 类，打洞可行性高）
//     - 不同 → Symmetric NAT（端点相关映射，打洞可行性低）
//  4. 探测完立即关闭临时 socket。
//
// ⚠️ 阶段 0 的能力边界（诚实说明）：
//
//	本实现只能区分「Symmetric vs 非 Symmetric」。要区分
//	Full Cone / Restricted Cone / Port-Restricted Cone 需要 STUN 服务器
//	支持 RFC 3489 的 CHANGE-REQUEST 或 RFC 5780 的 OTHER-ADDRESS，
//	而 Google / Cloudflare 这些公共服务器都不支持。
//	因此：
//	  - 映射端口一致时对外报 "full-cone"（落在服务端信令白名单内），
//	    但真正可靠的事实是 NATMappingIndependent == true；
//	  - 后续阶段的决策逻辑**应当使用 NATMappingIndependent / NATSymmetric**
//	    这两个布尔量，而不是字符串标签本身。
//
//	另外「只探测到一台服务器」时无法比较，此时类型为 unknown，
//	但仍然保留观测到的公网地址（PublicAddr 可用于信令上报）。

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/hysteria/extras/v2/realm"
)

// NATType NAT 类型。字符串取值与 /api/signal/exchange 的白名单一致。
type NATType string

const (
	NATUnknown        NATType = "unknown"
	NATFullCone       NATType = "full-cone"
	NATRestrictedCone NATType = "restricted-cone"
	NATPortRestricted NATType = "port-restricted"
	NATSymmetric      NATType = "symmetric"
)

// validNATTypes 白名单（与服务端 admin/signal.go 里的那份保持一致）
var validNATTypes = map[NATType]bool{
	NATUnknown:        true,
	NATFullCone:       true,
	NATRestrictedCone: true,
	NATPortRestricted: true,
	NATSymmetric:      true,
}

// IsValidNATType 判断字符串是否是合法的 NAT 类型
func IsValidNATType(s string) bool {
	return validNATTypes[NATType(s)]
}

// parseP2PFlag 解析 DHCP 应答第 11 段的 P2P 开关。
//
// ⭐ 向后兼容的关键：旧服务端只发 10 段，`len(parts) < 11` 时必须安全地
// 返回 false（而不是越界 panic，也不是默认开启）。
func parseP2PFlag(parts []string) bool {
	if len(parts) < 11 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(parts[10]), "on")
}

const (
	// 整个探测流程的总超时
	natDetectTotalTimeout = 10 * time.Second
)

// stunPerServerTimeout 单台 STUN 服务器的超时（realm 内部还会再套一层总超时）。
//
// ⭐ 是 var 而不是 const：测试需要把它压到几百毫秒来验证
// 「首位不可达时切到备选」这条路径，否则每个失败项都要等满 3 秒。
var stunPerServerTimeout = 3 * time.Second

// defaultSTUNServers 探测用的公共 STUN 服务器。
//
// 至少要两台**不同厂商**的服务器才能对比映射端口；多列几台是为了在
// 某些服务器被墙/不可达时仍能凑够两次有效观测（国内网络下
// Google 的 STUN 经常不可达，所以同时列了国内可用的）。
var defaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun.miwifi.com:3478",
	"stun.chat.bilibili.com:3478",
}

// parseBuiltinSTUNPorts 解析 DHCP 应答第 12 段（服务端内置 STUN 端点）。
//
// 形态（服务端 dhcp.go 下发）：
//   - "3478|3479"  服务端实际生效的端口列表（**通常两个**）
//   - "off" / "" / 段不存在  没有内置端点
//
// ⭐ 只发端口不发 IP：客户端用自己已经知道的服务器地址（`serverIP`）拼，
// 所以主机名 / 多地址部署都不用额外配置。
func parseBuiltinSTUNPorts(parts []string) []int {
	const idx = 11 // 第 12 段
	if len(parts) <= idx {
		return nil
	}
	raw := strings.TrimSpace(parts[idx])
	if raw == "" || strings.EqualFold(raw, "off") {
		return nil
	}
	var out []int
	for _, seg := range strings.Split(raw, "|") {
		p, err := strconv.Atoi(strings.TrimSpace(seg))
		if err != nil || p < 1 || p > 65535 {
			continue
		}
		out = append(out, p)
	}
	return out
}

// stunServerList 组装 NAT 探测用的 STUN 列表：
// **服务端内置端点放最前**（国内必然可达），公共 STUN 作为备选（去重）。
//
// ⚠️ 为什么必须保留备选：客户端的 classifyNAT 需要**至少两台**响应者才能对比映射端口；
// 服务端只起来一个端点（例如 3478 被占用）时，仍然需要一台公共 STUN 来配对。
// 两边都不可用时结果就是 NATUnknown → 不打洞（如实上报）。
//
// ⚠️ 精度：内置的两个端点是**同一个 IP 的不同端口**，所以它判定的是
// 「映射是否与目标**端口**有关」——足以区分 full-cone 与 symmetric
// （address-and-port-dependent），但 address-dependent（只看目标 IP）会被误判成
// full-cone（后果是打洞失败回落中继，不是安全问题）。
// **公共 STUN 可达时列表里就有不同 IP**，那时才真正覆盖 IP 维度。
//
// 环境变量 HY2_NO_PUBLIC_STUN=1：只用内置端点（手工验证「国内环境」/ 远程排障用）。
func (c *Hysteria2Client) stunServerList() []string {
	seen := map[string]struct{}{}
	var out []string

	for _, p := range c.builtinSTUNPorts {
		host := strings.TrimSpace(c.serverIP)
		if host == "" {
			break
		}
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	if noPublicSTUN() {
		if len(out) == 0 {
			// ⚠️ 调试开关**不能把探测彻底关死**：服务端没有下发内置端点时，
			//    回落公共 STUN（而不是返回空列表让探测必然失败）。
			log.Printf("⚠️ [NAT] 设置了 HY2_NO_PUBLIC_STUN，但服务端没有下发内置 STUN 端点 → 回落公共 STUN" +
				"（这是调试开关，勿用于生产）")
		} else {
			log.Printf("🌐 [NAT] HY2_NO_PUBLIC_STUN：只用 %d 个内置 STUN 端点（模拟公共 STUN 不可达）",
				len(out))
			return out
		}
	}
	for _, s := range defaultSTUNServers {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// noPublicSTUN 是否禁用公共 STUN。
//
// ⚠️⚠️ 这是**调试 / 排障开关，不是生产配置**：设上之后公共 STUN 备选会失效，
// 探测只依赖服务端内置端点。误设的后果：
//   - 服务端**开了**内置端点 → 探测照常（只是没有不同 IP 的第二来源，
//     见 stunServerList 的精度说明）；
//   - 服务端**没开**内置端点 → 回落公共 STUN（见上面的分支），不会把探测关死。
//
// 取值：`1` / `true`（大小写不敏感）= 开启；其它值（含 `0`/`false`/空/垃圾）一律视为关闭。
//
// 命名：本开关用 `HY2_` 前缀。现有 `HY_*` 变量（HY_DEBUG / HY_QUICDC_DEBUG /
// HY_TRAY / HY_DATA_DIR / HY_DEV / HY_TRUSTED_PROXIES / HY_STATIC_DIR / HY_ADMIN_HOSTS）
// **没有任何一个叫这个名字**，因此不存在冲突或覆盖。
func noPublicSTUN() bool {
	v := strings.TrimSpace(os.Getenv("HY2_NO_PUBLIC_STUN"))
	return v == "1" || strings.EqualFold(v, "true")
}

// NATProbeResult 一次 NAT 探测的结果
type NATProbeResult struct {
	// Type 对外汇报的类型（字符串标签，仅用于信令与日志）
	Type NATType
	// PublicAddr 观测到的公网地址，"ip:port"（取第一次成功观测）
	PublicAddr string
	// ObservedPorts 各次探测观测到的映射端口（去重升序）
	ObservedPorts []uint16
	// RespondedServers 成功返回结果的 STUN 服务器数量
	RespondedServers int
	// MappingIndependent 映射是否与**目的地址**无关（cone 类为 true）。
	// ⭐ 这是本模块最可靠的事实，后续阶段应优先使用它。
	//
	// ⚠️ 精度取决于响应者的地址分布：
	//   - 响应者来自**不同 IP**（两台以上公共 STUN）→ 真正覆盖 IP 与端口两个维度；
	//   - 响应者只有**同一 IP 的不同端口**（服务端内置的两个端点、且公共 STUN 不可达）
	//     → 只覆盖「端口」维度；address-dependent NAT（只看目标 IP）会被判成 true。
	//     后果是打洞失败后回落中继（不是安全问题）。
	MappingIndependent bool
	// Err 探测失败的原因（Type 为 unknown 时非空）
	Err error
}

// detectNAT 探测本机 NAT 类型。
//
// servers 为空时使用 defaultSTUNServers。
// 本函数会阻塞，调用方应当放到 goroutine 里跑（见 client.go）。
func detectNAT(ctx context.Context, servers []string) NATProbeResult {
	if len(servers) == 0 {
		servers = defaultSTUNServers
	}
	if len(servers) < 2 {
		return NATProbeResult{
			Type: NATUnknown,
			Err:  fmt.Errorf("至少需要两台 STUN 服务器才能对比映射端口"),
		}
	}

	ctx, cancel := context.WithTimeout(ctx, natDetectTotalTimeout)
	defer cancel()

	// ⭐ 临时 socket：探测完即关闭，绝不复用共享的 QUIC socket
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return NATProbeResult{
			Type: NATUnknown,
			Err:  fmt.Errorf("创建临时 UDP socket 失败: %w", err),
		}
	}
	defer socket.Close()

	observed := make([]netip.AddrPort, 0, len(servers))
	responded := 0

	for _, srv := range servers {
		if ctx.Err() != nil {
			break
		}
		// ⭐ 一次只问一台服务器，这样结果能明确归因到「哪个目的地」——
		//    这正是区分端点相关/无关映射所需要的。
		addrs, err := realm.Discover(ctx, socket, realm.STUNConfig{
			Servers: []string{srv},
			Timeout: stunPerServerTimeout,
			Family:  realm.AddrFamilyIPv4,
		})
		if err != nil || len(addrs) == 0 {
			log.Printf("⚠️ [NAT] STUN %s 未返回结果: %v", srv, err)
			continue
		}
		responded++
		observed = append(observed, addrs...)
		log.Printf("🔍 [NAT] STUN %s 观测到: %s", srv, joinAddrPorts(addrs))
	}

	return classifyNAT(observed, responded)
}

// classifyNAT 根据观测结果判定 NAT 类型（拆出来便于单测）
func classifyNAT(observed []netip.AddrPort, respondedServers int) NATProbeResult {
	res := NATProbeResult{
		Type:             NATUnknown,
		RespondedServers: respondedServers,
	}

	if len(observed) == 0 {
		res.Err = fmt.Errorf("所有 STUN 服务器都不可达")
		return res
	}

	// 取第一次观测作为对外地址
	res.PublicAddr = observed[0].String()

	// 端口去重
	portSet := make(map[uint16]struct{}, len(observed))
	for _, a := range observed {
		portSet[a.Port()] = struct{}{}
	}
	ports := make([]uint16, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	res.ObservedPorts = ports

	// 观测到多个不同端口 → 映射与目的地址相关 → Symmetric
	if len(ports) > 1 {
		res.Type = NATSymmetric
		res.MappingIndependent = false
		return res
	}

	// 端口一致，但要能确认「至少有两台服务器参与比较」才有意义
	if respondedServers < 2 {
		res.Type = NATUnknown
		res.Err = fmt.Errorf("只有 1 台 STUN 服务器响应，无法对比映射端口")
		return res
	}

	res.MappingIndependent = true
	// ⚠️ 只能判定为「端点无关映射」，无法区分 full / restricted / port-restricted cone，
	//    这里按白名单里最宽松的标签汇报，详见文件头说明。
	res.Type = NATFullCone
	return res
}

func joinAddrPorts(addrs []netip.AddrPort) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}
