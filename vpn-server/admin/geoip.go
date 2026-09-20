package admin

import (
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/phuslu/iploc"
)

// GeoFilter 地理围栏
type GeoFilter struct {
	mode         string          // "off" / "block" / "allow"
	countries    map[string]bool // 大写国家代码集合
	blockPrivate bool
	resolver     *ipResolver // ⭐ 安全审计 S5：真实客户端 IP 的解析策略
}

func NewGeoFilter(mode string, countries []string, blockPrivate bool) *GeoFilter {
	return NewGeoFilterWithResolver(mode, countries, blockPrivate, defaultIPResolver)
}

// NewGeoFilterWithResolver 允许注入自定义的客户端 IP 解析策略
func NewGeoFilterWithResolver(mode string, countries []string, blockPrivate bool, resolver *ipResolver) *GeoFilter {
	set := make(map[string]bool, len(countries))
	for _, c := range countries {
		set[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	if resolver == nil {
		resolver = defaultIPResolver
	}
	return &GeoFilter{
		mode:         mode,
		countries:    set,
		blockPrivate: blockPrivate,
		resolver:     resolver,
	}
}

// Middleware 包装 handler，执行地理围栏检查
//
// 规则：
//   - 本机 loopback（127.0.0.1 / ::1）始终放行 ⭐
//   - 私有网段：blockPrivate=true 时拒绝，否则放行
//   - 其他：按 mode 判断
func (g *GeoFilter) Middleware(next http.Handler) http.Handler {
	if g == nil || g.mode == "off" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ⭐ 安全审计 S5：这里必须用「不可伪造」的客户端 IP。
		//    默认只用 TCP 层对端地址；只有对端是配置好的受信代理时才会解析 XFF。
		ipStr := g.resolver.ClientIP(r)
		ip := net.ParseIP(ipStr)

		// ⭐ 本机 loopback 始终放行
		if ip != nil && ip.IsLoopback() {
			next.ServeHTTP(w, r)
			return
		}

		// 私有网段
		if ip != nil && isPrivateIP(ip) {
			if g.blockPrivate {
				log.Printf("🚫 [地理围栏] 拒绝私有 IP: %s", ipStr)
				http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// 无法解析 IP 时保守放行
		if ip == nil {
			next.ServeHTTP(w, r)
			return
		}

		// ⭐ 查询国家（iploc 需要 netip.Addr）
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			if g.mode == "allow" {
				log.Printf("🚫 [地理围栏] IP 无法转换，拒绝: %s", ipStr)
				http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		// 去掉 IPv4-mapped IPv6 前缀（::ffff:1.2.3.4 → 1.2.3.4）
		addr = addr.Unmap()

		country := iploc.IPCountry(addr)
		code := strings.ToUpper(string(country))

		if code == "" {
			// 无法识别国家
			if g.mode == "allow" {
				log.Printf("🚫 [地理围栏] 未知国家，拒绝: %s", ipStr)
				http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		inList := g.countries[code]

		allowed := false
		switch g.mode {
		case "block":
			allowed = !inList
		case "allow":
			allowed = inList
		default:
			allowed = true
		}

		if !allowed {
			log.Printf("🚫 [地理围栏] 拒绝 %s (%s) [mode=%s]", ipStr, code, g.mode)
			http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Describe 返回给日志用的简短描述
func (g *GeoFilter) Describe() string {
	if g == nil || g.mode == "off" {
		return "已关闭"
	}
	list := make([]string, 0, len(g.countries))
	for c := range g.countries {
		list = append(list, c)
	}
	return g.mode + " " + strings.Join(list, ",")
}

// ---------- 工具 ----------

// ipResolver 决定「真实客户端 IP」。
//
// ⭐ 安全审计 S5：默认**不信任**任何转发头。
//
// 原来的实现无条件信任 X-Forwarded-For / X-Real-IP，导致两个真实漏洞：
//  1. 地理围栏绕过：`X-Forwarded-For: 127.0.0.1` 会被判定为 loopback 而直接放行；
//  2. 登录爆破：限流按 IP 计数，攻击者每次请求换一个 XFF 值即可无限尝试。
//
// 正确做法：只有 TCP 层对端确实是配置好的受信反向代理时，才去看 XFF，
// 并且从**右往左**剥离受信代理，取第一个非受信地址——
// 因为 XFF 最左边的值才是客户端可以随意伪造的部分。
type ipResolver struct {
	trusted []netip.Prefix
}

// newIPResolver 解析逗号分隔的受信代理列表，支持 CIDR 或单个 IP。
// 传空字符串表示「没有任何受信代理」（默认，也是推荐配置）。
func newIPResolver(spec string) *ipResolver {
	r := &ipResolver{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			r.trusted = append(r.trusted, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(part); err == nil {
			a = a.Unmap()
			r.trusted = append(r.trusted, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return r
}

func (r *ipResolver) trusts(a netip.Addr) bool {
	if r == nil || len(r.trusted) == 0 || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// peerAddr 提取 TCP 层真实对端地址，不解析任何请求头。
func peerAddr(remoteAddr string) netip.Addr {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// ClientIP 返回用于限流与地理围栏判定的客户端 IP。
func (r *ipResolver) ClientIP(req *http.Request) string {
	peer := peerAddr(req.RemoteAddr)

	if peer.IsValid() && r.trusts(peer) {
		// 只有在受信代理后面才允许转发头生效
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				cand, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
				if err != nil {
					continue
				}
				cand = cand.Unmap()
				if !r.trusts(cand) {
					return cand.String()
				}
			}
		}
		if xri := req.Header.Get("X-Real-IP"); xri != "" {
			if a, err := netip.ParseAddr(strings.TrimSpace(xri)); err == nil {
				return a.Unmap().String()
			}
		}
	}

	if peer.IsValid() {
		return peer.String()
	}
	// 极端情况下（RemoteAddr 无法解析）退回原字符串，
	// 它仍然是内核提供的对端地址，客户端无法伪造。
	return req.RemoteAddr
}

// defaultIPResolver 不信任任何代理，只用 RemoteAddr。
var defaultIPResolver = newIPResolver("")

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"100.64.0.0/10",
		"fc00::/7",
		"fe80::/10",
	} {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			if network.Contains(ip) {
				return true
			}
		}
	}
	return false
}
