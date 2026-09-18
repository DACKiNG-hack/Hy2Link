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
}

func NewGeoFilter(mode string, countries []string, blockPrivate bool) *GeoFilter {
	set := make(map[string]bool, len(countries))
	for _, c := range countries {
		set[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	return &GeoFilter{
		mode:         mode,
		countries:    set,
		blockPrivate: blockPrivate,
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
		ipStr := extractClientIP(r)
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

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

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
