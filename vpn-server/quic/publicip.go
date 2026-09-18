package quic

//vpn-server\quic\publicip.go

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// GetPublicIP 兼容旧调用：默认使用 STUN
func GetPublicIP() string {
	return GetPublicIPWithSTUN(true)
}

// GetPublicIPWithSTUN 获取本机公网 IPv4 地址
// useSTUN=true：优先 STUN，失败后回退 HTTP
// useSTUN=false：直接走 HTTP，不尝试 STUN
func GetPublicIPWithSTUN(useSTUN bool) string {
	if useSTUN {
		log.Println("🔍 [公网IP] STUN 已启用，优先尝试 STUN 服务器...")
		ip := GetPublicIPViaSTUN()
		if ip != "" {
			return ip
		}
		log.Println("⚠️ [公网IP] STUN 获取失败，回退到 HTTP 接口")
	} else {
		log.Println("⏭️ [公网IP] STUN 已禁用，直接使用 HTTP 接口")
	}
	return getPublicIPViaHTTP()
}

// getPublicIPViaHTTP 通过多个 HTTP 接口获取公网 IPv4 地址
// 强制只使用 IPv4 接口
func getPublicIPViaHTTP() string {
	client := &http.Client{Timeout: 5 * time.Second}

	urls := []string{
		// IPv4 专用接口
		"https://api.ipify.org",           // 只返回 IPv4
		"https://ipv4.icanhazip.com",      // 只返回 IPv4
		"https://ipv4.ident.me",           // 只返回 IPv4
		"https://ipv4.wtfismyip.com/text", // 只返回 IPv4
		// 国内友好（默认也是 IPv4）
		"https://ip.3322.net",
		"https://myip.ipip.net",
	}

	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))

		// ⭐ 强制校验：必须是合法的 IPv4 地址
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() == nil {
			// 是 IPv6，跳过
			log.Printf("⏭️ [HTTP] %s 返回 IPv6 地址（%s），已跳过", u, ip)
			continue
		}
		if strings.ContainsAny(ip, " \n\t<>") {
			continue
		}

		log.Printf("🌐 [HTTP] 通过 %s 获取公网 IPv4: %s", u, ip)
		return ip
	}

	log.Println("⚠️ [公网IP] 所有 HTTP 接口均无法获取公网 IPv4")
	return ""
}
