package quic

//vpn-server\quic\stun.go

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/pion/stun"
)

// STUNServer 表示一个 STUN 服务器地址
type STUNServer struct {
	Host string
	Port int
}

// String 返回 host:port 格式的地址
func (s STUNServer) String() string {
	return net.JoinHostPort(s.Host, fmt.Sprintf("%d", s.Port))
}

// stunServers 是国内外均可访问的 STUN 服务器列表
// 强制使用 IPv4 解析
var stunServers = []STUNServer{
	// 国内服务器（优先）
	{Host: "stun.miwifi.com", Port: 3478},
	{Host: "stun.chat.bilibili.com", Port: 3478},
	{Host: "stun.hitv.com", Port: 3478},
	// 国际服务器（备选）
	{Host: "stun.cloudflare.com", Port: 3478},
	{Host: "stun.l.google.com", Port: 19302},
}

// GetPublicIPViaSTUN 通过 STUN 服务器获取本机公网 IPv4 地址
// 强制只接受 IPv4 结果，忽略任何 IPv6 响应
func GetPublicIPViaSTUN() string {
	for _, server := range stunServers {
		ip := querySTUNServer(server)
		if ip != "" {
			log.Printf("🌐 [STUN] 通过 %s 获取公网 IPv4: %s", server, ip)
			return ip
		}
	}
	log.Println("⚠️ [STUN] 所有 STUN 服务器均不可达")
	return ""
}

// querySTUNServer 向单个 STUN 服务器发起 Binding 请求
// 强制只接受 IPv4 响应
func querySTUNServer(server STUNServer) string {
	// 强制解析为 IPv4 地址
	ipAddr, err := net.ResolveIPAddr("ip4", server.Host)
	if err != nil {
		return ""
	}

	// 用 IPv4 地址建立 UDP4 连接
	target := &net.UDPAddr{
		IP:   ipAddr.IP,
		Port: server.Port,
	}
	conn, err := net.DialUDP("udp4", nil, target)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// 构造 STUN Binding 请求
	message, err := stun.Build(stun.BindingRequest, stun.TransactionID)
	if err != nil {
		return ""
	}

	// 发送请求
	if _, err := conn.Write(message.Raw); err != nil {
		return ""
	}

	// 读取响应
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	// 解析响应
	res := &stun.Message{Raw: buf[:n]}
	if err := res.Decode(); err != nil {
		return ""
	}

	// 提取 XOR-MAPPED-ADDRESS
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(res); err != nil {
		return ""
	}

	// ⭐ 关键：只接受 IPv4 地址，忽略 IPv6
	if xorAddr.IP.To4() == nil {
		return ""
	}

	return xorAddr.IP.String()
}
