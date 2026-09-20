package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultStreamWindow = 8388608
	DefaultConnWindow   = 20971520
	DefaultUDPBufSize   = 4194304
)

type ServerConfig struct {
	Port         int    `json:"port"`
	PortVPN      int    `json:"portVPN"`
	IPPoolStart  string `json:"ipPoolStart"`
	IPPoolEnd    string `json:"ipPoolEnd"`
	SubnetMask   string `json:"subnetMask"`
	StreamWindow int    `json:"streamWindow"`
	ConnWindow   int    `json:"connWindow"`
	AutoStart    bool   `json:"autoStart"`

	ServerTunEnabled bool   `json:"serverTunEnabled"`
	ServerTunIP      string `json:"serverTunIP"`
	ServerTunMask    string `json:"serverTunMask"`

	TCPSplitEnabled bool  `json:"tcpSplitEnabled"`
	TCPSplitPorts   []int `json:"tcpSplitPorts"`

	UDPReliableEnabled   bool     `json:"udpReliableEnabled"`
	UDPReliablePorts     []string `json:"udpReliablePorts"`
	UDPUnreliableEnabled bool     `json:"udpUnreliableEnabled"`
	UDPUnreliablePorts   []string `json:"udpUnreliablePorts"`

	MinClientVersion string `json:"minClientVersion"`
	MaxClientVersion string `json:"maxClientVersion"`

	// ⭐ 新增：Salamander 混淆
	ObfsEnabled  bool   `json:"obfsEnabled"`
	ObfsPassword string `json:"obfsPassword"`
}

type ServerStatus struct {
	Running   bool          `json:"running"`
	StartedAt time.Time     `json:"startedAt"`
	Uptime    float64       `json:"uptime"`
	LastError string        `json:"lastError"`
	Port      int           `json:"port"`
	Config    *ServerConfig `json:"config"`
}

func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		Port:         8443,
		PortVPN:      8444,
		IPPoolStart:  "192.168.30.11",
		IPPoolEnd:    "192.168.30.255",
		SubnetMask:   "255.255.255.0",
		StreamWindow: DefaultStreamWindow,
		ConnWindow:   DefaultConnWindow,
		AutoStart:    true,

		ServerTunEnabled: false,
		ServerTunIP:      "192.168.30.10",
		ServerTunMask:    "255.255.255.0",

		// ⭐ 默认全部关闭：
		//   - TCP 连接拆分：把 tcpSplitPorts 上的 TCP 走独立 BBR 连接
		//   - UDP 可靠（匹配端口）：走独立 matchConn（Cubic）
		//   - UDP 不可靠（对战端口）：走 QUIC Datagram
		// 这三项都是「低延迟优化」而非必需功能，默认关闭可以让
		// 新装服务端先用最简单的一条 bulk 数据面跑通，
		// 需要时再在面板里按需开启。
		// 注意：端口列表仍然保留，开启时无需重新填写。
		TCPSplitEnabled: false,
		TCPSplitPorts:   []int{22345, 443},

		UDPReliableEnabled:   false,
		UDPReliablePorts:     []string{"42300-42800"},
		UDPUnreliableEnabled: false,
		UDPUnreliablePorts:   []string{"50000-50550"},

		MinClientVersion: "",
		MaxClientVersion: "",

		// ⭐ 新增：默认不启用混淆
		ObfsEnabled:  false,
		ObfsPassword: "",
	}
}

func Load(path string) (*ServerConfig, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if err := cfg.Save(path); err != nil {
			return nil, fmt.Errorf("创建默认配置失败: %w", err)
		}
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	if cfg.PortVPN == 0 {
		cfg.PortVPN = 8444
	}
	if cfg.TCPSplitPorts == nil {
		cfg.TCPSplitPorts = []int{22345, 443}
	}
	if cfg.UDPReliablePorts == nil {
		cfg.UDPReliablePorts = []string{"42300-42800"}
	}
	if cfg.UDPUnreliablePorts == nil {
		cfg.UDPUnreliablePorts = []string{"50000-50550"}
	}
	return cfg, nil
}

func (c *ServerConfig) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ParsePortRange 解析 "42213" 或 "42300-42800"
func ParsePortRange(s string) (lo, hi int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("空端口")
	}
	if i := strings.Index(s, "-"); i >= 0 {
		lo, err = strconv.Atoi(strings.TrimSpace(s[:i]))
		if err != nil {
			return 0, 0, fmt.Errorf("无效起始端口: %q", s[:i])
		}
		hi, err = strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if err != nil {
			return 0, 0, fmt.Errorf("无效结束端口: %q", s[i+1:])
		}
		if lo < 1 || hi > 65535 || lo > hi {
			return 0, 0, fmt.Errorf("端口范围越界: %d-%d", lo, hi)
		}
		return lo, hi, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, fmt.Errorf("无效端口: %q", s)
	}
	if p < 1 || p > 65535 {
		return 0, 0, fmt.Errorf("端口越界: %d", p)
	}
	return p, p, nil
}

func ExpandPortRanges(ranges []string) []int {
	out := make([]int, 0, 2048)
	seen := make(map[int]bool)
	for _, s := range ranges {
		lo, hi, err := ParsePortRange(s)
		if err != nil {
			continue
		}
		for p := lo; p <= hi; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

func (c *ServerConfig) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("数据端口必须在 1-65535 之间")
	}
	if c.PortVPN < 1 || c.PortVPN > 65535 {
		return fmt.Errorf("控制端口必须在 1-65535 之间")
	}
	if c.Port == c.PortVPN {
		return fmt.Errorf("数据端口和控制端口不能相同")
	}
	startIP := net.ParseIP(c.IPPoolStart)
	endIP := net.ParseIP(c.IPPoolEnd)
	if startIP == nil || startIP.To4() == nil {
		return fmt.Errorf("IP 池起始地址无效: %s", c.IPPoolStart)
	}
	if endIP == nil || endIP.To4() == nil {
		return fmt.Errorf("IP 池结束地址无效: %s", c.IPPoolEnd)
	}
	if net.ParseIP(c.SubnetMask) == nil {
		return fmt.Errorf("子网掩码无效: %s", c.SubnetMask)
	}

	if c.ServerTunEnabled {
		if net.ParseIP(c.ServerTunIP) == nil {
			return fmt.Errorf("服务端 TUN IP 无效: %s", c.ServerTunIP)
		}
		if net.ParseIP(c.ServerTunMask) == nil {
			return fmt.Errorf("服务端 TUN 掩码无效: %s", c.ServerTunMask)
		}
	}

	if c.TCPSplitEnabled {
		if len(c.TCPSplitPorts) == 0 {
			return fmt.Errorf("启用 TCP 连接拆分时，端口列表不能为空")
		}
		seen := make(map[int]bool)
		for _, p := range c.TCPSplitPorts {
			if p < 1 || p > 65535 {
				return fmt.Errorf("TCP 拆分端口无效: %d（必须在 1-65535 之间）", p)
			}
			if seen[p] {
				return fmt.Errorf("TCP 拆分端口重复: %d", p)
			}
			seen[p] = true
		}
	}

	if c.UDPReliableEnabled {
		if len(c.UDPReliablePorts) == 0 {
			return fmt.Errorf("启用 UDP 可靠端口时，端口/范围列表不能为空")
		}
		for _, s := range c.UDPReliablePorts {
			if _, _, err := ParsePortRange(s); err != nil {
				return fmt.Errorf("UDP 可靠端口无效: %s（%v）", s, err)
			}
		}
	}

	if c.UDPUnreliableEnabled {
		if len(c.UDPUnreliablePorts) == 0 {
			return fmt.Errorf("启用 UDP 不可靠端口时，端口/范围列表不能为空")
		}
		for _, s := range c.UDPUnreliablePorts {
			if _, _, err := ParsePortRange(s); err != nil {
				return fmt.Errorf("UDP 不可靠端口无效: %s（%v）", s, err)
			}
		}
	}

	// ⭐ 新增：Salamander 混淆校验
	if c.ObfsEnabled {
		if len(c.ObfsPassword) < 4 {
			return fmt.Errorf("启用混淆时，混淆密码至少 4 字节（当前 %d 字节）", len(c.ObfsPassword))
		}
	}

	minVer := strings.TrimSpace(c.MinClientVersion)
	maxVer := strings.TrimSpace(c.MaxClientVersion)
	if minVer != "" && minVer != "0.0.0" {
		if !isValidSemVer(minVer) {
			return fmt.Errorf("最低客户端版本格式无效: %s（应为 X.Y.Z）", minVer)
		}
	}
	if maxVer != "" && maxVer != "0.0.0" {
		if !isValidSemVer(maxVer) {
			return fmt.Errorf("最高客户端版本格式无效: %s（应为 X.Y.Z）", maxVer)
		}
	}
	if minVer != "" && maxVer != "" && minVer != "0.0.0" && maxVer != "0.0.0" {
		if compareSemVer(minVer, maxVer) > 0 {
			return fmt.Errorf("最低客户端版本 (%s) 不能大于最高版本 (%s)", minVer, maxVer)
		}
	}

	return nil
}

func isValidSemVer(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

func compareSemVer(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		ai, _ := strconv.Atoi(aParts[i])
		bi, _ := strconv.Atoi(bParts[i])
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

func (c *ServerConfig) Clone() *ServerConfig {
	cp := *c
	if c.TCPSplitPorts != nil {
		cp.TCPSplitPorts = make([]int, len(c.TCPSplitPorts))
		copy(cp.TCPSplitPorts, c.TCPSplitPorts)
	}
	if c.UDPReliablePorts != nil {
		cp.UDPReliablePorts = make([]string, len(c.UDPReliablePorts))
		copy(cp.UDPReliablePorts, c.UDPReliablePorts)
	}
	if c.UDPUnreliablePorts != nil {
		cp.UDPUnreliablePorts = make([]string, len(c.UDPUnreliablePorts))
		copy(cp.UDPUnreliablePorts, c.UDPUnreliablePorts)
	}
	return &cp
}

func (c *ServerConfig) String() string {
	extra := ""
	if c.ServerTunEnabled {
		extra = fmt.Sprintf(" serverTun=%s", c.ServerTunIP)
	}
	tcpSplit := "off"
	if c.TCPSplitEnabled {
		ports := make([]string, 0, len(c.TCPSplitPorts))
		for _, p := range c.TCPSplitPorts {
			ports = append(ports, strconv.Itoa(p))
		}
		tcpSplit = "on[" + strings.Join(ports, "|") + "]"
	}
	udpRel := "off"
	if c.UDPReliableEnabled {
		udpRel = "on[" + strings.Join(c.UDPReliablePorts, "|") + "]"
	}
	udpUnrel := "off"
	if c.UDPUnreliableEnabled {
		udpUnrel = "on[" + strings.Join(c.UDPUnreliablePorts, "|") + "]"
	}
	verRange := "any"
	if c.MinClientVersion != "" || c.MaxClientVersion != "" {
		minV := c.MinClientVersion
		maxV := c.MaxClientVersion
		if minV == "" {
			minV = "0.0.0"
		}
		if maxV == "" {
			maxV = "∞"
		}
		verRange = fmt.Sprintf("[%s,%s]", minV, maxV)
	}

	// ⭐ 新增：混淆状态显示
	obfsTag := "off"
	if c.ObfsEnabled {
		obfsTag = fmt.Sprintf("on(pskLen=%d)", len(c.ObfsPassword))
	}

	return fmt.Sprintf("port=%d portVPN=%d pool=%s-%s stream=%d conn=%d tcpSplit=%s udpReliable=%s udpUnreliable=%s obfs=%s clientVer=%s%s",
		c.Port, c.PortVPN, c.IPPoolStart, c.IPPoolEnd,
		c.StreamWindow, c.ConnWindow, tcpSplit, udpRel, udpUnrel, obfsTag, verRange, extra)
}
