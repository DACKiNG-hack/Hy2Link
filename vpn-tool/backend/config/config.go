package config

// vpn-tool/backend/config/config.go
type ClientConfig struct {
	// Name ⭐ 连接名称（用户自定义，仅用于界面显示与 .hy2 分享）
	Name           string `json:"name"`
	IP             string `json:"ip"`
	Port           int    `json:"port"`    // 数据端口（hysteria + h3-data）
	PortVPN        int    `json:"portVPN"` // 控制端口（h3-ctrl）
	Username       string `json:"username"`
	Password       string `json:"password"`
	UseDHCP        bool   `json:"useDHCP"`
	StaticIP       string `json:"staticIP"`
	StaticMask     string `json:"staticMask"`
	SkipCertVerify bool   `json:"skipCertVerify"`

	// ⭐ 新增：Salamander 混淆（必须与服务端一致）
	ObfsEnabled  bool   `json:"obfsEnabled"`
	ObfsPassword string `json:"obfsPassword"`

	// ⭐ 1b-2A：本机「**禁用 P2P**」开关（客户端高级选项），默认 false = 不禁止（P2P 启用）。
	//
	// ⚠️ 为什么用「禁用」而不是「启用」语义：Go 的 bool 零值是 false，
	// 而这个开关**默认必须是「不禁止」**——否则所有旧配置、旧 .hy2 导入、
	// 以及任何只构造 `ClientConfig{...}` 的代码路径都会变成「静默禁用 P2P」
	// （实现本块时踩过：既有 punch 测试全部因 p2pLocalEnabled=false 失败）。
	//
	// 与服务端开关的关系（`P2PEffective` = 两者都满足才生效）：
	//   - 服务端开关（DHCP 第 11 段）权威：关着时客户端连 NAT 探测都不做；
	//   - 本机开关是**本机否决**：关掉后即使服务端允许，本机也不打洞、不建直连。
	// 运行期切换由 `Hysteria2Client.ApplyP2PLocal` 立即生效（关掉会清空路由并关闭已有直连路径）。
	P2PDisabled bool `json:"p2pDisabled"`
}
