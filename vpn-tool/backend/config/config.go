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
}
