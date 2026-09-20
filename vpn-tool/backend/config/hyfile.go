package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ⭐ .hy2 配置文件格式
//
// ⚠️ 安全提示（审计 S32）：这个文件是**不受信任的输入**——
// .hy2 关联会被自动注册，用户双击一个别人发来的 .hy2 就会走到这里。
// 因此 ParseHyFile 必须把每个字段都当作攻击者可控来处理。
type HY2File struct {
	V      int    `json:"v"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Server string `json:"server"`
	Port   int    `json:"port"`

	// Username ⭐ 服务端已停用全局密码（单用户模式），
	// 客户端必须以「用户名:密码」认证，因此用户名必须随配置一起分发。
	// 这是**新增字段**：旧 .hy2 文件没有它，导入后用户名会留空，
	// 需要在 UI 里补填；旧客户端读到未知字段会忽略，因此是向后兼容的。
	Username       string `json:"username"`
	Password       string `json:"password"`
	ObfsEnabled    bool   `json:"obfsEnabled"`
	ObfsPassword   string `json:"obfsPassword"`
	SkipCertVerify bool   `json:"skipCertVerify"`
}

const (
	HyFileExt     = ".hy2"
	HyFileType    = "hy2link"
	HyFileVersion = 1
)

// safeNameChar 用于生成文件名时做白名单过滤
func sanitizeForFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// validServerHost 校验 .hy2 里的 server 字段。
//
// ⭐ 安全审计 S32 / S33：原实现只检查「非空」，于是这个值会一路进入
// 指纹文件名拼接（`filepath.Join(dir, "fp_"+serverIP+".txt")`）。
// 由于 Windows 上反斜杠不会被过滤，`..\..\..\..\Users\Public\secret`
// 会经 filepath.Join 的词法归约变成 `C:\Users\Public\secret.txt`，
// 造成任意 *.txt 的存在性探测 / 删除 / 读取。
//
// 这里限定为「合法 IP 字面量」或「合法主机名」，从源头杜绝该问题。
func validServerHost(s string) error {
	if s == "" {
		return fmt.Errorf("缺少服务器地址")
	}
	if len(s) > 253 {
		return fmt.Errorf("服务器地址过长")
	}
	if net.ParseIP(s) != nil {
		return nil
	}
	// 主机名：不能含路径分隔符、盘符、空格或 Windows 保留字符
	if strings.ContainsAny(s, `\/:*?"<>| `) {
		return fmt.Errorf("服务器地址含非法字符: %q", s)
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return fmt.Errorf("服务器地址格式无效: %q", s)
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("服务器地址格式无效: %q", s)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-'
			if !ok {
				return fmt.Errorf("服务器地址格式无效: %q", s)
			}
		}
	}
	return nil
}

// validUsername 校验用户名。
//
// 服务端用第一个冒号切分「用户名:密码」（见 authenticator.go 的 parseAuth），
// 并且整个认证串尾部还带 ":vn=X.Y.Z" 版本段，因此用户名里
// 不能出现冒号、换行、回车或首尾空白。
func validUsername(s string) error {
	if len(s) > 64 {
		return fmt.Errorf("用户名过长（最多 64 字节）")
	}
	if strings.TrimSpace(s) != s {
		return fmt.Errorf("用户名不能以空白开头或结尾")
	}
	if strings.ContainsAny(s, ":\r\n\t") {
		return fmt.Errorf("用户名不能包含冒号、换行或制表符")
	}
	return nil
}

// ExportToFile 将 ClientConfig 导出为 .hy2 文件
func ExportToFile(cfg ClientConfig, path string) error {
	if !strings.HasSuffix(strings.ToLower(path), HyFileExt) {
		path += HyFileExt
	}
	f := HY2File{
		V:              HyFileVersion,
		Type:           HyFileType,
		Name:           cfg.Name,
		Server:         cfg.IP,
		Port:           cfg.Port,
		Username:       cfg.Username,
		Password:       cfg.Password,
		ObfsEnabled:    cfg.ObfsEnabled,
		ObfsPassword:   cfg.ObfsPassword,
		SkipCertVerify: cfg.SkipCertVerify,
	}
	if f.Name == "" {
		f.Name = cfg.IP
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// ⭐ 安全审计 S43：失败时不能把含明文口令的 .tmp 留在磁盘上。
		//    另外要说明：Windows 上 0600 只映射为「只读」属性，
		//    并不提供保密性，文件实际继承父目录 ACL。
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ParseHyFile 解析 .hy2 文件，返回 ClientConfig
func ParseHyFile(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	var f HY2File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("解析失败（不是有效的 .hy2 文件）: %w", err)
	}

	if f.Type != HyFileType {
		return nil, fmt.Errorf("不是 Hy2Link 配置文件（type=%s）", f.Type)
	}
	if f.V > HyFileVersion {
		return nil, fmt.Errorf("配置文件版本过高（v%d，当前支持 v%d）", f.V, HyFileVersion)
	}
	// ⭐ 安全审计 S32/S33
	if err := validServerHost(f.Server); err != nil {
		return nil, err
	}
	if f.Port <= 0 || f.Port > 65535 {
		return nil, fmt.Errorf("无效端口: %d", f.Port)
	}
	if f.Password == "" {
		return nil, fmt.Errorf("缺少认证密码")
	}
	if len(f.Password) > 512 || len(f.ObfsPassword) > 512 {
		return nil, fmt.Errorf("口令长度异常")
	}
	// 用户名可以留空（旧版 .hy2 没有这个字段），由 UI 提示补填；
	// 但只要非空就必须是合法格式，避免把分隔符/换行带进认证串。
	if f.Username != "" {
		if err := validUsername(f.Username); err != nil {
			return nil, err
		}
	}
	// ⭐ 安全审计 S32：混淆口令必须与服务端一致，且 Salamander 要求 >= 4 字节
	if f.ObfsEnabled && len(f.ObfsPassword) < 4 {
		return nil, fmt.Errorf("启用了混淆但混淆密码少于 4 字节")
	}

	cfg := &ClientConfig{
		Name:         strings.TrimSpace(f.Name),
		IP:           f.Server,
		Port:         f.Port,
		Username:     f.Username,
		Password:     f.Password,
		UseDHCP:      true,
		ObfsEnabled:  f.ObfsEnabled,
		ObfsPassword: f.ObfsPassword,

		// ⭐ 安全审计 S32（重要）：**忽略文件里的 skipCertVerify**。
		//
		// 该字段为 true 时会让 client.go 的 verifyPin / verifyPinOrCA
		// 在第一步就 return nil —— 指纹、CA、域名、有效期全部不检查。
		// 而 .hy2 关联是自动注册的，诱导双击一个文件即可把客户端
		// 降到「零 TLS 校验」，攻击者用自签证书就能完整中间人。
		// 该开关只能由用户在本机 UI 上对某个连接显式开启。
		SkipCertVerify: false,
	}
	return cfg, nil
}

// SuggestFileName 根据配置生成建议文件名
func SuggestFileName(cfg ClientConfig) string {
	// ⭐ 安全审计 S43：改用白名单过滤，避免恶意 server 值
	// 把反斜杠与 .. 带进保存对话框的建议文件名。
	host := sanitizeForFilename(cfg.IP)
	if host == "" {
		host = "hy2link"
	}
	if len(host) > 64 {
		host = host[:64]
	}
	return fmt.Sprintf("Hy2Link_%s_%s%s",
		host, time.Now().Format("20060102"), HyFileExt)
}

// DefaultDownloadsPath 返回合理的导出默认路径
func DefaultDownloadsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dl := filepath.Join(home, "Downloads")
	if _, err := os.Stat(dl); err == nil {
		return dl
	}
	return home
}
