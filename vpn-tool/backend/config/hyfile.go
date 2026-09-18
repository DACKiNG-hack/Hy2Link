package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ⭐ .hy2 配置文件格式
type HY2File struct {
	V              int    `json:"v"`
	Type           string `json:"type"`
	Name           string `json:"name"`
	Server         string `json:"server"`
	Port           int    `json:"port"`
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

// ExportToFile 将 ClientConfig 导出为 .hy2 文件
func ExportToFile(cfg ClientConfig, path string) error {
	if !strings.HasSuffix(strings.ToLower(path), HyFileExt) {
		path += HyFileExt
	}
	f := HY2File{
		V:              HyFileVersion,
		Type:           HyFileType,
		Name:           cfg.IP,
		Server:         cfg.IP,
		Port:           cfg.Port,
		Password:       cfg.Password,
		ObfsEnabled:    cfg.ObfsEnabled,
		ObfsPassword:   cfg.ObfsPassword,
		SkipCertVerify: cfg.SkipCertVerify,
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
	if f.Server == "" {
		return nil, fmt.Errorf("缺少服务器地址")
	}
	if f.Port <= 0 || f.Port > 65535 {
		return nil, fmt.Errorf("无效端口: %d", f.Port)
	}
	if f.Password == "" {
		return nil, fmt.Errorf("缺少认证密码")
	}

	cfg := &ClientConfig{
		IP:             f.Server,
		Port:           f.Port,
		Password:       f.Password,
		UseDHCP:        true,
		ObfsEnabled:    f.ObfsEnabled,
		ObfsPassword:   f.ObfsPassword,
		SkipCertVerify: f.SkipCertVerify,
	}
	return cfg, nil
}

// SuggestFileName 根据配置生成建议文件名
func SuggestFileName(cfg ClientConfig) string {
	host := cfg.IP
	host = strings.ReplaceAll(host, ":", "_")
	host = strings.ReplaceAll(host, "/", "_")
	if host == "" {
		host = "hy2link"
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
