package cert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Mode string

const (
	ModeSelfSigned Mode = "selfsigned"
	ModeACME       Mode = "acme"
)

type Config struct {
	Mode Mode `json:"mode"`

	// 自签
	SelfSignedCN   string `json:"selfSignedCN"`
	SelfSignedDays int    `json:"selfSignedDays"`

	// ACME
	ACMEDomain string `json:"acmeDomain"`
	ACMEEmail  string `json:"acmeEmail"`
}

func DefaultConfig() *Config {
	return &Config{
		Mode:           ModeSelfSigned,
		SelfSignedCN:   "hy2link.local",
		SelfSignedDays: 3650,
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if err := cfg.Save(path); err != nil {
			return nil, fmt.Errorf("创建默认证书配置失败: %w", err)
		}
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析证书配置失败: %w", err)
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeSelfSigned
	}
	if cfg.SelfSignedDays <= 0 {
		cfg.SelfSignedDays = 3650
	}
	if cfg.SelfSignedCN == "" {
		cfg.SelfSignedCN = "hy2link.local"
	}
	return cfg, nil
}

func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *Config) Validate() error {
	switch c.Mode {
	case ModeSelfSigned:
		if strings.TrimSpace(c.SelfSignedCN) == "" {
			return fmt.Errorf("自签通用名不能为空")
		}
		if c.SelfSignedDays < 1 || c.SelfSignedDays > 36500 {
			return fmt.Errorf("自签有效期必须在 1-36500 天之间")
		}
	case ModeACME:
		domain := strings.TrimSpace(c.ACMEDomain)
		if domain == "" {
			return fmt.Errorf("ACME 域名不能为空")
		}
		if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
			return fmt.Errorf("ACME 域名不能包含协议前缀")
		}
		if !strings.Contains(domain, ".") {
			return fmt.Errorf("ACME 域名格式无效: %s", domain)
		}
		if strings.TrimSpace(c.ACMEEmail) == "" {
			return fmt.Errorf("ACME 邮箱不能为空")
		}
	default:
		return fmt.Errorf("未知证书模式: %s", c.Mode)
	}
	return nil
}

func (c *Config) Clone() *Config {
	cp := *c
	return &cp
}
