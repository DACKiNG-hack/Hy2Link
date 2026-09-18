package cert

//vpn-server\cert\manager.go

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"path/filepath"
	"sync"
)

type Manager struct {
	cfg     *Config
	cfgPath string
	dataDir string

	mu   sync.RWMutex
	cert *tls.Certificate
	acme *acmeState
}

func NewManager(cfgPath, dataDir string) (*Manager, error) {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		cfg:     cfg,
		cfgPath: cfgPath,
		dataDir: dataDir,
	}
	return m, nil
}

func (m *Manager) Config() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Clone()
}

func (m *Manager) Mode() Mode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Mode
}

// ServerHostname 返回 DHCP 下发给客户端的 hostname
func (m *Manager) ServerHostname() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	switch m.cfg.Mode {
	case ModeACME:
		return m.cfg.ACMEDomain
	default:
		return m.cfg.SelfSignedCN
	}
}

func (m *Manager) certDir() string      { return filepath.Join(m.dataDir, "certs") }
func (m *Manager) certPath() string     { return filepath.Join(m.certDir(), "selfsigned.crt") }
func (m *Manager) keyPath() string      { return filepath.Join(m.certDir(), "selfsigned.key") }
func (m *Manager) acmeCacheDir() string { return filepath.Join(m.certDir(), "acme") }

// Load 加载当前配置的证书
func (m *Manager) Load() (tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.cfg.Validate(); err != nil {
		return tls.Certificate{}, err
	}

	switch m.cfg.Mode {
	case ModeSelfSigned:
		return m.loadSelfSignedLocked()
	case ModeACME:
		return m.loadACMELocked()
	default:
		return tls.Certificate{}, fmt.Errorf("未知证书模式: %s", m.cfg.Mode)
	}
}

func (m *Manager) loadSelfSignedLocked() (tls.Certificate, error) {
	// 优先从文件加载
	cert, err := loadSelfSigned(m.certPath(), m.keyPath())
	if err == nil {
		m.cert = &cert
		return cert, nil
	}

	// 不存在或损坏 → 重新生成
	log.Printf("🔐 [自签] 生成新证书 CN=%s 有效期=%d 天", m.cfg.SelfSignedCN, m.cfg.SelfSignedDays)
	cert, err = generateSelfSigned(m.cfg.SelfSignedCN, m.cfg.SelfSignedDays, m.certPath(), m.keyPath())
	if err != nil {
		return tls.Certificate{}, err
	}
	m.cert = &cert
	return cert, nil
}

func (m *Manager) loadACMELocked() (tls.Certificate, error) {
	if m.acme == nil {
		m.acme = &acmeState{
			manager: newACMEManager(m.cfg.ACMEDomain, m.cfg.ACMEEmail, m.acmeCacheDir()),
		}
		if err := m.acme.start(); err != nil {
			m.acme = nil
			return tls.Certificate{}, err
		}
	}

	// 尝试从缓存拿
	cert, err := m.acme.manager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: m.cfg.ACMEDomain,
	})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("获取 ACME 证书失败: %w", err)
	}
	m.cert = cert
	return *cert, nil
}

// GetTLSConfig 返回给 QUIC 用的 TLS 配置
func (m *Manager) GetTLSConfig(nextProtos []string) (*tls.Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cfg := &tls.Config{
		NextProtos: nextProtos,
	}

	switch m.cfg.Mode {
	case ModeSelfSigned:
		if m.cert == nil {
			return nil, fmt.Errorf("自签证书未加载")
		}
		cfg.Certificates = []tls.Certificate{*m.cert}
	case ModeACME:
		if m.acme == nil {
			return nil, fmt.Errorf("ACME 未初始化")
		}
		cfg.GetCertificate = m.acme.manager.GetCertificate
	default:
		return nil, fmt.Errorf("未知证书模式")
	}
	return cfg, nil
}

// Regenerate 重新生成自签证书
func (m *Manager) Regenerate() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg.Mode != ModeSelfSigned {
		return fmt.Errorf("只有自签模式可以重新生成")
	}
	log.Printf("🔐 [自签] 重新生成证书 CN=%s", m.cfg.SelfSignedCN)
	cert, err := generateSelfSigned(m.cfg.SelfSignedCN, m.cfg.SelfSignedDays, m.certPath(), m.keyPath())
	if err != nil {
		return err
	}
	m.cert = &cert
	return nil
}

// UpdateConfig 保存新配置（需要重启服务端生效）
func (m *Manager) UpdateConfig(newCfg *Config) error {
	if err := newCfg.Validate(); err != nil {
		return err
	}
	if err := newCfg.Save(m.cfgPath); err != nil {
		return err
	}
	m.mu.Lock()
	m.cfg = newCfg.Clone()
	m.mu.Unlock()
	log.Printf("🔐 [证书] 配置已更新: mode=%s", newCfg.Mode)
	return nil
}

// Info 返回当前证书信息
func (m *Manager) Info() (*Info, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var cert *x509.Certificate
	switch m.cfg.Mode {
	case ModeSelfSigned:
		if m.cert == nil {
			return nil, fmt.Errorf("证书未加载")
		}
		if len(m.cert.Certificate) == 0 {
			return nil, fmt.Errorf("证书为空")
		}
		c, err := x509.ParseCertificate(m.cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		cert = c
	case ModeACME:
		if m.acme == nil {
			return nil, fmt.Errorf("ACME 未初始化")
		}
		c, err := m.acme.manager.GetCertificate(&tls.ClientHelloInfo{ServerName: m.cfg.ACMEDomain})
		if err != nil {
			return nil, err
		}
		if len(c.Certificate) == 0 {
			return nil, fmt.Errorf("ACME 证书为空")
		}
		parsed, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return nil, err
		}
		cert = parsed
	default:
		return nil, fmt.Errorf("未知证书模式")
	}
	return ParseCertInfo(cert, string(m.cfg.Mode)), nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.acme != nil {
		m.acme.stop()
		m.acme = nil
	}
}
