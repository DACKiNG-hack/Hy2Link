package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// generateSelfSigned 生成自签证书（ECDSA P-256）
func generateSelfSigned(cn string, days int, certPath, keyPath string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成私钥失败: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成序列号失败: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Hy2Link"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{cn},
	}

	// 如果 CN 是 IP，加到 IPAddresses
	if ip := net.ParseIP(cn); ip != nil {
		template.IPAddresses = []net.IP{ip}
		template.DNSNames = nil
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("签发证书失败: %w", err)
	}

	// 保存证书
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("保存证书失败: %w", err)
	}

	// 保存私钥
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("序列化私钥失败: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("保存私钥失败: %w", err)
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}

// loadSelfSigned 从文件加载自签证书
func loadSelfSigned(certPath, keyPath string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certPath, keyPath)
}
