package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"
)

type Info struct {
	Mode        string    `json:"mode"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	DaysLeft    int       `json:"daysLeft"`
	Fingerprint string    `json:"fingerprint"`
	DNSNames    []string  `json:"dnsNames"`
	IsCA        bool      `json:"isCA"`
}

func ParseCertInfo(cert *x509.Certificate, mode string) *Info {
	fp := sha256.Sum256(cert.Raw)
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	if days < 0 {
		days = 0
	}
	return &Info{
		Mode:        mode,
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		DaysLeft:    days,
		Fingerprint: hex.EncodeToString(fp[:]),
		DNSNames:    cert.DNSNames,
		IsCA:        cert.IsCA,
	}
}
