package recon

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
)

// SSLInfo represents SSL/TLS certificate information
type SSLInfo struct {
	// Domain name
	Domain string

	// Certificate subject
	Subject string

	// Certificate issuer
	Issuer string

	// Valid from date
	ValidFrom time.Time

	// Valid until date
	ValidUntil time.Time

	// Is the certificate valid
	IsValid bool

	// Certificate version
	Version int

	// Serial number
	SerialNumber string

	// Subject Alternative Names
	SANs []string

	// Signature algorithm
	SignatureAlgorithm string

	// Public key algorithm
	PublicKeyAlgorithm string

	// Key size in bits
	KeySize int

	// Is self-signed
	IsSelfSigned bool
}

// SSLScanner performs SSL/TLS certificate analysis
type SSLScanner struct {
	// Target to scan
	target *core.Target

	// Results to store findings
	results *core.Results

	// Timeout for connections
	timeout time.Duration
}

// NewSSLScanner creates a new SSL scanner
func NewSSLScanner(target *core.Target, results *core.Results) *SSLScanner {
	return &SSLScanner{
		target:  target,
		results: results,
		timeout: 10 * time.Second,
	}
}

// Scan performs SSL/TLS certificate analysis for the target domain
func (s *SSLScanner) Scan() (*SSLInfo, error) {
	fmt.Printf("Analyzing SSL/TLS certificate for %s...\n", s.target.Domain)

	// Connect to the server
	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	// Try to connect to port 443
	conn, err := tls.DialWithDialer(dialer, "tcp", s.target.Domain+":443", &tls.Config{
		InsecureSkipVerify: true, // We want to analyze the certificate even if it's invalid
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:443: %w", s.target.Domain, err)
	}
	defer conn.Close()

	// Get the certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	// Analyze the first certificate (the server's certificate)
	cert := certs[0]

	// Check if self-signed
	isSelfSigned := cert.Issuer.String() == cert.Subject.String()

	// Create SSL info
	info := &SSLInfo{
		Domain:             s.target.Domain,
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		ValidFrom:          cert.NotBefore,
		ValidUntil:         cert.NotAfter,
		IsValid:            time.Now().After(cert.NotBefore) && time.Now().Before(cert.NotAfter),
		Version:            cert.Version,
		SerialNumber:       cert.SerialNumber.String(),
		SANs:               cert.DNSNames,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		IsSelfSigned:       isSelfSigned,
	}

	// Add result to the results collection
	s.results.Add(
		"ssl",
		"info",
		"SSL/TLS Certificate",
		fmt.Sprintf("SSL/TLS certificate for %s", s.target.Domain),
		info,
	)

	// Check for certificate issues
	if !info.IsValid {
		s.results.Add(
			"ssl",
			"high",
			"Invalid SSL Certificate",
			fmt.Sprintf("The SSL certificate for %s is not valid", s.target.Domain),
			info,
		)
	}

	if info.IsSelfSigned {
		s.results.Add(
			"ssl",
			"medium",
			"Self-Signed Certificate",
			fmt.Sprintf("The SSL certificate for %s is self-signed", s.target.Domain),
			info,
		)
	}

	// Check for expiration
	daysUntilExpiration := int(info.ValidUntil.Sub(time.Now()).Hours() / 24)
	if daysUntilExpiration < 30 {
		s.results.Add(
			"ssl",
			"medium",
			"Certificate Expiring Soon",
			fmt.Sprintf("The SSL certificate for %s will expire in %d days", s.target.Domain, daysUntilExpiration),
			info,
		)
	}

	return info, nil
}
