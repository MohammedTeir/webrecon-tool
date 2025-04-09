package recon

import (
	"fmt"
	"net"
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
)

// DNSInfo represents DNS information for a domain
type DNSInfo struct {
	// Domain name
	Domain string

	// A records (IPv4 addresses)
	ARecords []string

	// AAAA records (IPv6 addresses)
	AAAARecords []string

	// MX records (mail servers)
	MXRecords []string

	// NS records (name servers)
	NSRecords []string

	// TXT records
	TXTRecords []string

	// CNAME records
	CNAMERecords []string

	// SOA record
	SOARecord string
}

// DNSScanner performs DNS lookups
type DNSScanner struct {
	// Target to scan
	target *core.Target

	// Results to store findings
	results *core.Results

	// Timeout for DNS queries
	timeout time.Duration
}

// NewDNSScanner creates a new DNS scanner
func NewDNSScanner(target *core.Target, results *core.Results) *DNSScanner {
	return &DNSScanner{
		target:  target,
		results: results,
		timeout: 5 * time.Second,
	}
}

// Scan performs DNS lookups for the target domain
func (s *DNSScanner) Scan() (*DNSInfo, error) {
	fmt.Printf("Performing DNS lookups for %s...\n", s.target.Domain)

	info := &DNSInfo{
		Domain: s.target.Domain,
	}

	// Get A records (IPv4)
	ips, err := net.LookupIP(s.target.Domain)
	if err == nil {
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				info.ARecords = append(info.ARecords, ipv4.String())
				s.target.AddIPAddress(ipv4.String())
			} else {
				info.AAAARecords = append(info.AAAARecords, ip.String())
			}
		}
	}

	// Get MX records
	mxRecords, err := net.LookupMX(s.target.Domain)
	if err == nil {
		for _, mx := range mxRecords {
			info.MXRecords = append(info.MXRecords, fmt.Sprintf("%s (priority: %d)", mx.Host, mx.Pref))
		}
	}

	// Get NS records
	nsRecords, err := net.LookupNS(s.target.Domain)
	if err == nil {
		for _, ns := range nsRecords {
			info.NSRecords = append(info.NSRecords, ns.Host)
		}
	}

	// Get TXT records
	txtRecords, err := net.LookupTXT(s.target.Domain)
	if err == nil {
		info.TXTRecords = txtRecords
	}

	// Get CNAME record
	cname, err := net.LookupCNAME(s.target.Domain)
	if err == nil && cname != s.target.Domain+"." {
		info.CNAMERecords = append(info.CNAMERecords, cname)
	}

	// Add result to the results collection
	s.results.Add(
		"dns",
		"info",
		"DNS Information",
		fmt.Sprintf("DNS records for %s", s.target.Domain),
		info,
	)

	// Add detailed results for each record type
	if len(info.ARecords) > 0 {
		s.results.Add(
			"dns",
			"info",
			"A Records",
			fmt.Sprintf("IPv4 addresses for %s", s.target.Domain),
			info.ARecords,
		)
	}

	if len(info.MXRecords) > 0 {
		s.results.Add(
			"dns",
			"info",
			"MX Records",
			fmt.Sprintf("Mail servers for %s", s.target.Domain),
			info.MXRecords,
		)
	}

	if len(info.NSRecords) > 0 {
		s.results.Add(
			"dns",
			"info",
			"NS Records",
			fmt.Sprintf("Name servers for %s", s.target.Domain),
			info.NSRecords,
		)
	}

	return info, nil
}
