package recon

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
	"github.com/webrecon/webrecon-tool/internal/utils"
)

// WhoisInfo represents WHOIS information for a domain
type WhoisInfo struct {
	// Domain name
	Domain string

	// Registrar information
	Registrar string

	// Registration date
	CreatedDate string

	// Expiration date
	ExpiryDate string

	// Name servers
	NameServers []string

	// Registrant information
	Registrant string

	// Raw WHOIS data
	RawData string
}

// WhoisScanner performs WHOIS lookups
type WhoisScanner struct {
	// HTTP client for making requests
	client *utils.HTTPClient

	// Target to scan
	target *core.Target

	// Results to store findings
	results *core.Results
}

// NewWhoisScanner creates a new WHOIS scanner
func NewWhoisScanner(target *core.Target, results *core.Results) *WhoisScanner {
	return &WhoisScanner{
		client:  utils.NewHTTPClient(30 * time.Second),
		target:  target,
		results: results,
	}
}

// Scan performs a WHOIS lookup for the target domain
func (s *WhoisScanner) Scan() (*WhoisInfo, error) {
	fmt.Printf("Performing WHOIS lookup for %s...\n", s.target.Domain)

	// For simplicity, we'll use a public WHOIS API
	// In a production tool, you might want to use a proper WHOIS library or direct socket connection
	url := fmt.Sprintf("https://www.whois.com/whois/%s", s.target.Domain)
	
	body, err := s.client.GetBody(url)
	if err != nil {
		return nil, fmt.Errorf("WHOIS lookup failed: %w", err)
	}

	// Parse the WHOIS data
	info := &WhoisInfo{
		Domain:  s.target.Domain,
		RawData: body,
	}

	// Extract registrar
	registrarRegex := regexp.MustCompile(`(?i)Registrar:\s*(.+)`)
	if matches := registrarRegex.FindStringSubmatch(body); len(matches) > 1 {
		info.Registrar = strings.TrimSpace(matches[1])
	}

	// Extract creation date
	createdRegex := regexp.MustCompile(`(?i)Creation Date:\s*(.+)`)
	if matches := createdRegex.FindStringSubmatch(body); len(matches) > 1 {
		info.CreatedDate = strings.TrimSpace(matches[1])
	}

	// Extract expiry date
	expiryRegex := regexp.MustCompile(`(?i)Registry Expiry Date:\s*(.+)`)
	if matches := expiryRegex.FindStringSubmatch(body); len(matches) > 1 {
		info.ExpiryDate = strings.TrimSpace(matches[1])
	}

	// Extract name servers
	nsRegex := regexp.MustCompile(`(?i)Name Server:\s*(.+)`)
	nsMatches := nsRegex.FindAllStringSubmatch(body, -1)
	for _, match := range nsMatches {
		if len(match) > 1 {
			ns := strings.TrimSpace(match[1])
			info.NameServers = append(info.NameServers, ns)
		}
	}

	// Add result to the results collection
	s.results.Add(
		"whois",
		"info",
		"WHOIS Information",
		fmt.Sprintf("WHOIS information for %s", s.target.Domain),
		info,
	)

	return info, nil
}
