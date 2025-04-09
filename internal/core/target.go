package core

import (
	"fmt"
	"net/url"
	"strings"
)

// Target represents a target for scanning
type Target struct {
	// Original input from user
	RawInput string

	// Parsed URL
	URL *url.URL

	// Domain name (e.g., example.com)
	Domain string

	// Base domain without subdomain (e.g., example.com from sub.example.com)
	BaseDomain string

	// IP addresses associated with the domain
	IPAddresses []string

	// Subdomains discovered
	Subdomains []string
}

// NewTarget creates a new target from a URL string
func NewTarget(rawInput string) (*Target, error) {
	// Add scheme if not present
	if !strings.HasPrefix(rawInput, "http://") && !strings.HasPrefix(rawInput, "https://") {
		rawInput = "https://" + rawInput
	}

	// Parse URL
	parsedURL, err := url.Parse(rawInput)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Extract domain
	domain := parsedURL.Hostname()
	if domain == "" {
		return nil, fmt.Errorf("could not extract domain from URL")
	}

	// Extract base domain (this is a simplified version)
	parts := strings.Split(domain, ".")
	baseDomain := domain
	if len(parts) >= 2 {
		baseDomain = strings.Join(parts[len(parts)-2:], ".")
	}

	return &Target{
		RawInput:    rawInput,
		URL:         parsedURL,
		Domain:      domain,
		BaseDomain:  baseDomain,
		IPAddresses: []string{},
		Subdomains:  []string{},
	}, nil
}

// AddIPAddress adds an IP address to the target
func (t *Target) AddIPAddress(ip string) {
	// Check if IP already exists
	for _, existingIP := range t.IPAddresses {
		if existingIP == ip {
			return
		}
	}
	t.IPAddresses = append(t.IPAddresses, ip)
}

// AddSubdomain adds a subdomain to the target
func (t *Target) AddSubdomain(subdomain string) {
	// Check if subdomain already exists
	for _, existingSubdomain := range t.Subdomains {
		if existingSubdomain == subdomain {
			return
		}
	}
	t.Subdomains = append(t.Subdomains, subdomain)
}

// String returns a string representation of the target
func (t *Target) String() string {
	return t.Domain
}
