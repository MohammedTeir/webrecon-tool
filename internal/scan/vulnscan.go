package scan

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
	"github.com/webrecon/webrecon-tool/internal/utils"
)

// VulnInfo represents vulnerability scanning results
type VulnInfo struct {
	// Target domain
	Target string

	// Vulnerabilities found
	Vulnerabilities []Vulnerability

	// Scan start time
	StartTime time.Time

	// Scan end time
	EndTime time.Time
}

// Vulnerability represents a single vulnerability
type Vulnerability struct {
	// Name of the vulnerability
	Name string

	// Description of the vulnerability
	Description string

	// Severity (low, medium, high, critical)
	Severity string

	// URL where the vulnerability was found
	URL string

	// Additional details
	Details map[string]string
}

// VulnScanner performs vulnerability scanning
type VulnScanner struct {
	// Target to scan
	target *core.Target

	// Results to store findings
	results *core.Results

	// HTTP client
	client *utils.HTTPClient
}

// NewVulnScanner creates a new vulnerability scanner
func NewVulnScanner(target *core.Target, results *core.Results) *VulnScanner {
	return &VulnScanner{
		target:  target,
		results: results,
		client:  utils.NewHTTPClient(30 * time.Second),
	}
}

// Scan performs vulnerability scanning on the target
func (s *VulnScanner) Scan() (*VulnInfo, error) {
	fmt.Printf("Performing vulnerability scanning on %s...\n", s.target.Domain)

	info := &VulnInfo{
		Target:          s.target.Domain,
		Vulnerabilities: []Vulnerability{},
		StartTime:       time.Now(),
	}

	// Check for common security headers
	if err := s.checkSecurityHeaders(info); err != nil {
		fmt.Printf("Warning: Failed to check security headers: %v\n", err)
	}

	// Check for HTTP methods
	if err := s.checkHTTPMethods(info); err != nil {
		fmt.Printf("Warning: Failed to check HTTP methods: %v\n", err)
	}

	// Check for SSL/TLS vulnerabilities
	if err := s.checkSSLTLS(info); err != nil {
		fmt.Printf("Warning: Failed to check SSL/TLS: %v\n", err)
	}

	// Check for common web vulnerabilities
	if err := s.checkCommonVulnerabilities(info); err != nil {
		fmt.Printf("Warning: Failed to check common vulnerabilities: %v\n", err)
	}

	info.EndTime = time.Now()

	// Add summary result
	s.results.Add(
		"vulnscan",
		"info",
		"Vulnerability Scan Summary",
		fmt.Sprintf("Found %d vulnerabilities on %s", len(info.Vulnerabilities), s.target.Domain),
		info,
	)

	return info, nil
}

// checkSecurityHeaders checks for missing security headers
func (s *VulnScanner) checkSecurityHeaders(info *VulnInfo) error {
	url := fmt.Sprintf("https://%s", s.target.Domain)
	headers, err := s.client.GetHeaders(url)
	if err != nil {
		// Try HTTP if HTTPS fails
		url = fmt.Sprintf("http://%s", s.target.Domain)
		headers, err = s.client.GetHeaders(url)
		if err != nil {
			return fmt.Errorf("failed to get headers: %w", err)
		}
	}

	// Check for Content-Security-Policy
	if headers.Get("Content-Security-Policy") == "" {
		vuln := Vulnerability{
			Name:        "Missing Content-Security-Policy Header",
			Description: "The Content-Security-Policy header is missing. This header helps prevent XSS attacks.",
			Severity:    "medium",
			URL:         url,
			Details: map[string]string{
				"header": "Content-Security-Policy",
				"recommendation": "Implement a Content-Security-Policy header",
			},
		}
		info.Vulnerabilities = append(info.Vulnerabilities, vuln)
		s.results.Add(
			"vulnscan",
			"medium",
			vuln.Name,
			vuln.Description,
			vuln,
		)
	}

	// Check for X-Frame-Options
	if headers.Get("X-Frame-Options") == "" {
		vuln := Vulnerability{
			Name:        "Missing X-Frame-Options Header",
			Description: "The X-Frame-Options header is missing. This header helps prevent clickjacking attacks.",
			Severity:    "medium",
			URL:         url,
			Details: map[string]string{
				"header": "X-Frame-Options",
				"recommendation": "Implement X-Frame-Options header with DENY or SAMEORIGIN value",
			},
		}
		info.Vulnerabilities = append(info.Vulnerabilities, vuln)
		s.results.Add(
			"vulnscan",
			"medium",
			vuln.Name,
			vuln.Description,
			vuln,
		)
	}

	// Check for X-XSS-Protection
	if headers.Get("X-XSS-Protection") == "" {
		vuln := Vulnerability{
			Name:        "Missing X-XSS-Protection Header",
			Description: "The X-XSS-Protection header is missing. This header helps prevent XSS attacks in older browsers.",
			Severity:    "low",
			URL:         url,
			Details: map[string]string{
				"header": "X-XSS-Protection",
				"recommendation": "Implement X-XSS-Protection header with '1; mode=block' value",
			},
		}
		info.Vulnerabilities = append(info.Vulnerabilities, vuln)
		s.results.Add(
			"vulnscan",
			"low",
			vuln.Name,
			vuln.Description,
			vuln,
		)
	}

	// Check for X-Content-Type-Options
	if headers.Get("X-Content-Type-Options") == "" {
		vuln := Vulnerability{
			Name:        "Missing X-Content-Type-Options Header",
			Description: "The X-Content-Type-Options header is missing. This header prevents MIME type sniffing.",
			Severity:    "low",
			URL:         url,
			Details: map[string]string{
				"header": "X-Content-Type-Options",
				"recommendation": "Implement X-Content-Type-Options header with 'nosniff' value",
			},
		}
		info.Vulnerabilities = append(info.Vulnerabilities, vuln)
		s.results.Add(
			"vulnscan",
			"low",
			vuln.Name,
			vuln.Description,
			vuln,
		)
	}

	// Check for Strict-Transport-Security
	if headers.Get("Strict-Transport-Security") == "" && strings.HasPrefix(url, "https") {
		vuln := Vulnerability{
			Name:        "Missing Strict-Transport-Security Header",
			Description: "The Strict-Transport-Security header is missing. This header enforces secure connections to the server.",
			Severity:    "medium",
			URL:         url,
			Details: map[string]string{
				"header": "Strict-Transport-Security",
				"recommendation": "Implement Strict-Transport-Security header with 'max-age=31536000; includeSubDomains' value",
			},
		}
		info.Vulnerabilities = append(info.Vulnerabilities, vuln)
		s.results.Add(
			"vulnscan",
			"medium",
			vuln.Name,
			vuln.Description,
			vuln,
		)
	}

	// Check for Server header information disclosure
	if server := headers.Get("Server"); server != "" {
		vuln := Vulnerability{
			Name:        "Server Information Disclosure",
			Description: "The Server header discloses information about the web server software and version.",
			Severity:    "low",
			URL:         url,
			Details: map[string]string{
				"header": "Server",
				"value":  server,
				"recommendation": "Configure the server to hide version information",
			},
		}
		info.Vulnerabilities = append(info.Vulnerabilities, vuln)
		s.results.Add(
			"vulnscan",
			"low",
			vuln.Name,
			vuln.Description,
			vuln,
		)
	}

	return nil
}

// checkHTTPMethods checks for dangerous HTTP methods
func (s *VulnScanner) checkHTTPMethods(info *VulnInfo) error {
	url := fmt.Sprintf("https://%s", s.target.Domain)
	
	// Create a custom request to check allowed methods
	req, err := http.NewRequest("OPTIONS", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set user agent
	req.Header.Set("User-Agent", s.client.UserAgent)
	
	// Send the request
	resp, err := s.client.Client.Do(req)
	if err != nil {
		// Try HTTP if HTTPS fails
		url = fmt.Sprintf("http://%s", s.target.Domain)
		req, err = http.NewRequest("OPTIONS", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("User-Agent", s.client.UserAgent)
		resp, err = s.client.Client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}
	}
	defer resp.Body.Close()
	
	// Check for Allow or Public header
	methods := resp.Header.Get("Allow")
	if methods == "" {
		methods = resp.Header.Get("Public")
	}
	
	if methods != "" {
		// Check for dangerous methods
		if strings.Contains(methods, "TRACE") {
			vuln := Vulnerability{
				Name:        "TRACE Method Enabled",
				Description: "The TRACE method is enabled on the server. This can lead to Cross-Site Tracing (XST) attacks.",
				Severity:    "medium",
				URL:         url,
				Details: map[string]string{
					"methods": methods,
					"recommendation": "Disable the TRACE method on the server",
				},
			}
			info.Vulnerabilities = append(info.Vulnerabilities, vuln)
			s.results.Add(
				"vulnscan",
				"medium",
				vuln.Name,
				vuln.Description,
				vuln,
			)
		}
		
		if strings.Contains(methods, "PUT") || strings.Contains(methods, "DELETE") {
			vuln := Vulnerability{
				Name:        "Dangerous HTTP Methods Enabled",
				Description: "Dangerous HTTP methods (PUT/DELETE) are enabled on the server. This can lead to unauthorized modifications.",
				Severity:    "high",
				URL:         url,
				Details: map[string]string{
					"methods": methods,
					"recommendation": "Disable dangerous HTTP methods or implement proper authentication",
				},
			}
			info.Vulnerabilities = append(info.Vulnerabilities, vuln)
			s.results.Add(
				"vulnscan",
				"high",
				vuln.Name,
				vuln.Description,
				vuln,
			)
		}
	}
	
	return nil
}

// checkSSLTLS checks for SSL/TLS vulnerabilities
func (s *VulnScanner) checkSSLTLS(info *VulnInfo) error {
	// This is a simplified version. In a real tool, you would use a library like crypto/tls
	// to check for SSL/TLS vulnerabilities like weak ciphers, outdated protocols, etc.
	
	// For now, we'll just check if HTTPS is available
	url := fmt.Sprintf("https://%s", s.target.Domain)
	_, err := s.client.GetHeaders(url)
	if err != nil {
		vuln := Vulnerability{
			Name:        "HTTPS Not Available",
			Description: "The website does not support HTTPS or has an invalid SSL/TLS certificate.",
			Severity:    "high",
			URL:         fmt.Sprintf("http://%s", s.target.Domain),
			Details: map[string]string{
				"error": err.Error(),
				"recommendation": "Implement HTTPS with a valid SSL/TLS certificate",
			},
		}
		info.Vulnerabilities = append(info.Vulnerabilities, vuln)
		s.results.Add(
			"vulnscan",
			"high",
			vuln.Name,
			vuln.Description,
			vuln,
		)
	}
	
	return nil
}

// checkCommonVulnerabilities checks for common web vulnerabilities
func (s *VulnScanner) checkCommonVulnerabilities(info *VulnInfo) error {
	// This is a simplified version. In a real tool, you would implement more comprehensive checks
	// for vulnerabilities like XSS, SQL injection, CSRF, etc.
	
	// Check for common admin paths
	adminPaths := []string{
		"/admin", "/administrator", "/wp-admin", "/login", "/wp-login.php",
		"/admin.php", "/admin/login", "/adminlogin", "/admin/index.php",
		"/user/login", "/cpanel", "/phpmyadmin", "/dashboard",
	}
	
	for _, path := range adminPaths {
		url := fmt.Sprintf("https://%s%s", s.target.Domain, path)
		resp, err := s.client.Get(url)
		if err != nil {
			// Try HTTP if HTTPS fails
			url = fmt.Sprintf("http://%s%s", s.target.Domain, path)
			resp, err = s.client.Get(url)
			if err != nil {
				continue
			}
		}
		defer resp.Body.Close()
		
		// Check if the page exists (not 404)
		if resp.StatusCode != http.StatusNotFound {
			vuln := Vulnerability{
				Name:        "Admin Interface Exposed",
				Description: fmt.Sprintf("An admin interface was found at %s", path),
				Severity:    "medium",
				URL:         url,
				Details: map[string]string{
					"path": path,
					"status_code": fmt.Sprintf("%d", resp.StatusCode),
					"recommendation": "Restrict access to admin interfaces",
				},
			}
			info.Vulnerabilities = append(info.Vulnerabilities, vuln)
			s.results.Add(
				"vulnscan",
				"medium",
				vuln.Name,
				vuln.Description,
				vuln,
			)
		}
	}
	
	return nil
}
