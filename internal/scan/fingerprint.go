package scan

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
	"github.com/webrecon/webrecon-tool/internal/utils"
)

// TechInfo represents technology fingerprinting results
type TechInfo struct {
	// Target domain
	Target string

	// Web server information
	WebServer string

	// Server OS
	OperatingSystem string

	// Programming languages detected
	ProgrammingLanguages []string

	// Frameworks detected
	Frameworks []string

	// CMS detected
	CMS string

	// JavaScript libraries
	JavaScriptLibraries []string

	// Analytics tools
	Analytics []string

	// Headers
	Headers map[string]string

	// Cookies
	Cookies []string
}

// FingerprintScanner performs technology fingerprinting
type FingerprintScanner struct {
	// Target to scan
	target *core.Target

	// Results to store findings
	results *core.Results

	// HTTP client
	client *utils.HTTPClient
}

// NewFingerprintScanner creates a new fingerprint scanner
func NewFingerprintScanner(target *core.Target, results *core.Results) *FingerprintScanner {
	return &FingerprintScanner{
		target:  target,
		results: results,
		client:  utils.NewHTTPClient(30 * time.Second),
	}
}

// Scan performs technology fingerprinting on the target
func (s *FingerprintScanner) Scan() (*TechInfo, error) {
	fmt.Printf("Performing technology fingerprinting on %s...\n", s.target.Domain)

	info := &TechInfo{
		Target:              s.target.Domain,
		ProgrammingLanguages: []string{},
		Frameworks:          []string{},
		JavaScriptLibraries: []string{},
		Analytics:           []string{},
		Headers:             make(map[string]string),
		Cookies:             []string{},
	}

	// Get HTTP headers
	url := fmt.Sprintf("https://%s", s.target.Domain)
	headers, err := s.client.GetHeaders(url)
	if err != nil {
		// Try HTTP if HTTPS fails
		url = fmt.Sprintf("http://%s", s.target.Domain)
		headers, err = s.client.GetHeaders(url)
		if err != nil {
			return nil, fmt.Errorf("failed to get headers: %w", err)
		}
	}

	// Extract server information
	if server := headers.Get("Server"); server != "" {
		info.WebServer = server
		info.Headers["Server"] = server

		// Add result to the results collection
		s.results.Add(
			"fingerprint",
			"info",
			"Web Server",
			fmt.Sprintf("Web server: %s", server),
			server,
		)

		// Try to determine OS
		if strings.Contains(strings.ToLower(server), "windows") {
			info.OperatingSystem = "Windows"
		} else if strings.Contains(strings.ToLower(server), "ubuntu") || 
				  strings.Contains(strings.ToLower(server), "debian") || 
				  strings.Contains(strings.ToLower(server), "centos") || 
				  strings.Contains(strings.ToLower(server), "fedora") {
			info.OperatingSystem = "Linux"
		} else if strings.Contains(strings.ToLower(server), "macos") || 
				  strings.Contains(strings.ToLower(server), "darwin") {
			info.OperatingSystem = "macOS"
		}
	}

	// Extract other headers
	for name, values := range headers {
		for _, value := range values {
			info.Headers[name] = value
		}
	}

	// Get page content
	body, err := s.client.GetBody(url)
	if err != nil {
		fmt.Printf("Warning: Failed to get page content: %v\n", err)
	} else {
		// Detect programming languages
		s.detectProgrammingLanguages(body, info)

		// Detect frameworks
		s.detectFrameworks(body, info)

		// Detect CMS
		s.detectCMS(body, info)

		// Detect JavaScript libraries
		s.detectJavaScriptLibraries(body, info)

		// Detect analytics
		s.detectAnalytics(body, info)
	}

	// Add summary result
	s.results.Add(
		"fingerprint",
		"info",
		"Technology Fingerprinting",
		fmt.Sprintf("Technology stack for %s", s.target.Domain),
		info,
	)

	return info, nil
}

// detectProgrammingLanguages detects programming languages from page content
func (s *FingerprintScanner) detectProgrammingLanguages(body string, info *TechInfo) {
	// PHP
	if strings.Contains(body, "PHP") || 
	   strings.Contains(body, "php") || 
	   strings.Contains(info.Headers["X-Powered-By"], "PHP") {
		info.ProgrammingLanguages = append(info.ProgrammingLanguages, "PHP")
		s.results.Add(
			"fingerprint",
			"info",
			"Programming Language",
			"PHP detected",
			"PHP",
		)
	}

	// ASP.NET
	if strings.Contains(body, "ASP.NET") || 
	   strings.Contains(info.Headers["X-Powered-By"], "ASP.NET") || 
	   info.Headers["X-AspNet-Version"] != "" {
		info.ProgrammingLanguages = append(info.ProgrammingLanguages, "ASP.NET")
		s.results.Add(
			"fingerprint",
			"info",
			"Programming Language",
			"ASP.NET detected",
			"ASP.NET",
		)
	}

	// Java
	if strings.Contains(body, "Java") || 
	   strings.Contains(info.Headers["X-Powered-By"], "JSP") || 
	   strings.Contains(info.Headers["X-Powered-By"], "Servlet") {
		info.ProgrammingLanguages = append(info.ProgrammingLanguages, "Java")
		s.results.Add(
			"fingerprint",
			"info",
			"Programming Language",
			"Java detected",
			"Java",
		)
	}

	// Python
	if strings.Contains(body, "Python") || 
	   strings.Contains(info.Headers["X-Powered-By"], "Python") || 
	   strings.Contains(info.Headers["Server"], "Python") {
		info.ProgrammingLanguages = append(info.ProgrammingLanguages, "Python")
		s.results.Add(
			"fingerprint",
			"info",
			"Programming Language",
			"Python detected",
			"Python",
		)
	}

	// Ruby
	if strings.Contains(body, "Ruby") || 
	   strings.Contains(info.Headers["X-Powered-By"], "Ruby") || 
	   strings.Contains(info.Headers["Server"], "Ruby") {
		info.ProgrammingLanguages = append(info.ProgrammingLanguages, "Ruby")
		s.results.Add(
			"fingerprint",
			"info",
			"Programming Language",
			"Ruby detected",
			"Ruby",
		)
	}
}

// detectFrameworks detects frameworks from page content
func (s *FingerprintScanner) detectFrameworks(body string, info *TechInfo) {
	// Laravel
	if strings.Contains(body, "Laravel") || 
	   strings.Contains(info.Headers["X-Powered-By"], "Laravel") {
		info.Frameworks = append(info.Frameworks, "Laravel")
		s.results.Add(
			"fingerprint",
			"info",
			"Framework",
			"Laravel detected",
			"Laravel",
		)
	}

	// Django
	if strings.Contains(body, "Django") || 
	   strings.Contains(info.Headers["X-Powered-By"], "Django") {
		info.Frameworks = append(info.Frameworks, "Django")
		s.results.Add(
			"fingerprint",
			"info",
			"Framework",
			"Django detected",
			"Django",
		)
	}

	// Ruby on Rails
	if strings.Contains(body, "Ruby on Rails") || 
	   strings.Contains(info.Headers["X-Powered-By"], "Rails") {
		info.Frameworks = append(info.Frameworks, "Ruby on Rails")
		s.results.Add(
			"fingerprint",
			"info",
			"Framework",
			"Ruby on Rails detected",
			"Ruby on Rails",
		)
	}

	// Express.js
	if strings.Contains(body, "Express") || 
	   strings.Contains(info.Headers["X-Powered-By"], "Express") {
		info.Frameworks = append(info.Frameworks, "Express.js")
		s.results.Add(
			"fingerprint",
			"info",
			"Framework",
			"Express.js detected",
			"Express.js",
		)
	}
}

// detectCMS detects CMS from page content
func (s *FingerprintScanner) detectCMS(body string, info *TechInfo) {
	// WordPress
	if strings.Contains(body, "wp-content") || 
	   strings.Contains(body, "WordPress") {
		info.CMS = "WordPress"
		s.results.Add(
			"fingerprint",
			"info",
			"CMS",
			"WordPress detected",
			"WordPress",
		)
	}

	// Joomla
	if strings.Contains(body, "joomla") || 
	   strings.Contains(body, "Joomla") {
		info.CMS = "Joomla"
		s.results.Add(
			"fingerprint",
			"info",
			"CMS",
			"Joomla detected",
			"Joomla",
		)
	}

	// Drupal
	if strings.Contains(body, "drupal") || 
	   strings.Contains(body, "Drupal") {
		info.CMS = "Drupal"
		s.results.Add(
			"fingerprint",
			"info",
			"CMS",
			"Drupal detected",
			"Drupal",
		)
	}

	// Magento
	if strings.Contains(body, "magento") || 
	   strings.Contains(body, "Magento") {
		info.CMS = "Magento"
		s.results.Add(
			"fingerprint",
			"info",
			"CMS",
			"Magento detected",
			"Magento",
		)
	}
}

// detectJavaScriptLibraries detects JavaScript libraries from page content
func (s *FingerprintScanner) detectJavaScriptLibraries(body string, info *TechInfo) {
	// jQuery
	jqueryRegex := regexp.MustCompile(`jquery[.-](\d+\.\d+\.\d+)`)
	if matches := jqueryRegex.FindStringSubmatch(body); len(matches) > 1 {
		library := fmt.Sprintf("jQuery %s", matches[1])
		info.JavaScriptLibraries = append(info.JavaScriptLibraries, library)
		s.results.Add(
			"fingerprint",
			"info",
			"JavaScript Library",
			fmt.Sprintf("%s detected", library),
			library,
		)
	} else if strings.Contains(body, "jquery") {
		info.JavaScriptLibraries = append(info.JavaScriptLibraries, "jQuery")
		s.results.Add(
			"fingerprint",
			"info",
			"JavaScript Library",
			"jQuery detected",
			"jQuery",
		)
	}

	// React
	if strings.Contains(body, "react") || 
	   strings.Contains(body, "React") {
		info.JavaScriptLibraries = append(info.JavaScriptLibraries, "React")
		s.results.Add(
			"fingerprint",
			"info",
			"JavaScript Library",
			"React detected",
			"React",
		)
	}

	// Angular
	if strings.Contains(body, "angular") || 
	   strings.Contains(body, "Angular") {
		info.JavaScriptLibraries = append(info.JavaScriptLibraries, "Angular")
		s.results.Add(
			"fingerprint",
			"info",
			"JavaScript Library",
			"Angular detected",
			"Angular",
		)
	}

	// Vue.js
	if strings.Contains(body, "vue") || 
	   strings.Contains(body, "Vue") {
		info.JavaScriptLibraries = append(info.JavaScriptLibraries, "Vue.js")
		s.results.Add(
			"fingerprint",
			"info",
			"JavaScript Library",
			"Vue.js detected",
			"Vue.js",
		)
	}
}

// detectAnalytics detects analytics tools from page content
func (s *FingerprintScanner) detectAnalytics(body string, info *TechInfo) {
	// Google Analytics
	if strings.Contains(body, "google-analytics.com") || 
	   strings.Contains(body, "GoogleAnalytics") {
		info.Analytics = append(info.Analytics, "Google Analytics")
		s.results.Add(
			"fingerprint",
			"info",
			"Analytics",
			"Google Analytics detected",
			"Google Analytics",
		)
	}

	// Matomo/Piwik
	if strings.Contains(body, "matomo") || 
	   strings.Contains(body, "piwik") {
		info.Analytics = append(info.Analytics, "Matomo/Piwik")
		s.results.Add(
			"fingerprint",
			"info",
			"Analytics",
			"Matomo/Piwik detected",
			"Matomo/Piwik",
		)
	}
}
