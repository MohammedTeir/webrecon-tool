package recon

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
)

// SubdomainInfo represents subdomain enumeration results
type SubdomainInfo struct {
	// Base domain
	BaseDomain string

	// Discovered subdomains
	Subdomains []string

	// Resolved IP addresses for each subdomain
	IPAddresses map[string][]string
}

// SubdomainScanner performs subdomain enumeration
type SubdomainScanner struct {
	// Target to scan
	target *core.Target

	// Results to store findings
	results *core.Results

	// Number of concurrent workers
	concurrency int

	// Wordlist for brute forcing
	wordlist string

	// Timeout for DNS queries
	timeout time.Duration
}

// NewSubdomainScanner creates a new subdomain scanner
func NewSubdomainScanner(target *core.Target, results *core.Results, concurrency int, wordlist string) *SubdomainScanner {
	if concurrency <= 0 {
		concurrency = 10
	}

	return &SubdomainScanner{
		target:      target,
		results:     results,
		concurrency: concurrency,
		wordlist:    wordlist,
		timeout:     5 * time.Second,
	}
}

// Scan performs subdomain enumeration for the target domain
func (s *SubdomainScanner) Scan() (*SubdomainInfo, error) {
	fmt.Printf("Performing subdomain enumeration for %s...\n", s.target.Domain)

	info := &SubdomainInfo{
		BaseDomain:  s.target.BaseDomain,
		Subdomains:  []string{},
		IPAddresses: make(map[string][]string),
	}

	// Check if wordlist exists
	if s.wordlist == "" {
		s.wordlist = "wordlists/subdomains.txt"
	}

	// Open wordlist file
	file, err := os.Open(s.wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist file: %w", err)
	}
	defer file.Close()

	// Create a channel for subdomains to check
	subdomainChan := make(chan string, s.concurrency)

	// Create a channel for results
	resultChan := make(chan string, s.concurrency)

	// Create a wait group to wait for all workers to finish
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range subdomainChan {
				// Check if subdomain exists
				if s.checkSubdomain(subdomain) {
					resultChan <- subdomain
				}
			}
		}()
	}

	// Start a goroutine to close the result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Start a goroutine to read the wordlist and send subdomains to the channel
	go func() {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			prefix := strings.TrimSpace(scanner.Text())
			if prefix != "" {
				subdomain := prefix + "." + s.target.BaseDomain
				subdomainChan <- subdomain
			}
		}
		close(subdomainChan)
	}()

	// Collect results
	for subdomain := range resultChan {
		info.Subdomains = append(info.Subdomains, subdomain)
		s.target.AddSubdomain(subdomain)

		// Resolve IP addresses
		ips, err := net.LookupIP(subdomain)
		if err == nil {
			for _, ip := range ips {
				if ipv4 := ip.To4(); ipv4 != nil {
					info.IPAddresses[subdomain] = append(info.IPAddresses[subdomain], ipv4.String())
				}
			}
		}

		// Add result to the results collection
		s.results.Add(
			"subdomain",
			"info",
			"Subdomain Discovered",
			fmt.Sprintf("Discovered subdomain: %s", subdomain),
			map[string]interface{}{
				"subdomain": subdomain,
				"ips":       info.IPAddresses[subdomain],
			},
		)
	}

	// Add summary result
	s.results.Add(
		"subdomain",
		"info",
		"Subdomain Enumeration",
		fmt.Sprintf("Discovered %d subdomains for %s", len(info.Subdomains), s.target.BaseDomain),
		info,
	)

	return info, nil
}

// checkSubdomain checks if a subdomain exists by resolving its DNS records
func (s *SubdomainScanner) checkSubdomain(subdomain string) bool {
	_, err := net.LookupHost(subdomain)
	return err == nil
}
