package scan

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
)

// PortInfo represents port scanning results
type PortInfo struct {
	// Target IP address or domain
	Target string

	// Open ports and their services
	OpenPorts map[int]string

	// Scan start time
	StartTime time.Time

	// Scan end time
	EndTime time.Time
}

// PortScanner performs port scanning
type PortScanner struct {
	// Target to scan
	target *core.Target

	// Results to store findings
	results *core.Results

	// Number of concurrent workers
	concurrency int

	// Timeout for connections
	timeout time.Duration

	// Port range to scan
	startPort int
	endPort   int
}

// NewPortScanner creates a new port scanner
func NewPortScanner(target *core.Target, results *core.Results, concurrency int) *PortScanner {
	if concurrency <= 0 {
		concurrency = 100
	}

	return &PortScanner{
		target:      target,
		results:     results,
		concurrency: concurrency,
		timeout:     2 * time.Second,
		startPort:   1,
		endPort:     1024, // Common ports by default
	}
}

// SetPortRange sets the port range to scan
func (s *PortScanner) SetPortRange(start, end int) {
	if start > 0 && end >= start && end <= 65535 {
		s.startPort = start
		s.endPort = end
	}
}

// Scan performs port scanning on the target
func (s *PortScanner) Scan() (*PortInfo, error) {
	fmt.Printf("Performing port scan on %s (ports %d-%d)...\n", s.target.Domain, s.startPort, s.endPort)

	info := &PortInfo{
		Target:    s.target.Domain,
		OpenPorts: make(map[int]string),
		StartTime: time.Now(),
	}

	// Get target IP addresses if not already available
	if len(s.target.IPAddresses) == 0 {
		ips, err := net.LookupIP(s.target.Domain)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve domain: %w", err)
		}

		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				s.target.AddIPAddress(ipv4.String())
			}
		}
	}

	if len(s.target.IPAddresses) == 0 {
		return nil, fmt.Errorf("no IP addresses found for target")
	}

	// Use the first IP address for scanning
	targetIP := s.target.IPAddresses[0]

	// Create a channel for ports to scan
	portChan := make(chan int, s.concurrency)

	// Create a channel for results
	resultChan := make(chan int, s.concurrency)

	// Create a wait group to wait for all workers to finish
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				if s.isPortOpen(targetIP, port) {
					resultChan <- port
				}
			}
		}()
	}

	// Start a goroutine to close the result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Start a goroutine to send ports to the channel
	go func() {
		for port := s.startPort; port <= s.endPort; port++ {
			portChan <- port
		}
		close(portChan)
	}()

	// Collect results
	for port := range resultChan {
		// Try to determine the service
		service := s.getServiceName(port)
		info.OpenPorts[port] = service

		// Add result to the results collection
		s.results.Add(
			"portscan",
			"info",
			"Open Port",
			fmt.Sprintf("Port %d (%s) is open on %s", port, service, s.target.Domain),
			map[string]interface{}{
				"port":    port,
				"service": service,
				"ip":      targetIP,
			},
		)
	}

	info.EndTime = time.Now()

	// Add summary result
	s.results.Add(
		"portscan",
		"info",
		"Port Scan Summary",
		fmt.Sprintf("Found %d open ports on %s", len(info.OpenPorts), s.target.Domain),
		info,
	)

	return info, nil
}

// isPortOpen checks if a port is open on the target
func (s *PortScanner) isPortOpen(ip string, port int) bool {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// getServiceName returns the service name for a port
func (s *PortScanner) getServiceName(port int) string {
	// Common ports
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 443:
		return "HTTPS"
	case 465:
		return "SMTPS"
	case 587:
		return "SMTP (Submission)"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 8080:
		return "HTTP (Alternate)"
	case 8443:
		return "HTTPS (Alternate)"
	default:
		return "Unknown"
	}
}
