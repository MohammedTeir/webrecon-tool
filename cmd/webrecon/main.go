package main

import (
	"fmt"
	"os"
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
	"github.com/webrecon/webrecon-tool/internal/recon"
	"github.com/webrecon/webrecon-tool/internal/scan"
	"github.com/webrecon/webrecon-tool/internal/report"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: webrecon <target>")
		fmt.Println("Example: webrecon www.example.com")
		os.Exit(1)
	}

	targetURL := os.Args[1]
	fmt.Printf("Starting WebRecon scan on target: %s\n", targetURL)
	fmt.Println("This may take some time depending on the target website...")
	
	// Create output directory for results
	outputDir := "results"
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		fmt.Printf("Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Initialize target
	target, err := core.NewTarget(targetURL)
	if err != nil {
		fmt.Printf("Failed to initialize target: %v\n", err)
		os.Exit(1)
	}
	
	// Initialize results
	results := core.NewResults()
	
	// Start time for scan
	startTime := time.Now()
	
	// Run reconnaissance modules
	fmt.Println("\n[+] Running reconnaissance modules...")
	
	// WHOIS lookup
	fmt.Println("[*] Performing WHOIS lookup...")
	whoisScanner := recon.NewWhoisScanner(target, results)
	_, err = whoisScanner.Scan()
	if err != nil {
		fmt.Printf("[-] WHOIS lookup error: %v\n", err)
	} else {
		fmt.Println("[+] WHOIS lookup completed")
	}
	
	// DNS information
	fmt.Println("[*] Gathering DNS information...")
	dnsScanner := recon.NewDNSScanner(target, results)
	_, err = dnsScanner.Scan()
	if err != nil {
		fmt.Printf("[-] DNS information gathering error: %v\n", err)
	} else {
		fmt.Println("[+] DNS information gathering completed")
	}
	
	// Run scanning modules
	fmt.Println("\n[+] Running scanning modules...")
	
	// Port scanning
	fmt.Println("[*] Scanning ports...")
	portScanner := scan.NewPortScanner(target, results, 100)
	_, err = portScanner.Scan()
	if err != nil {
		fmt.Printf("[-] Port scanning error: %v\n", err)
	} else {
		fmt.Println("[+] Port scanning completed")
	}
	
	// Technology fingerprinting
	fmt.Println("[*] Fingerprinting technologies...")
	fingerprintScanner := scan.NewFingerprintScanner(target, results)
	_, err = fingerprintScanner.Scan()
	if err != nil {
		fmt.Printf("[-] Technology fingerprinting error: %v\n", err)
	} else {
		fmt.Println("[+] Technology fingerprinting completed")
	}
	
	// Vulnerability scanning
	fmt.Println("[*] Scanning for vulnerabilities...")
	vulnScanner := scan.NewVulnerabilityScanner(target, results)
	_, err = vulnScanner.Scan()
	if err != nil {
		fmt.Printf("[-] Vulnerability scanning error: %v\n", err)
	} else {
		fmt.Println("[+] Vulnerability scanning completed")
	}
	
	// Directory brute forcing
	fmt.Println("[*] Brute forcing directories...")
	dirScanner := scan.NewDirectoryScanner(target, results, 10)
	_, err = dirScanner.Scan()
	if err != nil {
		fmt.Printf("[-] Directory brute forcing error: %v\n", err)
	} else {
		fmt.Println("[+] Directory brute forcing completed")
	}
	
	// Generate reports
	fmt.Println("\n[+] Generating reports...")
	
	// Calculate scan duration
	duration := time.Since(startTime)
	
	// Generate reports
	generator := report.NewReportGenerator(results)
	
	// Generate markdown report
	mdReport, err := generator.GenerateMarkdown()
	if err != nil {
		fmt.Printf("[-] Markdown report generation error: %v\n", err)
	} else {
		mdReportPath := fmt.Sprintf("%s/report.md", outputDir)
		err = os.WriteFile(mdReportPath, []byte(mdReport), 0644)
		if err != nil {
			fmt.Printf("[-] Failed to write markdown report: %v\n", err)
		} else {
			fmt.Printf("[+] Markdown report saved to %s\n", mdReportPath)
		}
	}
	
	// Generate JSON report
	jsonReport, err := generator.GenerateJSON()
	if err != nil {
		fmt.Printf("[-] JSON report generation error: %v\n", err)
	} else {
		jsonReportPath := fmt.Sprintf("%s/report.json", outputDir)
		err = os.WriteFile(jsonReportPath, []byte(jsonReport), 0644)
		if err != nil {
			fmt.Printf("[-] Failed to write JSON report: %v\n", err)
		} else {
			fmt.Printf("[+] JSON report saved to %s\n", jsonReportPath)
		}
	}
	
	fmt.Printf("\n[+] Scan completed in %s\n", duration)
	fmt.Printf("[+] Results saved to %s directory\n", outputDir)
}
