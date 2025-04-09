package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
)

// Format represents the report format
type Format string

const (
	// FormatJSON represents JSON format
	FormatJSON Format = "json"
	
	// FormatMarkdown represents Markdown format
	FormatMarkdown Format = "md"
	
	// FormatHTML represents HTML format
	FormatHTML Format = "html"
)

// Generator generates reports from scan results
type Generator struct {
	// Target that was scanned
	target *core.Target
	
	// Results from the scan
	results *core.Results
	
	// Output file path
	outputFile string
	
	// Report format
	format Format
}

// NewGenerator creates a new report generator
func NewGenerator(target *core.Target, results *core.Results, outputFile string, format Format) *Generator {
	return &Generator{
		target:     target,
		results:    results,
		outputFile: outputFile,
		format:     format,
	}
}

// Generate generates a report in the specified format
func (g *Generator) Generate() (string, error) {
	fmt.Printf("Generating %s report for %s...\n", g.format, g.target.Domain)
	
	// Ensure output file has the correct extension
	outputFile := g.outputFile
	if !g.hasCorrectExtension(outputFile) {
		outputFile = fmt.Sprintf("%s.%s", outputFile, g.format)
	}
	
	var err error
	var content string
	
	switch g.format {
	case FormatJSON:
		content, err = g.generateJSON()
	case FormatMarkdown:
		content, err = g.generateMarkdown()
	case FormatHTML:
		content, err = g.generateHTML()
	default:
		return "", fmt.Errorf("unsupported format: %s", g.format)
	}
	
	if err != nil {
		return "", fmt.Errorf("failed to generate report: %w", err)
	}
	
	// Write to file
	err = os.WriteFile(outputFile, []byte(content), 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write report to file: %w", err)
	}
	
	return outputFile, nil
}

// hasCorrectExtension checks if the output file has the correct extension
func (g *Generator) hasCorrectExtension(file string) bool {
	return len(file) > len(string(g.format))+1 && 
		file[len(file)-len(string(g.format))-1:] == "."+string(g.format)
}

// generateJSON generates a JSON report
func (g *Generator) generateJSON() (string, error) {
	// Create report structure
	report := map[string]interface{}{
		"target": g.target,
		"results": g.results.Items,
		"summary": map[string]interface{}{
			"total_results": g.results.Count(),
			"scan_date": time.Now().Format(time.RFC3339),
		},
	}
	
	// Convert to JSON
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	return string(jsonData), nil
}

// generateMarkdown generates a Markdown report
func (g *Generator) generateMarkdown() (string, error) {
	// Create report content
	content := fmt.Sprintf("# Web Reconnaissance Report for %s\n\n", g.target.Domain)
	content += fmt.Sprintf("**Scan Date:** %s\n\n", time.Now().Format(time.RFC3339))
	
	// Add target information
	content += "## Target Information\n\n"
	content += fmt.Sprintf("- **Domain:** %s\n", g.target.Domain)
	content += fmt.Sprintf("- **Base Domain:** %s\n", g.target.BaseDomain)
	if len(g.target.IPAddresses) > 0 {
		content += "- **IP Addresses:**\n"
		for _, ip := range g.target.IPAddresses {
			content += fmt.Sprintf("  - %s\n", ip)
		}
	}
	if len(g.target.Subdomains) > 0 {
		content += "- **Subdomains:**\n"
		for _, subdomain := range g.target.Subdomains {
			content += fmt.Sprintf("  - %s\n", subdomain)
		}
	}
	content += "\n"
	
	// Group results by type
	resultsByType := make(map[string][]core.ScanResult)
	for _, result := range g.results.Items {
		resultsByType[result.Type] = append(resultsByType[result.Type], result)
	}
	
	// Add reconnaissance results
	if results, ok := resultsByType["whois"]; ok {
		content += "## WHOIS Information\n\n"
		for _, result := range results {
			content += fmt.Sprintf("### %s\n\n", result.Title)
			content += fmt.Sprintf("%s\n\n", result.Description)
		}
	}
	
	if results, ok := resultsByType["dns"]; ok {
		content += "## DNS Information\n\n"
		for _, result := range results {
			content += fmt.Sprintf("### %s\n\n", result.Title)
			content += fmt.Sprintf("%s\n\n", result.Description)
		}
	}
	
	if results, ok := resultsByType["ssl"]; ok {
		content += "## SSL/TLS Certificate Information\n\n"
		for _, result := range results {
			content += fmt.Sprintf("### %s\n\n", result.Title)
			content += fmt.Sprintf("%s\n\n", result.Description)
		}
	}
	
	if results, ok := resultsByType["subdomain"]; ok {
		content += "## Subdomain Enumeration\n\n"
		for _, result := range results {
			if result.Title == "Subdomain Enumeration" {
				content += fmt.Sprintf("### %s\n\n", result.Title)
				content += fmt.Sprintf("%s\n\n", result.Description)
			}
		}
	}
	
	// Add scanning results
	if results, ok := resultsByType["portscan"]; ok {
		content += "## Port Scanning\n\n"
		for _, result := range results {
			if result.Title == "Port Scan Summary" {
				content += fmt.Sprintf("### %s\n\n", result.Title)
				content += fmt.Sprintf("%s\n\n", result.Description)
			}
		}
		
		content += "### Open Ports\n\n"
		content += "| Port | Service |\n"
		content += "|------|--------|\n"
		for _, result := range results {
			if result.Title == "Open Port" {
				if data, ok := result.Data.(map[string]interface{}); ok {
					port := data["port"]
					service := data["service"]
					content += fmt.Sprintf("| %v | %v |\n", port, service)
				}
			}
		}
		content += "\n"
	}
	
	if results, ok := resultsByType["fingerprint"]; ok {
		content += "## Technology Fingerprinting\n\n"
		for _, result := range results {
			if result.Title == "Technology Fingerprinting" {
				content += fmt.Sprintf("### %s\n\n", result.Title)
				content += fmt.Sprintf("%s\n\n", result.Description)
			}
		}
		
		// Group fingerprinting results by category
		fingerprintByCategory := make(map[string][]core.ScanResult)
		for _, result := range results {
			if result.Title != "Technology Fingerprinting" {
				category := result.Title
				fingerprintByCategory[category] = append(fingerprintByCategory[category], result)
			}
		}
		
		for category, categoryResults := range fingerprintByCategory {
			content += fmt.Sprintf("### %s\n\n", category)
			for _, result := range categoryResults {
				content += fmt.Sprintf("- %s\n", result.Description)
			}
			content += "\n"
		}
	}
	
	if results, ok := resultsByType["vulnscan"]; ok {
		content += "## Vulnerability Scanning\n\n"
		
		// Group vulnerabilities by severity
		vulnsBySeverity := make(map[string][]core.ScanResult)
		for _, result := range results {
			if result.Title != "Vulnerability Scan Summary" {
				severity := result.Category
				vulnsBySeverity[severity] = append(vulnsBySeverity[severity], result)
			}
		}
		
		// Add vulnerabilities by severity
		for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
			if vulns, ok := vulnsBySeverity[severity]; ok && len(vulns) > 0 {
				content += fmt.Sprintf("### %s Severity\n\n", capitalize(severity))
				for _, vuln := range vulns {
					content += fmt.Sprintf("#### %s\n\n", vuln.Title)
					content += fmt.Sprintf("%s\n\n", vuln.Description)
				}
			}
		}
	}
	
	if results, ok := resultsByType["dirbrute"]; ok {
		content += "## Directory Brute Forcing\n\n"
		for _, result := range results {
			if result.Title == "Directory Brute Forcing Summary" {
				content += fmt.Sprintf("### %s\n\n", result.Title)
				content += fmt.Sprintf("%s\n\n", result.Description)
			}
		}
		
		content += "### Discovered Paths\n\n"
		content += "| Path | Status Code |\n"
		content += "|------|------------|\n"
		for _, result := range results {
			if result.Title == "Directory/File Found" {
				if data, ok := result.Data.(map[string]interface{}); ok {
					path := data["path"]
					statusCode := data["status_code"]
					content += fmt.Sprintf("| %v | %v |\n", path, statusCode)
				}
			}
		}
		content += "\n"
	}
	
	// Add summary
	content += "## Summary\n\n"
	content += fmt.Sprintf("Total results: %d\n\n", g.results.Count())
	
	return content, nil
}

// generateHTML generates an HTML report
func (g *Generator) generateHTML() (string, error) {
	// First generate markdown
	markdown, err := g.generateMarkdown()
	if err != nil {
		return "", err
	}
	
	// Convert markdown to HTML (simplified version)
	// In a real implementation, you would use a proper markdown to HTML converter
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Reconnaissance Report for %s</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
        }
        table {
            border-collapse: collapse;
            width: 100%%;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .critical {
            color: #d9534f;
            font-weight: bold;
        }
        .high {
            color: #f0ad4e;
            font-weight: bold;
        }
        .medium {
            color: #5bc0de;
        }
        .low {
            color: #5cb85c;
        }
    </style>
</head>
<body>
    <div class="container">
        <pre>%s</pre>
    </div>
</body>
</html>`, g.target.Domain, markdown)
	
	return html, nil
}

// capitalize capitalizes the first letter of a string
func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
