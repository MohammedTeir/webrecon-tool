# WebRecon Tool

WebRecon is a comprehensive CLI-driven web reconnaissance and vulnerability scanning tool written in Go. It automates the process of gathering information about web applications and identifying potential security vulnerabilities.

## Features

- **Reconnaissance**
  - WHOIS lookup
  - DNS information gathering
  - SSL/TLS certificate analysis
  - Subdomain enumeration

- **Scanning**
  - Port scanning
  - Technology fingerprinting
  - Vulnerability scanning
  - Directory brute forcing

- **Reporting**
  - Multiple output formats (JSON, Markdown, HTML)
  - Detailed reports with categorized findings
  - Severity-based vulnerability classification

## Installation

### Prerequisites

- Go 1.18 or higher
- Linux/macOS/Windows

### Building from Source

1. Clone the repository:
   ```
   git clone https://github.com/webrecon/webrecon-tool.git
   cd webrecon-tool
   ```

2. Build the tool:
   ```
   go build -o webrecon ./cmd/webrecon
   ```

3. (Optional) Move the binary to a directory in your PATH:
   ```
   sudo mv webrecon /usr/local/bin/
   ```

## Usage

### Basic Usage

```
./webrecon scan -t example.com
```

This will perform a full scan on the target domain and generate a report in the default format (Markdown).

### Available Commands

- `scan`: Perform a full scan (reconnaissance, port scanning, fingerprinting, vulnerability scanning, directory brute forcing)
- `recon`: Perform reconnaissance only
- `portscan`: Scan for open ports
- `fingerprint`: Identify technologies
- `vulnscan`: Check for vulnerabilities
- `dirbrute`: Perform directory brute forcing
- `help`: Display help information

### Command Options

```
Global Flags:
  -t, --target string       Target domain to scan
  -o, --output string       Output file (default "report")
  -f, --format string       Output format (json, md, html) (default "md")
  -j, --threads int         Number of concurrent threads (default 10)
  -w, --wordlist string     Custom wordlist for brute forcing
  -v, --verbose             Enable verbose output
  -h, --help                Help for webrecon
```

### Examples

#### Perform a Full Scan

```
./webrecon scan -t example.com
```

#### Perform Reconnaissance Only

```
./webrecon recon -t example.com
```

#### Scan for Open Ports

```
./webrecon portscan -t example.com
```

#### Identify Technologies

```
./webrecon fingerprint -t example.com
```

#### Check for Vulnerabilities

```
./webrecon vulnscan -t example.com
```

#### Perform Directory Brute Forcing

```
./webrecon dirbrute -t example.com -w /path/to/wordlist.txt
```

#### Generate JSON Report

```
./webrecon scan -t example.com -f json -o results
```

#### Generate HTML Report

```
./webrecon scan -t example.com -f html -o results
```

#### Increase Concurrency

```
./webrecon scan -t example.com -j 20
```

## Modules

### Reconnaissance Module

The reconnaissance module gathers basic information about the target domain:

- **WHOIS Lookup**: Retrieves domain registration information
- **DNS Information**: Gathers DNS records (A, AAAA, MX, NS, TXT, CNAME)
- **SSL/TLS Analysis**: Analyzes SSL/TLS certificates for security issues
- **Subdomain Enumeration**: Discovers subdomains associated with the target domain

### Scanning Modules

The scanning modules perform detailed analysis of the target:

- **Port Scanner**: Discovers open ports and identifies running services
- **Technology Fingerprinter**: Identifies web technologies, frameworks, and libraries
- **Vulnerability Scanner**: Checks for common web vulnerabilities
- **Directory Brute Forcer**: Discovers hidden directories and files

### Reporting Module

The reporting module generates comprehensive reports in various formats:

- **JSON**: Machine-readable format for integration with other tools
- **Markdown**: Human-readable format for documentation
- **HTML**: Web-based format for viewing in browsers

## Security Considerations

- This tool is designed for security professionals to assess their own systems or systems they have permission to test
- Always obtain proper authorization before scanning any system
- Some scanning techniques may be considered intrusive by target systems
- Use responsibly and ethically

## Customization

### Custom Wordlists

You can use custom wordlists for subdomain enumeration and directory brute forcing:

```
./webrecon scan -t example.com -w /path/to/wordlist.txt
```

### Rate Limiting

The tool implements rate limiting to avoid overwhelming target servers. You can adjust the number of concurrent threads:

```
./webrecon scan -t example.com -j 5  # Lower concurrency
./webrecon scan -t example.com -j 30 # Higher concurrency
```

## Troubleshooting

### Common Issues

- **Connection Errors**: Ensure the target domain is accessible and your internet connection is working
- **Permission Errors**: Some scanning techniques may require elevated privileges
- **Rate Limiting**: Target servers may implement rate limiting; try reducing concurrency
- **False Positives**: Vulnerability scanning may produce false positives; always verify findings manually

### Debugging

Use the verbose flag for detailed output:

```
./webrecon scan -t example.com -v
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
