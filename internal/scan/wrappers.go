package scan

import (
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
	"github.com/webrecon/webrecon-tool/internal/utils"
)

// NewVulnerabilityScanner creates a new vulnerability scanner
func NewVulnerabilityScanner(target *core.Target, results *core.Results) *VulnScanner {
	return &VulnScanner{
		target:  target,
		results: results,
		client:  utils.NewHTTPClient(30 * time.Second),
	}
}

// NewDirectoryScanner creates a new directory brute forcing scanner
func NewDirectoryScanner(target *core.Target, results *core.Results, concurrency int) *DirBruteScanner {
	return NewDirBruteScanner(target, results, concurrency, "wordlists/directories.txt")
}
