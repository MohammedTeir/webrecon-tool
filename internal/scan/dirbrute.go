package scan

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/webrecon/webrecon-tool/internal/core"
	"github.com/webrecon/webrecon-tool/internal/utils"
)

// DirBruteInfo represents directory brute forcing results
type DirBruteInfo struct {
	// Target domain
	Target string

	// Base URL
	BaseURL string

	// Discovered paths
	DiscoveredPaths map[string]int

	// Wordlist used
	Wordlist string

	// Number of paths checked
	PathsChecked int

	// Scan start time
	StartTime time.Time

	// Scan end time
	EndTime time.Time
}

// DirBruteScanner performs directory brute forcing
type DirBruteScanner struct {
	// Target to scan
	target *core.Target

	// Results to store findings
	results *core.Results

	// HTTP client
	client *utils.HTTPClient

	// Number of concurrent workers
	concurrency int

	// Wordlist for brute forcing
	wordlist string
}

// NewDirBruteScanner creates a new directory brute forcing scanner
func NewDirBruteScanner(target *core.Target, results *core.Results, concurrency int, wordlist string) *DirBruteScanner {
	if concurrency <= 0 {
		concurrency = 10
	}

	return &DirBruteScanner{
		target:      target,
		results:     results,
		client:      utils.NewHTTPClient(10 * time.Second),
		concurrency: concurrency,
		wordlist:    wordlist,
	}
}

// Scan performs directory brute forcing on the target
func (s *DirBruteScanner) Scan() (*DirBruteInfo, error) {
	fmt.Printf("Performing directory brute forcing on %s...\n", s.target.Domain)

	// Determine base URL
	baseURL := fmt.Sprintf("https://%s", s.target.Domain)
	_, err := s.client.GetHeaders(baseURL)
	if err != nil {
		// Try HTTP if HTTPS fails
		baseURL = fmt.Sprintf("http://%s", s.target.Domain)
		_, err = s.client.GetHeaders(baseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to target: %w", err)
		}
	}

	info := &DirBruteInfo{
		Target:         s.target.Domain,
		BaseURL:        baseURL,
		DiscoveredPaths: make(map[string]int),
		Wordlist:       s.wordlist,
		PathsChecked:   0,
		StartTime:      time.Now(),
	}

	// Check if wordlist exists
	if s.wordlist == "" {
		s.wordlist = "wordlists/directories.txt"
	}

	// Open wordlist file
	file, err := os.Open(s.wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist file: %w", err)
	}
	defer file.Close()

	// Create a channel for paths to check
	pathChan := make(chan string, s.concurrency)

	// Create a channel for results
	resultChan := make(chan struct {
		path   string
		status int
	}, s.concurrency)

	// Create a wait group to wait for all workers to finish
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathChan {
				status, err := s.checkPath(baseURL, path)
				if err == nil && status != http.StatusNotFound {
					resultChan <- struct {
						path   string
						status int
					}{path, status}
				}
				info.PathsChecked++
			}
		}()
	}

	// Start a goroutine to close the result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Start a goroutine to read the wordlist and send paths to the channel
	go func() {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			path := strings.TrimSpace(scanner.Text())
			if path != "" {
				// Ensure path starts with /
				if !strings.HasPrefix(path, "/") {
					path = "/" + path
				}
				pathChan <- path
			}
		}
		close(pathChan)
	}()

	// Collect results
	for result := range resultChan {
		info.DiscoveredPaths[result.path] = result.status

		// Determine category based on status code
		category := "info"
		if result.status >= 200 && result.status < 300 {
			category = "low"
		} else if result.status >= 300 && result.status < 400 {
			category = "info"
		} else if result.status >= 400 && result.status < 500 {
			category = "info"
		} else if result.status >= 500 {
			category = "medium"
		}

		// Add result to the results collection
		s.results.Add(
			"dirbrute",
			category,
			"Directory/File Found",
			fmt.Sprintf("Found %s (Status: %d)", result.path, result.status),
			map[string]interface{}{
				"path":        result.path,
				"status_code": result.status,
				"url":         baseURL + result.path,
			},
		)
	}

	info.EndTime = time.Now()

	// Add summary result
	s.results.Add(
		"dirbrute",
		"info",
		"Directory Brute Forcing Summary",
		fmt.Sprintf("Found %d paths on %s", len(info.DiscoveredPaths), s.target.Domain),
		info,
	)

	return info, nil
}

// checkPath checks if a path exists on the target
func (s *DirBruteScanner) checkPath(baseURL, path string) (int, error) {
	url := baseURL + path
	resp, err := s.client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
