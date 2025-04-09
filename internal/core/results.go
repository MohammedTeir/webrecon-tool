package core

import (
	"fmt"
	"sync"
	"time"
)

// ScanResult represents a single result from a scan
type ScanResult struct {
	// Type of result (e.g., "whois", "dns", "port", "vulnerability")
	Type string

	// Category for grouping results (e.g., "info", "low", "medium", "high", "critical")
	Category string

	// Short description of the result
	Title string

	// Detailed description
	Description string

	// Raw data associated with the result
	Data interface{}

	// Timestamp when the result was found
	Timestamp time.Time
}

// Results manages and aggregates scan results
type Results struct {
	// All results from the scan
	Items []ScanResult

	// Mutex for thread safety
	mu sync.Mutex
}

// NewResults creates a new Results instance
func NewResults() *Results {
	return &Results{
		Items: []ScanResult{},
	}
}

// Add adds a new result to the collection
func (r *Results) Add(resultType, category, title, description string, data interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Items = append(r.Items, ScanResult{
		Type:        resultType,
		Category:    category,
		Title:       title,
		Description: description,
		Data:        data,
		Timestamp:   time.Now(),
	})
}

// GetByType returns all results of a specific type
func (r *Results) GetByType(resultType string) []ScanResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	var filtered []ScanResult
	for _, result := range r.Items {
		if result.Type == resultType {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

// GetByCategory returns all results of a specific category
func (r *Results) GetByCategory(category string) []ScanResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	var filtered []ScanResult
	for _, result := range r.Items {
		if result.Category == category {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

// Count returns the total number of results
func (r *Results) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Items)
}

// String returns a string representation of the results
func (r *Results) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return fmt.Sprintf("Total results: %d", len(r.Items))
}
