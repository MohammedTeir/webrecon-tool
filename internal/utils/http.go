package utils

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPClient represents a custom HTTP client with configurable options
type HTTPClient struct {
	// Underlying HTTP client
	Client *http.Client

	// Default headers to include in all requests
	DefaultHeaders map[string]string

	// User agent to use for requests
	UserAgent string
}

// NewHTTPClient creates a new HTTP client with default settings
func NewHTTPClient(timeout time.Duration) *HTTPClient {
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &HTTPClient{
		Client: &http.Client{
			Timeout: timeout,
		},
		DefaultHeaders: map[string]string{},
		UserAgent:      "WebRecon-Tool/1.0",
	}
}

// SetUserAgent sets the user agent for the client
func (c *HTTPClient) SetUserAgent(userAgent string) {
	c.UserAgent = userAgent
}

// AddDefaultHeader adds a default header to all requests
func (c *HTTPClient) AddDefaultHeader(key, value string) {
	c.DefaultHeaders[key] = value
}

// Get performs a GET request to the specified URL
func (c *HTTPClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set user agent
	req.Header.Set("User-Agent", c.UserAgent)

	// Set default headers
	for key, value := range c.DefaultHeaders {
		req.Header.Set(key, value)
	}

	return c.Client.Do(req)
}

// GetBody performs a GET request and returns the response body as a string
func (c *HTTPClient) GetBody(url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}

// GetHeaders performs a HEAD request and returns the response headers
func (c *HTTPClient) GetHeaders(url string) (http.Header, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set user agent
	req.Header.Set("User-Agent", c.UserAgent)

	// Set default headers
	for key, value := range c.DefaultHeaders {
		req.Header.Set(key, value)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	return resp.Header, nil
}
