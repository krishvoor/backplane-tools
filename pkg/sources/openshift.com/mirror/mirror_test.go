package mirror

import (
	"net/url"
	"testing"
)

// The test is to verify that NewSource correctly intializes the mirror source.
func TestNewSource(t *testing.T) {
	s := NewSource()

	if s == nil {
		t.Fatalf("NewSource() returned nil")
	}

	if s.Source == nil {
		t.Fatalf("NewSource() returned a Source with a nil underlying Source")
	}
}

// TestBaseURLUsesHTTPS is a security regression test that ensures the mirror.
// endpoint always uses HTTPS instead of an insecure HTTP connection.
func TestBaseURLUsesHTTPS(t *testing.T) {
	parsedURL, err := url.Parse(baseURL)

	if err != nil {
		t.Fatalf("failed to parse baseURL: %v", err)
	}

	if parsedURL.Scheme != "https" {
		t.Errorf("baseURL scheme is not https: got %s", parsedURL.Scheme)
	}
}
