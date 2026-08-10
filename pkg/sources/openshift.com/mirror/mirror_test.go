package mirror

import (
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
