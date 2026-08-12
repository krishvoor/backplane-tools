package utils

import (
	"strings"
	"testing"
)

func TestGetLineInReaderMatchingKey(t *testing.T) {
	t.Parallel()

	data := "abc123  openshift-client-linux-4.22.8.tar.gz\n"
	line, err := GetLineInReaderMatchingKey(strings.NewReader(data), "openshift-client-linux-4.22.8.tar.gz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(line, "abc123") {
		t.Fatalf("got line %q", line)
	}
}

func TestGetLineInReaderMatchingKey_NoMatch(t *testing.T) {
	t.Parallel()

	_, err := GetLineInReaderMatchingKey(strings.NewReader("foo bar\n"), "missing")
	if err == nil {
		t.Fatal("expected error for no match")
	}
}
