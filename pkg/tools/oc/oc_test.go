package oc

import (
	"testing"

	"github.com/openshift/backplane-tools/pkg/utils"
)

const testDataSignedChecksum = "../../utils/testdata/oc-sha256sum.txt.gpg"

func TestExtractChecksumFromBytes(t *testing.T) {
	t.Parallel()

	plaintext, err := utils.VerifyAndExtractSignedMessage(testDataSignedChecksum, utils.RedHatReleaseKey2ArmoredPublicKey)
	if err != nil {
		t.Fatalf("fixture verification failed: %v", err)
	}

	tool := New()
	const archiveName = "openshift-client-linux-4.22.8.tar.gz"
	const wantChecksum = "22cb5df5206569ca2c8ca3b56f55f5af9dbd68fc35ea237a4069e06ffd6e9218"

	checksum, err := tool.extractChecksumFromBytes(plaintext, archiveName)
	if err != nil {
		t.Fatalf("extractChecksumFromBytes failed: %v", err)
	}
	if checksum != wantChecksum {
		t.Fatalf("got checksum %q, want %q", checksum, wantChecksum)
	}
}

func TestExtractChecksumFromBytes_NoMatch(t *testing.T) {
	t.Parallel()

	tool := New()
	_, err := tool.extractChecksumFromBytes([]byte("foo bar\n"), "missing-archive.tar.gz")
	if err == nil {
		t.Fatal("expected error when archive name is not in checksum data")
	}
}

func TestExtractChecksumFromBytes_InvalidLine(t *testing.T) {
	t.Parallel()

	tool := New()
	// Line matches the key pattern but has no valid checksum tokens.
	_, err := tool.extractChecksumFromBytes([]byte("openshift-client-linux-4.22.8.tar.gz\n"), "openshift-client-linux-4.22.8.tar.gz")
	if err == nil {
		t.Fatal("expected error for malformed checksum line")
	}
}
