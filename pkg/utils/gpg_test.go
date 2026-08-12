package utils

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// testDataSignedChecksum is a real sha256sum.txt.gpg fetched from
// mirror.openshift.com's oc client release directory. It is a real,
// Red Hat-signed artifact used to validate that VerifyAndExtractSignedMessage
// works against production data, not a synthetic/mocked signature.
const testDataSignedChecksum = "testdata/oc-sha256sum.txt.gpg"

func TestVerifyAndExtractSignedMessage_ValidSignature(t *testing.T) {
	t.Parallel()

	plaintext, err := VerifyAndExtractSignedMessage(testDataSignedChecksum, RedHatReleaseKey2ArmoredPublicKey)
	if err != nil {
		t.Fatalf("expected successful verification, got error: %v", err)
	}

	if !strings.Contains(string(plaintext), "openshift-client-") {
		t.Fatalf("expected verified plaintext to contain checksum entries, got:\n%s", plaintext)
	}
}

func TestVerifyAndExtractSignedMessage_TamperedContentFailsVerification(t *testing.T) {
	t.Parallel()

	original, err := os.ReadFile(testDataSignedChecksum)
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	tampered := make([]byte, len(original))
	copy(tampered, original)
	// Flip a byte roughly in the middle of the compressed/signed payload to
	// simulate an on-path attacker tampering with the file in transit.
	tampered[len(tampered)/2] ^= 0xFF

	tamperedPath := filepath.Join(t.TempDir(), "tampered-sha256sum.txt.gpg")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("failed to write tampered fixture: %v", err)
	}

	_, err = VerifyAndExtractSignedMessage(tamperedPath, RedHatReleaseKey2ArmoredPublicKey)
	if err == nil {
		t.Fatal("expected verification of tampered content to fail, but it succeeded")
	}
}

func TestVerifyAndExtractSignedMessage_WrongKeyFailsVerification(t *testing.T) {
	t.Parallel()

	// An unrelated, freshly-generated key should not be able to verify a message
	// signed by the Red Hat release key.
	unrelatedKey := generateTestArmoredPublicKey(t)

	_, err := VerifyAndExtractSignedMessage(testDataSignedChecksum, unrelatedKey)
	if err == nil {
		t.Fatal("expected verification with an unrelated key to fail, but it succeeded")
	}
}

func TestVerifyAndExtractSignedMessage_NoKeysProvided(t *testing.T) {
	t.Parallel()

	_, err := VerifyAndExtractSignedMessage(testDataSignedChecksum)
	if err == nil {
		t.Fatal("expected an error when no public keys are provided")
	}
}

func TestVerifyAndExtractSignedMessage_FileNotFound(t *testing.T) {
	t.Parallel()

	_, err := VerifyAndExtractSignedMessage("/nonexistent/sha256sum.txt.gpg", RedHatReleaseKey2ArmoredPublicKey)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestVerifyAndExtractSignedMessage_InvalidArmoredKey(t *testing.T) {
	t.Parallel()

	_, err := VerifyAndExtractSignedMessage(testDataSignedChecksum, "not-a-valid-armored-key")
	if err == nil {
		t.Fatal("expected error for invalid armored key")
	}
}

func TestVerifyAndExtractSignedMessage_InvalidSignedMessage(t *testing.T) {
	t.Parallel()

	invalidPath := filepath.Join(t.TempDir(), "invalid-sha256sum.txt.gpg")
	if err := os.WriteFile(invalidPath, []byte("not an openpgp message"), 0o600); err != nil {
		t.Fatalf("failed to write invalid fixture: %v", err)
	}

	_, err := VerifyAndExtractSignedMessage(invalidPath, RedHatReleaseKey2ArmoredPublicKey)
	if err == nil {
		t.Fatal("expected error for invalid signed message")
	}
}

func TestRedHatReleaseKey2ArmoredPublicKey_HasExpectedKeyID(t *testing.T) {
	t.Parallel()

	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(RedHatReleaseKey2ArmoredPublicKey))
	if err != nil {
		t.Fatalf("failed to parse pinned key: %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("expected exactly 1 entity in pinned key ring, got %d", len(entities))
	}

	const expectedKeyID = "199E2F91FD431D51"
	gotKeyID := entities[0].PrimaryKey.KeyIdString()
	if !strings.EqualFold(gotKeyID, expectedKeyID) {
		t.Fatalf("unexpected key id: got %s, want %s", gotKeyID, expectedKeyID)
	}
}

// generateTestArmoredPublicKey creates a throwaway OpenPGP key pair, purely to
// exercise the "verification fails against a key that isn't the signer" path.
func generateTestArmoredPublicKey(t *testing.T) string {
	t.Helper()

	entity, err := openpgp.NewEntity("test", "", "test@example.com", nil)
	if err != nil {
		t.Fatalf("failed to generate throwaway test key: %v", err)
	}

	var buf bytes.Buffer
	armorWriter, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatalf("failed to create armor encoder: %v", err)
	}
	if err := entity.Serialize(armorWriter); err != nil {
		t.Fatalf("failed to serialize test key: %v", err)
	}
	if err := armorWriter.Close(); err != nil {
		t.Fatalf("failed to close armor encoder: %v", err)
	}

	return buf.String()
}
