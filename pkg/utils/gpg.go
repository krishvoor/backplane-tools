package utils

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const FedoraSigningKeyURL string = "https://fedoraproject.org/fedora.gpg"

func VerifyGPGSignature(targetFilePath, signatureFilePath string) error {
	targetFile, err := os.Open(targetFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file '%s': %w", targetFilePath, err)
	}
	defer func() {
		closeErr := targetFile.Close()
		if closeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to close file '%s': %v\n", targetFilePath, err)
		}
	}()

	signatureFile, err := os.Open(signatureFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file '%s': %w", signatureFilePath, err)
	}
	defer func() {
		closeErr := signatureFile.Close()
		if closeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to close '%s': %v\n", signatureFilePath, err)
		}
	}()

	fedoraKey, err := GetFedoraGPGKeys()
	if err != nil {
		return fmt.Errorf("failed to retrieve Fedora GPG signing keys: %w", err)
	}
	defer func() {
		closeErr := fedoraKey.Close()
		if closeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to close fedora signing key: %v\n", err)
		}
	}()

	keyRing, err := openpgp.ReadKeyRing(fedoraKey)
	if err != nil {
		return fmt.Errorf("failed to read Fedora GPG signing keys: %w", err)
	}

	_, err = openpgp.CheckArmoredDetachedSignature(keyRing, targetFile, signatureFile, &packet.Config{})
	if err != nil {
		return fmt.Errorf("failed to verify file signature: %w", err)
	}

	return nil
}

func GetFedoraGPGKeys() (io.ReadCloser, error) {
	resp, err := http.Get(FedoraSigningKeyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to GET '%s': %w", FedoraSigningKeyURL, err)
	}

	return resp.Body, nil
}

// VerifyAndExtractSignedMessage verifies an OpenPGP signed message (e.g. a file produced
// by `gpg --sign`/`gpg --output foo.gpg --sign foo.txt`, as opposed to a *detached*
// signature) against the provided armored public key(s) and returns the verified
// plaintext contents on success.
//
// Callers should pass one or more pinned, embedded public keys (see e.g.
// RedHatReleaseKey2ArmoredPublicKey) rather than a key fetched over the network at
// verification time. Doing so ensures integrity does not rely solely on the transport
// (e.g. HTTPS to a mirror/CDN) used to fetch the signed message, protecting against a
// network-adjacent or proxying attacker who tampers with content in transit.
func VerifyAndExtractSignedMessage(signedFilePath string, armoredPublicKeys ...string) ([]byte, error) {
	if len(armoredPublicKeys) == 0 {
		return nil, errors.New("no public keys provided for signature verification")
	}

	signedFile, err := os.Open(signedFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file '%s': %w", signedFilePath, err)
	}
	defer func() {
		closeErr := signedFile.Close()
		if closeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to close file '%s': %v\n", signedFilePath, closeErr)
		}
	}()

	var keyRing openpgp.EntityList
	for _, armoredKey := range armoredPublicKeys {
		entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse pinned public key: %w", err)
		}
		keyRing = append(keyRing, entities...)
	}

	md, err := openpgp.ReadMessage(signedFile, keyRing, nil, &packet.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to read signed message '%s': %w", signedFilePath, err)
	}

	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed for '%s': %w", signedFilePath, err)
	}

	if !md.IsSigned || md.SignedBy == nil {
		return nil, fmt.Errorf("'%s' is not signed by any of the pinned public keys", signedFilePath)
	}
	if md.SignatureError != nil {
		return nil, fmt.Errorf("signature verification failed for '%s': %w", signedFilePath, md.SignatureError)
	}

	return plaintext, nil
}
