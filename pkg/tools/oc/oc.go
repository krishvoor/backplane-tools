package oc

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/openshift/backplane-tools/pkg/sources/openshift.com/mirror"
	"github.com/openshift/backplane-tools/pkg/tools/base"
	"github.com/openshift/backplane-tools/pkg/utils"
)

// Tool implements the interface to manage the 'backplane-cli' binary

type Tool struct {
	base.Mirror
}

func New() *Tool {
	t := &Tool{
		Mirror: base.Mirror{
			Default:  base.NewDefault("oc"),
			Source:   mirror.NewSource(),
			BaseSlug: fmt.Sprintf("/pub/openshift-v4/%s/clients/ocp/stable/", runtime.GOARCH),
		},
	}
	return t
}

func (t *Tool) Install() error {
	version, err := t.LatestVersion()
	if err != nil {
		return fmt.Errorf("failed to retrieve version info: %w", err)
	}

	versionedDir := filepath.Join(t.ToolDir(), version)
	err = os.MkdirAll(versionedDir, os.FileMode(0o755))
	if err != nil {
		return fmt.Errorf("failed to create version-specific directory '%s': %w", versionedDir, err)
	}

	// Download client archive
	clientArchiveName := fmt.Sprintf("openshift-client-%s-%s.tar.gz", runtime.GOOS, version)
	if runtime.GOOS == "darwin" {
		// 'darwin' OSes are referred to as 'mac' in mirror.openshift.com
		clientArchiveName = fmt.Sprintf("openshift-client-mac-%s.tar.gz", version)
	}

	clientArchiveSlug, err := url.JoinPath(t.BaseSlug, clientArchiveName)
	if err != nil {
		return fmt.Errorf("failed to build client URL: %w", err)
	}
	clientArchiveFilePath, err := t.Source.DownloadFile(clientArchiveSlug, versionedDir)
	if err != nil {
		return fmt.Errorf("failed to download client archive file %s: %w", clientArchiveSlug, err)
	}
	err = os.Chmod(clientArchiveFilePath, os.FileMode(0o755))
	if err != nil {
		return fmt.Errorf("failed to update file mode for %s: %w", clientArchiveFilePath, err)
	}

	// Download the GPG-signed checksum file rather than the plaintext sha256sum.txt.
	// mirror.openshift.com serves both the client archive and its checksums over the
	// same HTTPS connection, so an adjacent-network or proxying attacker able to tamper
	// with one in transit could just as easily tamper with the other, defeating a
	// checksum comparison alone. Verifying sha256sum.txt.gpg against a pinned Red Hat
	// release key - rather than a key fetched over the network - anchors integrity to a
	// trust root that doesn't depend on the transport used to fetch the artifacts.
	checksumSlug, err := url.JoinPath(t.BaseSlug, "sha256sum.txt.gpg")
	if err != nil {
		return fmt.Errorf("failed to build checksum URL: %w", err)
	}

	checksumFilePath, err := t.Source.DownloadFile(checksumSlug, versionedDir)
	if err != nil {
		return fmt.Errorf("failed to download checksum file %s: %w", checksumSlug, err)
	}

	verifiedChecksumData, err := utils.VerifyAndExtractSignedMessage(checksumFilePath, utils.RedHatReleaseKey2ArmoredPublicKey)
	if err != nil {
		return fmt.Errorf("failed to verify GPG signature on checksum file %s: %w", checksumFilePath, err)
	}

	checksum, err := t.extractChecksumFromBytes(verifiedChecksumData, clientArchiveName)
	if err != nil {
		return fmt.Errorf("failed to retrieve checksum from file %s: %w", checksumFilePath, err)
	}

	// Checksum client archive & compare
	archiveSum, err := utils.Sha256sum(clientArchiveFilePath)
	if err != nil {
		return fmt.Errorf("failed to calculate checksum for '%s': %w", clientArchiveFilePath, err)
	}

	if strings.TrimSpace(archiveSum) != strings.TrimSpace(checksum) {
		sourceURL, err := t.Source.BuildURL(clientArchiveSlug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to construct source URL for manual retrieval: %v\n", err)
			return fmt.Errorf("checksum for %s does not match the calculated value: expected '%s', got '%s'. Please retry installation", clientArchiveFilePath, strings.TrimSpace(checksum), strings.TrimSpace(archiveSum))
		}
		return fmt.Errorf("checksum for %s does not match the calculated value: expected '%s', got '%s'. Please retry installation. If issue persists, this tool can be downloaded manually at %s", clientArchiveFilePath, strings.TrimSpace(checksum), strings.TrimSpace(archiveSum), sourceURL)
	}

	// Unarchive client
	err = utils.Unarchive(clientArchiveFilePath, versionedDir)
	if err != nil {
		return fmt.Errorf("failed to unarchive %s: %w", clientArchiveFilePath, err)
	}

	// Link as latest
	latestFilePath := t.SymlinkPath()
	err = os.Remove(latestFilePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing symlink at '%s': %w", latestFilePath, err)
	}

	clientBinaryFilepath := filepath.Join(versionedDir, t.Name())
	err = os.Symlink(clientBinaryFilepath, latestFilePath)
	if err != nil {
		return fmt.Errorf("failed to link %s to %s: %w", clientBinaryFilepath, latestFilePath, err)
	}

	return nil
}

func (t *Tool) extractChecksumFromBytes(checksumData []byte, searchPattern string) (string, error) {
	line, err := utils.GetLineInReaderMatchingKey(bytes.NewReader(checksumData), searchPattern)
	if err != nil {
		return "", err
	}

	tokens := strings.Fields(line)
	if len(tokens) != 2 {
		return "", fmt.Errorf("failed to parse checksum info: expected 2 tokens, got %d.\nChecksum info retrieved:\n%s", len(tokens), line)
	}
	return tokens[0], nil
}
