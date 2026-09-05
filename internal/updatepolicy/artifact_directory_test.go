package updatepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsurePrivateArtifactDirectoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "updates")
	if err := os.Symlink(realDir, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := EnsurePrivateArtifactDirectory(link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink update directory was accepted: %v", err)
	}
}

func TestEnsurePrivateArtifactDirectoryRejectsBroadUnixMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics do not apply on Windows")
	}
	dir := filepath.Join(t.TempDir(), "updates")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateArtifactDirectory(dir); err == nil || !strings.Contains(err.Error(), "permissions must be private") {
		t.Fatalf("broad update directory permissions were accepted: %v", err)
	}
}

func TestValidateOwnedArtifactPathRequiresDirectDigestChild(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "updates")
	if err := EnsurePrivateArtifactDirectory(dir); err != nil {
		t.Fatal(err)
	}
	payload := []byte("verified update")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	owned := filepath.Join(dir, digest[:16]+"-RouterVPN.zip")
	if err := ValidateOwnedArtifactPath(dir, owned, digest); err != nil {
		t.Fatalf("valid owned artifact rejected: %v", err)
	}
	for _, path := range []string{
		filepath.Join(filepath.Dir(dir), digest[:16]+"-outside.zip"),
		filepath.Join(dir, "nested", digest[:16]+"-nested.zip"),
		filepath.Join(dir, strings.Repeat("0", 16)+"-wrong.zip"),
	} {
		if err := ValidateOwnedArtifactPath(dir, path, digest); err == nil {
			t.Fatalf("unowned artifact path accepted: %s", path)
		}
	}
}
