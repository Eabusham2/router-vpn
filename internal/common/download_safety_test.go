package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDownloadSafetyContract(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for the repository safety contract tests")
	}
	script := filepath.Join("..", "..", "server", "scripts", "test_download_safety.py")
	cmd := exec.Command(python, script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("download/package safety tests failed: %v\n%s", err, out)
	}
}
