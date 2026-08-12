package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDownloadJobProgressCleanupContract(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for download job contract tests")
	}
	script := filepath.Join("..", "..", "server", "scripts", "test_download_jobs.py")
	cmd := exec.Command(python, script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("download job/progress tests failed: %v\n%s", err, out)
	}
}
