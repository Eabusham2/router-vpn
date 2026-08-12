package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFullRepositoryAudit(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for the full repository audit")
	}
	script := filepath.Join("..", "..", "deploy", "full-audit-v4.py")
	cmd := exec.Command(python, script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("full Router VPN audit failed: %v\n%s", err, out)
	}
}
