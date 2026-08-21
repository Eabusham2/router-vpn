package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func runRepositoryPythonAudit(t *testing.T, scriptName string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for the repository audits")
	}
	script := filepath.Join("..", "..", "deploy", scriptName)
	cmd := exec.Command(python, script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("repository audit %s failed: %v\n%s", scriptName, err, out)
	}
}

func TestFullRepositoryAudit(t *testing.T) {
	runRepositoryPythonAudit(t, "full-audit-v4.py")
}

func TestLinuxFullConnectionProfileShippingAudit(t *testing.T) {
	runRepositoryPythonAudit(t, "linux-full-profile-shipping-audit.py")
}
