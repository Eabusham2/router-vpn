package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestTypedSetupImportContract(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for Setup Center import contract tests")
	}
	script := filepath.Join("..", "..", "server", "scripts", "test_setup_imports.py")
	cmd := exec.Command(python, script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("typed Setup Center import tests failed: %v\n%s", err, out)
	}
}
