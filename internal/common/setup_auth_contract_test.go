package common

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSetupCenterAuthAndPairingContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Setup Center auth is a Linux/server POSIX contract covered by the authoritative Ubuntu release audit")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for Setup Center auth/pairing tests")
	}
	script := filepath.Join("..", "..", "server", "scripts", "test_setup_auth.py")
	cmd := exec.Command(python, script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Setup Center auth/pairing tests failed: %v\n%s", err, out)
	}
}
