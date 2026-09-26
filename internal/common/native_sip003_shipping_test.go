package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeSIP003ShippingCompilerAndProof(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python is required for native SIP003 shipping checks")
	}
	cmd := exec.Command(python, filepath.Join("..", "..", "deploy", "test_native_sip003_shipping.py"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native SIP003 shipping contract: %v\n%s", err, output)
	}
}
