package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeCompositeShippingCompilerAndEncryptedProof(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python is required for native composite shipping checks")
	}
	cmd := exec.Command(python, filepath.Join("..", "..", "deploy", "test_mobile_composite_shipping.py"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native composite shipping contract: %v\n%s", err, output)
	}
}
