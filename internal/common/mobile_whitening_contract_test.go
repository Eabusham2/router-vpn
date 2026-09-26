package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeWhiteningBuildComposition(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python required for native Start Layer composition")
	}
	cmd := exec.Command(python, filepath.Join("..", "..", "deploy", "test_prepare_mobile_whitening.py"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Start Layer composition: %v\n%s", err, output)
	}
}
