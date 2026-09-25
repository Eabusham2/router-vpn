package applexray

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPinnedNativeCompositionAndFailureScope(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python is required to verify native engine composition")
	}
	cmd := exec.Command(python, filepath.Join("..", "..", "deploy", "test_prepare_apple_xray.py"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native composition failed: %v\n%s", err, out)
	}
}
