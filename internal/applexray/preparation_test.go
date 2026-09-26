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
	responseCheck := exec.Command(python, filepath.Join("..", "..", "deploy", "test_xray_response_ownership.py"))
	if out, err := responseCheck.CombinedOutput(); err != nil {
		t.Fatalf("HTTP response ownership regression: %v\n%s", err, out)
	}
	cmd := exec.Command(python, filepath.Join("..", "..", "deploy", "test_prepare_apple_xray.py"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native composition failed: %v\n%s", err, out)
	}
}

func TestSharedNativeXrayPreparation(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python is required for shared native runtime preparation")
	}
	cmd := exec.Command(python, filepath.Join("..", "..", "deploy", "test_shared_xray_runtime.py"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shared Xray preparation: %v\n%s", err, output)
	}
}

func TestCorrectedEngineBundleValidation(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python is required for corrected engine package verification")
	}
	cmd := exec.Command(python, filepath.Join("..", "..", "deploy", "test_bundled_xray.py"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("corrected engine package: %v\n%s", err, output)
	}
}
