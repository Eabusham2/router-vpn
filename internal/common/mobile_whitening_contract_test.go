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
	for _, script := range []string{"test_prepare_mobile_whitening.py", "test_mobile_buffer_policy.py"} {
		cmd := exec.Command(python, filepath.Join("..", "..", "deploy", script))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native Start Layer %s: %v\n%s", script, err, output)
		}
	}
}
