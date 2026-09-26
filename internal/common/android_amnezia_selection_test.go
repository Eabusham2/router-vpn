package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAndroidAmneziaExactProfileSelection(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python required for Android Amnezia selection regression")
	}
	command := exec.Command(python, filepath.Join("..", "..", "android", "test_android_amnezia_selection.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Android Amnezia profile selection: %v\n%s", err, output)
	}
}
