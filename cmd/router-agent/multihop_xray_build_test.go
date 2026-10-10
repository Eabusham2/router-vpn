package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPrivateRelayBuildIncludesTheOwnedNativeXrayImplementation(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python is required to verify the private native relay build")
	}
	command := exec.Command(python, filepath.Join("..", "..", "deploy", "test_native_xray_relay_build.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native Xray relay build contract: %v\n%s", err, output)
	}
}
