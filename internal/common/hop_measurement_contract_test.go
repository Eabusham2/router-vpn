package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeHopMeasurementsAreWiredToOwnedServices(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Skip("Python validation runs in the authoritative release lane")
	}
	cmd := exec.Command(python, filepath.Join("..", "..", "deploy", "test_native_hop_measurement.py"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native hop measurement contract: %v\n%s", err, output)
	}
}
