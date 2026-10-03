package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPinnedGVisorSchedulerPreparation(t *testing.T) {
	command := exec.Command("python3", filepath.Join("..", "..", "deploy", "test_gvisor_scheduler_preparation.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("gVisor preparation integrity regression: %v\n%s", err, output)
	}
}
