package common

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Run the actual Python generator, not a token-presence surrogate. This must
// remain in the normal Go suite used by source and publication gates.
func TestXHTTPGenerationPreservesThePairedHybridPQServer(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python is required for the generated XHTTP runtime contract")
	}
	command := exec.Command(python, filepath.Join("..", "..", "deploy", "test_xhttp_pq_generation.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("XHTTP generated identity regression: %v\n%s", err, output)
	}
}
