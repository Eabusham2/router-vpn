package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Execute the shipping administrator pairer and offline compiler. The Python
// suite explicitly separates parser/transaction tests from native traffic.
func TestPrivatePQPairingUsesTheShippingCompiler(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python is required for native PQ pairing verification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, filepath.Join("..", "..", "deploy", "test_native_pq_pairing.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("private PQ pairing: %v\n%s", err, output)
	}
}
