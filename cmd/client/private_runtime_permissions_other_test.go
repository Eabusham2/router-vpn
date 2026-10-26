//go:build !windows

package main

import (
	"os"
	"testing"
)

func makeDNSRuntimeTestPublic(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}
