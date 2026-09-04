package main

import (
	"os"
	"strings"
	"testing"
)

func TestSpeedLabEarlyFailuresAlwaysSurfaceRollbackFailure(t *testing.T) {
	body, err := os.ReadFile("speed_lab.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, required := range []string{
		"func speedLabRestoreAfterFailure(a *app, snapshot speedLabTemporarySnapshot, cause error) error",
		"cleanupErr := a.speedLabRestoreTemporary(snapshot)",
		"temporary-path rollback also failed:",
		"speedLabRestoreAfterFailure(a, snapshot, startErr)",
		"speedLabRestoreAfterFailure(a, snapshot, cause)",
		"speedLabRestoreAfterFailure(a, snapshot, err)",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("Speed Lab early rollback contract lost %q", required)
		}
	}
	if strings.Contains(source, "_ = a.speedLabRestoreTemporary(snapshot)") {
		t.Fatal("Speed Lab still discards an early temporary-path rollback error")
	}
}
