package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestStopModeRetainsRuntimeIdentityWhenCleanupFails(t *testing.T) {
	root := t.TempDir()
	bad := filepath.Join(root, "fail-stop.sh")
	good := filepath.Join(root, "ok-stop.sh")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\nexit 23\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	a := &app{
		cfg:   common.ClientConfig{ScriptsDir: root},
		modes: []common.Mode{{ID: "wg", StopCommand: []string{bad}}},
		state: state{Connected: true, Mode: "wg", LogicalMode: "raw", RuntimeMode: "wg", Base: "wg", RouterID: "home", Phase: "connected"},
	}
	err := a.stopModeWithIntent(true)
	if err == nil || !strings.Contains(err.Error(), "mode cleanup failed") {
		t.Fatalf("expected cleanup failure, got %v", err)
	}
	if a.state.Phase != "failed" || a.state.Mode != "wg" || a.state.RouterID != "home" || a.state.RuntimeMode != "wg" || a.state.Base != "wg" {
		t.Fatalf("failed stop erased retry identity: %+v", a.state)
	}
	if a.state.Connected {
		t.Fatal("failed stop still reported Connected")
	}
	if a.state.LastError == "" {
		t.Fatal("failed stop did not preserve error")
	}

	a.modes[0].StopCommand = []string{good}
	if err := a.stopModeWithIntent(true); err != nil {
		t.Fatalf("retry stop failed: %v", err)
	}
	if a.state.Phase != "off" || a.state.Mode != "off" || a.state.RouterID != "home" || a.state.RuntimeMode != "" || a.state.Base != "" {
		t.Fatalf("successful retry did not commit off state: %+v", a.state)
	}
}
