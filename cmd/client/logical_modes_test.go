package main

import (
	"os"
	"path/filepath"
	"testing"

	"router-vpn/internal/common"
)

func TestAllRuntimeCandidate(t *testing.T) {
	tests := []struct {
		in       string
		wantID   string
		wantBase string
	}{
		{"max-tls-wg", "max-tls-wg", "wg"},
		{"max-quic-wg\n", "max-quic-wg", "wg"},
		{"max-tls-awg", "max-tls-awg", "awg"},
		{" max-quic-awg ", "max-quic-awg", "awg"},
	}
	for _, tt := range tests {
		got, err := allRuntimeCandidate(tt.in)
		if err != nil {
			t.Fatalf("allRuntimeCandidate(%q): %v", tt.in, err)
		}
		if got.RuntimeID != tt.wantID || got.Base != tt.wantBase {
			t.Fatalf("allRuntimeCandidate(%q) = %#v, want runtime=%q base=%q", tt.in, got, tt.wantID, tt.wantBase)
		}
	}
	if _, err := allRuntimeCandidate("all"); err == nil {
		t.Fatal("expected unknown ALL branch to fail")
	}
}

func TestPersistBasePreferenceRollsBackOnDiskFailure(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &app{
		cfg:      common.ClientConfig{ProfilesFile: filepath.Join(blocker, "routers.json")},
		profiles: common.RouterProfileStore{SelectedID: "home", Profiles: []common.RouterProfile{{ID: "home", BaseTunnel: "wg"}}},
		state:    state{Mode: "off", Phase: "off"},
	}
	if err := a.persistBasePreference("awg"); err == nil {
		t.Fatal("expected profile persistence failure")
	}
	if got := a.profiles.Profiles[0].BaseTunnel; got != "wg" {
		t.Fatalf("failed base persistence left in-memory base %q, want wg", got)
	}
}
