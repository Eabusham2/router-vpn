package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestUsageMetadataRollsRAMBackWhenPersistenceFails(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real-routers.json")
	storePath := filepath.Join(dir, "routers.json")
	if err := os.WriteFile(realPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, storePath); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	usedAt := time.Date(2026, 8, 26, 23, 0, 0, 0, time.UTC)
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: storePath},
		profiles: common.RouterProfileStore{
			SelectedID: "home",
			Profiles: []common.RouterProfile{{
				ID: "home", Name: "Home", UseCount: 7, LastUsedAt: "2026-08-01T00:00:00Z",
			}},
		},
		state: state{Connected: true, Phase: "connected", RouterID: "home"},
	}
	err := a.recordProfileUsageLocked("home", usedAt)
	if err == nil {
		t.Fatal("usage metadata persistence failure was ignored")
	}
	got := a.profiles.Profiles[0]
	if got.UseCount != 7 || got.LastUsedAt != "2026-08-01T00:00:00Z" {
		t.Fatalf("failed persistence changed RAM usage metadata: %+v", got)
	}
	if !a.state.Connected || a.state.Phase != "connected" {
		t.Fatalf("metadata failure changed proven connection truth: %+v", a.state)
	}
	body, readErr := os.ReadFile(realPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != "{}\n" {
		t.Fatalf("symlink target changed: %q", string(body))
	}
}

func TestUsageMetadataPersistsAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routers.json")
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: path},
		profiles: common.RouterProfileStore{
			SelectedID: "home",
			Profiles: []common.RouterProfile{{ID: "home", Name: "Home"}},
		},
	}
	usedAt := time.Date(2026, 8, 26, 23, 15, 0, 0, time.UTC)
	if err := a.recordProfileUsageLocked("home", usedAt); err != nil {
		t.Fatal(err)
	}
	got := a.profiles.Profiles[0]
	if got.UseCount != 1 || got.LastUsedAt != usedAt.Format(time.RFC3339) {
		t.Fatalf("usage metadata not committed in RAM: %+v", got)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("usage metadata store mode=%#o", info.Mode().Perm())
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".routers.json.tmp-*")); err != nil {
		t.Fatal(err)
	} else if len(matches) != 0 {
		t.Fatalf("temporary profile files survived usage commit: %v", matches)
	}
}
