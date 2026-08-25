package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAdminMutationFailureReportsIncompleteRollback(t *testing.T) {
	message := adminMutationFailure(errors.New("persist failed"), errors.New("policy restore failed"))
	if !strings.Contains(message, "persist failed") || !strings.Contains(message, "rollback incomplete") || !strings.Contains(message, "policy restore failed") {
		t.Fatalf("rollback failure truth lost: %q", message)
	}
}

func TestAdminRollbackRestoresRAMAndReturnsLiveRestoreFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake nft command uses a POSIX shell")
	}
	dir := t.TempDir()
	fakeNFT := filepath.Join(dir, "nft")
	if err := os.WriteFile(fakeNFT, []byte("#!/bin/sh\necho injected nft failure >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	a := testMutationServer(t)
	old := defaultAdminState()
	old.LANAccess = true
	a.state = cloneAdminState(old)
	a.state.LANAccess = false
	err := a.rollbackLocked(old, true, false)
	if err == nil || !strings.Contains(err.Error(), "policy restore") {
		t.Fatalf("rollback failure not reported: %v", err)
	}
	if a.state.LANAccess != old.LANAccess || a.state.ForwardingMaster != old.ForwardingMaster {
		t.Fatalf("rollback did not restore RAM: got=%+v old=%+v", a.state, old)
	}
}
