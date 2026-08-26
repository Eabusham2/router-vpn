package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func privateOperationRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	return root
}

func TestProfileSettingsBusyFailsClosedForUnknownAndTransitionPhases(t *testing.T) {
	for _, phase := range []string{"requested", "starting", "checking", "auto:trying:wg", "multihop:proving-exit", "reconnecting", "stopping", "future-unknown"} {
		if !profileSettingsBusy(false, phase) {
			t.Fatalf("phase %q unexpectedly permits mutation", phase)
		}
	}
	for _, phase := range []string{"", "off", "failed"} {
		if profileSettingsBusy(false, phase) {
			t.Fatalf("stable disconnected phase %q unexpectedly blocks recovery mutation", phase)
		}
	}
	if !profileSettingsBusy(true, "off") {
		t.Fatal("connected state must fail closed even if phase text is stale")
	}
}

func TestOperationGuardSerializesConnectionAndMutationTransactions(t *testing.T) {
	privateOperationRoot(t)
	a := &app{state: state{Mode: "off", Phase: "off"}}
	req := httptest.NewRequest("POST", "/api/profile/save", nil)

	releaseMutation, err := a.beginMutationOperation(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.beginConnectionOperation(); err == nil {
		t.Fatal("connection transaction overlapped an active settings mutation")
	}
	releaseMutation()

	_, finishConnection, err := a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.beginMutationOperation(req); err == nil {
		t.Fatal("settings mutation overlapped an active connection transaction")
	}
	finishConnection()

	releaseMutation, err = a.beginMutationOperation(req)
	if err != nil {
		t.Fatalf("operation lock was not released after connection transaction: %v", err)
	}
	releaseMutation()
}

func TestConnectionOperationCancellationBlocksAdoption(t *testing.T) {
	privateOperationRoot(t)
	a := &app{state: state{Mode: "off", Phase: "off"}}
	_, finish, err := a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	a.cancelConnectionOperation()
	if err := a.checkConnectionOperation(); err == nil {
		t.Fatal("cancelled connection transaction remained eligible to adopt a runtime")
	}
}

func TestConnectionOperationPreflightsPrivateRuntimeBeforeRequested(t *testing.T) {
	root := privateOperationRoot(t)
	a := &app{state: state{Mode: "off", Phase: "off"}}
	_, finish, err := a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	if a.state.Phase != "requested" || a.connectionContext == nil || a.connectionCancel == nil {
		t.Fatalf("safe preflight did not enter requested state: phase=%q ctx=%v cancel=%v", a.state.Phase, a.connectionContext != nil, a.connectionCancel != nil)
	}
	for _, category := range []string{"native-standard-exit", "native-multihop", "openvpn-standard-exit"} {
		path := filepath.Join(root, "run", category)
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("private runtime category %s was not safely prepared: info=%v err=%v", category, info, statErr)
		}
	}
	finish()
	if a.state.Phase != "off" || a.connectionContext != nil || a.connectionCancel != nil {
		t.Fatalf("finish did not clear requested state: phase=%q", a.state.Phase)
	}
}

func TestConnectionOperationRejectsPoisonedRuntimeBeforeStateChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows CI may not grant symlink privileges")
	}
	root := privateOperationRoot(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "run")); err != nil {
		t.Fatal(err)
	}
	a := &app{state: state{Mode: "off", Phase: "off"}}
	if _, _, err := a.beginConnectionOperation(); err == nil {
		t.Fatal("connection operation accepted a symlinked private runtime root")
	}
	if a.state.Phase != "off" || a.connectionContext != nil || a.connectionCancel != nil {
		t.Fatalf("failed preflight mutated connection state: phase=%q ctx=%v cancel=%v", a.state.Phase, a.connectionContext != nil, a.connectionCancel != nil)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed runtime preflight touched symlink target: %v", entries)
	}
	// A failed preflight must also release the operation mutex for recovery.
	release, err := a.beginMutationOperation(httptest.NewRequest(http.MethodPost, "/api/profile/save", nil))
	if err != nil {
		t.Fatalf("failed connection preflight leaked operation lock: %v", err)
	}
	release()
}

func TestNodeBoundOperationSerializesWithoutRequiringDisconnect(t *testing.T) {
	privateOperationRoot(t)
	a := &app{state: state{Connected: true, Phase: "connected"}}
	release, err := a.beginNodeBoundOperation()
	if err != nil {
		t.Fatalf("stable connected node-bound operation should be allowed: %v", err)
	}
	defer release()
	if _, err := a.beginMutationOperation(httptest.NewRequest(http.MethodPost, "/api/profile/select", nil)); err == nil {
		t.Fatal("profile mutation overlapped active node-bound operation")
	}
	if _, _, err := a.beginConnectionOperation(); err == nil {
		t.Fatal("new connection overlapped active node-bound operation")
	}
}
