package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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

func TestNodeBoundOperationSerializesWithoutRequiringDisconnect(t *testing.T) {
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
