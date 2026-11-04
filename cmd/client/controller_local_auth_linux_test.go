//go:build linux

package main

import (
	"context"
	"errors"
	"testing"
)

// The portable EOF test owns actual HTTP work and an operation, but no installed
// native service. Model only its protection-view boundary; production still
// requires the authenticated service or independent native absence proof.
func testLocalControllerProtectionBoundary(t *testing.T, a *app) {
	testLocalControllerLinuxProtectionView(t, a, linuxStandardServiceProtectionData{AbsenceProved: true}, nil)
}

func testLocalControllerLinuxProtectionView(t *testing.T, a *app, data linuxStandardServiceProtectionData, failure error) {
	t.Helper()
	client := &linuxStandardServiceProtectionClient{app: a, controller: a.localController}
	client.exchange = func(ctx context.Context, request linuxStandardServiceRequest) (*linuxStandardServiceProtectionData, error) {
		if ctx == nil || ctx.Err() != nil || request.Schema != 1 || request.Action != "protection-view" || !validControllerOwnerToken(request.Session) {
			t.Fatal("controller fixture received another service operation")
		}
		view := data
		return &view, failure
	}
	linuxStandardServiceProtectionClients.Store(a, client)
	t.Cleanup(func() { linuxStandardServiceProtectionClients.Delete(a) })
}

func TestLocalControllerOperationRejectsUnresolvedServiceProtection(t *testing.T) {
	for _, name := range []string{"absence-unproved", "active", "pending", "service-failure", "transport-failure", "controller-replaced"} {
		t.Run(name, func(t *testing.T) {
			privateOperationRoot(t)
			a := &app{state: state{Mode: "off", Phase: "off"}, localController: testLocalControllerOwner()}
			view := linuxStandardServiceProtectionData{AbsenceProved: true}
			var failure error
			switch name {
			case "absence-unproved":
				view.AbsenceProved = false
			case "active":
				view.Active = true
			case "pending":
				view.Pending = true
			case "service-failure":
				view.Failure = "original service observation failed"
			case "transport-failure":
				failure = errors.New("original service channel failed")
			}
			testLocalControllerLinuxProtectionView(t, a, view, failure)
			if name == "controller-replaced" {
				a.localController = testLocalControllerOwner()
			}
			if _, finish, err := a.beginConnectionOperation(); err == nil {
				finish()
				t.Fatal("unresolved original protection admitted a new connection operation")
			}
			if a.state.Phase != "off" || a.connectionContext != nil || a.connectionCancel != nil {
				t.Fatal("rejected service protection changed the original operation state")
			}
			if !a.operationMu.TryLock() {
				t.Fatal("rejected service protection retained the connection transaction")
			}
			a.operationMu.Unlock()
		})
	}
}
