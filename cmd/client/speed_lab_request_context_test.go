package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSpeedLabRequestCancellationOnlyCancelsCapturedOwner(t *testing.T) {
	owner, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	parent, cancelRequest := context.WithCancel(context.Background())
	defer cancelRequest()
	a := &app{connectionContext: owner, connectionCancel: cancelOwner}
	req := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", nil).WithContext(parent)
	bound, release, err := a.speedLabRequestContext(req, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	newOwner, cancelNewOwner := context.WithCancel(context.Background())
	defer cancelNewOwner()
	// Simulate the old HTTP request completing after another session starts.
	a.mu.Lock()
	a.connectionContext, a.connectionCancel = newOwner, cancelNewOwner
	a.mu.Unlock()
	cancelRequest()
	select {
	case <-owner.Done():
	case <-time.After(time.Second):
		t.Fatal("the original operation was not cancelled")
	}
	if newOwner.Err() != nil {
		t.Fatal("a late request callback cancelled the replacement VPN session")
	}
	if !errors.Is(bound.Context().Err(), context.Canceled) {
		t.Fatal("measurement did not inherit request cancellation")
	}
}

func TestSpeedLabDisconnectCancelsMeasurementContext(t *testing.T) {
	owner, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	a := &app{connectionContext: owner, connectionCancel: cancelOwner}
	req := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", nil)
	bound, release, err := a.speedLabRequestContext(req, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cancelOwner() // The same cancellation signal used by Disconnect.
	select {
	case <-bound.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("Disconnect left the measurement running")
	}
	if req.Context().Err() != nil {
		t.Fatal("the independent caller request was mutated")
	}
}

func TestSpeedLabRequestCleanupDisarmsLateCancellation(t *testing.T) {
	owner, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	parent, cancelRequest := context.WithCancel(context.Background())
	defer cancelRequest()
	a := &app{connectionContext: owner, connectionCancel: cancelOwner}
	req := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", nil).WithContext(parent)
	bound, release, err := a.speedLabRequestContext(req, owner)
	if err != nil {
		t.Fatal(err)
	}
	release()
	cancelRequest()
	if owner.Err() != nil {
		t.Fatal("a completed test retained its request cancellation callback")
	}
	if !errors.Is(bound.Context().Err(), context.Canceled) {
		t.Fatal("measurement context was not released")
	}
}

func TestSpeedLabRequestRejectsStaleOperationOwner(t *testing.T) {
	owner, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	other, cancelOther := context.WithCancel(context.Background())
	defer cancelOther()
	a := &app{connectionContext: owner, connectionCancel: cancelOwner}
	req := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", nil)
	if _, release, err := a.speedLabRequestContext(req, other); err == nil {
		if release != nil {
			release()
		}
		t.Fatal("a stale connection owner could bind a new measurement")
	}
	if owner.Err() != nil {
		t.Fatal("rejecting a stale owner cancelled the active operation")
	}
}
