package main

import (
	"context"
	"testing"
)

func TestConnectionCancellationIntentPrecedesCallback(t *testing.T) {
	privateOperationRoot(t)
	a := &app{state: state{Mode: "off", Phase: "off"}}
	operation, finish, err := a.beginConnectionTransaction()
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.mu.Lock()
	actualCancel := a.connectionCancel
	a.connectionCancel = func() {
		close(entered)
		<-release
		actualCancel()
	}
	a.mu.Unlock()
	go func() { a.cancelConnectionOperation(); close(joined) }()
	<-entered
	a.mu.Lock()
	intent, selected := a.connectionCancelIntent, a.connectionContext
	a.mu.Unlock()
	if intent != operation || selected != operation || operation.Err() != nil {
		close(release)
		<-joined
		t.Fatal("cancellation intent was not committed for the exact live operation before its callback")
	}
	if a.checkCapturedConnectionOperation(operation) == nil || !a.sameConnectionOperation(operation) {
		close(release)
		<-joined
		t.Fatal("recorded cancellation allowed new admission or discarded original cleanup ownership")
	}
	// A delayed callback remains tied to its original operation even if a
	// captured transaction installs a replacement context in the meantime.
	replacement, cancelReplacement := context.WithCancel(context.Background())
	defer cancelReplacement()
	a.mu.Lock()
	a.connectionContext, a.connectionCancel = replacement, cancelReplacement
	a.mu.Unlock()
	if err := a.checkCapturedConnectionOperation(replacement); err != nil {
		close(release)
		<-joined
		t.Fatal("original cancellation intent rejected the replacement operation", err)
	}
	close(release)
	<-joined
	a.mu.Lock()
	replaced, oldIntent := a.connectionContext, a.connectionCancelIntent
	a.mu.Unlock()
	if operation.Err() != context.Canceled || replacement.Err() != nil || replaced != replacement || oldIntent == replacement {
		t.Fatal("delayed original cancellation changed or marked its replacement operation")
	}
}

func TestConnectionCancellationIntentClearsWithOriginalFinish(t *testing.T) {
	privateOperationRoot(t)
	a := &app{state: state{Mode: "off", Phase: "off"}}
	operation, finish, err := a.beginConnectionTransaction()
	if err != nil {
		t.Fatal(err)
	}
	a.cancelConnectionOperation()
	a.mu.Lock()
	intent := a.connectionCancelIntent
	a.mu.Unlock()
	if intent != operation {
		finish()
		t.Fatal("original cancellation had no captured intent")
	}
	finish()
	a.mu.Lock()
	cleared := a.connectionContext == nil && a.connectionCancel == nil && a.connectionCancelIntent == nil
	a.mu.Unlock()
	if !cleared {
		t.Fatal("ordinary finish retained its ended original cancellation intent")
	}
	next, finishNext, err := a.beginConnectionTransaction()
	if err != nil {
		t.Fatal(err)
	}
	defer finishNext()
	a.mu.Lock()
	intent = a.connectionCancelIntent
	a.mu.Unlock()
	if next == operation || next.Err() != nil || intent != nil {
		t.Fatal("a new original operation inherited stale cancellation intent")
	}
}
