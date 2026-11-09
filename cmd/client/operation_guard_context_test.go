package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// These cases cancel only after the actual contextual mutex wait observes its
// caller. No scheduler delay stands in for entering the held owner boundary.
type connectionAdmissionWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *connectionAdmissionWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func connectionAdmissionCancelHeld(t *testing.T, held *sync.Mutex, work func(context.Context) error) {
	t.Helper()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	caller := &connectionAdmissionWaitingContext{Context: parent, waiting: make(chan struct{})}
	held.Lock()
	var release sync.Once
	unlock := func() { release.Do(held.Unlock) }
	defer unlock()
	result := make(chan error, 1)
	go func() { result <- work(caller) }()
	select {
	case <-caller.waiting:
	case err := <-result:
		t.Fatalf("admission did not wait for its held original owner: %v", err)
	case <-time.After(2 * time.Second):
		cancel()
		unlock()
		<-result
		t.Fatal("held admission never observed its original caller")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("held admission did not return the original cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		unlock()
		<-result
		t.Fatal("cancelled admission waited for an unrelated owner to unlock")
	}
}

func TestConnectionAdmissionContextKeepsHeldOriginalOwners(t *testing.T) {
	for _, boundary := range []string{"application", "protection"} {
		t.Run(boundary, func(t *testing.T) {
			privateOperationRoot(t)
			a := &app{state: state{Mode: "off", Phase: "off"}}
			held := &a.mu
			if boundary == "protection" {
				a.nodeProtection = &desktopNodeProtectionSlot{known: true}
				held = &a.nodeProtection.mu
			}
			connectionAdmissionCancelHeld(t, held, func(ctx context.Context) error {
				operation, finish, err := a.beginConnectionOperationContext(ctx)
				if finish != nil {
					finish()
				}
				if operation != nil || finish != nil {
					return errors.New("cancelled admission published a connection transaction")
				}
				return err
			})
			if a.connectionContext != nil || a.connectionCancel != nil || a.state.Phase != "off" {
				t.Fatal("cancelled admission changed original connection state")
			}
			if !a.operationMu.TryLock() {
				t.Fatal("cancelled admission retained the application transaction")
			}
			a.operationMu.Unlock()
		})
	}
}

func TestConnectionAdmissionContextRetainsOriginalLifetimeAndReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		name := "original"
		if replace {
			name = "replacement"
		}
		t.Run(name, func(t *testing.T) {
			privateOperationRoot(t)
			a := &app{state: state{Mode: "off", Phase: "off"}}
			type key struct{}
			caller, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "original request"), 10*time.Second)
			defer cancel()
			operation, finish, err := a.beginConnectionOperationContext(caller)
			if err != nil {
				t.Fatal(err)
			}
			deadline, _ := caller.Deadline()
			actual, bounded := operation.Deadline()
			if !bounded || !actual.Equal(deadline) || operation.Value(key{}) != "original request" {
				finish()
				t.Fatal("admission replaced the original values or deadline")
			}
			replacement, retire := context.WithCancel(context.Background())
			defer retire()
			if replace {
				a.mu.Lock()
				a.connectionContext, a.connectionCancel = replacement, retire
				a.state.Phase = "replacement-proving"
				a.mu.Unlock()
			}
			cancel()
			if operation.Err() != context.Canceled || replacement.Err() != nil {
				finish()
				t.Fatal("original cancellation was detached or reached a replacement")
			}
			finish()
			if replace {
				if a.connectionContext != replacement || a.state.Phase != "replacement-proving" || replacement.Err() != nil {
					t.Fatal("original finish changed its replacement")
				}
			} else if a.connectionContext != nil || a.connectionCancel != nil || a.state.Phase != "off" {
				t.Fatal("original finish retained a retired requested state")
			}
			if !a.operationMu.TryLock() {
				t.Fatal("original finish did not release its own transaction")
			}
			a.operationMu.Unlock()
		})
	}
}

func TestConnectionAdmissionContextKeepsMeasurementInvalidationOwned(t *testing.T) {
	for _, boundary := range []string{"dns-slot", "dns-operation", "latency-slot", "latency-operation"} {
		t.Run(boundary, func(t *testing.T) {
			measurement, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := &app{}
			var held *sync.Mutex
			if boundary == "dns-slot" || boundary == "dns-operation" {
				a.dnsMeasurements = &desktopDNSSlot{current: &desktopDNSOperation{cancel: cancel}}
				held = &a.dnsMeasurements.mu
				if boundary == "dns-operation" {
					held = &a.dnsMeasurements.current.mu
				}
			} else {
				a.latencyMeasurements = &desktopLatencySlot{current: &desktopLatencyOperation{cancel: cancel}}
				held = &a.latencyMeasurements.mu
				if boundary == "latency-operation" {
					held = &a.latencyMeasurements.current.mu
				}
			}
			connectionAdmissionCancelHeld(t, held, func(ctx context.Context) error {
				return invalidateDesktopDNSResultsContext(ctx, a)
			})
			if measurement.Err() != nil {
				t.Fatal("cancelled admission invalidated an unentered measurement owner")
			}
			if err := invalidateDesktopDNSResultsContext(context.Background(), a); err != nil || measurement.Err() != context.Canceled {
				t.Fatal("live invalidation failed to reach the same retained measurement", err)
			}
		})
	}
}

func TestConnectionAdmissionContextKeepsRetainedProtectionRead(t *testing.T) {
	for _, boundary := range []string{"application", "slot"} {
		t.Run(boundary, func(t *testing.T) {
			a := &app{nodeProtection: &desktopNodeProtectionSlot{}}
			held := &a.mu
			if boundary == "slot" {
				held = &a.nodeProtection.mu
			}
			connectionAdmissionCancelHeld(t, held, func(ctx context.Context) error {
				_, err := a.retainedDesktopNodeProtectionContext(ctx)
				return err
			})
			retained, err := a.retainedDesktopNodeProtectionContext(context.Background())
			if err != nil || !retained {
				t.Fatal("unknown protection was converted into absence", err)
			}
			a.nodeProtection.known = true
			retained, err = a.retainedDesktopNodeProtectionContext(context.Background())
			if err != nil || retained {
				t.Fatal("proved empty protection remained a legacy transition blocker", err)
			}
		})
	}
}

func TestConnectionAdmissionContextRejectsRetiredPrivatePreparation(t *testing.T) {
	root := privateOperationRoot(t)
	caller, cancel := context.WithCancel(context.Background())
	cancel()
	if err := preflightPrivateConnectionRuntimeContext(caller); !errors.Is(err, context.Canceled) {
		t.Fatal("retired preparation lost the original cancellation", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "run")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retired preparation created a new private runtime root", err)
	}
	a := &app{}
	if operation, finish, err := a.beginConnectionOperationContext(caller); err == nil || operation != nil || finish != nil {
		t.Fatal("retired request created a connection transaction", err)
	}
	if operation, finish, err := a.beginConnectionOperationContext(nil); err == nil || operation != nil || finish != nil {
		t.Fatal("missing request created a connection transaction", err)
	}
}
