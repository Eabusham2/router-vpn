//go:build linux

package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectionAdmissionContextLinuxServiceKeepsHeldOwner(t *testing.T) {
	for _, boundary := range []string{"application", "service"} {
		t.Run(boundary, func(t *testing.T) {
			a := &app{}
			var calls atomic.Int32
			client := &linuxStandardServiceProtectionClient{app: a,
				exchange: func(context.Context, linuxStandardServiceRequest) (*linuxStandardServiceProtectionData, error) {
					calls.Add(1)
					return nil, errors.New("unentered native service")
				}}
			linuxStandardServiceProtectionClients.Store(a, client)
			t.Cleanup(func() { linuxStandardServiceProtectionClients.Delete(a) })
			var held *sync.Mutex = &a.mu
			if boundary == "service" {
				held = &client.mu
			}
			connectionAdmissionCancelHeld(t, held, func(ctx context.Context) error {
				capture := a.captureLinuxStandardServiceProtectionForParent(ctx, nil)
				if capture == nil || capture.Available || capture.Absent || capture.ScopedAbsent {
					return errors.New("cancelled service capture fabricated protection or absence")
				}
				return capture.Failure
			})
			if calls.Load() != 0 {
				t.Fatal("cancelled service admission entered the native exchange")
			}
			if actual, _ := linuxStandardServiceProtectionClients.Load(a); actual != client {
				t.Fatal("cancelled observation replaced its retained service owner")
			}
		})
	}
}

func TestConnectionAdmissionContextLinuxServiceRejectsLateReceipt(t *testing.T) {
	for _, late := range []bool{false, true} {
		name := "live"
		if late {
			name = "cancelled-receipt"
		}
		t.Run(name, func(t *testing.T) {
			a := &app{}
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			client := &linuxStandardServiceProtectionClient{app: a,
				exchange: func(ctx context.Context, request linuxStandardServiceRequest) (*linuxStandardServiceProtectionData, error) {
					calls++
					if ctx != caller || request.Action != "protection-view" || request.Session == "" {
						return nil, errors.New("native protection observation replaced its caller or request")
					}
					if late {
						cancel()
					}
					return &linuxStandardServiceProtectionData{Owned: true, Active: true}, nil
				}}
			linuxStandardServiceProtectionClients.Store(a, client)
			t.Cleanup(func() { linuxStandardServiceProtectionClients.Delete(a) })
			capture := a.captureLinuxStandardServiceProtectionForParent(caller, nil)
			if calls != 1 || capture == nil {
				t.Fatal("protection observation did not use its original service")
			}
			if late {
				if capture.Available || !errors.Is(capture.Failure, context.Canceled) {
					t.Fatal("late native receipt became current protection", capture.Failure)
				}
			} else if !capture.Available || !capture.Owned || !capture.Active || capture.Failure != nil {
				t.Fatal("live original service receipt was rejected", capture.Failure)
			}
		})
	}
}

func TestConnectionAdmissionContextLinuxRetiredCallerCannotObserveParent(t *testing.T) {
	for _, boundary := range []string{"stop", "parent-protection", "combined-protection", "transition"} {
		t.Run(boundary, func(t *testing.T) {
			controller := &ownedDesktopController{}
			parent := &desktopLinuxNodeParent{controller: controller, gate: make(chan struct{}, 1)}
			controller.nodeParent = parent
			a := &app{localController: controller}
			caller, cancel := context.WithCancel(context.Background())
			cancel()
			result := make(chan error, 1)
			go func() {
				switch boundary {
				case "stop":
					_, err := a.captureDesktopNodeStopContext(caller)
					result <- err
				case "parent-protection":
					capture := a.captureDesktopParentProfileProtectionContext(caller)
					if capture == nil {
						result <- nil
					} else {
						result <- capture.failure
					}
				case "combined-protection":
					capture := a.capturePlatformProfileProtectionContext(caller)
					if capture == nil {
						result <- nil
					} else {
						result <- capture.failure
					}
				default:
					result <- a.guardDesktopLinuxNodeLegacyTransitionContext(caller)
				}
			}()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("retired parent observation lost its caller or claimed absence", err)
				}
			case <-time.After(time.Second):
				parent.gate <- struct{}{}
				<-result
				t.Fatal("retired request started a fresh parent observation budget")
			}
			if _, exists := linuxStandardServiceProtectionClients.Load(a); exists {
				linuxStandardServiceProtectionClients.Delete(a)
				t.Fatal("retired parent observation created a replacement service owner")
			}
		})
	}
}
