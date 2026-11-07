package main

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

type desktopTorComparisonCallerKey struct{}

// The child owns real private mailbox files and a joined process. Its timings
// are explicit fixture receipts; these controls do not claim Tor wire traffic.
func TestDesktopTorComparisonCallerHeldOwners(t *testing.T) {
	for _, boundary := range []string{"client", "claim", "proof", "app", "workspace", "identity", "issue", "await-cleanup", "cleanup-client", "cleanup-claim"} {
		t.Run(boundary, func(t *testing.T) {
			a, launch, client := desktopTorComparisonFixture(t, "tor-compare-context")
			parent, cancelParent := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelParent()
			if err := client.Prepare(parent); err != nil {
				t.Fatal(err)
			}
			previous := client.last
			mutex := &client.mu
			switch boundary {
			case "claim", "cleanup-claim":
				mutex = &launch.tor.mu
			case "proof":
				mutex = &launch.tor.proofMu
			case "app":
				mutex = &a.mu
			case "workspace", "issue", "await-cleanup":
				mutex = &launch.workspaceMu
			}
			release := measurementHeldLock(mutex)
			defer release()
			ctx, cancel := context.WithTimeout(parent, 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				switch boundary {
				case "identity":
					var identity string
					identity, err = client.IdentityContext(ctx)
					if identity != "" {
						err = errors.New("held identity returned a candidate")
					}
				case "issue":
					_, err = client.issue(ctx, mobiletor.DesktopTorCompareVerify, false)
				case "await-cleanup":
					_, err = client.await(ctx, previous, true)
				case "cleanup-client", "cleanup-claim":
					err = client.Close(ctx)
				default:
					var duration time.Duration
					duration, err = client.ProbeLast(ctx)
					if duration != 0 {
						err = errors.New("expired owner returned a scored duration")
					}
				}
				done <- err
			}()
			if err := measurementContextResult(t, done, release); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("native comparison did not retain the original held-lock deadline", err)
			}
			release()
			if !client.claimed() || client.closed || desktopNodeProcessExited(launch) {
				t.Fatal("expired observation retired its unjoined native owner")
			}
			if boundary != "issue" && client.last != previous {
				t.Fatal("expired admission changed the retained native request")
			}
			if boundary == "issue" {
				if client.last == previous || client.last.request.Sequence != previous.request.Sequence+1 {
					t.Fatal("entered failed publication lost its exact retryable request")
				}
				select {
				case <-client.last.issued:
				default:
					t.Fatal("failed file admission left an unjoined publication")
				}
				if _, err := launch.directoryRoot.Stat(mobiletor.DesktopTorCompareRequestFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("expired file admission published a new request", err)
				}
			}
		})
	}
}

func TestDesktopTorComparisonConstructorCallerHeldOwners(t *testing.T) {
	for _, boundary := range []string{"proof", "claim", "app", "workspace"} {
		t.Run(boundary, func(t *testing.T) {
			a, launch, _ := desktopTorRunningFixture(t, "tor-compare-context")
			parent, cancelParent := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelParent()
			if _, err := a.waitDesktopTorProof(parent, launch); err != nil {
				t.Fatal(err)
			}
			mutex := &launch.tor.proofMu
			switch boundary {
			case "claim":
				mutex = &launch.tor.mu
			case "app":
				mutex = &a.mu
			case "workspace":
				mutex = &launch.workspaceMu
			}
			release := measurementHeldLock(mutex)
			defer release()
			ctx, cancel := context.WithTimeout(parent, 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				client, err := newDesktopTorComparisonClientContext(ctx, a, launch, comparisonTargets[0])
				if client != nil {
					err = errors.New("expired constructor retained a new native claim")
				}
				done <- err
			}()
			if err := measurementContextResult(t, done, release); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("native comparison constructor lost caller admission", err)
			}
			release()
			if launch.tor.comparison != nil || launch.tor.comparisonGeneration != 0 {
				t.Fatal("expired constructor changed the native generation")
			}
		})
	}
}

func TestDesktopTorComparisonNetworkObserverReceivesCaller(t *testing.T) {
	for _, stage := range []string{"constructor", "probe"} {
		t.Run(stage, func(t *testing.T) {
			a, launch, client := desktopTorComparisonFixture(t, "tor-compare-context")
			parent, cancelParent := context.WithTimeout(context.WithValue(context.Background(), desktopTorComparisonCallerKey{}, "original-tor-round"), 5*time.Second)
			defer cancelParent()
			if stage == "constructor" {
				if err := client.Close(parent); err != nil {
					t.Fatal(err)
				}
			} else if err := client.Prepare(parent); err != nil {
				t.Fatal(err)
			}
			original := launch.tor.networkIdentityContext
			defer func() { launch.tor.networkIdentityContext = original }()
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			entered := make(chan struct{})
			var once sync.Once
			launch.tor.networkIdentityContext = func(caller context.Context) (string, error) {
				once.Do(func() { close(entered) })
				if caller.Value(desktopTorComparisonCallerKey{}) != "original-tor-round" {
					return "", errors.New("native observer lost exact caller values")
				}
				limit, ok := caller.Deadline()
				want, _ := parent.Deadline()
				if !ok || limit.After(want) {
					return "", errors.New("native observer lost caller deadline")
				}
				<-caller.Done()
				return "", caller.Err()
			}
			done := make(chan error, 1)
			go func() {
				if stage == "constructor" {
					_, err := newDesktopTorComparisonClientContext(ctx, a, launch, comparisonTargets[0])
					done <- err
				} else {
					duration, err := client.ProbeLast(ctx)
					if duration != 0 {
						err = errors.New("cancelled network observer supplied a duration")
					}
					done <- err
				}
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatal("actual native observer was bypassed", err)
			case <-parent.Done():
				t.Fatal("actual native observer was not entered")
			}
			cancel()
			if err := measurementContextResult(t, done, cancelParent); !errors.Is(err, context.Canceled) {
				t.Fatal("actual native observer lost caller cancellation", err)
			}
		})
	}
}

func TestDesktopTorComparisonRejectsClaimReplacementDuringObservation(t *testing.T) {
	for _, replacement := range []string{"same-generation-owner", "generation"} {
		t.Run(replacement, func(t *testing.T) {
			_, launch, client := desktopTorComparisonFixture(t, "tor-compare-context")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := client.Prepare(ctx); err != nil {
				t.Fatal(err)
			}
			previous := client.last
			original := launch.tor.networkIdentityContext
			replaced := &desktopTorComparisonClient{}
			defer func() {
				launch.tor.networkIdentityContext = original
				launch.tor.mu.Lock()
				launch.tor.comparison, launch.tor.comparisonGeneration = client, client.base.Generation
				launch.tor.mu.Unlock()
			}()
			var once sync.Once
			launch.tor.networkIdentityContext = func(caller context.Context) (string, error) {
				once.Do(func() {
					launch.tor.mu.Lock()
					defer launch.tor.mu.Unlock()
					if replacement == "same-generation-owner" {
						launch.tor.comparison = replaced
					} else {
						launch.tor.comparisonGeneration++
					}
				})
				return original(caller)
			}
			if duration, err := client.ProbeLast(ctx); err == nil || duration != 0 {
				t.Fatal("replaced native claim produced a timing", duration, err)
			}
			if client.last != previous || client.claimed() || client.Identity() != "" {
				t.Fatal("replaced claim published a request or retained a candidate identity")
			}
			if replacement == "same-generation-owner" && launch.tor.comparison != replaced || replacement == "generation" && launch.tor.comparisonGeneration != client.base.Generation+1 {
				t.Fatal("failed original observation changed the replacement owner")
			}
		})
	}
}
