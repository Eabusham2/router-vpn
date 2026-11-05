package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type desktopMTUSnapshotEnteredContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *desktopMTUSnapshotEnteredContext) Deadline() (time.Time, bool) {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Deadline()
}

func (c *desktopMTUSnapshotEnteredContext) Err() error {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Err()
}

func TestDesktopMTUSnapshotOriginalContextAdmission(t *testing.T) {
	for _, family := range []string{"external", "tor"} {
		t.Run(family, func(t *testing.T) {
			for _, boundary := range []string{"app", "runtime", "workspace", "proof"} {
				if family == "external" && boundary == "proof" {
					continue
				}
				t.Run(boundary, func(t *testing.T) {
					var a *app
					var launch *desktopNodeLaunch
					if family == "tor" {
						a, launch = desktopTorMTUControllerFixture(t, "tor-mtu-hold")
					} else {
						a, launch = desktopMTUControllerFixture(t, "mtu-hold")
					}
					identity, err := capturedDesktopMeasurementRuntime(launch)
					if err != nil {
						t.Fatal(err)
					}
					mutex := &a.mu
					switch boundary {
					case "runtime":
						mutex = identity.mu
					case "workspace":
						mutex = &launch.workspaceMu
					case "proof":
						mutex = &launch.tor.proofMu
					}
					mutex.Lock()
					locked := true
					defer func() {
						if locked {
							mutex.Unlock()
						}
					}()
					parent, cancel := context.WithCancel(context.Background())
					defer cancel()
					ctx := &desktopMTUSnapshotEnteredContext{Context: parent, entered: make(chan struct{})}
					done := make(chan error, 1)
					go func() { _, err := captureDesktopMTUSnapshotContext(ctx, a, launch); done <- err }()
					select {
					case <-ctx.entered:
					case <-time.After(time.Second):
						t.Fatal("snapshot did not enter original observation")
					}
					cancel()
					select {
					case err := <-done:
						if !errors.Is(err, context.Canceled) {
							t.Fatal("lost original cancellation", err)
						}
					case <-time.After(time.Second):
						mutex.Unlock()
						locked = false
						<-done
						t.Fatal("snapshot waited for held original mutex after cancellation")
					}
					mutex.Unlock()
					locked = false
					retry, stop := context.WithTimeout(context.Background(), time.Second)
					defer stop()
					snapshot, err := captureDesktopMTUSnapshotContext(retry, a, launch)
					if err != nil || snapshot.launch != launch {
						t.Fatal("cancelled observation retired original healthy runtime", err)
					}
				})
			}
		})
	}
}

func TestDesktopMTURunCreatesCallerContextBeforeSnapshot(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-hold")
	a.mu.Lock()
	locked := true
	defer func() {
		if locked {
			a.mu.Unlock()
		}
	}()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &desktopMTUSnapshotEnteredContext{Context: parent, entered: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := a.runDesktopExternalMTU(ctx, launch, true); done <- err }()
	select {
	case <-ctx.entered:
	case <-time.After(time.Second):
		cancel()
		a.mu.Unlock()
		locked = false
		<-done
		t.Fatal("MTU run captured state before creating original caller context")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		a.mu.Unlock()
		locked = false
		<-done
		t.Fatal("run ignored caller during snapshot")
	}
}

func TestDesktopMTUProofObservationRetainsMixedFailure(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-hold")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loss := errors.New("original physical owner disappeared")
	launch.external.networkIdentityContext = func(context.Context) (string, error) { cancel(); return "", errors.Join(loss, context.Canceled) }
	_, err := captureDesktopMTUSnapshotContext(ctx, a, launch)
	if !errors.Is(err, loss) || !errors.Is(err, context.Canceled) {
		t.Fatal("mixed original loss was replaced by observer expiry", err)
	}
}

func TestDesktopMTUSnapshotRejectsOriginalSessionReplacement(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-hold")
	original := launch.external.mtu
	defer func() { launch.external.mtu = original }()
	replaced := false
	launch.external.networkIdentityContext = func(ctx context.Context) (string, error) {
		if !replaced {
			replaced = true
			launch.external.mu.Lock()
			launch.external.mtu = &desktopMTUSession{profileID: original.profileID, profileToken: original.profileToken}
			launch.external.mu.Unlock()
		}
		return launch.external.network, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := captureDesktopMTUSnapshotContext(ctx, a, launch); err == nil {
		t.Fatal("snapshot adopted replacement session during original proof")
	}
}
