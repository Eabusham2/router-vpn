package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/desktopnetwork"
)

func TestDesktopTorContextualMonitorSurvivesRequestCompletion(t *testing.T) {
	for _, route := range []string{"tor", "external"} {
		t.Run(route, func(t *testing.T) {
			f := newDesktopTorConnectFixture(t)
			f.unified = route == "external"
			var armed atomic.Bool
			var observations atomic.Int32
			observed := make(chan struct{})
			f.driver.readNetwork = func(ctx context.Context) (string, error) {
				if ctx == nil || ctx.Err() != nil {
					return "", errors.New("live monitor borrowed a completed request")
				}
				if armed.Load() && observations.Add(1) == 2 {
					close(observed)
				}
				return "captured-periodic-network", nil
			}
			request, cancel := context.WithCancel(context.Background())
			defer cancel()
			response, done := desktopTorCallerRequest(t, f, request, externalProfileConnectRequest{ProfileID: f.a.profiles.Profiles[0].ID})
			desktopTorCallerJoin(t, done)
			if response.Code != http.StatusOK || f.launch == nil || f.launch.command == nil || f.launch.command.Process == nil {
				t.Fatal("public Connect did not retain the actual fixture child", response.Code, response.Body.String())
			}
			cancel()
			f.a.mu.Lock()
			finished := f.a.connectionContext == nil && f.a.connectionCancel == nil
			f.a.mu.Unlock()
			if !finished {
				t.Fatal("fixture kept the completed connection operation alive")
			}

			launch := f.launch
			ctx, finish := context.WithTimeout(context.Background(), 3*time.Second)
			defer finish()
			if err := desktopnetwork.LockContext(ctx, &launch.tor.proofMu); err != nil {
				t.Fatal(err)
			}
			launch.tor.mu.Lock()
			before := launch.tor.lastProofHeartbeat
			launch.tor.mu.Unlock()
			// No proof/current read is invoked by the test after arming. The
			// two observations must surround the actual periodic proof read.
			armed.Store(true)
			launch.tor.proofMu.Unlock()
			select {
			case <-observed:
			case <-desktopNodeProcessDone(launch):
				t.Fatal("request completion retired the connected fixture child")
			case <-ctx.Done():
				t.Fatal("periodic proof ignored its captured contextual network observer", ctx.Err())
			}
			// Join that proof reader before asserting its committed heartbeat;
			// entering the callback alone does not prove a successful cycle.
			if err := desktopnetwork.LockContext(ctx, &launch.tor.proofMu); err != nil {
				t.Fatal(err)
			}
			launch.tor.mu.Lock()
			after := launch.tor.lastProofHeartbeat
			launch.tor.mu.Unlock()
			launch.tor.proofMu.Unlock()
			f.a.mu.Lock()
			connected := f.a.state.Connected && f.a.state.Phase == "connected" && f.a.cmd == launch.command
			f.a.mu.Unlock()
			retained, found := desktopNodeOwners.Load(f.a)
			if before == 0 || after <= before || !connected || !found || retained != launch || desktopNodeProcessExited(launch) {
				t.Fatal("completed periodic proof failed to retain the original child and a newer heartbeat", before, after, connected)
			}
			stopDesktopTorLifecycleFixture(t, f.a)
		})
	}
}

func TestDesktopTorContextualMonitorRejectsFailedOrForeignOwner(t *testing.T) {
	for _, change := range []string{"cancelled-observer", "empty-network", "changed-network", "foreign-owner", "foreign-command"} {
		t.Run(change, func(t *testing.T) {
			a, launch, _ := desktopTorRunningFixture(t, "proof")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
				t.Fatal(err)
			}
			var legacyCalls atomic.Int32
			launch.tor.networkIdentity = func() string {
				legacyCalls.Add(1)
				return launch.tor.network
			}
			launch.tor.networkIdentityContext = func(ctx context.Context) (string, error) {
				switch change {
				case "cancelled-observer":
					return launch.tor.network, context.Canceled
				case "empty-network":
					return "", nil
				case "changed-network":
					return "replacement-network", nil
				default:
					return launch.tor.network, ctx.Err()
				}
			}
			retained, command := launch, launch.command
			if change == "foreign-owner" {
				retained = &desktopNodeLaunch{}
				desktopNodeOwners.Store(a, retained)
			}
			if change == "foreign-command" {
				command = &exec.Cmd{}
				a.mu.Lock()
				a.cmd = command
				a.mu.Unlock()
			}
			if a.desktopTorMonitorCurrent(launch) {
				t.Fatal("failed contextual observation or foreign owner retained a current Tor proof", change)
			}
			actual, found := desktopNodeOwners.Load(a)
			a.mu.Lock()
			untouched := a.cmd == command
			a.mu.Unlock()
			if legacyCalls.Load() != 0 || !found || actual != retained || !untouched || desktopNodeProcessExited(launch) {
				t.Fatal("rejected proof borrowed a legacy observer or changed process ownership", change, legacyCalls.Load())
			}
			if _, err := launch.directoryRoot.Lstat("stop.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("proof admission alone acquired another operation's teardown", err)
			}
			// The isolated predicate never ran an automatic stop. Retire only
			// this fixture's original child through its exact owned protocol.
			desktopNodeOwners.Store(a, launch)
			a.mu.Lock()
			a.cmd = launch.command
			a.mu.Unlock()
			if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
				t.Fatal("failed observation prevented owned cleanup", err)
			}
		})
	}
}
