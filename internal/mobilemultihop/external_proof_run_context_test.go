package mobilemultihop

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/nativeopenvpn"
)

type externalRunKey struct{}

func TestExternalProofDefaultRunKeepsCapturedLifetimeAndPhaseBudgets(t *testing.T) {
	request, engine, _ := externalRequestFixture(t, "")
	request.ctx = context.WithValue(request.ctx, externalRunKey{}, "captured-vpn-context")
	var admission, network context.Context
	engine.dns = func(ctx context.Context, _ string) error {
		network = ctx
		deadline, bounded := ctx.Deadline()
		if ctx.Value(externalRunKey{}) != "captured-vpn-context" || !bounded || time.Until(deadline) < 44*time.Second || time.Until(deadline) > 45*time.Second {
			return errors.New("default proof lost captured values or separate network budget")
		}
		return nil
	}
	_, err := request.RunObserved(func(ctx context.Context) error {
		if ctx.Value(externalRunKey{}) != "captured-vpn-context" {
			return errors.New("native host observation lost captured lifetime context")
		}
		if admission == nil {
			admission = ctx
			deadline, bounded := ctx.Deadline()
			if !bounded || time.Until(deadline) > 1500*time.Millisecond {
				return errors.New("native admission lost original bounded read")
			}
		}
		return nil
	})
	if err != nil || admission == nil || network == nil || admission == network || admission.Err() == nil || network.Err() == nil || request.ctx.Err() != nil || !request.Healthy() {
		t.Fatal("default proof did not preserve independent admission, network proof and VPN lifetimes", err)
	}
}

func TestExternalProofRunCancellationOwnsAdmissionLocks(t *testing.T) {
	for _, phase := range []string{"run-mutex-caller", "run-mutex-owner", "controller-admission", "controller-capture"} {
		t.Run(phase, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			var request *ExternalProofRequest
			var engine *externalRunCaptureEngine
			var traffic *[]string
			var observe func(context.Context) error
			entered := make(chan struct{})
			var mu *sync.Mutex
			var locked atomic.Bool
			if strings.HasPrefix(phase, "run-mutex-") {
				request, _, traffic = externalRequestFixture(t, "")
				mu = &request.runMu
				mu.Lock()
				locked.Store(true)
			} else {
				var native *externalExecutionEngine
				request, native = externalExecutionRequest(t, "auto", "")
				engine = &externalRunCaptureEngine{externalExecutionEngine: native}
				request.engine = engine
				mu = &request.execution.mu
				var reads atomic.Int32
				engine.observe = func(ctx context.Context) (string, error) {
					if phase == "controller-capture" && reads.Add(1) == 2 {
						mu.Lock()
						locked.Store(true)
						close(entered)
						<-ctx.Done()
					}
					return request.identity, nil
				}
				if phase == "controller-admission" {
					observe = func(context.Context) error { mu.Lock(); locked.Store(true); close(entered); return nil }
				}
			}
			var releaseOnce sync.Once
			release := func() {
				if locked.Load() {
					releaseOnce.Do(mu.Unlock)
				}
			}
			done := make(chan error, 1)
			joined := make(chan struct{})
			go func() { defer close(joined); _, err := request.RunContext(parent, observe); done <- err }()
			t.Cleanup(func() {
				cancel()
				release()
				select {
				case <-joined:
					release()
				case <-time.After(time.Second):
					t.Error("original admission fixture did not join")
				}
			})
			if strings.HasPrefix(phase, "run-mutex-") {
				// A finite cancellation arrives while the real admission mutex
				// remains held; no synthetic context reader replaces that lock.
				retire := cancel
				if phase == "run-mutex-owner" {
					retire = request.Cancel
				}
				timer := time.AfterFunc(40*time.Millisecond, retire)
				defer timer.Stop()
			} else {
				select {
				case <-entered:
					cancel()
				case err := <-done:
					t.Fatal("comparison bypassed captured lock boundary", err)
				case <-time.After(time.Second):
					cancel()
					t.Fatal("comparison did not enter original capture")
				}
			}
			select {
			case err := <-done:
				release()
				if !errors.Is(err, context.Canceled) {
					t.Fatal("admission lost original cancellation", err)
				}
			case <-time.After(time.Second):
				cancel()
				release()
				<-done
				t.Fatal("original proof cancellation waited on the captured admission mutex")
			}
			if request.succeeded.Load() || engine != nil && (engine.selections.Load() != 0 || len(engine.dnsCalls) != 0 || len(engine.leaseRequests) != 0) || traffic != nil && len(*traffic) != 0 {
				t.Fatal("cancelled admission started a comparison or proof socket")
			}
		})
	}
}

type externalRunEngine struct {
	*externalProofFixture
	observe func(context.Context) (string, error)
	legacy  atomic.Int32
}

func (e *externalRunEngine) Identity() string {
	e.legacy.Add(1)
	return "legacy-reader-must-not-authorize-proof"
}
func (e *externalRunEngine) IdentityContext(ctx context.Context) (string, error) {
	return e.observe(ctx)
}

func TestExternalProofRunRetainsOriginalCaller(t *testing.T) {
	for _, phase := range []string{"success", "nil", "cancel-before", "identity", "admission", "private-entry", "public-entry", "dns", "exit", "delivery", "late-entry", "late-dns", "late-exit", "replaced-entry", "replaced-dns", "replaced-exit", "close", "owner-cancel"} {
		t.Run(phase, func(t *testing.T) {
			entry := "router-wg"
			if phase == "public-entry" {
				entry = "socks5"
			}
			request, original, _ := externalRequestFixture(t, entry)
			successor, _, successorCalls := externalRequestFixture(t, "")
			if _, err := successor.Run(); err != nil {
				t.Fatal("independent successor proof", err)
			}
			deadline := time.Now().Add(2 * time.Second)
			parent, cancel := context.WithDeadline(context.WithValue(context.Background(), externalRunKey{}, phase), deadline)
			defer cancel()
			entered := make(chan struct{})
			var once sync.Once
			var calls []string
			check := func(ctx context.Context) error {
				limit, bounded := ctx.Deadline()
				if ctx.Value(externalRunKey{}) != phase || !bounded || limit.After(deadline) {
					return errors.New("proof callback replaced its original caller or deadline")
				}
				return nil
			}
			visit := func(ctx context.Context, stage string) error {
				if err := check(ctx); err != nil {
					return err
				}
				calls = append(calls, stage)
				target := phase == stage || phase == "late-"+stage || (phase == "late-entry" && stage == "private-entry") || (phase == "close" || phase == "owner-cancel") && stage == "dns"
				if target {
					once.Do(func() { close(entered) })
					<-ctx.Done()
					return nil // A late success cannot overrule the original cancellation.
				}
				if phase == "replaced-"+stage || phase == "replaced-entry" && stage == "private-entry" {
					original.current.Store(false)
				}
				return nil
			}
			engine := &externalRunEngine{externalProofFixture: original}
			engine.observe = func(ctx context.Context) (string, error) {
				if phase == "identity" {
					if err := visit(ctx, "identity"); err != nil {
						return "", err
					}
				} else if err := check(ctx); err != nil {
					return "", err
				}
				return original.Identity(), nil
			}
			request.engine = engine
			request.private = func(ctx context.Context) error { return visit(ctx, "private-entry") }
			original.dns = func(ctx context.Context, _ string) error { return visit(ctx, "dns") }
			request.public = func(ctx context.Context, tag, _ string) error {
				if tag != ExternalFinalTag {
					return visit(ctx, "public-entry")
				}
				return visit(ctx, "exit")
			}
			observe := func(ctx context.Context) error {
				if phase == "admission" && len(calls) == 0 {
					return visit(ctx, "admission")
				}
				if phase == "delivery" && request.succeeded.Load() {
					return visit(ctx, "delivery")
				}
				return check(ctx)
			}
			if phase == "cancel-before" {
				cancel()
			}
			type result struct {
				raw string
				err error
			}
			done := make(chan result, 1)
			go func() {
				ctx := context.Context(parent)
				if phase == "nil" {
					ctx = nil
				}
				raw, err := request.RunContext(ctx, observe)
				done <- result{raw, err}
			}()
			held := phase != "success" && phase != "nil" && phase != "cancel-before" && !strings.HasPrefix(phase, "replaced-")
			if held {
				select {
				case <-entered:
				case actual := <-done:
					t.Fatal("proof bypassed original operation callback", actual.err)
				case <-time.After(time.Second):
					cancel()
					<-done
					t.Fatal("proof did not enter its original operation")
				}
				switch phase {
				case "close":
					if err := request.Close(); err != nil {
						t.Fatal("original proof did not join", err)
					}
				case "owner-cancel":
					request.Cancel()
				default:
					cancel()
				}
			}
			var actual result
			select {
			case actual = <-done:
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("proof retained a detached operation worker")
			}
			if engine.legacy.Load() != 0 {
				t.Fatal("proof used legacy identity observations")
			}
			if !successor.Healthy() || len(*successorCalls) != 2 {
				t.Fatal("old operation changed the independent successor")
			}
			if phase == "success" {
				if actual.err != nil || actual.raw == "" || strings.Join(calls, ",") != "private-entry,dns,exit" {
					t.Fatal("original proof did not complete its required path", actual.err, calls)
				}
				cancel()
				engine.observe = func(ctx context.Context) (string, error) { return original.Identity(), ctx.Err() }
				if !request.Healthy() {
					t.Fatal("ended proof caller retired the retained VPN")
				}
			} else {
				if actual.err == nil || actual.raw != "" || request.succeeded.Load() {
					t.Fatal("cancelled or replaced operation published proof", actual.err)
				}
				if held || phase == "cancel-before" {
					if !errors.Is(actual.err, context.Canceled) {
						t.Fatal("original cancellation was lost", actual.err)
					}
				}
				if phase == "nil" || phase == "cancel-before" || phase == "identity" || phase == "admission" {
					for _, call := range calls {
						if call != "identity" && call != "admission" {
							t.Fatal("unadmitted operation started proof traffic", calls)
						}
					}
				}
			}
		})
	}
}

type externalRunRemoteEngine struct {
	*directOpenVPNProofEngine
	read   func(context.Context) (nativeopenvpn.RemoteReceipt, error)
	legacy atomic.Int32
}

func (e *externalRunRemoteEngine) OpenVPNRemote(string) (nativeopenvpn.RemoteReceipt, error) {
	e.legacy.Add(1)
	return nativeopenvpn.RemoteReceipt{}, errors.New("legacy remote cannot authorize proof")
}
func (e *externalRunRemoteEngine) OpenVPNRemoteContext(ctx context.Context, tag string) (nativeopenvpn.RemoteReceipt, error) {
	if tag != ExternalFinalTag {
		return nativeopenvpn.RemoteReceipt{}, errors.New("wrong captured remote tag")
	}
	return e.read(ctx)
}

func TestExternalProofRunOwnsConnectedRemoteObservation(t *testing.T) {
	for _, phase := range []string{"success", "capture-held", "capture-replaced", "readback-held", "readback-replaced", "pending-cancel"} {
		t.Run(phase, func(t *testing.T) {
			request, original, _, _, receipt := directOpenVPNProofFixture(t, "tcp")
			parent, cancel := context.WithCancel(context.WithValue(context.Background(), externalRunKey{}, phase))
			defer cancel()
			entered := make(chan struct{})
			var once sync.Once
			var reads atomic.Int32
			engine := &externalRunRemoteEngine{directOpenVPNProofEngine: original}
			engine.read = func(ctx context.Context) (nativeopenvpn.RemoteReceipt, error) {
				if ctx.Value(externalRunKey{}) != phase {
					return nativeopenvpn.RemoteReceipt{}, errors.New("remote observation detached caller")
				}
				n := reads.Add(1)
				if phase == "capture-held" && n == 1 || phase == "readback-held" && n == 2 {
					once.Do(func() { close(entered) })
					<-ctx.Done()
				}
				if phase == "capture-replaced" && n == 1 {
					original.current.Store(false)
				}
				if phase == "readback-replaced" && n == 2 {
					changed := receipt
					changed.Generation++
					return changed, nil
				}
				if phase == "pending-cancel" {
					once.Do(func() { close(entered) })
					return nativeopenvpn.RemoteReceipt{}, nativeopenvpn.ErrRemotePending
				}
				return receipt, nil
			}
			request.engine = engine
			done := make(chan error, 1)
			go func() { _, err := request.RunContext(parent, nil); done <- err }()
			if strings.HasSuffix(phase, "held") || phase == "pending-cancel" {
				select {
				case <-entered:
					cancel()
				case err := <-done:
					t.Fatal("remote observation bypassed original callback", err)
				case <-time.After(time.Second):
					cancel()
					<-done
					t.Fatal("remote observation was not admitted")
				}
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("original remote observation did not join")
			}
			if engine.legacy.Load() != 0 {
				t.Fatal("proof used detached connected-remote callback")
			}
			if phase == "success" {
				if err != nil || !request.succeeded.Load() || original.dnsCalls.Load() != 1 || original.publicCalls.Load() != 1 {
					t.Fatal("bounded connected-remote proof failed", err)
				}
			} else {
				if err == nil || request.succeeded.Load() || original.dnsCalls.Load() != 0 || original.publicCalls.Load() != 0 {
					t.Fatal("unowned remote reached DNS or exit proof", err)
				}
				if strings.HasPrefix(phase, "capture-") || phase == "pending-cancel" {
					if request.openvpnRemote.Load() != nil {
						t.Fatal("late original remote was adopted after cancellation or replacement")
					}
				}
			}
		})
	}
}

type externalRunCaptureEngine struct {
	*externalExecutionEngine
	observe    func(context.Context) (string, error)
	selections atomic.Int32
}

func (e *externalRunCaptureEngine) IdentityContext(ctx context.Context) (string, error) {
	return e.observe(ctx)
}
func (e *externalRunCaptureEngine) Select(tag string) error {
	e.selections.Add(1)
	return e.externalExecutionEngine.Select(tag)
}
func (e *externalRunCaptureEngine) SelectContext(ctx context.Context, tag string) error {
	e.selections.Add(1)
	return e.externalExecutionEngine.SelectContext(ctx, tag)
}

func TestExternalProofRunCannotAdoptReplacementComparison(t *testing.T) {
	for _, phase := range []string{"before-admission", "during-capture", "caller-ended-capture"} {
		t.Run(phase, func(t *testing.T) {
			request, native := externalExecutionRequest(t, "auto", "")
			parent, cancel := context.WithCancel(context.WithValue(context.Background(), externalRunKey{}, phase))
			defer cancel()
			engine := &externalRunCaptureEngine{externalExecutionEngine: native}
			var reads atomic.Int32
			engine.observe = func(ctx context.Context) (string, error) {
				if ctx.Value(externalRunKey{}) != phase {
					return "", errors.New("comparison replaced original proof caller")
				}
				n := reads.Add(1)
				if phase == "before-admission" || phase == "during-capture" && n >= 2 {
					engine.mu.Lock()
					engine.identity = "replacement-native-owner"
					engine.mu.Unlock()
					return "replacement-native-owner", nil
				}
				if phase == "caller-ended-capture" && n == 2 {
					cancel()
				}
				return request.identity, nil
			}
			request.engine = engine
			raw, err := request.RunContext(parent, nil)
			if err == nil || raw != "" || request.succeeded.Load() || engine.selections.Load() != 0 || len(native.dnsCalls) != 0 || len(native.leaseRequests) != 0 {
				t.Fatal("original proof started a replacement comparison", err, engine.selections.Load())
			}
		})
	}
}

func TestExternalProofRetainedLegacyObservationsKeepBoundedCaller(t *testing.T) {
	for _, phase := range []string{"health", "path", "execution"} {
		t.Run(phase, func(t *testing.T) {
			request, original, _ := externalRequestFixture(t, "")
			if _, err := request.Run(); err != nil {
				t.Fatal(err)
			}
			engine := &externalRunEngine{externalProofFixture: original}
			var reads atomic.Int32
			engine.observe = func(ctx context.Context) (string, error) {
				reads.Add(1)
				deadline, bounded := ctx.Deadline()
				if !bounded || time.Until(deadline) > 1500*time.Millisecond {
					return "", errors.New("retained observation has no original budget")
				}
				<-ctx.Done()
				return "", ctx.Err()
			}
			request.engine = engine
			switch phase {
			case "health":
				if request.Healthy() {
					t.Fatal("timed-out health read returned success")
				}
			case "path":
				if !errors.Is(request.VerifyCurrentPath(), context.DeadlineExceeded) {
					t.Fatal("path read lost its original timeout")
				}
			case "execution":
				if request.Execution() != "" {
					t.Fatal("timed-out execution read returned a selection")
				}
			}
			if reads.Load() != 1 || engine.legacy.Load() != 0 || !request.succeeded.Load() || request.ctx.Err() != nil {
				t.Fatal("expired observer retired the healthy VPN or used legacy callback")
			}
			engine.observe = func(ctx context.Context) (string, error) { return original.Identity(), ctx.Err() }
			if !request.Healthy() {
				t.Fatal("original VPN did not survive expired observation")
			}
		})
	}
}
