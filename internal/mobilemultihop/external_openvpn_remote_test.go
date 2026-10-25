package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

func externalOpenVPNMappedExecutionFixture(t *testing.T) (string, string) {
	t.Helper()
	source, capture := externalOpenVPNExecutionFixture(t, "auto", "")
	graph, captured := externalTestRead(t, source), externalTestRead(t, capture)
	external := captured["profile"].(map[string]any)["external"].(map[string]any)
	original := external["openvpn"].(map[string]any)
	original["config"] = strings.Replace(original["config"].(string), "203.0.113.20 443", "203.0.113.21 443", 1)
	public, err := multihoprelay.ExternalOpenVPNServerDescriptor(externalOpenVPNServerProfile(t, external))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(public)
	var descriptor map[string]any
	if json.Unmarshal(raw, &descriptor) != nil {
		t.Fatal("descriptor")
	}
	external["openvpn_pairing"].(map[string]any)["server"] = descriptor
	delete(external, "response_probe")
	external["openvpn_response_probes"] = map[string]any{
		"203.0.113.20": map[string]any{"url": "https://203.0.113.20/first-response", "server_name": "example.com"},
		"203.0.113.21": map[string]any{"url": "https://203.0.113.21:9443/second-response", "server_name": "example.com"},
	}
	endpoint, err := nativeopenvpn.CompileProfile(nativeopenvpn.Profile{Config: original["config"].(string), Username: original["username"].(string), Password: original["password"].(string)}, ExternalFinalTag, "entry-wg")
	if err != nil {
		t.Fatal(err)
	}
	graph["endpoints"] = []any{externalTestFind(t, graph, "entry-wg"), endpoint}
	return externalTestJSON(t, graph), externalTestJSON(t, captured)
}

func mappedOpenVPNTargets(t *testing.T) {
	t.Helper()
	old := Targets
	Targets = []string{"http://1.1.1.1/public-a", "http://1.0.0.1/public-b"}
	t.Cleanup(func() { Targets = old })
}
func mappedOpenVPNChange(e *externalExecutionEngine, tag string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	receipt := e.remotes[tag]
	receipt.Generation++
	e.remotes[tag] = receipt
}

func TestOpenVPNMappedComparisonUsesEachActualRemoteAndRestoresProvedExecution(t *testing.T) {
	mappedOpenVPNTargets(t)
	for _, restored := range []string{"", "local", "server"} {
		t.Run(restored, func(t *testing.T) {
			source, capture := externalOpenVPNMappedExecutionFixture(t)
			r, e := externalExecutionCapturedRequest(t, source, capture, restored)
			if _, err := r.Run(); err != nil {
				t.Fatal(err, r.ProgressJSON())
			}
			expected := restored
			if expected == "" {
				expected = "server"
			}
			if !r.Healthy() || r.Execution() != expected {
				t.Fatal("wrong retained execution", r.ProgressJSON())
			}
			e.mu.Lock()
			before := e.remoteQueries
			for tag, addresses := range e.nodeDials {
				want := "203.0.113.20:443"
				if tag == ServerTag {
					want = "203.0.113.21:9443"
				}
				for _, address := range addresses {
					if address != want {
						e.mu.Unlock()
						t.Fatal("probe ignored actual remote", tag, address)
					}
				}
			}
			if restored == "" {
				local, server := e.probeTargets[LocalTag], e.probeTargets[ServerTag]
				if len(local) != 2 || len(server) != 5 || local[1] != server[1] || server[1] != server[3] {
					e.mu.Unlock()
					t.Fatal("Compare changed its one external endpoint", local, server)
				}
			}
			e.mu.Unlock()
			if err := r.VerifyCurrentPath(); err != nil {
				t.Fatal(err)
			}
			e.mu.Lock()
			after := e.remoteQueries
			e.mu.Unlock()
			if expected == "server" && after <= before {
				t.Fatal("retained Server check used a cached receipt")
			}
			if restored == "" {
				var progress Progress
				if json.Unmarshal([]byte(r.ProgressJSON()), &progress) != nil || len(progress.Measurements) != 2 {
					t.Fatal("missing comparison evidence")
				}
				for _, row := range progress.Measurements {
					if !row.Eligible || row.ScoreMS == nil || *row.ScoreMS != (row.LastNodeMS+row.ExternalMS)/2 {
						t.Fatal("candidate average formula changed")
					}
				}
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpenVPNMappedGenerationChangeDisqualifiesEachProofBoundary(t *testing.T) {
	mappedOpenVPNTargets(t)
	for _, phase := range []string{"DNS", "last node", "external", "winner repetition"} {
		t.Run(phase, func(t *testing.T) {
			source, capture := externalOpenVPNMappedExecutionFixture(t)
			restored := "server"
			if phase == "winner repetition" {
				restored = ""
			}
			r, e := externalExecutionCapturedRequest(t, source, capture, restored)
			switch phase {
			case "DNS":
				e.onDNS = func(tag string) { mappedOpenVPNChange(e, tag) }
			case "last node":
				e.onNode = func(tag string) { mappedOpenVPNChange(e, tag) }
			case "external":
				e.onPublic = func(tag string) {
					e.mu.Lock()
					count := len(e.probeTargets[tag])
					e.mu.Unlock()
					if count == 2 {
						mappedOpenVPNChange(e, tag)
					}
				}
			case "winner repetition":
				e.onNode = func(tag string) {
					e.mu.Lock()
					count := e.nodeCalls[tag]
					e.mu.Unlock()
					if tag == ServerTag && count == 2 {
						mappedOpenVPNChange(e, tag)
					}
				}
			}
			value, err := r.Run()
			if phase == "winner repetition" {
				// Compare may retain its other fully re-proved candidate when
				// the lower first score becomes invalid during repetition.
				if err != nil || value == "" || !r.Healthy() || r.Execution() != "local" {
					t.Fatal("failed winner reused or valid fallback lost", err, r.ProgressJSON())
				}
			} else if err == nil || value != "" || r.Healthy() {
				t.Fatal("changed remote generation produced a result", phase, r.ProgressJSON())
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			for _, process := range e.runner.processes {
				if process.Alive() {
					t.Fatal("failed candidate retained provider lease")
				}
			}
		})
	}
}

func TestOpenVPNMappedRetainedMeasurementsRequireFreshRemoteAndCannotAdoptNewGeneration(t *testing.T) {
	mappedOpenVPNTargets(t)
	for _, boundary := range []string{"retained path", "MTU", "Speed Lab", "DNS Retest"} {
		t.Run(boundary, func(t *testing.T) {
			source, capture := externalOpenVPNMappedExecutionFixture(t)
			r, e := externalExecutionCapturedRequest(t, source, capture, "server")
			if _, err := r.Run(); err != nil {
				t.Fatal(err)
			}
			// No sleep: the next operation must reject before the background watcher runs.
			mappedOpenVPNChange(e, ServerTag)
			var err error
			switch boundary {
			case "retained path":
				err = r.VerifyCurrentPath()
			case "MTU":
				_, _, err = r.MTUAuthority(source, externalTestJSON(t, r.policy.capture))
			case "Speed Lab":
				owned := &externalMeasurementEngine{proof: r, engine: e, identity: e.Identity()}
				err = owned.VerifyMeasurement(context.Background())
			case "DNS Retest":
				_, _, err = r.DNSMeasurementAuthority(source, externalTestJSON(t, r.policy.capture), r.session)
			}
			if err == nil || r.Healthy() {
				t.Fatal("measurement adopted the replacement OpenVPN generation")
			}
		})
	}
}

func TestOpenVPNMappedServerRequiresFreshRemoteCapabilityBeforeLeaseMutation(t *testing.T) {
	mappedOpenVPNTargets(t)
	for _, capability := range []string{"missing", "cached-connected-transport-v0", "fresh-connected-transport-v2"} {
		t.Run(capability, func(t *testing.T) {
			source, capture := externalOpenVPNMappedExecutionFixture(t)
			r, e := externalExecutionCapturedRequest(t, source, capture, "server")
			e.badOpenVPNCapability = capability
			if result, err := r.Run(); err == nil || result != "" || r.Healthy() {
				t.Fatal("Server accepted an absent or unsupported connected-remote contract")
			}
			e.mu.Lock()
			mutations := len(e.leaseRequests)
			e.mu.Unlock()
			if mutations != 0 || len(e.runner.processes) != 0 {
				t.Fatal("unsupported remote contract opened a provider lease")
			}
		})
	}
}

type ordinaryOpenVPNRemoteEngine struct {
	*externalProofFixture
	remote atomic.Pointer[nativeopenvpn.RemoteReceipt]
}

func (e *ordinaryOpenVPNRemoteEngine) OpenVPNRemote(tag string) (nativeopenvpn.RemoteReceipt, error) {
	if tag != ExternalFinalTag || e.Identity() == "" {
		return nativeopenvpn.RemoteReceipt{}, errors.New("wrong ordinary OpenVPN owner")
	}
	if value := e.remote.Load(); value != nil {
		return *value, nil
	}
	return nativeopenvpn.RemoteReceipt{}, nativeopenvpn.ErrRemotePending
}

func TestOpenVPNMappedOrdinaryLocalRetainsActualRemoteWithoutCreatingSelector(t *testing.T) {
	for _, boundary := range []string{"retained", "DNS", "exit", "wrong remote", "missing observer"} {
		t.Run(boundary, func(t *testing.T) {
			source, capture := externalOpenVPNMappedExecutionFixture(t)
			captured := externalTestRead(t, capture)
			captured["profile"].(map[string]any)["multihop_execution"] = "local"
			policy, err := NewExternalPolicy(source, externalTestJSON(t, captured))
			if err != nil || policy.capture.Execution != nil {
				t.Fatal("ordinary Local gained comparison machinery", err)
			}
			base := &externalProofFixture{}
			base.current.Store(true)
			e := &ordinaryOpenVPNRemoteEngine{externalProofFixture: base}
			receipt := nativeopenvpn.RemoteReceipt{Remote: nativeopenvpn.Remote{Host: "203.0.113.21", Port: 443, Network: "tcp"}, Generation: 7, ConnectedAt: time.Now().UnixMilli()}
			if boundary == "wrong remote" {
				receipt.Host = "203.0.113.22"
			}
			e.remote.Store(&receipt)
			if boundary == "missing observer" {
				if _, err := NewExternalProofRequest(context.Background(), policy, "local-session", base); err == nil {
					t.Fatal("ordinary mapped Local accepted an unobservable native endpoint")
				}
				return
			}
			r, err := NewExternalProofRequest(context.Background(), policy, "local-session", e)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
			change := func() { current := *e.remote.Load(); current.Generation++; e.remote.Store(&current) }
			r.private = func(context.Context) error { return nil }
			base.dns = func(context.Context, string) error {
				if boundary == "DNS" {
					change()
				}
				return nil
			}
			r.public = func(context.Context, string, string) error {
				if boundary == "exit" {
					change()
				}
				return nil
			}
			result, err := r.Run()
			if boundary == "retained" {
				if err != nil || result == "" || !r.Healthy() || r.Execution() != "" || r.VerifyCurrentPath() != nil {
					t.Fatal("ordinary Local native generation was not proved", err)
				}
				change()
				if r.Healthy() || r.VerifyCurrentPath() == nil {
					t.Fatal("ordinary Local retained a replacement transport generation")
				}
			} else if err == nil || result != "" || r.Healthy() {
				t.Fatal("unproved or changed ordinary remote became Connected")
			}
		})
	}
}

func TestOpenVPNMappedFreshStatusCancellationDrainsOwnedLease(t *testing.T) {
	mappedOpenVPNTargets(t)
	source, capture := externalOpenVPNMappedExecutionFixture(t)
	r, e := externalExecutionCapturedRequest(t, source, capture, "server")
	if _, err := r.Run(); err != nil {
		t.Fatal(err)
	}
	reached := make(chan struct{})
	var once sync.Once
	e.mu.Lock()
	e.onRemote = func(ctx context.Context, tag string) {
		if tag == ServerTag {
			once.Do(func() { close(reached) })
			<-ctx.Done()
		}
	}
	e.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- r.VerifyCurrentPath() }()
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("fresh status did not enter owned request")
	}
	r.Cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled status accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("status cancellation did not propagate")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if r.Healthy() {
		t.Fatal("cancelled owner remained healthy")
	}
	for _, p := range e.runner.processes {
		if p.Alive() {
			t.Fatal("cancelled status retained provider session")
		}
	}
}

func TestOpenVPNMappedWatchPreservesConcurrentFreshMeasurementOfSameGeneration(t *testing.T) {
	mappedOpenVPNTargets(t)
	source, capture := externalOpenVPNMappedExecutionFixture(t)
	r, e := externalExecutionCapturedRequest(t, source, capture, "server")
	if _, err := r.Run(); err != nil {
		t.Fatal(err)
	}
	c := r.execution
	initial := c.openvpnActive.Load()
	captured := &openVPNRemoteState{tag: initial.tag, receipt: initial.receipt, deadline: time.Now().Add(time.Second)}
	c.openvpnActive.Store(captured)
	entered, release := make(chan struct{}), make(chan struct{})
	var once atomic.Bool
	e.mu.Lock()
	e.onRemoteResponse = func(ctx context.Context) {
		if once.CompareAndSwap(false, true) {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	}
	e.mu.Unlock()
	defer close(release)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("native watch did not enter its owned status read")
	}
	if err := r.VerifyCurrentPath(); err != nil {
		t.Fatal("concurrent fresh native query failed", err)
	}
	refreshed := c.openvpnActive.Load()
	if refreshed == captured || refreshed.receipt != captured.receipt || !refreshed.deadline.After(captured.deadline) {
		t.Fatal("fresh measurement did not extend its exact proved generation")
	}
	// Release the older watch only after its captured deadline. This is tied
	// to that deadline and the actual blocked query, not to a scheduler guess.
	timer := time.NewTimer(time.Until(captured.deadline.Add(time.Millisecond)))
	defer timer.Stop()
	<-timer.C
	release <- struct{}{}
	deadline := time.After(time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for c.openvpnActive.Load() == refreshed && r.Healthy() {
		select {
		case <-deadline:
			t.Fatal("older watch did not finish its private query")
		case <-tick.C:
		}
	}
	if !r.Healthy() || c.openvpnActive.Load().receipt != captured.receipt {
		t.Fatal("older watch invalidated the same freshly proved transport")
	}
	// The same overlap rule cannot revive an actually expired current owner.
	expired := &openVPNRemoteState{tag: captured.tag, receipt: captured.receipt, deadline: time.Now().Add(-time.Second)}
	c.openvpnActive.Store(expired)
	if c.refreshOpenVPNRemote(captured) {
		t.Fatal("expired current receipt was revived")
	}
}
