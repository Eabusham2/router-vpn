package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/nativeopenvpn"
)

// These controls exercise the shared proof/measurement owner. Native transport
// receipt and DNS/public I/O are explicit test boundaries; the separate native
// OpenVPN Box suites exercise the actual TLS, packets and interface generation.
type directOpenVPNProofEngine struct {
	*externalProofFixture
	remote       atomic.Pointer[nativeopenvpn.RemoteReceipt]
	failed       atomic.Bool
	observations atomic.Int32
	dnsCalls     atomic.Int32
	publicCalls  atomic.Int32
	onObserve    func()
	onDNS        func()
	onPublic     func()
}

func (e *directOpenVPNProofEngine) OpenVPNRemote(tag string) (nativeopenvpn.RemoteReceipt, error) {
	if tag != ExternalFinalTag || e.Identity() == "" {
		return nativeopenvpn.RemoteReceipt{}, errors.New("wrong captured native OpenVPN owner")
	}
	e.observations.Add(1)
	if e.onObserve != nil {
		e.onObserve()
	}
	if e.failed.Load() {
		return nativeopenvpn.RemoteReceipt{}, errors.New("private-native-provider-error")
	}
	if receipt := e.remote.Load(); receipt != nil {
		return *receipt, nil
	}
	return nativeopenvpn.RemoteReceipt{}, nativeopenvpn.ErrRemotePending
}
func (e *directOpenVPNProofEngine) OpenVPNRemoteContext(ctx context.Context, tag string) (nativeopenvpn.RemoteReceipt, error) {
	if err := ctx.Err(); err != nil {
		return nativeopenvpn.RemoteReceipt{}, err
	}
	receipt, err := e.OpenVPNRemote(tag)
	return receipt, errors.Join(err, ctx.Err())
}

func directOpenVPNProofFixture(t *testing.T, network string) (*ExternalProofRequest, *directOpenVPNProofEngine, string, string, nativeopenvpn.RemoteReceipt) {
	t.Helper()
	graph, captured := externalTestFixture(t, "hysteria2", "")
	externalOpenVPNReplace(t, graph, captured, false, network)
	source, capture := externalTestJSON(t, graph), externalTestJSON(t, captured)
	policy, err := NewExternalPolicy(source, capture)
	if err != nil {
		t.Fatal(err)
	}
	external := policy.capture.Profile["external"].(map[string]any)
	if policy.capture.Execution != nil || len(policy.capture.Entry) != 0 ||
		external["response_probe"] != nil || external["openvpn_response_probes"] != nil || external["openvpn_pairing"] != nil {
		t.Fatal("ordinary OpenVPN fixture gained provider comparison authority or a predecessor")
	}
	base := &externalProofFixture{}
	base.current.Store(true)
	engine := &directOpenVPNProofEngine{externalProofFixture: base}
	base.dns = func(ctx context.Context, tag string) error {
		if ctx.Err() != nil || tag != "tun-in" {
			return errors.New("wrong selected DNS owner")
		}
		engine.dnsCalls.Add(1)
		if engine.onDNS != nil {
			engine.onDNS()
		}
		return nil
	}
	base.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("shared owner fixture must not open ambient or public sockets")
	}
	request, err := NewExternalProofRequest(context.Background(), policy, "ordinary-openvpn-proof", engine)
	if err != nil {
		t.Fatal(err)
	}
	request.public = func(ctx context.Context, tag, ip string) error {
		if ctx.Err() != nil || tag != ExternalFinalTag || ip != "203.0.113.88" {
			return errors.New("wrong captured public proof owner")
		}
		engine.publicCalls.Add(1)
		if engine.onPublic != nil {
			engine.onPublic()
		}
		return nil
	}
	t.Cleanup(func() {
		if err := request.Close(); err != nil {
			t.Error("original ordinary proof did not join", err)
		}
	})
	receipt := nativeopenvpn.RemoteReceipt{Remote: nativeopenvpn.Remote{Host: "203.0.113.24", Port: 1194, Network: network},
		Generation: 7, ConnectedAt: time.Now().UnixMilli()}
	return request, engine, source, capture, receipt
}

func TestExternalOpenVPNDirectProofRequiresActualRemoteWithoutResponseProbes(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			request, engine, source, capture, receipt := directOpenVPNProofFixture(t, network)
			if request.openvpnTransport == nil || request.openvpnRemote.Load() != nil || request.Healthy() || request.execution != nil {
				t.Fatal("ordinary imported OpenVPN omitted transport authority or fabricated a connected receipt")
			}
			engine.remote.Store(&receipt)
			raw, err := request.Run()
			var proof ExternalProofResult
			if err != nil || json.Unmarshal([]byte(raw), &proof) != nil || !request.Healthy() || request.Execution() != "" ||
				proof.SessionID != request.session || proof.SourceSHA256 != request.policy.SourceSHA256() ||
				proof.ConfigSHA256 != externalDigest([]byte(request.policy.Config())) || !proof.DNSProven || proof.EntryProven ||
				proof.EntryID != "" || proof.Execution != "" || proof.IP != "203.0.113.88" {
				t.Fatal("ordinary OpenVPN lost its complete proved source or gained comparison state", err)
			}
			captured := request.openvpnRemote.Load()
			if captured == nil || *captured != receipt || engine.observations.Load() < 2 || engine.dnsCalls.Load() != 1 || engine.publicCalls.Load() != 1 {
				t.Fatal("ordinary proof did not capture and recheck its actual native generation")
			}
			if err := request.VerifyCurrentPath(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := request.MTUAuthority(source, capture); err != nil {
				t.Fatal("current native generation lost MTU authority", err)
			}
			if _, _, err := request.DNSMeasurementAuthority(source, capture, request.session); err != nil {
				t.Fatal("current native generation lost selected DNS measurement authority", err)
			}
			measurement, err := request.NewHopMeasurement(source, capture, request.session, engine)
			if err != nil {
				t.Fatal("current native generation lost Speed Lab authority", err)
			}
			if err := measurement.Close(); err != nil {
				t.Fatal(err)
			}
			if engine.dnsCalls.Load() != 1 || engine.publicCalls.Load() != 1 || request.openvpnRemote.Load() != captured {
				t.Fatal("retained authority replayed proof or adopted a different receipt")
			}
		})
	}
}

func TestExternalOpenVPNDirectProofRejectsUnownedOrChangedReceipt(t *testing.T) {
	for _, fault := range []string{"missing-observer", "wrong-host", "wrong-port", "wrong-network", "zero-generation", "zero-connected-at", "observer-error", "DNS-generation", "exit-generation"} {
		t.Run(fault, func(t *testing.T) {
			request, engine, _, _, receipt := directOpenVPNProofFixture(t, "tcp")
			if fault == "missing-observer" {
				unexpected, err := NewExternalProofRequest(context.Background(), request.policy, "missing-observer", engine.externalProofFixture)
				if unexpected != nil {
					_ = unexpected.Close()
				}
				if err == nil || unexpected != nil || engine.dnsCalls.Load() != 0 || engine.publicCalls.Load() != 0 {
					t.Fatal("ordinary import accepted an engine without native remote observation")
				}
				return
			}
			change := func() { next := receipt; next.Generation++; engine.remote.Store(&next) }
			switch fault {
			case "wrong-host":
				receipt.Host = "203.0.113.99"
			case "wrong-port":
				receipt.Port++
			case "wrong-network":
				receipt.Network = "udp"
			case "zero-generation":
				receipt.Generation = 0
			case "zero-connected-at":
				receipt.ConnectedAt = 0
			case "observer-error":
				engine.failed.Store(true)
			case "DNS-generation":
				engine.onDNS = change
			case "exit-generation":
				engine.onPublic = change
			}
			engine.remote.Store(&receipt)
			raw, err := request.Run()
			if err == nil || raw != "" || request.Healthy() || strings.Contains(err.Error(), "private-native-provider-error") {
				t.Fatal("ordinary import accepted a foreign, failed or changed native remote", fault, err)
			}
			wantDNS, wantPublic := int32(0), int32(0)
			if fault == "DNS-generation" || fault == "exit-generation" {
				wantDNS = 1
			}
			if fault == "exit-generation" {
				wantPublic = 1
			}
			if engine.dnsCalls.Load() != wantDNS || engine.publicCalls.Load() != wantPublic {
				t.Fatal("invalid native observation entered a later proof boundary")
			}
		})
	}
}

func TestExternalOpenVPNDirectRetainedOperationsRejectReplacementGeneration(t *testing.T) {
	for _, boundary := range []string{"path", "MTU", "DNS-retest", "Speed-Lab", "fallback", "pending"} {
		t.Run(boundary, func(t *testing.T) {
			request, engine, source, capture, receipt := directOpenVPNProofFixture(t, "tcp")
			engine.remote.Store(&receipt)
			if _, err := request.Run(); err != nil {
				t.Fatal(err)
			}
			captured := request.openvpnRemote.Load()
			next := receipt
			next.Generation++
			if boundary == "fallback" {
				next.Host, next.Port = "2001:db8::24", 443
			}
			engine.remote.Store(&next)
			if boundary == "pending" {
				engine.remote.Store(nil)
			}
			var err error
			switch boundary {
			case "MTU":
				_, _, err = request.MTUAuthority(source, capture)
			case "DNS-retest":
				_, _, err = request.DNSMeasurementAuthority(source, capture, request.session)
			case "Speed-Lab":
				owned := &externalMeasurementEngine{proof: request, engine: engine, identity: engine.Identity()}
				err = owned.VerifyMeasurement(context.Background())
			default:
				err = request.VerifyCurrentPath()
			}
			if err == nil || request.Healthy() || captured == nil || request.openvpnRemote.Load() != captured || *captured != receipt ||
				engine.dnsCalls.Load() != 1 || engine.publicCalls.Load() != 1 {
				t.Fatal("retained operation adopted or reproved a replacement native transport", boundary, err)
			}
		})
	}
}

func TestExternalOpenVPNDirectPendingReceiptCancellationJoinsExactRequest(t *testing.T) {
	request, engine, _, _, _ := directOpenVPNProofFixture(t, "tcp")
	entered, release := make(chan struct{}), make(chan struct{})
	var observed, released sync.Once
	engine.onObserve = func() {
		observed.Do(func() { close(entered) })
		<-release
	}
	// This cleanup precedes the fixture's Close so even a failed assertion
	// releases and joins the actual observation callback, without a leaked wait.
	t.Cleanup(func() { released.Do(func() { close(release) }) })
	type completion struct {
		value string
		err   error
	}
	done := make(chan completion, 1)
	go func() { value, err := request.Run(); done <- completion{value, err} }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary proof did not enter its pending native observation")
	}
	successor, replacement, _, _, receipt := directOpenVPNProofFixture(t, "udp")
	replacement.remote.Store(&receipt)
	if _, err := successor.Run(); err != nil {
		t.Fatal(err)
	}
	request.Cancel()
	closed := make(chan error, 1)
	go func() { closed <- request.Close() }()
	select {
	case err := <-closed:
		t.Fatal("Close returned before its entered native observation joined", err)
	default:
	}
	released.Do(func() { close(release) })
	select {
	case completed := <-done:
		if completed.err == nil || completed.value != "" {
			t.Fatal("cancelled native observation returned a successful proof")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled native observation did not finish")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("original proof teardown did not join")
	}
	if request.Healthy() || request.openvpnRemote.Load() != nil || engine.dnsCalls.Load() != 0 || engine.publicCalls.Load() != 0 ||
		!successor.Healthy() || replacement.dnsCalls.Load() != 1 || replacement.publicCalls.Load() != 1 {
		t.Fatal("pending cancellation adopted a receipt or retired the replacement proof")
	}
}
