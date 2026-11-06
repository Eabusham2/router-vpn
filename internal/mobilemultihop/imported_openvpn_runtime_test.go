package mobilemultihop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"router-vpn/internal/nativeopenvpn"
	"router-vpn/internal/routechoice"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type importedOpenVPNEngineFixture struct {
	*importedProofEngine
	mu                       sync.Mutex
	state                    ImportedOpenVPNState
	failure                  error
	observe                  func(context.Context) error
	onDNS, onFinal, onPublic func()
}

func (e *importedOpenVPNEngineFixture) ImportedOpenVPNStateContext(ctx context.Context, tag string) (ImportedOpenVPNState, error) {
	if tag != "entry-wg" {
		return ImportedOpenVPNState{}, errors.New("foreign observation tag")
	}
	if e.observe != nil {
		if err := e.observe(ctx); err != nil {
			return ImportedOpenVPNState{}, err
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil {
		return ImportedOpenVPNState{}, ctx.Err()
	}
	return e.state, e.failure
}
func (e *importedOpenVPNEngineFixture) change(fn func(*ImportedOpenVPNState)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	fn(&e.state)
}
func (e *importedOpenVPNEngineFixture) DNSProof(ctx context.Context) error {
	if e.onDNS != nil {
		e.onDNS()
	}
	return e.importedProofEngine.DNSProof(ctx)
}
func (e *importedOpenVPNEngineFixture) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	connection, err := e.importedProofEngine.Dial(ctx, tag, address)
	if tag == "entry-wg" && e.onPublic != nil {
		e.onPublic()
	}
	if tag != "entry-wg" && e.onFinal != nil {
		e.onFinal()
	}
	return connection, err
}
func importedOpenVPNRuntimeFixture(t *testing.T, network string) (*Controller, *importedOpenVPNEngineFixture) {
	t.Helper()
	c := importedPacketCompile(t, importedOpenVPNFixture(t, network, "shadowsocks", "", ""))
	certificate, trust := externalPublicProofCertificate(t, "1.1.1.1")
	body := "ip=203.0.113.88\n"
	dial, _, _ := externalPublicProofPeer(t, certificate, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/check" {
			_, _ = w.Write([]byte("actual public probe"))
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+c.meta.ExitToken {
			http.Error(w, "foreign credentials", 403)
			return
		}
		fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":"router-vpn-private-agent-v1"}`, c.meta.ExitNodeID)
	}))
	t.Cleanup(final.Close)
	e := &importedOpenVPNEngineFixture{importedProofEngine: &importedProofEngine{id: "captured-openvpn-owner", selected: LocalTag, public: dial, final: final}, state: ImportedOpenVPNState{Remote: nativeopenvpn.RemoteReceipt{Remote: nativeopenvpn.Remote{Host: "203.0.113.24", Port: 1194, Network: network}, Generation: 1, ConnectedAt: 1700000000000}, MTU: 1500}}
	c.engine, c.engineID, c.externalResponseTLS = e, e.id, trust
	return c, e
}
func TestImportedOpenVPNRequiresOriginalConnectedCapacity(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, fault := range []string{"success", "missing-reader", "pending-cancel", "foreign-host", "foreign-port", "foreign-network", "zero-generation", "zero-connected-at", "small-mtu", "oversized-mtu", "late-cancel", "late-close"} {
			t.Run(network+"/"+fault, func(t *testing.T) {
				c, e := importedOpenVPNRuntimeFixture(t, network)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				switch fault {
				case "missing-reader":
					c.engine = e.importedProofEngine
				case "pending-cancel":
					e.failure = nativeopenvpn.ErrRemotePending
					cancel()
				case "foreign-host":
					e.state.Remote.Host = "203.0.113.99"
				case "foreign-port":
					e.state.Remote.Port++
				case "foreign-network":
					if network == "tcp" {
						e.state.Remote.Network = "udp"
					} else {
						e.state.Remote.Network = "tcp"
					}
				case "zero-generation":
					e.state.Remote.Generation = 0
				case "zero-connected-at":
					e.state.Remote.ConnectedAt = 0
				case "small-mtu":
					e.state.MTU = 1499
				case "oversized-mtu":
					e.state.MTU = 65536
				case "late-cancel":
					e.observe = func(context.Context) error { cancel(); return nil }
				case "late-close":
					e.observe = func(context.Context) error { c.invalidate(); return nil }
				}
				opened, err := (driver{c}).Open(ctx, c.candidate(routechoice.Local))
				if fault != "success" {
					if err == nil {
						t.Fatal("unowned native state created a candidate")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				proof := opened.(*trial)
				if proof.openvpnRemote == nil || *proof.openvpnRemote != e.state.Remote || proof.openvpnEntryMTU != 1500 {
					t.Fatal("candidate did not capture native state")
				}
				if err := proof.Verify(ctx); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestImportedOpenVPNRetiresOriginalTupleAtEveryProofBoundary(t *testing.T) {
	for _, phase := range []string{"public", "dns", "final", "last-node", "external", "measurement", "refresh"} {
		for _, change := range []string{"generation", "connected-at", "remote", "mtu-increase", "mtu-decrease", "mtu-below-capacity", "read-failure"} {
			t.Run(phase+"/"+change, func(t *testing.T) {
				c, e := importedOpenVPNRuntimeFixture(t, "udp")
				// An initial negotiated capacity above the compiled minimum is valid, but
				// neither improvement nor reduction can preserve this captured owner.
				e.state.MTU = 1600
				original := e.state
				proof := &trial{owner: c, tag: LocalTag, openvpnRemote: &original.Remote, openvpnEntryMTU: original.MTU}
				c.progress = Progress{Complete: true, Stage: "selected", Execution: "local"}
				active := &openVPNRemoteState{tag: LocalTag, receipt: original.Remote, entryMTU: original.MTU, deadline: time.Now().Add(time.Minute)}
				c.openvpnActive.Store(active)
				changed := func() {
					e.change(func(s *ImportedOpenVPNState) {
						switch change {
						case "generation":
							s.Remote.Generation++
						case "connected-at":
							s.Remote.ConnectedAt++
						case "remote":
							s.Remote.Host = "203.0.113.99"
						case "mtu-increase":
							s.MTU++
						case "mtu-decrease":
							s.MTU--
						case "mtu-below-capacity":
							s.MTU = 1400
						case "read-failure":
							e.failure = nativeopenvpn.ErrRemotePending
						}
					})
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var err error
				switch phase {
				case "public":
					e.onPublic = changed
					err = proof.Verify(ctx)
				case "dns":
					e.onDNS = changed
					err = proof.Verify(ctx)
				case "final":
					e.onFinal = changed
					err = proof.Verify(ctx)
				case "last-node":
					e.onFinal = changed
					_, err = proof.ProbeLast(ctx)
				case "external":
					old := Targets
					Targets = []string{"http://1.1.1.1/check"}
					defer func() { Targets = old }()
					e.onFinal = changed
					_, err = proof.ProbeExternal(ctx, Targets[0])
				case "measurement":
					input := &importedHopInput{e.importedProofEngine}
					measured := &importedMeasurementEngine{owner: c, engine: input, identity: input.Identity()}
					if err = measured.VerifyMeasurement(ctx); err != nil {
						t.Fatal("original tuple measurement refused", err)
					}
					changed()
					err = measured.VerifyMeasurement(ctx)
				case "refresh":
					changed()
					err = c.VerifyCurrentPath(ctx)
				}
				if err == nil || c.valid() || c.Healthy() {
					t.Fatal("changed original tuple retained proof/measurement authority", err)
				}
			})
		}
	}
}
func TestImportedOpenVPNObservationCancellationJoinsWatch(t *testing.T) {
	c, e := importedOpenVPNRuntimeFixture(t, "tcp")
	state := e.state
	c.progress = Progress{Complete: true, Stage: "selected", Execution: "local"}
	c.openvpnActive.Store(&openVPNRemoteState{tag: LocalTag, receipt: state.Remote, entryMTU: state.MTU, deadline: time.Now().Add(time.Minute)})
	entered, joined := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	e.observe = func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-ctx.Done()
		close(joined)
		return ctx.Err()
	}
	c.watchOpenVPNRemote()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not enter native observation")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("close abandoned native observation")
	}
	if c.Healthy() || c.refreshOpenVPNRemote(c.openvpnActive.Load()) {
		t.Fatal("post-close result acquired authority")
	}
}
func TestImportedOpenVPNRefreshRequiresCapturedCapacity(t *testing.T) {
	c, e := importedOpenVPNRuntimeFixture(t, "udp")
	original := &openVPNRemoteState{tag: LocalTag, receipt: e.state.Remote, entryMTU: 1500, deadline: time.Now().Add(time.Minute)}
	replacement := *original
	replacement.entryMTU = 1600
	c.openvpnActive.Store(&replacement)
	if c.refreshOpenVPNRemote(original) {
		t.Fatal("old capacity refreshed a replacement owner")
	}
}

func (e *importedOpenVPNEngineFixture) IdentityContext(ctx context.Context) (string, error) {
	return e.id, ctx.Err()
}
func (e *importedOpenVPNEngineFixture) SelectedContext(ctx context.Context) (string, error) {
	return e.selected, ctx.Err()
}

func TestImportedOpenVPNMeasurementCancellationPreservesOnlyUnchangedProof(t *testing.T) {
	for _, operation := range []string{"mtu", "hop"} {
		for _, fault := range []string{"cancel", "deadline", "cancel-and-capacity", "cancel-and-generation", "cancel-and-read-failure"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				c, e := importedOpenVPNRuntimeFixture(t, "tcp")
				original := e.state
				c.progress = Progress{Complete: true, Stage: "selected", Execution: "local"}
				c.openvpnActive.Store(&openVPNRemoteState{tag: LocalTag, receipt: original.Remote, entryMTU: original.MTU, deadline: time.Now().Add(time.Minute)})
				if !c.Healthy() {
					t.Fatal("original proof missing")
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if fault == "deadline" {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(context.Background(), time.Millisecond)
					defer stop()
				}
				e.observe = func(observe context.Context) error {
					// Hop Identity does its own fresh health read before the caller-owned
					// reproof. Change/cancel only when the actual measurement context enters.
					if observe != ctx {
						return nil
					}
					if fault == "deadline" {
						<-ctx.Done()
					} else {
						cancel()
					}
					switch fault {
					case "cancel-and-capacity":
						return errors.Join(ctx.Err(), errors.New("observed capacity changed"))
					case "cancel-and-generation":
						return errors.Join(ctx.Err(), errors.New("observed generation changed"))
					case "cancel-and-read-failure":
						return errors.Join(ctx.Err(), nativeopenvpn.ErrRemotePending)
					}
					return ctx.Err()
				}
				var err error
				if operation == "mtu" {
					err = c.VerifyCurrentPath(ctx)
				} else {
					input := &importedHopInput{e.importedProofEngine}
					measured := &importedMeasurementEngine{owner: c, engine: input, identity: input.Identity()}
					err = measured.VerifyMeasurement(ctx)
				}
				e.observe = nil
				if err == nil {
					t.Fatal("cancelled measurement produced proof")
				}
				if fault == "cancel" || fault == "deadline" {
					if !c.Healthy() || !c.valid() {
						t.Fatal("cancelled observation retired unchanged established path", err)
					}
					active := c.openvpnActive.Load()
					if active.receipt != original.Remote || active.entryMTU != original.MTU {
						t.Fatal("cancellation recaptured a replacement tuple")
					}
				} else if c.valid() || c.Healthy() {
					t.Fatal("context hid independently witnessed authority loss", err)
				}
			})
		}
	}
}

func TestImportedOpenVPNLayeredReceiptKeepsOriginalPublicOwner(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(network+"/"+layer, func(t *testing.T) {
				c := importedPacketCompile(t, importedOpenVPNFixture(t, network, "shadowsocks", layer, ""))
				e := &importedOpenVPNEngineFixture{importedProofEngine: &importedProofEngine{id: "layered-original", selected: LocalTag}, state: ImportedOpenVPNState{Remote: nativeopenvpn.RemoteReceipt{Remote: nativeopenvpn.Remote{Host: "203.0.113.24", Port: 1194, Network: network}, Generation: 1, ConnectedAt: 1700000000000}, MTU: 1500}}
				c.engine, c.engineID = e, e.id
				if _, err := c.readImportedOpenVPN(context.Background()); err != nil {
					t.Fatal("captured public receipt rejected", err)
				}
				e.state.Remote.Host = "10.93.0.1"
				if _, err := c.readImportedOpenVPN(context.Background()); err == nil {
					t.Fatal("private inner tuple substituted for original public owner")
				}
			})
		}
	}
}

func TestImportedOpenVPNMultipleReceiptOwnersRemainExact(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, mapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mapped-%v", layer, mapped), func(t *testing.T) {
				args := importedOpenVPNFixture(t, "udp", "shadowsocks", layer, "")
				graph, capture := externalTestRead(t, args[0]), externalTestRead(t, args[1])
				profile := capture["profile"].(map[string]any)
				external := profile["external"].(map[string]any)
				transport := external["openvpn"].(map[string]any)
				second := "203.0.113.24"
				if mapped {
					second = "203.0.113.25"
				}
				transport["config"] = transport["config"].(string) + "remote " + second + " 443 tcp\n"
				compiled, err := nativeopenvpn.CompileProfile(nativeopenvpn.Profile{Config: transport["config"].(string), Username: transport["username"].(string), Password: transport["password"].(string)}, ExternalFinalTag, "")
				if err != nil {
					t.Fatal(err)
				}
				graph["endpoints"] = []any{compiled}
				if mapped {
					first := external["start_layer"].(map[string]any)
					secondLayer := externalTestRead(t, externalTestJSON(t, first))
					secondLayer["transport"].(map[string]any)["server"] = second
					secondLayer["transport"].(map[string]any)["password"] = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s="
					delete(external, "start_layer")
					delete(external, "response_probe")
					external["openvpn_response_probes"] = map[string]any{"203.0.113.24": map[string]any{"url": "https://203.0.113.24/response"}, second: map[string]any{"url": "https://" + second + "/response"}}
					external["openvpn_start_layers"] = map[string]any{"203.0.113.24": first, second: secondLayer}
				}
				args[0], args[1] = externalTestJSON(t, graph), externalTestJSON(t, capture)
				c := importedPacketCompile(t, args)
				remotes, err := nativeopenvpn.Remotes(c.imported.openvpnTransport)
				if err != nil || len(remotes) != 2 {
					t.Fatal("complete remote mapping lost", err)
				}
				e := &importedOpenVPNEngineFixture{importedProofEngine: &importedProofEngine{id: "multiple-original", selected: LocalTag}, state: ImportedOpenVPNState{MTU: c.imported.openvpnMTU}}
				c.engine, c.engineID = e, e.id
				for _, remote := range remotes {
					e.state.Remote = nativeopenvpn.RemoteReceipt{Remote: remote, Generation: 2, ConnectedAt: 1700000000000}
					if _, err := c.readImportedOpenVPN(context.Background()); err != nil {
						t.Fatal("captured remote rejected", remote, err)
					}
				}
				if !mapped && (remotes[0].Host != "203.0.113.24" || remotes[1].Host != "203.0.113.24") {
					t.Fatal("single-host layer did not retain original public remotes")
				}
				for _, host := range []string{"10.93.0.99", "198.51.100.99"} {
					e.state.Remote.Host = host
					if _, err := c.readImportedOpenVPN(context.Background()); err == nil {
						t.Fatal("foreign private/public tuple acquired authority", host)
					}
				}
			})
		}
	}
}
