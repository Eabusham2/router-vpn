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
	"router-vpn/internal/routechoice"
)

// This fixture retains actual TLS/HTTP public and private proof exchanges. It
// models the native packet owner; encrypted packet/REALITY peer traffic remains
// a separate native acceptance requirement.
type importedPacketXrayProofEngine struct {
	*importedSOCKSXrayProofEngine
	stateMu sync.Mutex
	state   ImportedOpenVPNState
	reads   atomic.Int32
}

func (e *importedPacketXrayProofEngine) ImportedOpenVPNStateContext(ctx context.Context, tag string) (ImportedOpenVPNState, error) {
	if err := ctx.Err(); err != nil {
		return ImportedOpenVPNState{}, err
	}
	if tag != "entry-wg" {
		return ImportedOpenVPNState{}, errors.New("packet REALITY requested a foreign OpenVPN owner")
	}
	e.reads.Add(1)
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	return e.state, ctx.Err()
}

func (e *importedPacketXrayProofEngine) changeState(change func(*ImportedOpenVPNState)) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	change(&e.state)
}

func importedPacketXrayProofFixture(t *testing.T, kind, fault string) (*Controller, *importedPacketXrayProofEngine, *atomic.Int32) {
	t.Helper()
	plan, base, public := importedXraySourceProofFixture(t, importedPacketXrayFixture(t, kind, "aes-256-gcm+xor-whitening", "aes-256-gcm"), fault)
	engine := &importedPacketXrayProofEngine{importedSOCKSXrayProofEngine: base}
	if strings.HasPrefix(kind, "openvpn-") {
		engine.state = ImportedOpenVPNState{Remote: nativeopenvpn.RemoteReceipt{
			Remote:     nativeopenvpn.Remote{Host: "203.0.113.24", Port: 1194, Network: strings.TrimPrefix(kind, "openvpn-")},
			Generation: 1, ConnectedAt: 1700000000000,
		}, MTU: 1500}
	}
	plan.engine = engine
	return plan, engine, public
}

type importedPacketXrayNoDNS struct {
	Engine
	reader *importedPacketXrayProofEngine
}

func (e *importedPacketXrayNoDNS) ImportedOpenVPNStateContext(ctx context.Context, tag string) (ImportedOpenVPNState, error) {
	return e.reader.ImportedOpenVPNStateContext(ctx, tag)
}

func (e *importedPacketXrayNoDNS) IdentityContext(ctx context.Context) (string, error) {
	return e.reader.IdentityContext(ctx)
}

func (e *importedPacketXrayNoDNS) SelectedContext(ctx context.Context) (string, error) {
	return e.reader.SelectedContext(ctx)
}

func TestImportedPacketRealityVisionRequiresBothProofsAndDNS(t *testing.T) {
	for _, kind := range importedPacketXrayKinds {
		t.Run(kind, func(t *testing.T) {
			for _, fault := range []string{"success", "wrong-public-ip", "wrong-paired-final", "dns-failure", "cancel-during-dns", "missing-dns-capability", "changed-owner"} {
				t.Run(fault, func(t *testing.T) {
					plan, engine, public := importedPacketXrayProofFixture(t, kind, fault)
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					switch fault {
					case "dns-failure":
						engine.dnsFailure = errors.New("original selected DNS rejected")
					case "cancel-during-dns":
						engine.afterDNS = cancel
					case "missing-dns-capability":
						plan.engine = &importedPacketXrayNoDNS{Engine: engine, reader: engine}
					case "changed-owner":
						engine.afterDNS = engine.replace
					}
					trial, err := (driver{plan}).Open(ctx, plan.candidate(routechoice.Local))
					if err != nil {
						t.Fatal("original packet path could not capture its native owner", err)
					}
					err = trial.Verify(ctx)
					if fault == "success" {
						if err != nil || public.Load() != 1 || engine.dnsCalls.Load() != 1 || engine.finalCalls.Load() != 1 {
							t.Fatal("packet REALITY lost one of its distinct original proofs", err)
						}
					} else if err == nil {
						t.Fatal("packet REALITY retained a failed, replaced or cancelled proof")
					}
					if public.Load() != 1 {
						t.Fatal("packet REALITY negative did not reach the actual public TLS proof")
					}
					if fault != "success" && fault != "wrong-paired-final" && engine.finalCalls.Load() != 0 {
						t.Fatal("packet REALITY continued final proof after a failed prerequisite")
					}
					if (fault == "wrong-public-ip" || fault == "missing-dns-capability") && engine.dnsCalls.Load() != 0 {
						t.Fatal("packet REALITY manufactured a selected DNS result")
					}
					if strings.HasPrefix(kind, "openvpn-") {
						if engine.reads.Load() < 2 {
							t.Fatal("OpenVPN REALITY did not recheck its original connected remote and capacity")
						}
					} else if engine.reads.Load() != 0 {
						t.Fatal("WG/AWG REALITY borrowed an OpenVPN connection receipt")
					}
				})
			}
		})
	}
}

func TestImportedPacketRealityVisionRetainedRuntime(t *testing.T) {
	for _, kind := range importedPacketXrayKinds {
		t.Run(kind, func(t *testing.T) {
			for _, retirement := range []string{"close", "network-change", "replacement"} {
				t.Run(retirement, func(t *testing.T) {
					plan, engine, public := importedPacketXrayProofFixture(t, kind, "success")
					old := Targets
					Targets = []string{"http://1.1.1.1/check"}
					defer func() { Targets = old }()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := plan.Run(ctx, engine); err != nil {
						t.Fatal("packet REALITY original Local execution failed", err)
					}
					if !plan.Healthy() || engine.Selected() != LocalTag || !plan.progress.Complete || plan.progress.Execution != "local" || public.Load() == 0 || engine.dnsCalls.Load() == 0 || engine.finalCalls.Load() == 0 || engine.externalCalls.Load() == 0 {
						t.Fatal("packet REALITY became ready without the original Local path and all proofs")
					}
					original := &importedSOCKSXrayHopEngine{engine.importedSOCKSXrayProofEngine}
					measurement, err := plan.NewImportedHopMeasurement(original)
					if err != nil {
						t.Fatal("proved packet REALITY owner could not create its own hop measurement", err)
					}
					defer measurement.Close()
					switch retirement {
					case "close":
						if err := plan.Close(); err != nil {
							t.Fatal(err)
						}
					case "network-change":
						plan.NetworkChanged()
					case "replacement":
						engine.replace()
					}
					if plan.Healthy() || plan.MatchesEngine(engine) {
						t.Fatal("retired packet REALITY kept original readiness")
					}
					if _, err := plan.NewImportedHopMeasurement(original); err == nil {
						t.Fatal("retired packet REALITY acquired replacement measurement authority")
					}
					if _, err := (&trial{owner: plan, tag: LocalTag}).ProbeExternal(ctx, "http://1.1.1.1/check"); err == nil {
						t.Fatal("retired packet REALITY admitted another routed probe")
					}
				})
			}
		})
	}
}

func TestImportedPacketRealityVisionOpenVPNConnectedOwner(t *testing.T) {
	for _, kind := range []string{"openvpn-tcp", "openvpn-udp"} {
		t.Run(kind, func(t *testing.T) {
			for _, fault := range []string{"missing-reader", "foreign-host", "foreign-port", "foreign-network", "generation", "connected-at", "mtu-increase", "mtu-decrease"} {
				t.Run(fault, func(t *testing.T) {
					plan, engine, public := importedPacketXrayProofFixture(t, kind, "success")
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					candidate, err := (driver{plan}).Open(ctx, plan.candidate(routechoice.Local))
					if err != nil {
						t.Fatal("original connected OpenVPN capture failed", err)
					}
					engine.afterDNS = func() {
						if fault == "missing-reader" {
							plan.engine = engine.importedSOCKSXrayProofEngine
							return
						}
						engine.changeState(func(state *ImportedOpenVPNState) {
							switch fault {
							case "foreign-host":
								state.Remote.Host = "203.0.113.99"
							case "foreign-port":
								state.Remote.Port++
							case "foreign-network":
								if state.Remote.Network == "tcp" {
									state.Remote.Network = "udp"
								} else {
									state.Remote.Network = "tcp"
								}
							case "generation":
								state.Remote.Generation++
							case "connected-at":
								state.Remote.ConnectedAt++
							case "mtu-increase":
								state.MTU++
							case "mtu-decrease":
								state.MTU--
							}
						})
					}
					if err := candidate.Verify(ctx); err == nil || plan.valid() || plan.Healthy() {
						t.Fatal("REALITY retained a substituted connected OpenVPN owner", err)
					}
					if public.Load() != 1 || engine.dnsCalls.Load() != 1 || engine.finalCalls.Load() != 0 {
						t.Fatal("OpenVPN owner negative did not reject at the original DNS/final proof boundary")
					}
				})
			}
		})
	}
}
