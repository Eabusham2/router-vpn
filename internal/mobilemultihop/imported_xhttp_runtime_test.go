package mobilemultihop

import (
	"context"
	"errors"
	"router-vpn/internal/nativeopenvpn"
	"router-vpn/internal/routechoice"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These tests execute the captured controller, public TLS/private HTTP proofs,
// and cancellation/retirement. The native engine and selected DNS are modeled;
// pinned encrypted peer and DNS wire tests are separate mandatory gates.
func importedXHTTPProofFixture(t *testing.T, kind, fault string) (*Controller, *importedPacketXrayProofEngine, *atomic.Int32) {
	t.Helper()
	plan, base, public := importedXraySourceProofFixture(t, importedXHTTPFixture(t, kind, "aes-256-gcm+xor-whitening", "aes-256-gcm"), fault)
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

func TestImportedXHTTPRequiresBothProofsAndDNS(t *testing.T) {
	for _, kind := range importedPQKinds {
		t.Run(kind, func(t *testing.T) {
			for _, fault := range []string{"success", "wrong-public-ip", "wrong-paired-final", "dns-failure", "cancel-during-dns", "missing-dns-capability", "changed-owner"} {
				t.Run(fault, func(t *testing.T) {
					plan, engine, public := importedXHTTPProofFixture(t, kind, fault)
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
							t.Fatal("imported XHTTP lost one of its distinct original proofs", err)
						}
					} else if err == nil {
						t.Fatal("imported XHTTP retained a failed, replaced or cancelled proof")
					}
					if public.Load() != 1 {
						t.Fatal("imported XHTTP negative did not reach the actual public TLS proof")
					}
					if fault != "success" && fault != "wrong-paired-final" && engine.finalCalls.Load() != 0 {
						t.Fatal("imported XHTTP continued final proof after a failed prerequisite")
					}
					if (fault == "wrong-public-ip" || fault == "missing-dns-capability") && engine.dnsCalls.Load() != 0 {
						t.Fatal("imported XHTTP manufactured a selected DNS result")
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

func TestImportedXHTTPRetainedRuntime(t *testing.T) {
	for _, kind := range importedPQKinds {
		t.Run(kind, func(t *testing.T) {
			for _, retirement := range []string{"close", "network-change", "replacement"} {
				t.Run(retirement, func(t *testing.T) {
					plan, engine, public := importedXHTTPProofFixture(t, kind, "success")
					old := Targets
					Targets = []string{"http://1.1.1.1/check"}
					defer func() { Targets = old }()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := plan.Run(ctx, engine); err != nil {
						t.Fatal("imported XHTTP original Local execution failed", err)
					}
					if !plan.Healthy() || engine.Selected() != LocalTag || !plan.progress.Complete || plan.progress.Execution != "local" || public.Load() == 0 || engine.dnsCalls.Load() == 0 || engine.finalCalls.Load() == 0 || engine.externalCalls.Load() == 0 {
						t.Fatal("imported XHTTP became ready without the original Local path and all proofs")
					}
					original := &importedSOCKSXrayHopEngine{engine.importedSOCKSXrayProofEngine}
					measurement, err := plan.NewImportedHopMeasurement(original)
					if err != nil {
						t.Fatal("proved imported XHTTP owner could not create its own hop measurement", err)
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
						t.Fatal("retired imported XHTTP kept original readiness")
					}
					if _, err := plan.NewImportedHopMeasurement(original); err == nil {
						t.Fatal("retired imported XHTTP acquired replacement measurement authority")
					}
					if _, err := (&trial{owner: plan, tag: LocalTag}).ProbeExternal(ctx, "http://1.1.1.1/check"); err == nil {
						t.Fatal("retired imported XHTTP admitted another routed probe")
					}
				})
			}
		})
	}
}
