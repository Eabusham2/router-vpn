package mobilemultihop

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The shared owned-pipe fixture exercises real public TLS/HTTP and private
// proof requests. Actual CONNECT authentication, TLS and REALITY traffic remain
// separate native-peer requirements.
func TestImportedCONNECTRealityVisionRequiresBothProofsAndDNS(t *testing.T) {
	for _, kind := range []string{"http-connect", "https-connect"} {
		t.Run(kind, func(t *testing.T) {
			for _, fault := range []string{"success", "wrong-public-ip", "wrong-paired-final", "dns-failure", "cancel-during-dns", "missing-dns-capability", "changed-owner"} {
				t.Run(fault, func(t *testing.T) {
					plan, engine, public := importedXraySourceProofFixture(t, importedCONNECTXrayFixture(t, kind, "aes-256-gcm+xor-whitening", "aes-256-gcm"), fault)
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					switch fault {
					case "dns-failure":
						engine.dnsFailure = errors.New("original selected DNS rejected")
					case "cancel-during-dns":
						engine.afterDNS = cancel
					case "missing-dns-capability":
						plan.engine = &importedNoDNS{Engine: engine}
					case "changed-owner":
						engine.afterDNS = engine.replace
					}
					err := (&trial{owner: plan, tag: LocalTag}).Verify(ctx)
					if fault == "success" {
						if err != nil || public.Load() != 1 || engine.dnsCalls.Load() != 1 || engine.finalCalls.Load() != 1 {
							t.Fatal("CONNECT REALITY lost one of its distinct original proofs", err)
						}
					} else if err == nil {
						t.Fatal("CONNECT REALITY retained a failed or cancelled proof")
					}
					if public.Load() != 1 {
						t.Fatal("CONNECT REALITY negative did not reach the actual public TLS proof")
					}
					if fault != "success" && fault != "wrong-paired-final" && engine.finalCalls.Load() != 0 {
						t.Fatal("CONNECT REALITY continued final proof after a failed original prerequisite")
					}
					if (fault == "wrong-public-ip" || fault == "missing-dns-capability") && engine.dnsCalls.Load() != 0 {
						t.Fatal("CONNECT REALITY manufactured a selected DNS result")
					}
				})
			}
		})
	}
}
func TestImportedCONNECTRealityVisionRetainedRuntime(t *testing.T) {
	for _, kind := range []string{"http-connect", "https-connect"} {
		t.Run(kind, func(t *testing.T) {
			for _, retirement := range []string{"close", "network-change", "replacement"} {
				t.Run(retirement, func(t *testing.T) {
					plan, engine, public := importedXraySourceProofFixture(t, importedCONNECTXrayFixture(t, kind, "aes-256-gcm", "aes-256-gcm+xor-whitening"), "success")
					old := Targets
					Targets = []string{"http://1.1.1.1/check"}
					defer func() { Targets = old }()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := plan.Run(ctx, engine); err != nil {
						t.Fatal("CONNECT REALITY original Local execution failed", err)
					}
					if !plan.Healthy() || engine.Selected() != LocalTag || !plan.progress.Complete || plan.progress.Execution != "local" || public.Load() == 0 || engine.dnsCalls.Load() == 0 || engine.finalCalls.Load() == 0 || engine.externalCalls.Load() == 0 {
						t.Fatal("CONNECT REALITY became ready without its original Local path and proofs")
					}
					original := &importedSOCKSXrayHopEngine{engine}
					measurement, err := plan.NewImportedHopMeasurement(original)
					if err != nil {
						t.Fatal("proved CONNECT REALITY owner could not create its own hop measurement", err)
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
						t.Fatal("retired CONNECT REALITY graph kept original readiness")
					}
					if _, err := plan.NewImportedHopMeasurement(original); err == nil {
						t.Fatal("retired CONNECT REALITY graph acquired replacement measurement authority")
					}
					if _, err := (&trial{owner: plan, tag: LocalTag}).ProbeExternal(ctx, "http://1.1.1.1/check"); err == nil {
						t.Fatal("retired CONNECT REALITY graph admitted another routed probe")
					}
				})
			}
		})
	}
}
