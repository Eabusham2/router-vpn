package mobilemultihop

import (
	"context"
	"errors"
	"math"
	"net"
	"sync/atomic"
	"testing"

	"router-vpn/internal/hopmeasure"
)

func nodeChainProofClockFixture(t *testing.T, family string) *NodeChain {
	t.Helper()
	if family == "paired" {
		return nodeChainFixture(t, 3, "")
	}
	chain, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, "wg", "")))
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// The existing engine fixture executes the original authenticated private
// HTTP and imported-middle public TLS proof. Only native route selection is
// doubled. No elapsed value is manufactured or installed-host proof claimed.
func TestNodeChainProofIntervalRetainsBothOriginalPaths(t *testing.T) {
	for _, family := range []string{"paired", "imported"} {
		t.Run(family, func(t *testing.T) {
			chain := nodeChainProofClockFixture(t, family)
			engine := newNodeChainTestEngine(t, chain)
			source, config := chain.SourceSHA256(), chain.ConfigSHA256()
			var captures atomic.Int32
			chain.runtime.testInterval = func() (hopmeasure.Interval, error) {
				captures.Add(1)
				return hopmeasure.StartInterval()
			}
			if err := chain.Run(context.Background(), engine); err != nil {
				t.Fatal(err)
			}
			progress := chain.Progress()
			if !progress.Ready || !progress.Complete || !progress.DNSProven || !progress.PublicProven ||
				len(progress.Prefixes) != len(chain.proofs) || captures.Load() < int32(2*len(chain.proofs)) {
				t.Fatal("checked interval omitted an original routed prefix or second proof pass", progress)
			}
			for i, row := range progress.Prefixes {
				if !row.Proven || row.ProfileID != chain.proofs[i].ProfileID || row.Position != i ||
					row.ResponseMS <= 0 || math.IsNaN(row.ResponseMS) || math.IsInf(row.ResponseMS, 0) {
					t.Fatal("original proof published an invalid elapsed interval", row)
				}
			}
			if family == "imported" && (progress.Prefixes[1].Kind != "public-path" || progress.Prefixes[1].Label == "") {
				t.Fatal("checked interval changed the imported public-proof distinction")
			}
			if chain.SourceSHA256() != source || chain.ConfigSHA256() != config || chain.HealthyContext(context.Background()) != nil {
				t.Fatal("checked interval changed original source or native ownership")
			}
		})
	}
}

func TestNodeChainProofIntervalFailureCannotPublish(t *testing.T) {
	for _, family := range []string{"paired", "imported"} {
		for _, fault := range []string{"capture", "completion", "cancel"} {
			t.Run(family+"/"+fault, func(t *testing.T) {
				chain := nodeChainProofClockFixture(t, family)
				engine := newNodeChainTestEngine(t, chain)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var captures, targetDials atomic.Int32
				engine.beforeDial = func(_ context.Context, tag string) (net.Conn, bool) {
					if tag == chain.proofs[1].Tag {
						targetDials.Add(1)
					}
					return nil, false // Keep the actual original HTTP/TLS route fixture.
				}
				clockFailure := errors.New("original interval capture unavailable")
				chain.runtime.testInterval = func() (hopmeasure.Interval, error) {
					if captures.Add(1) == 2 {
						switch fault {
						case "capture":
							return hopmeasure.Interval{}, clockFailure
						case "completion":
							// A missing captured clock cannot yield an elapsed sample.
							// Same-tick/regression/domain controls live with Interval.
							return hopmeasure.Interval{}, nil
						case "cancel":
							cancel()
						}
					}
					return hopmeasure.StartInterval()
				}
				err := chain.Run(ctx, engine)
				if err == nil {
					t.Fatal("invalid original interval published a completed prefix")
				}
				if fault == "capture" && !errors.Is(err, clockFailure) || fault == "cancel" && ctx.Err() != context.Canceled {
					t.Fatal("proof lost original clock or caller failure", err)
				}
				progress := chain.Progress()
				if captures.Load() != 2 || progress.Ready || !progress.Complete || progress.Stage != "failed" || progress.DNSProven || progress.PublicProven ||
					len(progress.Prefixes) != 1 || chain.HealthyContext(context.Background()) == nil {
					t.Fatal("invalid elapsed proof acquired readiness or a published score", progress)
				}
				row := progress.Prefixes[0]
				if !row.Proven || row.ResponseMS <= 0 || math.IsNaN(row.ResponseMS) || math.IsInf(row.ResponseMS, 0) {
					t.Fatal("failed later interval changed the earlier genuine proof")
				}
				wantDials := int32(0)
				if fault == "completion" {
					wantDials = 1
				}
				if targetDials.Load() != wantDials {
					t.Fatal("clock failure skipped its intended real proof boundary", targetDials.Load(), wantDials)
				}
			})
		}
	}
}
