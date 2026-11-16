package mobilemultihop

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func candidatePreparationOpenVPNSource(t *testing.T, count int, mode, network string) (NodeChainSource, string) {
	t.Helper()
	source := nodeChainOpenVPNPrefixFixture(t, count, mode, network, "")
	target, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	return source, candidateInventoryFixture(t, "original-openvpn-candidate-catalog", target)
}

func TestNodeChainCandidatePreparationOpenVPNKeepsOnlyPacketPrefixes(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, network := range []string{"tcp", "udp"} {
			for _, count := range []int{1, 2, 6} {
				t.Run(fmt.Sprintf("%s/%s/%d", mode, network, count+2), func(t *testing.T) {
					source, inventory := candidatePreparationOpenVPNSource(t, count, mode, network)
					for position := 0; position < count; position++ {
						p, err := NewNodeChainCandidatePreparation(startJSON(t, source), position, inventory)
						if err != nil {
							t.Fatal("saved OpenVPN suffix prevented independent packet prefix", err)
						}
						graph, saved := externalTestRead(t, p.Config()), externalTestRead(t, p.original.Config())
						if !reflect.DeepEqual(graph["inbounds"], saved["inbounds"]) || !reflect.DeepEqual(graph["route"].(map[string]any)["rules"], saved["route"].(map[string]any)["rules"]) {
							t.Fatal("saved device protections changed for prefix preparation")
						}
						if graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag || strings.Contains(p.Config(), "openvpn-client") {
							t.Fatal("prefix preparation constructed OpenVPN or opened application ingress")
						}
						if !reflect.DeepEqual(p.proofs, p.original.proofs[:position+1]) {
							t.Fatal("selected original packet proofs changed")
						}
						for _, proof := range p.original.proofs[position+1:] {
							if strings.Contains(p.Config(), proof.Tag) {
								t.Fatal("unselected suffix acquired runnable authority", proof.Position)
							}
						}
						middle, err := p.original.OpenVPNMiddleCapture()
						if err != nil || strings.Contains(p.Config(), middle.Remote.Host) {
							t.Fatal("saved OpenVPN remote became prefix runtime dependency", err)
						}
						metadata := externalTestRead(t, p.Metadata())
						if metadata["ready"] != false || metadata["application_open"] != false || metadata["dns_open"] != false || metadata["mtu_measurement"] != "configured-bounds-only" {
							t.Fatal("source preparation fabricated live proof or measured MTU")
						}
						physical, err := p.PhysicalEgress()
						if err != nil || !nodeChainSamePhysical(physical, p.original.physical) {
							t.Fatal("saved physical egress changed", err)
						}
						mtu, err := p.MTUPlan()
						if err != nil || len(mtu.Prefixes) != position+1 || mtu.Original > mtu.Ceiling {
							t.Fatal("prefix MTU bounds lost original membership", err)
						}
						replay, err := ParseNodeChainCandidatePreparation(p.Source())
						if err != nil || replay.Config() != p.Config() || replay.CaptureSHA256() != p.CaptureSHA256() {
							t.Fatal("original private prefix source did not round trip", err)
						}
					}
				})
			}
		}
	}
}

func TestNodeChainCandidatePreparationOpenVPNSuffixRemainsOnlyProvenance(t *testing.T) {
	source, inventory := candidatePreparationOpenVPNSource(t, 2, "wg", "tcp")
	original, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
	if err != nil {
		t.Fatal(err)
	}
	otherSource, _ := candidatePreparationOpenVPNSource(t, 2, "wg", "udp")
	// Change only the original, uncontacted imported member. Preserve every
	// packet prefix and the paired final source byte for byte.
	source.Nodes[2] = otherSource.Nodes[2]
	changed, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Config() != original.Config() || changed.SourceSHA256() == original.SourceSHA256() || changed.CaptureSHA256() == original.CaptureSHA256() || changed.OriginalSourceSHA256() == original.OriginalSourceSHA256() {
		t.Fatal("uncontacted OpenVPN provenance was ignored or became a runtime suffix")
	}
	for _, position := range []int{-1, 2, 3, 4} {
		if _, err := NewNodeChainCandidatePreparation(startJSON(t, source), position, inventory); err == nil {
			t.Fatal("OpenVPN, final or foreign position became a packet prefix", position)
		}
	}
	if NodeChainCandidateInputSupported(source.Nodes[2]) {
		t.Fatal("saved OpenVPN acquired a guessed TCP timing target")
	}
	if _, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, candidateInventoryFixture(t, "original-openvpn-candidate-catalog", source.Nodes[2])); err == nil {
		t.Fatal("saved OpenVPN became an unproved candidate endpoint")
	}
	// Identical copied private objects are not the original capture owner.
	copy := *changed.original.openVPNMiddle
	changed.original.openVPNMiddle = &copy
	if changed.Config() != "" || changed.Source() != "" || changed.Metadata() != "" {
		t.Fatal("copied saved OpenVPN owner retained prefix authority")
	}
}

func TestNodeChainCandidatePreparationOpenVPNRuntimeFiftyAndRetirement(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(mode+"/"+network, func(t *testing.T) {
				source, inventory := candidatePreparationOpenVPNSource(t, 6, mode, network)
				p, err := NewNodeChainCandidatePreparation(startJSON(t, source), 5, inventory)
				if err != nil {
					t.Fatal(err)
				}
				runtime, owner := candidatePreparationRuntimeFromSource(t, p)
				if err := runtime.StartContext(t.Context()); err != nil {
					t.Fatal("unreachable saved OpenVPN prevented prefix proofs", err)
				}
				progress := runtime.Progress()
				if !progress.Prepared || progress.ApplicationOpen || progress.DNSOpen || len(progress.Prefixes) != 6 {
					t.Fatal("prepared prefix became a full connection", progress)
				}
				measurement, err := runtime.NewMeasurementContext(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer measurement.Close()
				request := strings.Repeat("d", 32)
				deadline := time.Now().Add(hopmeasure.RequestTimeout)
				if err := measurement.Start(request, p.candidates.targets[0].ID); err != nil {
					t.Fatal(err)
				}
				// Drain bounds one cleanup observation, not the complete fifty.
				// Keep the original worker within its unchanged request deadline.
				for {
					if err := measurement.Drain(request); err == nil {
						break
					}
					if !time.Now().Before(deadline) {
						t.Fatal("original fifty exceeded its request budget", measurement.StatusJSON())
					}
				}
				status := candidateStatus(t, measurement)
				if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || owner.count.Load() != 50 || status.PrefixPosition != 5 || status.Measurement != "routed-tcp-connect" {
					t.Fatal("original packet prefix lost actual fifty TCP connections", status, owner.count.Load())
				}
				if owner.lease.active.Load() || owner.lease.released.Load() != 1 {
					t.Fatal("completed fifty lost its original hold retirement")
				}
				if err := runtime.CloseContext(context.Background()); err != nil {
					t.Fatal(err)
				}
				// The live observer may re-prove the same captured prefix while
				// fifty real connections run. Join it before inspecting its calls;
				// a cancelled last round may end partway through that same order.
				base := owner.nodeChainTestEngine
				base.mu.Lock()
				calls, dns := append([]string(nil), base.calls...), base.dnsCalls
				base.mu.Unlock()
				var expected []string
				for _, proof := range p.proofs {
					expected = append(expected, proof.Tag)
				}
				if len(calls) < len(expected) || dns != 0 || owner.lease.active.Load() || owner.lease.released.Load() != 1 {
					t.Fatal("prefix work reached suffix/DNS or lost original hold", calls, dns)
				}
				for i, tag := range calls {
					if tag != expected[i%len(expected)] {
						t.Fatal("prefix re-proof contacted a foreign or reordered member", calls)
					}
				}
				if runtime.Progress().Prepared || runtime.HealthyContext(t.Context()) == nil {
					t.Fatal("retired OpenVPN saved-prefix preparation retained authority")
				}
			})
		}
	}
}
