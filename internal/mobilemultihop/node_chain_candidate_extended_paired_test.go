package mobilemultihop

import (
	"context"
	"router-vpn/internal/hopmeasure"
	"strings"
	"testing"
	"time"
)

func TestNodeChainExtendedCandidatePacketAuthority(t *testing.T) {
	source := extendedPairedFixture(t, 16, 3000)
	input := startJSON(t, source)
	chain, err := NewNodeChain(input)
	if err != nil {
		t.Fatal(err)
	}
	position := 8
	inv := candidateInventoryFixture(t, "deep-original", source.Nodes[len(source.Nodes)-1])
	plan, err := chain.NewCandidatePlan(position, inv)
	if err != nil || plan.PacketCandidateDepth(position, chain.proofs[position].ProfileID, chain.proofs[position].Tag) != 16 {
		t.Fatal("deep plan", err)
	}
	if plan.PacketCandidateDepth(position, "borrowed", chain.proofs[position].Tag) != 0 {
		t.Fatal("foreign original position accepted")
	}
	prep, err := NewNodeChainCandidatePreparation(input, position, inv)
	if err != nil || prep.ExtendedPacketDepth() != 16 || len(prep.mtu.Prefixes) != position+1 {
		t.Fatal("closed deep packet bounds", err)
	}
	runtime, owner := candidatePreparationRuntimeFromSource(t, prep)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err = runtime.StartContext(ctx); err != nil {
		t.Fatal("deep prefix proof", err)
	}
	legacy := hopmeasure.CandidatePrefix{Position: position, ID: plan.prefix.ProfileID, Tag: plan.prefix.Tag, CaptureSHA256: prep.capture}
	if value, err := hopmeasure.NewCapturedPrefixCandidatesContext(ctx, runtime, legacy, plan.targets, NodeChainInputLimit); err == nil || value != nil {
		t.Fatal("plain integer acquired deep capability")
	}
	service, err := runtime.NewMeasurementContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	request := strings.Repeat("e", 32)
	if err := service.StartContext(ctx, request, plan.targets[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := service.Drain(request); err != nil {
		t.Fatal(err)
	}
	status := candidateStatus(t, service)
	if !status.Drained || status.PrefixPosition != position || len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark.Distribution.Samples != 50 ||
		owner.count.Load() != 50 || status.Measurement != hopmeasure.CandidateTCPMeasurement {
		t.Fatal("50 complete attributable deep handshakes required", status)
	}
}
