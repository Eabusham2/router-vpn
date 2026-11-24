package mobilemultihop

import (
	"router-vpn/internal/hopmeasure"
	"strings"
	"testing"
)

func responsePlanFixture(t *testing.T) (*NodeChainCandidatePlan, *NodeChainCandidatePreparation) {
	t.Helper()
	graph := nodeChainImportedSSPrefixFixture(t, 1, "wg", NativeStartLayerMethod, false)
	return responsePlanFromFixture(t, graph, 1)
}
func responsePlanFromFixture(t *testing.T, graph NodeChainSource, position int) (*NodeChainCandidatePlan, *NodeChainCandidatePreparation) {
	t.Helper()
	src := startJSON(t, graph)
	chain, err := NewNodeChain(src)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := candidateSourceFixture(t, "paired", NativeStartLayerMethod)
	inventory := candidateInventoryFixture(t, "paired-private-response-catalog-1", candidate)
	p, err := chain.NewCandidatePlan(position, inventory)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := NewNodeChainCandidatePreparation(src, position, inventory)
	if err != nil {
		t.Fatal(err)
	}
	return p, prep
}

func TestNodeChainExtendedImportedResponseCandidateScope(t *testing.T) {
	for _, count := range []int{9, 16} {
		selected := count - 2
		graph := nodeChainMultipleImportedFixture(t, extendedSelectedLayout(count), "wg", "")
		plan, prep := responsePlanFromFixture(t, graph, selected)
		if plan.measurement != hopmeasure.CandidatePrivateResponseMeasurement || plan.ResponseCandidateDepth(selected, plan.prefix.ProfileID, plan.prefix.Tag) != count || prep.ExtendedCandidateDepth() != count || prep.ExtendedPacketDepth() != 0 || len(prep.mtu.Prefixes) != selected+1 {
			t.Fatal("extended response lost its original full source, closed MTU or stream proof", count)
		}
		if plan.ResponseCandidateDepth(selected, "foreign", plan.prefix.Tag) != 0 || plan.ResponseCandidateDepth(selected-1, plan.prefix.ProfileID, plan.prefix.Tag) != 0 || plan.PacketCandidateDepth(selected, plan.prefix.ProfileID, plan.prefix.Tag) != 0 {
			t.Fatal("extended response was transferable to another prefix or measurement", count)
		}
		reopened, err := ParseNodeChainMultipleImportedCandidatePreparation(prep.Source())
		if err != nil || reopened.CaptureSHA256() != prep.CaptureSHA256() || reopened.ExtendedCandidateDepth() != count {
			t.Fatal("closed extended response did not replay exact original", count, err)
		}
		if count == 16 {
			interior, closed := responsePlanFromFixture(t, graph, 8)
			if interior.ResponseCandidateDepth(8, interior.prefix.ProfileID, interior.prefix.Tag) != count || closed.ExtendedCandidateDepth() != count {
				t.Fatal("interior position failed complete original qualification")
			}
			// The next original member is outside this measured prefix, but
			// remains part of the original connected and closed source seals.
			interior.chain.importedSSMemberAt(10).input += " "
			closed.original.importedSSMemberAt(10).input += " "
			if interior.validate() == nil || closed.validate() == nil || interior.ResponseCandidateDepth(8, interior.prefix.ProfileID, interior.prefix.Tag) != 0 || closed.ExtendedCandidateDepth() != 0 {
				t.Fatal("replaced later original source retained a score capability")
			}
		}
		plan.prefix.Tag = "changed"
		if plan.ResponseCandidateDepth(selected, plan.prefix.ProfileID, plan.prefix.Tag) != 0 {
			t.Fatal("replaced original prefix retained extended stream authority")
		}
	}
}

func TestNodeChainPrivateCandidateResponseSource(t *testing.T) {
	p, prep := responsePlanFixture(t)
	a := p.chain
	if a.CandidatePrefixMeasurement(0) != hopmeasure.CandidateTCPMeasurement || a.CandidatePrefixMeasurement(1) != hopmeasure.CandidatePrivateResponseMeasurement || a.CandidatePrefixMeasurement(2) != "" {
		t.Fatal("prefix metric is not original-position specific")
	}
	if len(prep.proofs) != 2 || len(prep.ImportedPrefixProofs()) != 1 || len(prep.mtu.Prefixes) != 2 || prep.proofs[1] != p.prefix || !strings.Contains(prep.Metadata(), hopmeasure.CandidatePrivateResponseMeasurement) || !strings.Contains(p.Metadata(), hopmeasure.CandidatePrivateResponseMeasurement) {
		t.Fatal("incomplete original closed purpose")
	}
	for _, platform := range []string{"linux", "windows", "darwin"} {
		policy, err := NewDesktopNodeCandidatePreparationPolicy(prep, strings.Repeat("a", 32), platform, 0)
		if err != nil || policy.Validate() != nil || len(policy.Metadata().Prefixes) != 2 || policy.Metadata().ApplicationOpen || policy.Metadata().DNSOpen {
			t.Fatal("qualified closed desktop projection", platform, err)
		}
		if _, err := policy.ProtectionMembersSHA256(); err != nil {
			t.Fatal("lost original complete device policy", platform, err)
		}
	}
	for _, secret := range []string{p.responses[0].Token, p.responses[0].Password, p.responses[0].API, p.targets[0].Address} {
		if strings.Contains(p.Metadata(), secret) || strings.Contains(prep.Metadata(), secret) {
			t.Fatal("private source leaked")
		}
	}
	imported, _ := candidateSourceFixture(t, "external", NativeStartLayerMethod)
	if NodeChainCandidateInputSupportedForMeasurement(imported, hopmeasure.CandidatePrivateResponseMeasurement) {
		t.Fatal("unpaired imported node acquired private proof")
	}
	if value, err := a.NewCandidatePlan(1, candidateInventoryFixture(t, "unpaired", imported)); err == nil || value != nil {
		t.Fatal("unpaired source granted a scored private target")
	}
	addr := p.responses[0].Target.Address
	if !prep.AllowsDial(p.prefix.Tag, addr) || prep.AllowsDial(a.proofs[0].Tag, addr) || prep.AllowsDial(a.proofs[2].Tag, addr) {
		t.Fatal("candidate target escaped its selected prefix")
	}
	p.responses[0].Token += "x"
	if p.validate() == nil || p.Metadata() != "" {
		t.Fatal("mutated captured private key retained score authority")
	}
}
