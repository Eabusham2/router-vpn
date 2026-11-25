package mobilemultihop

import (
	"slices"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func TestSelectedPairedStreamOriginal(t *testing.T) {
	layout := nodeChainImportedLayout{"selected-private-stream", 4, []int{1}}
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			original, prep, src := multipleImportedExecutionFixture(t, layout, "wg", "", execution, "")
			policy, e := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, src))
			if e != nil || policy == nil {
				t.Fatal("operator private-stream policy", e)
			}
			member := src.Server.Members[1]
			if !original.selectedPrivateStream(2) || !src.Server.PrivateStreamAt(2) || member.NodeID != original.proofs[2].NodeID || member.SourceSHA256 != original.proofs[2].SourceSHA256 || member.StreamIdentitySHA256 == "" || member.ClientPublicKey != "" || member.ServerPublicKey != "" || !slices.Equal(src.Request.LocalPacketPositions, []int{0}) {
				t.Fatal("private stream became another packet or lost its identity")
			}
			var originalSource NodeChainSource
			if exactJSON([]byte(original.sourceJSON), &originalSource, NodeChainInputLimit) != nil {
				t.Fatal("original")
			}
			localKey, _, e := chainCompanionKeys(originalSource.IdentitySources[2], original.nodes[2].profile)
			if e != nil {
				t.Fatal(e)
			}
			entryKey, entryRemote, e := chainCompanionKeys(originalSource.IdentitySources[0], original.nodes[0].profile)
			if e != nil {
				t.Fatal(e)
			}
			exitKey, _, e := chainCompanionKeys(originalSource.IdentitySources[3], original.nodes[3].profile)
			if e != nil {
				t.Fatal(e)
			}
			for _, modify := range []func(*multihoprelay.NodeChainMember){
				func(m *multihoprelay.NodeChainMember) { m.NodeID = original.proofs[0].NodeID },
				func(m *multihoprelay.NodeChainMember) { m.SourceSHA256 = original.proofs[1].SourceSHA256 },
				func(m *multihoprelay.NodeChainMember) { m.StreamIdentitySHA256 = externalDigest([]byte(localKey)) },
				func(m *multihoprelay.NodeChainMember) { m.StreamIdentitySHA256 = externalDigest([]byte(entryKey)) },
				func(m *multihoprelay.NodeChainMember) { m.StreamIdentitySHA256 = externalDigest([]byte(entryRemote)) },
				func(m *multihoprelay.NodeChainMember) { m.StreamIdentitySHA256 = externalDigest([]byte(exitKey)) },
				func(m *multihoprelay.NodeChainMember) { m.ClientPublicKey = localKey },
				func(m *multihoprelay.NodeChainMember) { m.NodeKind = "external" },
				func(m *multihoprelay.NodeChainMember) { m.StartLayer = "aes-256-gcm" },
			} {
				foreign := src
				foreign.Server = src.Server.Clone()
				foreign.Request = src.Request.Clone()
				modify(&foreign.Server.Members[1])
				foreign.Request.DescriptorSHA256, _ = foreign.Server.Digest()
				if got, e := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, foreign)); e == nil || got != nil {
					t.Fatal("changed original private stream acquired selection")
				}
			}
		})
	}
}
