package mobilemultihop

import (
	"encoding/json"
	"testing"
)

func TestMobileOrderedExternalFinalKeepsOriginalResolver(t *testing.T) {
	for _, dns := range []string{"home", "custom"} {
		t.Run(dns, func(t *testing.T) {
			source := externalFinalSourceFixture(t, 4, dns)
			var final nodeChainImportedInput
			if err := json.Unmarshal([]byte(source.Nodes[3]), &final); err != nil {
				t.Fatal(err)
			}
			var raw externalPolicyCapture
			if err := json.Unmarshal([]byte(final.Capture), &raw); err != nil {
				t.Fatal(err)
			}
			raw.Entry, raw.EntryTag, raw.PredecessorConfig = nil, "", ""
			for _, key := range []string{"multihop_entry_mode", "multihop_entry_id", "multihop_exit_id", "multihop_enabled", "multihop_execution"} {
				delete(raw.Profile, key)
			}
			imported, err := NodeChainImportedMemberInput(final.Config, startJSON(t, raw))
			if err != nil {
				t.Fatal(err)
			}
			typed, err := NodeChainExternalFinalFromEntry(source.Nodes[0], imported)
			if err != nil {
				t.Fatal(err)
			}
			source.Nodes[3] = typed
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			proofs := chain.ProofInventory()
			route := externalTestRead(t, chain.Config())
			d := route["dns"].(map[string]any)
			resolver := d["servers"].([]any)[0].(map[string]any)
			for _, row := range d["servers"].([]any) {
				if r := row.(map[string]any); r["tag"] == d["final"] {
					resolver = r
				}
			}
			want := proofs[0].Tag
			if dns == "custom" {
				want = proofs[3].Tag
			}
			if resolver["detour"] != want || proofs[3].ProfileID != raw.ExitID || proofs[3].NodeID != "" {
				t.Fatalf("final %s resolver or public identity changed", dns)
			}
			if _, err := NodeChainExternalFinalFromEntry(source.Nodes[1], imported); err == nil {
				t.Fatal("accepted a stream as the original WireGuard entry")
			}
			if _, err := NodeChainExternalFinalFromEntry(source.Nodes[0], typed); err == nil {
				t.Fatal("accepted a previously paired final as an original import")
			}
		})
	}
}

func TestMobileExternalFinalClosedEntryPreparation(t *testing.T) {
	for _, count := range []int{3, 9} {
		source := externalFinalSourceFixture(t, count, "home")
		inventory, _ := entryInventory(t)
		p, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
		if err != nil || p.multipleOriginal == nil {
			t.Fatal(count, "original closed WireGuard prefix", err)
		}
		restored, err := ParseNodeChainCandidatePreparationCapture(p.Source())
		if err != nil || restored.SourceSHA256() != p.SourceSHA256() {
			t.Fatal(count, "closed prefix replay", err)
		}
		if _, err = NewNodeChainCandidatePreparation(startJSON(t, source), count-1, inventory); err == nil {
			t.Fatal("public exit admitted as a candidate prefix")
		}
	}
}
