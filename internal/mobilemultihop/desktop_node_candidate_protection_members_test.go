package mobilemultihop

import (
	"strings"
	"testing"
)

func TestDesktopCandidateProtectionMembersBindUnselectedRestrictions(t *testing.T) {
	var previous string
	for _, final := range []string{"off", "on-connect", "always"} {
		p := desktopCandidatePreparationFixture(t, "wg", "darwin", 0, 0, func(i int, profile map[string]any) {
			profile["kill_switch_policy"], profile["home_lan_access"], profile["ipv6_mode"] = "off", true, "on"
			if i == 0 {
				profile["kill_switch_policy"], profile["home_lan_access"], profile["ipv6_mode"] = "always", false, "off"
			}
			if i == 2 {
				profile["kill_switch_policy"] = final
			}
		})
		digest, err := p.ProtectionMembersSHA256()
		if err != nil || len(digest) != 64 || digest == previous || p.Metadata().KillSwitchPolicy != "always" || p.Metadata().HomeLANAccess || p.Metadata().IPv6Mode != "off" {
			t.Fatal("member binding omitted an unselected restriction or changed the established aggregate", err)
		}
		rows := [][]any{}
		for i, proof := range p.original.original.proofs {
			policy, ipv6, lan := "off", "on", true
			if i == 0 {
				policy, ipv6, lan = "always", "off", false
			}
			if i == 2 {
				policy = final
			}
			rows = append(rows, []any{proof.ProfileID, proof.Mode, "router-vpn", policy, ipv6, lan})
		}
		if digest != desktopExternalObjectDigest([]any{"routervpn-prefix-protection-members-v1", rows}) {
			t.Fatal("member digest changed canonical wire rows")
		}
		reopened, err := ParseDesktopNodeCandidatePreparationPolicy(p.Source())
		if err != nil {
			t.Fatal(err)
		}
		again, err := reopened.ProtectionMembersSHA256()
		if err != nil || again != digest {
			t.Fatal("private source replay changed member binding", err)
		}
		p.metadata.SourceSHA256 = strings.Repeat("f", 64)
		if _, err := p.ProtectionMembersSHA256(); err == nil {
			t.Fatal("foreign source supplied baseline members")
		}
		previous = digest
	}
	var missing *DesktopNodeCandidatePreparationPolicy
	if _, err := missing.ProtectionMembersSHA256(); err == nil {
		t.Fatal("nil source supplied baseline members")
	}
}

func TestDesktopCandidateProtectionMembersIncludeOriginalImportedMiddle(t *testing.T) {
	source := nodeChainImportedFixture(t, "wg", "")
	target, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	prep, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, candidateInventoryFixture(t, "captured-members", target))
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewDesktopNodeCandidatePreparationPolicy(prep, desktopNodeTestSession, "darwin", 0)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := p.ProtectionMembersSHA256()
	if err != nil || len(digest) != 64 {
		t.Fatal("unselected imported member lost its own policy identity", err)
	}
	old := p.original.original.importedMiddle.selection.Profile["id"]
	p.original.original.importedMiddle.selection.Profile["id"] = "foreign-member"
	if _, err := p.ProtectionMembersSHA256(); err == nil {
		t.Fatal("imported member substitution was adopted")
	}
	p.original.original.importedMiddle.selection.Profile["id"] = old
}
