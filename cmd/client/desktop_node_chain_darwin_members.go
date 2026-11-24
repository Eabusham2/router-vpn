package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"router-vpn/internal/common"
	"router-vpn/internal/macosprocess"
)

// These original device-policy rows accompany the sealed complete graph.
// Explicit ordered drafts need not overwrite the saved control's preferences.
// They carry no API token, transport credential, endpoint or socket permission.
func newDesktopMacOSNodeChainSelection(chain *desktopNodeChainLaunch) (desktopMacOSNodeChainSelection, error) {
	var empty desktopMacOSNodeChainSelection
	bad := errors.New("macOS ordered baseline lost its complete original member policy")
	if chain == nil || !chain.originalPolicyCurrent() {
		return empty, bad
	}
	_, meta, _, err := chain.readPolicy()
	if err != nil || meta.TargetOS != "darwin" || len(chain.selection.Nodes) < 2 || len(chain.selection.Nodes) > common.MultihopPhysicalTraversalDepth {
		return empty, bad
	}
	if len(chain.selection.Nodes) > common.MultihopMaximumNodes {
		if schema, err := desktopNodeChainSourceSchema(chain.selection.Nodes); err != nil || schema != 6 && (schema != 1 || chain.macOSFamily() != macosprocess.NodeChainFamily) {
			return empty, bad
		}
	}
	rows := make([][]any, 0, len(chain.selection.Nodes))
	kill, ipv6, lan := "off", "on", true
	seen := map[string]bool{}
	for _, member := range chain.selection.Nodes {
		p := common.CloneRouterProfile(member.Profile)
		if common.NormalizeRouterProfile(&p) != nil || p.ID == "" || seen[p.ID] {
			return empty, bad
		}
		seen[p.ID] = true
		kind := p.NodeKind
		if kind == "" {
			kind = "router-vpn"
		}
		if kind != "router-vpn" && kind != "external" {
			return empty, bad
		}
		policy := desktopOwnedNodeProtectionPolicy(p)
		if policy != "off" && policy != "on-connect" && policy != "always" {
			return empty, bad
		}
		rows = append(rows, []any{p.ID, member.Mode, kind, policy, p.IPv6Mode, p.HomeLANAccess})
		if policy == "always" || kill == "off" && policy == "on-connect" {
			kill = policy
		}
		if p.IPv6Mode == "off" {
			ipv6 = "off"
		}
		lan = lan && p.HomeLANAccess
	}
	if kill != meta.KillSwitchPolicy || ipv6 != meta.IPv6Mode || lan != meta.HomeLANAccess || chain.selection.Nodes[len(rows)-1].Profile.ID != meta.ProfileID {
		return empty, bad
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return empty, bad
	}
	digest := sha256.Sum256(append([]byte("routervpn-ordered-protection-members-v1\n"), raw...))
	capture := desktopMacOSNodeChainSelection{Schema: 3, Family: chain.macOSFamily(), ProfileID: meta.ProfileID,
		Session: meta.SessionID, Source: meta.SourceSHA256, Config: meta.ConfigSHA256, HomeLAN: meta.HomeLANAccess, Policy: meta.KillSwitchPolicy,
		MembersJSON: string(raw), MembersSHA256: hex.EncodeToString(digest[:])}
	if !capture.valid() {
		return empty, bad
	}
	return capture, nil
}
