package mobilemultihop

// ProtectionMembersSHA256 binds the complete saved graph's ordered identities
// and device restrictions for a desktop baseline. It is derived only from the
// original sealed policy, including members outside the runnable prefix. It
// supplies neither native ownership nor permission to open application/DNS.
func (p *DesktopNodeCandidatePreparationPolicy) ProtectionMembersSHA256() (string, error) {
	if p.Validate() != nil {
		return "", desktopNodeCandidatePreparationError
	}
	original := p.original.original
	if len(original.proofs) != len(original.nodes) || len(original.nodes) < 2 || len(original.nodes) > NodeChainMaximumNodes {
		return "", desktopNodeCandidatePreparationError
	}
	rows := make([][]any, 0, len(original.nodes))
	kill, ipv6, lan := "off", "on", true
	for position, node := range original.nodes {
		proof := original.proofs[position]
		kind := "router-vpn"
		var profile map[string]any
		if position == 1 && original.importedMiddle != nil {
			if proof.NodeKind != "external" {
				return "", desktopNodeCandidatePreparationError
			}
			profile, kind = original.importedMiddle.selection.Profile, "external"
		} else {
			if node == nil || proof.NodeKind != "" {
				return "", desktopNodeCandidatePreparationError
			}
			profile = node.profile
		}
		// Validate already checked the original member seals. Read their
		// canonical device fields without repeating native graph compilation.
		policy, err := externalDesktopKillPolicy(profile)
		if err != nil {
			return "", err
		}
		memberIPv6, blocked, err := externalDevicePolicy(profile)
		if err != nil {
			return "", err
		}
		device := nodeChainImportedDevicePolicy{policy, memberIPv6, len(blocked) == 0}

		rows = append(rows, []any{proof.ProfileID, proof.Mode, kind, device.KillSwitchPolicy, device.IPv6Mode, device.HomeLANAccess})
		if device.KillSwitchPolicy == "always" || kill == "off" && device.KillSwitchPolicy == "on-connect" {
			kill = device.KillSwitchPolicy
		}
		if device.IPv6Mode == "off" {
			ipv6 = "off"
		}
		lan = lan && device.HomeLANAccess
	}
	if kill != p.metadata.KillSwitchPolicy || ipv6 != p.metadata.IPv6Mode || lan != p.metadata.HomeLANAccess {
		return "", desktopNodeCandidatePreparationError
	}
	return desktopExternalObjectDigest([]any{"routervpn-prefix-protection-members-v1", rows}), nil
}
