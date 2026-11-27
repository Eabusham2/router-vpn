package mobilemultihop

// Append preparation keeps device policy independent from every forwarding
// member. These accessors are called only after the exact purpose was validated.
func (p *NodeChainCandidatePreparation) devicePolicyProfile() map[string]any {
	if p.appendSource != nil {
		return p.appendSource.device.profile
	}
	return p.original.finalPreferences()
}
func (p *NodeChainCandidatePreparation) devicePolicyFixedMTU() (int, error) {
	if p.appendSource != nil && p.appendSource.record.DeviceFixedMTU != 0 {
		return p.appendSource.record.DeviceFixedMTU, nil
	}
	return fixedMTU(p.devicePolicyProfile())
}
func (p *NodeChainCandidatePreparation) controlProfileID() string {
	if p.appendSource != nil {
		return predecessorText(p.appendSource.device.profile, "id")
	}
	return candidatePreparationControl(p.original)
}

func appendProfileDevicePolicy(profile map[string]any) (nodeChainImportedDevicePolicy, error) {
	kill, err := externalDesktopKillPolicy(profile)
	if err != nil {
		return nodeChainImportedDevicePolicy{}, err
	}
	ipv6, blocked, err := externalDevicePolicy(profile)
	if err != nil {
		return nodeChainImportedDevicePolicy{}, err
	}
	return nodeChainImportedDevicePolicy{KillSwitchPolicy: kill, IPv6Mode: ipv6, HomeLANAccess: len(blocked) == 0}, nil
}

func (s *NodeChainCandidateAppendSource) devicePolicies() ([]nodeChainImportedDevicePolicy, error) {
	if s.validate() != nil {
		return nil, nodeChainCandidateAppendError
	}
	result := make([]nodeChainImportedDevicePolicy, len(s.nodes)+1)
	device, err := appendProfileDevicePolicy(s.device.profile)
	if err != nil {
		return nil, err
	}
	result[0] = device
	for i, node := range s.nodes {
		var policy nodeChainImportedDevicePolicy
		if member := s.imports[i]; member != nil {
			policy, err = member.devicePolicy()
		} else {
			policy, err = appendProfileDevicePolicy(node.profile)
		}
		if err != nil {
			return nil, err
		}
		result[i+1] = policy
	}
	return result, nil
}

func (p *DesktopNodeCandidatePreparationPolicy) appendMetadataCurrent() bool {
	original, derived, metadata := p.original.appendSource, p.preparation.appendSource, p.metadata
	if original == nil {
		return derived == nil && metadata.Purpose == "" && metadata.AppendPosition == 0 &&
			metadata.DraftRevision == "" && metadata.DeviceRevision == "" && metadata.DeviceSourceSHA256 == "" &&
			metadata.DeviceMTURevision == "" && metadata.DeviceFixedMTU == 0
	}
	return derived != nil && original != derived && original.seal == derived.seal &&
		metadata.Purpose == nodeChainCandidateAppendPurpose && metadata.AppendPosition == len(original.nodes) &&
		metadata.DraftRevision == original.record.DraftRevision && metadata.DeviceRevision == original.record.DeviceRevision &&
		metadata.DeviceSourceSHA256 == original.device.source && metadata.DeviceMTURevision == original.record.DeviceMTURevision &&
		metadata.DeviceFixedMTU == original.record.DeviceFixedMTU
}

func (p *DesktopNodeCandidatePreparationPolicy) appendProtectionMembersSHA256() (string, error) {
	source := p.original.appendSource
	if source == nil || source.validate() != nil || !p.appendMetadataCurrent() {
		return "", desktopNodeCandidatePreparationError
	}
	policies, err := source.devicePolicies()
	if err != nil {
		return "", err
	}
	// The separate device row cannot be confused with a route member, even
	// when the selected control is also an actual prefix member.
	rows := [][]any{{"device-policy", predecessorText(source.device.profile, "id"), source.device.source,
		source.record.DeviceRevision, source.record.DeviceMTURevision, source.record.DeviceFixedMTU,
		policies[0].KillSwitchPolicy, policies[0].IPv6Mode, policies[0].HomeLANAccess}}
	kill, ipv6, lan := "off", "on", true
	for i, policy := range policies {
		if i > 0 {
			proof := source.proofs[i-1]
			rows = append(rows, []any{"prefix-member", proof.Position, proof.ProfileID, proof.NodeID, proof.Mode,
				proof.StartLayer, proof.SourceSHA256, policy.KillSwitchPolicy, policy.IPv6Mode, policy.HomeLANAccess})
		}
		if policy.KillSwitchPolicy == "always" || kill == "off" && policy.KillSwitchPolicy == "on-connect" {
			kill = policy.KillSwitchPolicy
		}
		if policy.IPv6Mode == "off" {
			ipv6 = "off"
		}
		lan = lan && policy.HomeLANAccess
	}
	if kill != p.metadata.KillSwitchPolicy || ipv6 != p.metadata.IPv6Mode || lan != p.metadata.HomeLANAccess {
		return "", desktopNodeCandidatePreparationError
	}
	return desktopExternalObjectDigest([]any{"routervpn-append-prefix-protection-members-v1", source.sourceSHA, rows}), nil
}
