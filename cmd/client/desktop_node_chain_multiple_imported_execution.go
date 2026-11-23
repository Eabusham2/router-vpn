package main

import (
	"encoding/json"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This selects a typed constructor from the already validated original Local
// source. The schema is descriptive; the complete constructor still validates
// every imported position and retains the original source and physical owner.
func desktopNodeChainMultipleImportedExecutionSource(original *desktopNodeChainLaunch) bool {
	if original == nil || original.policy == nil || original.connectPolicy != nil || original.socksPolicy != nil {
		return false
	}
	source := original.policy.OriginalChain()
	if source == nil {
		return false
	}
	input, err := source.LaunchInput()
	if err != nil {
		return false
	}
	var header struct {
		Schema json.RawMessage `json:"schema"`
	}
	return json.Unmarshal([]byte(input), &header) == nil && string(header.Schema) == "6"
}

// Keep concrete nil checks: a typed nil must never count as a native owner.
func desktopNodeChainExecutionPhysicalCountWithMultiple(paired *mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy,
	connect *mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy, socks *mobilemultihop.DesktopNodeChainSOCKSExecutionPhysicalPolicy,
	openvpn *mobilemultihop.DesktopNodeChainOpenVPNExecutionPhysicalPolicy, multiple *mobilemultihop.DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) int {
	count := desktopNodeChainExecutionPhysicalCount(paired, connect, socks, openvpn)
	if multiple != nil {
		count++
	}
	return count
}

// Catalog capability only. The complete captured compiler, independently
// provisioned Server descriptor and native owners still precede admission.
func desktopNodeChainMultipleImportedExecutionShape(members []desktopNodeChainMember) bool {
	if len(members) < 4 || len(members) > mobilemultihop.NodeChainExtendedLocalMaximumNodes || members[len(members)-1].Mode != "shadowsocks" {
		return false
	}
	if len(members) > mobilemultihop.NodeChainMaximumNodes {
		if schema, err := desktopNodeChainSourceSchema(members); err != nil || schema != 6 {
			return false
		}
	}
	ids, proofs := map[string]bool{}, map[string]bool{}
	public, onlyPosition := 0, -1
	for position, member := range members {
		profile := member.Profile
		if !validProfileID(profile.ID) || ids[profile.ID] {
			return false
		}
		ids[profile.ID] = true
		if profile.NodeKind == "external" || profile.External != nil {
			if position == 0 || position == len(members)-1 || member.Mode != "shadowsocks" || !desktopNodeChainImportedExecutionMiddle(profile) || profile.StartLayer != "" && profile.StartLayer != "off" {
				return false
			}
			public++
			onlyPosition = position
			continue
		}
		if profile.NodeKind != "" && profile.NodeKind != "router-vpn" || !common.ValidNodeProofID(profile.NodeProofID) || proofs[profile.NodeProofID] || position < len(members)-1 && !mobilemultihop.NodeChainPrefixMode(member.Mode) {
			return false
		}
		if layer := profile.StartLayer; layer != "" && layer != "off" && layer != "aes-256-gcm" && layer != "aes-256-gcm+xor-whitening" {
			return false
		}
		proofs[profile.NodeProofID] = true
	}
	return public > 1 || public == 1 && onlyPosition != len(members)-2
}

func desktopMultipleImportedExecutionMembers(members []desktopNodeChainMember, requested string) bool {
	return (requested == "server" || requested == "auto") && desktopNodeChainMultipleImportedExecutionShape(members) && desktopOrderedExecutionMembers(members, requested) == nil
}

func desktopMultipleImportedExecutionChoices() []string {
	if nativeDesktopImportedTrioExecutionPlatformSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
}
