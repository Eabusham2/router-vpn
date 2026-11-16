package main

import (
	"encoding/base64"
	"errors"
	"net/netip"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This is a source-shape predicate, never native execution authority. The
// original catalog tokens, complete compiler and retained preparation still
// precede any physical admission, lease, selected proof or connection change.
func desktopNodeChainImportedExecutionMiddle(profile common.RouterProfile) bool {
	if !desktopNodeChainImported(profile, "shadowsocks") {
		return false
	}
	ss := profile.External.Shadowsocks
	address, err := netip.ParseAddr(ss.Server)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.String() != ss.Server || profile.Endpoint != ss.Server {
		return false
	}
	key, err := base64.StdEncoding.Strict().DecodeString(ss.Password)
	defer clear(key)
	return err == nil && base64.StdEncoding.EncodeToString(key) == ss.Password
}

// Paired execution retains its existing source bounds. Only the original
// literal schema-two complete prefix or separately typed CONNECT path can add one imported member.
func desktopOrderedExecutionMembers(members []desktopNodeChainMember, requested string) error {
	bad := errors.New("ordered imported execution requires its original complete literal SS2022 or CONNECT path, or typed SOCKS trio")
	if !validDesktopOrderedExecution(requested) {
		return bad
	}
	if requested == "local" {
		return nil
	}
	imported := 0
	for _, member := range members {
		if member.Profile.NodeKind == "external" || member.Profile.External != nil {
			imported++
		}
	}
	if imported == 0 {
		return nil
	}
	if imported != 1 || len(members) < 3 || len(members) > 8 {
		return bad
	}
	middle := len(members) - 2
	if members[len(members)-1].Mode != "shadowsocks" || !(members[middle].Mode == "shadowsocks" && desktopNodeChainImportedExecutionMiddle(members[middle].Profile) || desktopNodeChainCONNECTExecutionShape(members) || desktopNodeChainSOCKSExecutionShape(members)) {
		return bad
	}
	ids, proofs := map[string]bool{}, map[string]bool{}
	for i, member := range members {
		p := member.Profile
		if !validProfileID(p.ID) || ids[p.ID] {
			return bad
		}
		ids[p.ID] = true
		if i == middle {
			continue
		}
		if i < middle && !mobilemultihop.NodeChainPrefixMode(member.Mode) || p.NodeKind != "" && p.NodeKind != "router-vpn" || p.External != nil || !common.ValidNodeProofID(p.NodeProofID) || proofs[p.NodeProofID] {
			return bad
		}
		proofs[p.NodeProofID] = true
	}
	return nil
}

// Presentation/source-shape only. The original typed Local compiler and the
// separate execution preparation still validate every credential and owner.
func desktopNodeChainCONNECTExecutionShape(members []desktopNodeChainMember) bool {
	if len(members) < 3 || len(members) > mobilemultihop.NodeChainMaximumNodes {
		return false
	}
	middle, final := len(members)-2, len(members)-1
	if members[final].Mode != "shadowsocks" || !desktopNodeChainCONNECTMiddle(members[middle].Profile, members[middle].Mode) ||
		members[final].Profile.StartLayer != "" && members[final].Profile.StartLayer != "off" {
		return false
	}
	for _, member := range members[:middle] {
		layer := member.Profile.StartLayer
		if !mobilemultihop.NodeChainPrefixMode(member.Mode) || layer != "" && layer != "off" && layer != "aes-256-gcm" && layer != "aes-256-gcm+xor-whitening" {
			return false
		}
	}
	return true
}

func desktopCONNECTTrioExecutionMembers(members []desktopNodeChainMember, requested string) bool {
	return (requested == "server" || requested == "auto") && desktopNodeChainCONNECTExecutionShape(members) && desktopOrderedExecutionMembers(members, requested) == nil
}
