package main

import (
	"errors"
	"net/netip"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This public shape selects the schema-six Local compiler. The restored
// original native sources independently prove every private and public role.
func desktopPairedStreamRoles(rows []common.MultihopNodeSelection, imported func(int) bool) bool {
	if len(rows) < 4 || !mobilemultihop.NodeChainPrefixMode(rows[0].Mode) || rows[len(rows)-1].Mode != "shadowsocks" || imported(len(rows)-1) {
		return false
	}
	stream, hasPrivate, hasImport := false, false, false
	for i, row := range rows[:len(rows)-1] {
		if mobilemultihop.NodeChainPrefixMode(row.Mode) && !stream && !imported(i) {
			continue
		}
		if i == 0 || row.Mode != "shadowsocks" {
			return false
		}
		stream = true
		if imported(i) {
			hasImport = true
		} else {
			hasPrivate = true
		}
	}
	return hasPrivate && hasImport
}

// Source shape only. The complete native compiler still captures each private
// import, original public proof and selected DNS before a connection can run.
func desktopNodeChainSourceSchema(members []desktopNodeChainMember) (int, error) {
	bad := errors.New("ordered imports require their complete Local source and supported positions")
	if len(members) < 2 || len(members) > mobilemultihop.NodeChainExtendedLocalMaximumNodes {
		return 0, bad
	}
	if desktopPairedStreamRoles(nodeChainSelectedReferences(members), func(i int) bool { return members[i].Profile.NodeKind == "external" }) {
		for _, member := range members {
			p := member.Profile
			if p.StartLayer != "" && p.StartLayer != "off" {
				return 0, bad
			}
			if p.NodeKind == "external" {
				if !desktopNodeChainImportedExecutionMiddle(p) {
					return 0, bad
				}
				addr, err := netip.ParseAddr(p.External.Shadowsocks.Server)
				if err != nil || addr.Zone() != "" || addr.Is4In6() {
					return 0, bad
				}
			} else if p.External != nil || p.NodeKind != "" && p.NodeKind != "router-vpn" || !common.ValidNodeProofID(p.NodeProofID) {
				return 0, bad
			}
		}
		return 6, nil
	}
	if len(members) > mobilemultihop.NodeChainMaximumNodes {
		last := len(members) - 1
		refs := nodeChainSelectedReferences(members)
		packets := common.ExtendedMixedLocalPacketCount(refs)
		paired := common.ExtendedPairedLocalMultihopSelection(refs)
		if paired {
			packets = last
		} else if common.ExtendedLocalMultihopSelection(refs) {
			packets = 1
		} else if packets == 0 {
			return 0, bad
		}
		for position, member := range members {
			p := member.Profile
			if position < packets || position == last {
				if p.External != nil || p.NodeKind != "" && p.NodeKind != "router-vpn" || p.StartLayer != "" && p.StartLayer != "off" {
					return 0, bad
				}
				continue
			}
			if !desktopNodeChainImportedExecutionMiddle(p) || member.Mode != "shadowsocks" || p.StartLayer != "" && p.StartLayer != "off" {
				return 0, bad
			}
			if addr, err := netip.ParseAddr(p.External.Shadowsocks.Server); err != nil || addr.Zone() != "" || addr.Is4In6() {
				return 0, bad
			}
		}
		if paired {
			return 1, nil
		}
		return 6, nil
	}
	if members[0].Profile.NodeKind == "external" || members[0].Profile.External != nil {
		if len(members) != 3 || members[2].Mode != "shadowsocks" ||
			members[2].Profile.External != nil || members[2].Profile.NodeKind != "" && members[2].Profile.NodeKind != "router-vpn" {
			return 0, bad
		}
		for _, member := range members[:2] {
			if member.Mode != "shadowsocks" || !desktopNodeChainImportedExecutionMiddle(member.Profile) {
				return 0, bad
			}
		}
		return 7, nil
	}
	var positions []int
	for position, member := range members {
		if member.Profile.NodeKind == "external" || member.Profile.External != nil {
			if member.Profile.NodeKind != "external" || member.Profile.External == nil ||
				position == 0 || position == len(members)-1 || members[len(members)-1].Mode != "shadowsocks" {
				return 0, bad
			}
			positions = append(positions, position)
		}
	}
	if len(positions) == 0 {
		return 1, nil
	}
	if len(positions) == 1 && positions[0] == len(members)-2 {
		member := members[positions[0]]
		switch {
		case desktopNodeChainImported(member.Profile, member.Mode):
			return 2, nil
		case desktopNodeChainSOCKSMiddle(member.Profile, member.Mode):
			return 3, nil
		case desktopNodeChainCONNECTMiddle(member.Profile, member.Mode):
			return 4, nil
		case desktopNodeChainOpenVPNMiddle(member.Profile, member.Mode):
			return 5, nil
		default:
			return 0, bad
		}
	}
	for _, position := range positions {
		member := members[position]
		if member.Mode != "shadowsocks" || !desktopNodeChainImportedExecutionMiddle(member.Profile) {
			return 0, bad
		}
	}
	return 6, nil
}

func desktopNodeChainHasCustomEntry(members []desktopNodeChainMember) bool {
	schema, err := desktopNodeChainSourceSchema(members)
	return err == nil && schema == 7
}
