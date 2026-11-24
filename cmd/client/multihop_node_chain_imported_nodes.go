package main

import (
	"errors"
	"net/netip"

	"router-vpn/internal/mobilemultihop"
)

// Source shape only. The complete native compiler still captures each private
// import, original public proof and selected DNS before a connection can run.
func desktopNodeChainSourceSchema(members []desktopNodeChainMember) (int, error) {
	bad := errors.New("ordered imports require their complete Local source and supported positions")
	if len(members) < 2 || len(members) > mobilemultihop.NodeChainExtendedLocalMaximumNodes {
		return 0, bad
	}
	if len(members) > mobilemultihop.NodeChainMaximumNodes {
		last := len(members) - 1
		if members[1].Mode == "wg" {
			for i, m := range members {
				mode := "wg"
				if i == last {
					mode = "shadowsocks"
				}
				p := m.Profile
				if m.Mode != mode || p.External != nil || p.NodeKind != "" && p.NodeKind != "router-vpn" || p.StartLayer != "" && p.StartLayer != "off" {
					return 0, bad
				}
			}
			return 1, nil
		}
		for position, member := range members {
			p := member.Profile
			if position == 0 || position == last {
				mode := "wg"
				if position == last {
					mode = "shadowsocks"
				}
				if member.Mode != mode || p.External != nil || p.NodeKind != "" && p.NodeKind != "router-vpn" || p.StartLayer != "" && p.StartLayer != "off" {
					return 0, bad
				}
				continue
			}
			if member.Mode != "shadowsocks" || !desktopNodeChainImportedExecutionMiddle(p) {
				return 0, bad
			}
			if _, err := netip.ParseAddr(p.External.Shadowsocks.Server); err != nil {
				return 0, bad
			}
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
