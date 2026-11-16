package main

import (
	"errors"

	"router-vpn/internal/mobilemultihop"
)

// Source shape only. The complete native compiler still captures each private
// import, original public proof and selected DNS before a connection can run.
func desktopNodeChainSourceSchema(members []desktopNodeChainMember) (int, error) {
	bad := errors.New("ordered imports require their complete Local source and independent interior positions")
	if len(members) < 2 || len(members) > mobilemultihop.NodeChainMaximumNodes {
		return 0, bad
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
