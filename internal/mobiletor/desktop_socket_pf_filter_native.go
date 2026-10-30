package mobiletor

import (
	"errors"
	"net/netip"
	"strings"
)

// This is an application-owned value passed to the SDK adapter. It is not an
// OS structure, pointer, transaction ticket or permission to select an anchor.
type desktopPFNativeFilter struct {
	Action, Direction, Quick, Family, Protocol uint8
	User, KeepState, FlagsAny, Floating        uint8
	MatchTagNot                                uint8
	UID                                        uint32
	SourcePort, DestinationPort                uint16
	Source, SourceMask                         [16]byte
	Destination, DestinationMask               [16]byte
	Interface, Tag, MatchTag, Label, Anchor    string
}

// An anchor-call record may create a referenced namespace even before that
// child contains rules. Keep that reference inside the same captured owner as
// the filter queue; a private loader must not manufacture foreign anchors.
func desktopPFNativeDispatch(anchor, owner, call string) bool {
	if !desktopPFInventoryPath(owner) || !desktopPFInventoryPath(anchor) ||
		(anchor != owner && !strings.HasPrefix(anchor, owner+"/")) ||
		len(call) > 63 || !desktopPFFilterAnchor.MatchString(call) {
		return false
	}
	target := strings.TrimPrefix(call, "/")
	if !strings.HasPrefix(call, "/") {
		target = anchor + "/" + call
	}
	return desktopPFInventoryPath(target) && target != anchor && strings.HasPrefix(target, owner+"/")
}

func desktopPFNativeName(value string) bool {
	if len(value) > 63 {
		return false
	}
	for _, ch := range []byte(value) {
		if ch < 32 || ch > 126 || ch == '"' || ch == '\\' {
			return false
		}
	}
	return true
}

func desktopPFNativeAddress(prefix netip.Prefix, family uint8) ([16]byte, [16]byte, error) {
	var address, mask [16]byte
	if prefix == (netip.Prefix{}) {
		return address, mask, nil
	}
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" ||
		(prefix.Addr().Is4() && family != 4) || (prefix.Addr().Is6() && family != 6) {
		return address, mask, errors.New("native PF address lost its exact family or canonical prefix")
	}
	if family == 4 {
		value := prefix.Addr().As4()
		copy(address[:], value[:])
	} else {
		address = prefix.Addr().As16()
	}
	for bit := 0; bit < prefix.Bits(); bit++ {
		mask[bit/8] |= 0x80 >> uint(bit%8)
	}
	return address, mask, nil
}

func desktopPFNativeProject(rule desktopPFFilterRule) (desktopPFNativeFilter, error) {
	invalid := func() (desktopPFNativeFilter, error) {
		return desktopPFNativeFilter{}, errors.New("native PF record is not a complete supported filter")
	}
	if rule.Interface != "" && !desktopPFFilterInterface.MatchString(rule.Interface) ||
		!desktopPFNativeName(rule.Tag) || !desktopPFNativeName(rule.MatchTag) || !desktopPFNativeName(rule.Label) ||
		(rule.Family != 0 && rule.Family != 4 && rule.Family != 6) ||
		(rule.Protocol != 0 && rule.Protocol != 6 && rule.Protocol != 17 && rule.Protocol != 58) ||
		rule.Protocol == 58 && rule.Family != 6 ||
		(rule.User || rule.SourcePort != 0 || rule.DestinationPort != 0) && rule.Protocol != 6 && rule.Protocol != 17 ||
		!rule.User && rule.UID != 0 || rule.FlagsAny && rule.Protocol != 6 || rule.Floating && !rule.KeepState ||
		rule.MatchTagNot && rule.MatchTag == "" {
		return invalid()
	}
	flag := func(value bool) uint8 {
		if value {
			return 1
		}
		return 0
	}
	result := desktopPFNativeFilter{Quick: flag(rule.Quick), Family: rule.Family, Protocol: rule.Protocol,
		User: flag(rule.User), UID: rule.UID, SourcePort: rule.SourcePort, DestinationPort: rule.DestinationPort,
		KeepState: flag(rule.KeepState), FlagsAny: flag(rule.FlagsAny), Floating: flag(rule.Floating),
		MatchTagNot: flag(rule.MatchTagNot), Interface: rule.Interface, Tag: rule.Tag, MatchTag: rule.MatchTag,
		Label: rule.Label, Anchor: rule.Anchor}
	switch rule.Action {
	case "pass":
		result.Action = 1
	case "block":
		if rule.KeepState {
			return invalid()
		}
		result.Action = 2
	case "anchor":
		if len(rule.Anchor) > 63 || !desktopPFFilterAnchor.MatchString(rule.Anchor) ||
			!desktopPFInventoryPath(strings.TrimPrefix(rule.Anchor, "/")) ||
			rule != (desktopPFFilterRule{Action: "anchor", Direction: "out", Anchor: rule.Anchor}) {
			return invalid()
		}
		result.Action = 3
	default:
		return invalid()
	}
	if rule.Action != "anchor" && rule.Anchor != "" {
		return invalid()
	}
	switch rule.Direction {
	case "in":
		result.Direction = 1
	case "out":
		result.Direction = 2
	default:
		return invalid()
	}
	var sourceErr, destinationErr error
	result.Source, result.SourceMask, sourceErr = desktopPFNativeAddress(rule.Source, rule.Family)
	result.Destination, result.DestinationMask, destinationErr = desktopPFNativeAddress(rule.Destination, rule.Family)
	if err := errors.Join(sourceErr, destinationErr); err != nil {
		return desktopPFNativeFilter{}, err
	}
	return result, nil
}
