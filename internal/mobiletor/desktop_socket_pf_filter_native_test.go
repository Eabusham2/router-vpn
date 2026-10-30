package mobiletor

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestDesktopPFFilterNativeDispatchPreservesOwner(t *testing.T) {
	const owner = "com.apple/000.router-vpn"
	for _, pair := range [][2]string{{owner, "psession"}, {owner + "/psession", "/" + owner + "/ggeneration"}} {
		if !desktopPFNativeDispatch(pair[0], owner, pair[1]) {
			t.Fatal("native PF dispatch rejected the captured owner reference", pair)
		}
	}
	for _, pair := range [][2]string{
		{owner, "/com.apple/foreign"}, {owner, "/com.apple"}, {owner, "/" + owner},
		{owner, "../foreign"}, {owner, "child/../../foreign"}, {owner, "child\x00"},
		{owner + "-foreign", "/" + owner + "/ggeneration"}, {"com.apple/foreign", "child"},
	} {
		if desktopPFNativeDispatch(pair[0], owner, pair[1]) {
			t.Fatal("native PF dispatch escaped or recursively adopted its anchor owner", pair)
		}
	}
}

func TestDesktopPFFilterNativeByteProjection(t *testing.T) {
	rule := desktopPFFilterRule{Action: "pass", Direction: "out", Quick: true, Interface: "en7", Family: 4, Protocol: 17,
		Source: netip.MustParsePrefix("192.0.2.0/24"), Destination: netip.MustParsePrefix("198.51.100.1/32"),
		SourcePort: 43821, DestinationPort: 443, User: true, UID: 0x7fffffff, Tag: "owned", Label: "socket"}
	actual, err := desktopPFNativeProject(rule)
	want := desktopPFNativeFilter{Action: 1, Direction: 2, Quick: 1, Interface: "en7", Family: 4, Protocol: 17,
		Source: [16]byte{192, 0, 2, 0}, SourceMask: [16]byte{255, 255, 255, 0},
		Destination: [16]byte{198, 51, 100, 1}, DestinationMask: [16]byte{255, 255, 255, 255},
		SourcePort: 43821, DestinationPort: 443, User: 1, UID: 0x7fffffff, Tag: "owned", Label: "socket"}
	if err != nil || actual != want {
		t.Fatalf("native PF input changed the independent network-order/UID projection: got %+v want %+v error %v", actual, want, err)
	}
	rule.Family = 6
	rule.Protocol = 6
	rule.FlagsAny = true
	rule.Source = netip.MustParsePrefix("2001:db8:1234:8000::/49")
	rule.Destination = netip.MustParsePrefix("2001:db8::1/128")
	actual, err = desktopPFNativeProject(rule)
	if err != nil || actual.Source != [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x80} ||
		actual.SourceMask != [16]byte{255, 255, 255, 255, 255, 255, 128} ||
		actual.Destination != [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} ||
		actual.DestinationMask != [16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255} ||
		actual.Family != 6 || actual.Protocol != 6 || actual.FlagsAny != 1 || actual.KeepState != 0 {
		t.Fatal("native IPv6 mask/address or TCP state policy changed", actual, err)
	}
}

func TestDesktopPFFilterNativeNoImplicitUIDOrAddress(t *testing.T) {
	rule := desktopPFFilterRule{Action: "pass", Direction: "out", Family: 4, Protocol: 17, User: true, UID: 0}
	actual, err := desktopPFNativeProject(rule)
	if err != nil || actual.User != 1 || actual.UID != 0 || actual.Source != [16]byte{} || actual.SourceMask != [16]byte{} {
		t.Fatal("explicit root UID or any-address projection was substituted", actual, err)
	}
	rule.User = false
	without, err := desktopPFNativeProject(rule)
	if err != nil || without.User != 0 || reflect.DeepEqual(actual, without) {
		t.Fatal("native UID absence collapsed into the explicit root identity", without, err)
	}
	for _, invalid := range []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 33), netip.PrefixFrom(netip.MustParseAddr("2001:db8::1"), 129)} {
		rule.Source = invalid
		if value, err := desktopPFNativeProject(rule); err == nil || value != (desktopPFNativeFilter{}) {
			t.Fatal("invalid constructed prefix widened to any address", value, err)
		}
	}
}

func TestDesktopPFFilterNativeRejectsMalformedRecord(t *testing.T) {
	baseline := desktopPFFilterRule{Action: "pass", Direction: "out", Family: 4, Protocol: 17,
		Source: netip.MustParsePrefix("192.0.2.1/32"), Destination: netip.MustParsePrefix("198.51.100.2/32")}
	for name, change := range map[string]func(*desktopPFFilterRule){
		"unknown-action":          func(r *desktopPFFilterRule) { r.Action = "nat" },
		"unknown-direction":       func(r *desktopPFFilterRule) { r.Direction = "both" },
		"unknown-family":          func(r *desktopPFFilterRule) { r.Family = 7 },
		"unknown-protocol":        func(r *desktopPFFilterRule) { r.Protocol = 99 },
		"lost-address-family":     func(r *desktopPFFilterRule) { r.Family = 0 },
		"opposite-address-family": func(r *desktopPFFilterRule) { r.Family = 6 },
		"host-bits":               func(r *desktopPFFilterRule) { r.Source = netip.MustParsePrefix("192.0.2.1/24") },
		"mapped-address":          func(r *desktopPFFilterRule) { r.Family = 6; r.Source = netip.MustParsePrefix("::ffff:192.0.2.1/128") },
		"implicit-uid":            func(r *desktopPFFilterRule) { r.UID = 501 },
		"uid-wrong-transport":     func(r *desktopPFFilterRule) { r.Protocol = 0; r.User = true },
		"port-wrong-transport":    func(r *desktopPFFilterRule) { r.Protocol = 0; r.DestinationPort = 443 },
		"udp-tcp-flags":           func(r *desktopPFFilterRule) { r.FlagsAny = true },
		"stateful-block":          func(r *desktopPFFilterRule) { r.Action = "block"; r.KeepState = true },
		"floating-without-state":  func(r *desktopPFFilterRule) { r.Floating = true },
		"unscoped-negation":       func(r *desktopPFFilterRule) { r.MatchTagNot = true },
		"hidden-anchor":           func(r *desktopPFFilterRule) { r.Anchor = "foreign" },
		"invalid-interface":       func(r *desktopPFFilterRule) { r.Interface = "en0 all" },
		"embedded-nul":            func(r *desktopPFFilterRule) { r.Tag = "owned\x00other" },
		"escaped-label":           func(r *desktopPFFilterRule) { r.Label = "owned\\n" },
		"partial-anchor":          func(r *desktopPFFilterRule) { r.Action = "anchor"; r.Anchor = "valid" },
	} {
		t.Run(name, func(t *testing.T) {
			rule := baseline
			change(&rule)
			if value, err := desktopPFNativeProject(rule); err == nil || value != (desktopPFNativeFilter{}) {
				t.Fatal("native SDK adapter accepted an invalid or widened record", value, err)
			}
		})
	}
	for _, rule := range []desktopPFFilterRule{
		{Action: "anchor", Direction: "out", Anchor: "/com.apple/000.router-vpn/gabcdefghijklmnopqrstuvwxabcdefgh"},
		{Action: "block", Direction: "out", Quick: true, MatchTag: "owned", MatchTagNot: true},
		{Action: "pass", Direction: "in", Protocol: 17, Family: 4, KeepState: true, Floating: true},
	} {
		if _, err := desktopPFNativeProject(rule); err != nil {
			t.Fatal("complete native filter record was rejected", rule, err)
		}
	}
}
