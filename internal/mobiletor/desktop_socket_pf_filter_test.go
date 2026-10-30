package mobiletor

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestDesktopPFFilterExactSocketAndTunnel(t *testing.T) {
	rules, err := desktopPFCompileFilters("pass out on en7 inet proto tcp from 192.0.2.10 port 41111 to 198.51.100.7 port 443 user 1073741825 flags any tag \"rvpn:allowed\" no state label \"rvpn:socket\"\n" +
		"pass out on utun42 all tag \"rvpn:allowed\" no state label \"rvpn:tunnel\"\n")
	if err != nil || len(rules) != 2 {
		t.Fatal("complete owned filter projection failed", rules, err)
	}
	want := desktopPFFilterRule{Action: "pass", Direction: "out", Interface: "en7", Family: 4, Protocol: 6,
		Source: netip.MustParsePrefix("192.0.2.10/32"), Destination: netip.MustParsePrefix("198.51.100.7/32"),
		SourcePort: 41111, DestinationPort: 443, User: true, UID: 1073741825, FlagsAny: true,
		Tag: "rvpn:allowed", Label: "rvpn:socket"}
	if !reflect.DeepEqual(rules[0], want) {
		t.Fatalf("native filter projection changed the exact socket/UID/device policy: got %+v want %+v", rules[0], want)
	}
	if !reflect.DeepEqual(rules[1], desktopPFFilterRule{Action: "pass", Direction: "out", Interface: "utun42", Tag: "rvpn:allowed", Label: "rvpn:tunnel"}) {
		t.Fatal("retained tunnel admission acquired another tuple or state policy", rules[1])
	}
	udp, err := desktopPFCompileFilters("pass out on en8 inet6 proto udp from 2001:db8::1 port 55111 to 2001:db8:1::2 port 443 user 2147483647 tag \"v6-owner\" no state\n")
	if err != nil || len(udp) != 1 || udp[0].Family != 6 || udp[0].Protocol != 17 || udp[0].UID != 2147483647 || udp[0].FlagsAny || udp[0].Source != netip.MustParsePrefix("2001:db8::1/128") || udp[0].Destination != netip.MustParsePrefix("2001:db8:1::2/128") {
		t.Fatal("native IPv6 UDP projection lost a captured field", udp, err)
	}
}

func TestDesktopPFFilterOrderedExpansionAndDeny(t *testing.T) {
	rules, err := desktopPFCompileFilters("pass out inet6 proto icmp6 from { ::, fe80::/10 } to { fe80::/10, ff00::/8 } tag \"link\" no state\n" +
		"block drop out quick to { 127.78.1.10, 127.78.1.11, fd73:1::1, fd73:1::2 } ! tagged \"owned\" label \"deny\"\n")
	if err != nil || len(rules) != 8 {
		t.Fatal("bounded PF address cross-product failed", rules, err)
	}
	expected := [][2]string{{"::/128", "fe80::/10"}, {"::/128", "ff00::/8"}, {"fe80::/10", "fe80::/10"}, {"fe80::/10", "ff00::/8"}}
	for index, pair := range expected {
		if rules[index].Source.String() != pair[0] || rules[index].Destination.String() != pair[1] || rules[index].Family != 6 || rules[index].Protocol != 58 {
			t.Fatal("PF expansion reordered or changed the link-maintenance scope", index, rules[index])
		}
	}
	for index, family := range []uint8{4, 4, 6, 6} {
		rule := rules[index+4]
		if rule.Action != "block" || !rule.Quick || rule.Family != family || !rule.MatchTagNot || rule.MatchTag != "owned" || rule.Label != "deny" || rule.KeepState {
			t.Fatal("native deny expansion lost direction, tag negation or quick semantics", rule)
		}
	}
}

func TestDesktopPFFilterAnchorAndStateFixture(t *testing.T) {
	for _, name := range []string{"p" + strings.Repeat("1", 32), "/com.apple/000.t-012345abcdef/g" + strings.Repeat("a", 32)} {
		rules, err := desktopPFCompileFilters("anchor \"" + name + "\" out all\n")
		if err != nil || len(rules) != 1 || rules[0].Action != "anchor" || rules[0].Anchor != name || rules[0].Direction != "out" || rules[0].Quick {
			t.Fatal("native anchor projection changed the complete dispatch identity", rules, err)
		}
	}
	for _, direction := range []string{"in", "out"} {
		rules, err := desktopPFCompileFilters("pass " + direction + " on lo0 inet proto udp to 127.78.1.11 keep state\n")
		if err != nil || len(rules) != 1 || !rules[0].KeepState || rules[0].Direction != direction || rules[0].Floating {
			t.Fatal("foreign-state negative fixture changed its explicit policy", rules, err)
		}
	}
	rules, err := desktopPFCompileFilters("pass out quick on lo0 inet proto udp from 127.78.1.10 to 127.78.1.11 port 55111 keep state (floating)\n")
	if err != nil || len(rules) != 1 || !rules[0].KeepState || !rules[0].Floating || !rules[0].Quick {
		t.Fatal("native state-retirement fixture lost its explicit floating state", rules, err)
	}
	if empty, err := desktopPFCompileFilters("\n \t\n"); err != nil || len(empty) != 0 {
		t.Fatal("empty filter transaction did not preserve native retirement", empty, err)
	}
}

func TestDesktopPFFilterRejectsWidenedOrUnsupportedPolicy(t *testing.T) {
	for _, source := range []string{
		"include \"/etc/pf.conf\"", "set skip on lo0", "table <any> persist", "nat on en0 from any to any -> 192.0.2.1",
		"pass out all", "pass all no state", "pass out all no state keep state", "pass out all no state no state",
		"pass out quick quick all no state", "pass out on en0 all no state route-to en1", "block return out all",
		"block drop out all tagged ! \"owner\"", "block drop out all ! \"owner\"", "block drop out all ! tagged \"owner\" keep state",
		"pass out inet proto udp to node.example no state", "pass out inet proto udp to 192.0.2.1 port 0 no state",
		"pass out inet proto udp to 192.0.2.1 port 65536 no state", "pass out inet proto udp to 192.0.2.1 port +53 no state",
		"pass out inet proto udp to 192.0.2.1 port 053 no state", "pass out inet to 192.0.2.1 port 53 no state",
		"pass out inet proto udp to 192.0.2.1 user 4294967296 no state", "pass out inet proto udp to 192.0.2.1 user root no state",
		"pass out inet proto udp to 192.0.2.1 flags any no state", "pass out inet6 proto icmp6 to ::1 user 1 no state",
		"pass out inet proto icmp6 to 192.0.2.1 no state", "pass out inet to ::1 no state", "pass out inet6 to ::ffff:192.0.2.1 no state",
		"pass out inet6 to fe80::1%en0 no state", "pass out inet to 192.0.2.1/24 no state", "pass out inet to { } no state",
		"pass out inet to { 192.0.2.1 192.0.2.2 } no state", "pass out inet to { 192.0.2.1, } no state",
		"pass out inet to { 192.0.2.1, ::1 } no state", "pass out inet to { { 192.0.2.1 } } no state",
		"pass out all tag \"owner\"suffix no state", "pass out all tag \"owner\\n\" no state", "pass out all tag \"\" no state",
		"pass out all tag \"" + strings.Repeat("x", 64) + "\" no state", "pass out all tag owner no state",
		"pass out all tag \"owner\" no state # ignore", "pass out all tag \"unterminated no state",
		"pass out all no state\r", "pass out all\x00 no state", "pass out all tag \"ownér\" no state",
		"anchor \"../foreign\" out all", "anchor \"/com.apple//foreign\" out all", "anchor \"/com.apple/./foreign\" out all",
		"anchor \"foreign\" in all", "anchor \"foreign\" out quick all", "anchor \"foreign/*\" out all",
		"pass out inet proto udp to 192.0.2.1 keep state (if-bound)", "pass out inet proto udp to 192.0.2.1 keep state (floating floating)",
	} {
		t.Run(source, func(t *testing.T) {
			if rules, err := desktopPFCompileFilters(source); err == nil || rules != nil {
				t.Fatal("native filter compiler accepted unsupported or weakened policy", rules, err)
			}
		})
	}
}

func TestDesktopPFFilterCompleteInputBounds(t *testing.T) {
	for _, source := range []string{
		strings.Repeat(" ", 512*1024+1), strings.Repeat(" ", 4097),
		strings.Repeat("block drop out all\n", desktopPFFilterLimit+1),
		"block drop out to { " + strings.Repeat("192.0.2.1, ", 32) + "192.0.2.1 }\n",
	} {
		if rules, err := desktopPFCompileFilters(source); err == nil || rules != nil {
			t.Fatal("native filter compiler exceeded its explicit record/input bound", len(rules), err)
		}
	}
	if rules, err := desktopPFCompileFilters(strings.Repeat("block drop out all\n", desktopPFFilterLimit)); err != nil || len(rules) != desktopPFFilterLimit {
		t.Fatal("native filter compiler rejected its inclusive complete rule bound", len(rules), err)
	}
}
