package mobiletor

import (
	"net/netip"
	"strings"
	"testing"
)

func TestDesktopPFIsolatedGuardSurvivesMissingGeneration(t *testing.T) {
	capture := desktopSocketFixtureCapture()
	uid := uint32(0x40000001)
	for _, scope := range []string{"", "to { 127.78.1.10, 127.78.1.11 }"} {
		baseline, err := desktopPFCompileFilters(desktopPFIsolatedBaseline(capture.SessionID))
		if err != nil || len(baseline) != 1 || baseline[0].Action != "anchor" || baseline[0].Anchor != "p"+capture.SessionID {
			t.Fatal("Off baseline acquired whole-host traffic authority", baseline, err)
		}
		pointer := desktopPFIsolatedPointer(capture, "com.apple/000.router-vpn/g-original", uid, scope)
		rules, err := desktopPFCompileFilters(pointer)
		if err != nil {
			t.Fatal(err)
		}
		anchor, resets, guards := -1, 0, 0
		for index, rule := range rules {
			if _, err := desktopPFNativeProject(rule); err != nil {
				t.Fatal("Off slot escaped qualified finite native projection", err)
			}
			if rule.Action == "anchor" {
				if anchor != -1 || rule.Anchor != "/com.apple/000.router-vpn/g-original" {
					t.Fatal("Off slot substituted captured generation", rule)
				}
				anchor = index
				continue
			}
			if !rule.User || rule.UID != uid || rule.Protocol != 6 && rule.Protocol != 17 || rule.KeepState {
				t.Fatal("Off slot acquired another UID, transport or state owner", rule)
			}
			if rule.Action == "pass" {
				if anchor != -1 || rule.Tag == "" || rule.Quick || rule.Protocol == 6 && !rule.FlagsAny {
					t.Fatal("Off reset can admit before captured generation", rule)
				}
				resets++
			} else if rule.Action == "block" {
				if anchor == -1 || !rule.Quick || !rule.MatchTagNot || rule.MatchTag == "" {
					t.Fatal("Off missing generation has no retained UID deny", rule)
				}
				guards++
			} else {
				t.Fatal("Off slot acquired unknown authority", rule)
			}
		}
		if resets < 2 || guards != resets || anchor < 2 {
			t.Fatal("Off slot lost an independent TCP/UDP guard", pointer)
		}
	}
}

func TestDesktopPFIsolatedStatesPreserveUnrelatedHost(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.10:41001")
	foreign := "all udp 192.0.2.10:41002 -> 198.51.100.1:53 MULTIPLE:MULTIPLE\n" +
		"en0 tcp 192.0.2.10:41001 -> 198.51.100.2:443 ESTABLISHED:ESTABLISHED\n" +
		"all udp 2001:db8::10[41001] <- 2001:db8:1::1[53] SINGLE:NO_TRAFFIC\n"
	if err := desktopPFIsolatedStatesAbsent([]byte(foreign), "udp", local); err != nil {
		t.Fatal("Off refused unrelated host state instead of its original socket", err)
	}
	for _, line := range []string{
		"all udp 192.0.2.10:41001 -> 198.51.100.99:9999 SINGLE:NO_TRAFFIC",
		"en0 udp 198.51.100.99:9999 <- 192.0.2.10:41001 MULTIPLE:MULTIPLE",
		"all udp 10.0.0.1:53 (192.0.2.10:41001) -> 198.51.100.99:53 MULTIPLE:MULTIPLE",
		"all udp 0.0.0.0:0 -> 198.51.100.99:53 MULTIPLE:MULTIPLE",
		"all udp 0.0.0.0:41001 -> 198.51.100.99:53 MULTIPLE:MULTIPLE",
		"all udp 192.0.2.10:41001 -> 0.0.0.0:0 MULTIPLE:MULTIPLE",
		"all udp [::ffff:192.0.2.10]:41001 -> 198.51.100.99:53 MULTIPLE:MULTIPLE",
	} {
		if desktopPFIsolatedStatesAbsent([]byte(foreign+line), "udp", local) == nil {
			t.Fatal("Off accepted stale state matching its original local endpoint", line)
		}
	}
	if desktopPFIsolatedStatesAbsent([]byte("all tcp 2001:db8::2[1234] <- 2001:db8:1::1[443] ESTABLISHED:ESTABLISHED"), "tcp", netip.MustParseAddrPort("[2001:db8::2]:1234")) == nil {
		t.Fatal("Off omitted native IPv6 state endpoint")
	}
	if desktopPFIsolatedStatesAbsent([]byte("all udp fe80::2%en0[1234] <- fe80::1%en0[53] MULTIPLE:MULTIPLE"), "udp", netip.MustParseAddrPort("[fe80::2]:1234")) == nil {
		t.Fatal("Off omitted scoped native IPv6 state endpoint")
	}
	for _, malformed := range []string{"partial", "all udp 192.0.2.10 -> 198.51.100.1:53 MULTIPLE:MULTIPLE", "all udp 192.0.2.10:53 -> missing MULTIPLE:MULTIPLE", "all unknown 192.0.2.10:53 -> 198.51.100.1:53 MULTIPLE:MULTIPLE", strings.Repeat("x", (2<<20)+1)} {
		if desktopPFIsolatedStatesAbsent([]byte(malformed), "udp", local) == nil {
			t.Fatal("Off converted incomplete state readback into absence")
		}
	}
	for _, field := range []string{"(192.0.2.10:41002", "192.0.2.10:41002)", "((192.0.2.10:41002))", "()", "[2001:db8::10:41002", "2001:db8::10[41002", "2001:db8::10]41002[", "[2001:db8::10]]:41002"} {
		line := "all udp " + field + " -> 198.51.100.1:53 MULTIPLE:MULTIPLE"
		if desktopPFIsolatedStatesAbsent([]byte(line), "udp", local) == nil {
			t.Fatal("Off converted malformed alias or bracket syntax to absence", line)
		}
	}
	for _, invalid := range []netip.AddrPort{{}, netip.MustParseAddrPort("0.0.0.0:41001"), netip.MustParseAddrPort("192.0.2.10:0")} {
		if desktopPFIsolatedStatesAbsent(nil, "udp", invalid) == nil {
			t.Fatal("Off accepted unbound or missing original socket")
		}
	}
}
