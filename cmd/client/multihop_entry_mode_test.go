package main

import (
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestNativeMultihopEntryModeSelectionKeepsExactControlAndLegacyBase(t *testing.T) {
	control := common.RouterProfile{BaseTunnel: "wg", MultihopEntryMode: "reality-xhttp"}
	entry := common.RouterProfile{BaseTunnel: "awg", MultihopEntryMode: "max-quic-awg"}
	mode, base, err := resolveNativeMultihopEntryMode(control, entry, "", "")
	if err != nil || mode != "reality-xhttp" || base != "native" {
		t.Fatal("saved graph mode was replaced by the hop's separate graph", mode, base, err)
	}
	for _, requested := range mobilemultihop.NodeMultihopEntryModes() {
		mode, base, err := resolveNativeMultihopEntryMode(control, entry, requested, "wg")
		if err != nil || mode != requested || base != desktopExternalEntryBase(requested) {
			t.Fatal("explicit raw mode was replaced by legacy base or saved graph", requested, mode, base, err)
		}
	}
	control.MultihopEntryMode = ""
	mode, base, err = resolveNativeMultihopEntryMode(control, entry, "", "auto")
	if err != nil || mode != "" || base != "awg" {
		t.Fatal("legacy AWG source discovery was replaced by a guessed variant", mode, base, err)
	}
	mode, base, err = resolveNativeMultihopEntryMode(control, entry, "", "wg")
	if err != nil || mode != "" || base != "wg" {
		t.Fatal("explicit legacy base lost its precedence", mode, base, err)
	}
	for _, bad := range []string{"native", "tor", "WG", " wg", "wireguard"} {
		if _, _, err := resolveNativeMultihopEntryMode(control, entry, "wg", bad); err == nil {
			t.Fatal("invalid legacy request base admitted", bad)
		}
	}
	for _, bad := range []string{"auto", "naive", "WG", " wg", "reality-xhttp ", "not-real"} {
		if _, _, err := resolveNativeMultihopEntryMode(control, entry, bad, ""); err == nil {
			t.Fatal("malformed raw entry gained a fallback", bad)
		}
		control.MultihopEntryMode = bad
		if _, _, err := resolveNativeMultihopEntryMode(control, entry, "", ""); err == nil {
			t.Fatal("malformed saved graph gained a fallback", bad)
		}
	}
}
