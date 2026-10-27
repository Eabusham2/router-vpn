package mobiletor

import (
	"strings"
	"testing"
)

func TestDesktopBridgeDNSSelectionMatchesTheNativeCapturedGraph(t *testing.T) {
	entry, _ := desktopEntryFixture(t, "wg", "", nil)
	for _, mode := range []string{"home", "custom"} {
		for _, transport := range []string{"udp", "tcp", "tls", "https", "h3"} {
			t.Run(mode+"/"+transport, func(t *testing.T) {
				exit := desktopEntryExit(entry)
				exit["dns_mode"], exit["dns_protocol"], exit["dns_host"] = mode, transport, "9.9.9.9"
				exit["dns_port"], exit["dns_server_name"], exit["dns_path"] = 5353, "selected.example", "/selected?node=one"
				if mode == "home" {
					exit["dns_host"] = "10.80.0.53"
				}
				source := torHostEncode(t, exit)
				selected, err := SelectDesktopBridgeDNS(source, entry.Profile(), false)
				policy, compileErr := NewDesktopBridgePolicyWithPredecessor(source, desktopSession, desktopIsolation, "linux", entry)
				if mode == "custom" && (transport == "udp" || transport == "h3") {
					if err == nil || compileErr == nil {
						t.Fatal("Tor circuit acquired a datagram resolver")
					}
					return
				}
				if err != nil || compileErr != nil || selected != policy.Metadata().DNS || selected.Transport != transport || selected.Port != 5353 {
					t.Fatal("editor/runtime resolver differs from the actual native graph", selected, err, compileErr)
				}
			})
		}
	}
}

func TestDesktopBridgeDNSRejectsAnotherPrivateEntryAndKeepsIdleHomeUnresolved(t *testing.T) {
	entry, _ := desktopEntryFixture(t, "wg", "", nil)
	for _, fault := range []string{"wrong-entry", "wrong-exit", "same-node", "missing-entry", "direct-entry", "server-no-entry", "compare", "no-token", "public-api", "different-home", "public-home", "unpaired-home", "malformed-entry"} {
		t.Run(fault, func(t *testing.T) {
			exit := desktopEntryExit(entry)
			exit["dns_mode"], exit["dns_protocol"], exit["dns_host"] = "home", "udp", "10.80.0.53"
			entryJSON := entry.Profile()
			switch fault {
			case "wrong-entry":
				exit["multihop_entry_id"] = "replacement"
			case "wrong-exit":
				exit["multihop_exit_id"] = "replacement"
			case "same-node":
				exit["id"], exit["multihop_exit_id"] = entry.ID(), entry.ID()
			case "missing-entry":
				entryJSON = ""
			case "direct-entry":
				exit["multihop_enabled"] = false
			case "server-no-entry":
				exit["multihop_execution"], entryJSON = "server", ""
			case "compare":
				exit["multihop_execution"] = fault
			case "no-token":
				entryJSON = strings.Replace(entryJSON, "entry-private-token", "", 1)
			case "public-api":
				entryJSON = strings.Replace(entryJSON, "http://10.80.0.1:8787", "http://1.1.1.1:8787", 1)
			case "different-home":
				exit["dns_host"] = "192.168.44.53"
			case "public-home":
				exit["dns_host"] = "1.1.1.1"
			case "unpaired-home":
				entryJSON = strings.Replace(entryJSON, "10.80.0.53", "", 1)
			case "malformed-entry":
				entryJSON = "{}"
			}
			if _, err := SelectDesktopBridgeDNS(torHostEncode(t, exit), entryJSON, true); err == nil {
				t.Fatal("unowned Home DNS was accepted", fault)
			}
		})
	}
	exit := desktopProfile()
	exit["dns_mode"], exit["dns_protocol"], exit["dns_host"] = "home", "udp", ""
	selected, err := SelectDesktopBridgeDNS(torHostEncode(t, exit), "", true)
	if err != nil || selected.Address != "" || selected.Transport != "udp" {
		t.Fatal("idle Home acquired a public replacement", selected, err)
	}
	if _, err := SelectDesktopBridgeDNS(torHostEncode(t, exit), "", false); err == nil {
		t.Fatal("idle Home intent granted a runnable direct Tor resolver")
	}
}
