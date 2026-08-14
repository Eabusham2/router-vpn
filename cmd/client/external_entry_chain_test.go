package main

import (
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func taggedRuntimeItem(items []any, tag string) map[string]any {
	for _, item := range items {
		m, _ := item.(map[string]any)
		if m != nil && m["tag"] == tag {
			return m
		}
	}
	return nil
}

func TestExternalEntryChainsToEverySingBoxStandardExit(t *testing.T) {
	control := common.RouterProfile{DNSMode: "fastest", FastestDNSHost: "1.1.1.1", EffectiveMTU: 1320}
	protocols := []string{"wireguard", "socks5", "shadowsocks", "hysteria2"}
	for _, entryProtocol := range protocols {
		for _, exitProtocol := range protocols {
			t.Run(entryProtocol+"-to-"+exitProtocol, func(t *testing.T) {
				entry := validTestStandardExit(entryProtocol)
				entry.ID = "entry-test"
				exit := validTestStandardExit(exitProtocol)
				exit.ID = "exit-test"
				cfg, err := buildExternalEntryStandardExitConfig(control, entry, exit)
				if err != nil { t.Fatal(err) }
				if cfg["route"].(map[string]any)["final"] != "custom-exit" { t.Fatalf("unexpected final route: %#v", cfg["route"]) }
				endpoints := cfg["endpoints"].([]any)
				outbounds := cfg["outbounds"].([]any)
				entryItem := taggedRuntimeItem(endpoints, "external-entry")
				if entryItem == nil { entryItem = taggedRuntimeItem(outbounds, "external-entry") }
				if entryItem == nil { t.Fatalf("external entry tag missing: endpoints=%#v outbounds=%#v", endpoints, outbounds) }
				exitItem := taggedRuntimeItem(endpoints, "custom-exit")
				if exitItem == nil { exitItem = taggedRuntimeItem(outbounds, "custom-exit") }
				if exitItem == nil || exitItem["detour"] != "external-entry" { t.Fatalf("final exit does not detour through external entry: %#v", exitItem) }
				dns := cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["detour"] != "custom-exit" { t.Fatalf("DNS escaped final external exit: %#v", dns) }
			})
		}
	}
}

func TestExternalOpenVPNEntryFailsClosed(t *testing.T) {
	entry := validTestStandardExit("openvpn")
	if _, _, _, err := externalEntryGraph(entry); err == nil || !strings.Contains(err.Error(), "not yet as an upstream hop") {
		t.Fatalf("external OpenVPN entry must fail closed, got %v", err)
	}
}

func TestOpenVPNBridgeCanUseExternalStandardEntries(t *testing.T) {
	for _, protocol := range []string{"wireguard", "socks5", "shadowsocks", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			entry := validTestStandardExit(protocol)
			cfg, err := externalEntryBridgeConfig(entry, openVPNEntrySOCKSPort)
			if err != nil { t.Fatal(err) }
			inbounds := cfg["inbounds"].([]any)
			if len(inbounds) != 1 || inbounds[0].(map[string]any)["listen"] != "127.0.0.1" { t.Fatalf("bridge is not loopback-only: %#v", inbounds) }
			final, _ := cfg["route"].(map[string]any)["final"].(string)
			if final != "external-entry" && final != "external-entry-egress" { t.Fatalf("unexpected bridge final: %q", final) }
			if final == "external-entry-egress" {
				out := taggedRuntimeItem(cfg["outbounds"].([]any), final)
				if out == nil || out["detour"] != "external-entry" { t.Fatalf("WireGuard bridge does not detour through entry endpoint: %#v", out) }
			}
		})
	}
}
