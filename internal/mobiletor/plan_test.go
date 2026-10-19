package mobiletor

import (
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

const obfs4Bridge = "obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0"
const meekBridge = "meek_lite 192.0.2.2:2 url=https://bridge.example/ front=front.example"

func TestPlanUsesSharedBridgeGrammarAndOnlyOwnedListeners(t *testing.T) {
	config := common.ExternalTorBridgeConfig{Transport: "custom", Bridges: []string{"Bridge " + obfs4Bridge, meekBridge}}
	original := append([]string(nil), config.Bridges...)
	plan, err := NewPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.Bridges, original) {
		t.Fatal("caller profile mutated")
	}
	args, err := plan.Arguments("/private/tor", map[string]string{"obfs4": "127.0.0.1:18001", "meek_lite": "127.0.0.1:18002"})
	if err != nil {
		t.Fatal(err)
	}
	wanted := []string{"--UseBridges", "1", "--ClientTransportPlugin", "meek_lite socks5 127.0.0.1:18002", "--ClientTransportPlugin", "obfs4 socks5 127.0.0.1:18001", "--Bridge", obfs4Bridge}
	joined := strings.Join(args, "\x00")
	for i := 0; i < len(wanted); i += 2 {
		if !strings.Contains(joined, wanted[i]+"\x00"+wanted[i+1]) {
			t.Fatalf("missing generated option %s", wanted[i])
		}
	}
	if strings.Contains(joined, " exec ") || strings.Contains(joined, "ControlPort\x00auto") {
		t.Fatal("process helper or TCP control port escaped into native Tor arguments")
	}
	for _, listeners := range []map[string]string{
		{"obfs4": "127.0.0.1:18001"},
		{"obfs4": "0.0.0.0:18001", "meek_lite": "127.0.0.1:18002"},
		{"obfs4": "127.0.0.1:18001", "meek_lite": "127.0.0.1:18001"},
		{"obfs4": "127.0.0.1:18001 exec evil", "meek_lite": "127.0.0.1:18002"},
	} {
		if _, err := plan.Arguments("/private/tor", listeners); err == nil {
			t.Fatal("unowned listener accepted")
		}
	}
	plan.Bridges[0].Line += "\nSocksPort 0.0.0.0:9050"
	if _, err := plan.Arguments("/private/tor", map[string]string{"obfs4": "127.0.0.1:18001", "meek_lite": "127.0.0.1:18002"}); err == nil {
		t.Fatal("mutated bridge plan injected torrc")
	}
}

func TestPlanRejectsUnsafeImportsBeforeNativeStartup(t *testing.T) {
	for _, bridge := range []string{obfs4Bridge + "\nRunAsDaemon 1", "exec /tmp/tor", "obfs4 127.0.0.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=x", obfs4Bridge + " plugin=/tmp/a"} {
		if _, err := NewPlan(common.ExternalTorBridgeConfig{Bridges: []string{bridge}}); err == nil {
			t.Fatal("unsafe bridge imported")
		}
	}
}
