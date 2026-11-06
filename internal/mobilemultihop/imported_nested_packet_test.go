package mobilemultihop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"router-vpn/internal/mobilemtu"
	"strconv"
	"testing"
)

func importedNestedPacketFixture(t *testing.T, protocol, mode, a, b string) []string {
	args := importedPacketFixture(t, protocol, "shadowsocks", a, "")
	final := importedPacketFinalFixture(t, "shadowsocks", NativeStartLayerMethod, mode, "", b)
	copy(args[2:6], final[2:6])
	g := externalTestRead(t, args[0])
	externalTestFind(t, g, ExternalFinalTag)["mtu"] = 1500
	args[0] = externalTestJSON(t, g)
	c := externalTestRead(t, args[1])
	c["profile"].(map[string]any)["external"].(map[string]any)[protocol].(map[string]any)["mtu"] = 1500
	args[1] = externalTestJSON(t, c)
	return args
}

func TestImportedEntryNestedPacketCompleteGraphs(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			for _, a := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, b := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					name := "packet-" + protocol + "--final-" + mode + "--" + a + "--" + b
					t.Run(name, func(t *testing.T) {
						normal := func(s string) string {
							if s == "off" {
								return ""
							}
							return s
						}
						args := importedNestedPacketFixture(t, protocol, mode, normal(a), normal(b))
						p := importedPacketCompile(t, args)
						g := externalTestRead(t, p.Config())
						entry := externalTestFind(t, g, "entry-wg")
						final := externalTestFind(t, g, LocalTag)
						if entry["mtu"] != float64(1500) || p.meta.PacketMTUState != "configured-unmeasured" {
							t.Fatal("original entry or unmeasured bound lost")
						}
						if p.meta.ExitPacketEffectiveMTU != strconv.Itoa(int(final["mtu"].(float64))) {
							t.Fatal("effective endpoint bound metadata differs from compiled graph")
						}
						if p.meta.EntryAPI != "" || p.meta.EntryNodeID != "" || p.meta.ExitNodeID == "" {
							t.Fatal("independent proof authority lost")
						}
						original := externalTestFind(t, externalTestRead(t, args[0]), ExternalFinalTag)
						for _, key := range []string{"private_key", "address", "amnezia"} {
							if !reflect.DeepEqual(entry[key], original[key]) {
								t.Fatal("entry identity changed", key)
							}
						}
						tun := g["inbounds"].([]any)[0].(map[string]any)
						actual := int(tun["mtu"].(float64))
						mtu, err := mobilemtu.NewPlan(p.Config(), actual)
						if err != nil {
							t.Fatal(err)
						}
						if mtu.Ceiling > int(final["mtu"].(float64)) {
							t.Fatal("MTU optimizer can escape endpoint cap")
						}
						// A malicious endpoint expansion cannot be hidden by the small TUN or
						// the authenticated wrapper; reject it before any native construction.
						final["mtu"] = 9000
						if _, err = mobilemtu.NewPlan(externalTestJSON(t, g), actual); err == nil {
							t.Fatal("expanded endpoint envelope admitted")
						}
						if root := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); root != "" {
							data, _ := json.Marshal(append(args, p.SourceSHA256(), p.Config()))
							if err = os.WriteFile(filepath.Join(root, name+".json"), data, 0600); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		}
	}
}

func TestImportedEntryNestedPacketRefusesInsufficientEntry(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		args := importedNestedPacketFixture(t, "wireguard", mode, "", "aes-256-gcm")
		g := externalTestRead(t, args[0])
		externalTestFind(t, g, ExternalFinalTag)["mtu"] = 1280
		args[0] = externalTestJSON(t, g)
		c := externalTestRead(t, args[1])
		c["profile"].(map[string]any)["external"].(map[string]any)["wireguard"].(map[string]any)["mtu"] = 1280
		args[1] = externalTestJSON(t, c)
		if _, err := NewImportedEntry(args[0], args[1], args[2], args[3], args[4], args[5], args[6]); err == nil {
			t.Fatal("undersized captured entry admitted", mode)
		}
	}
}
