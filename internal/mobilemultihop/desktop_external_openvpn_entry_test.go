package mobilemultihop

import (
	"reflect"
	"router-vpn/internal/nativeopenvpn"
	"strings"
	"testing"
)

func desktopExternalOpenVPNEntryInput(t *testing.T, network, final string) (map[string]any, map[string]any) {
	t.Helper()
	graph, capture := externalTestFixture(t, final, "wireguard")
	externalOpenVPNReplace(t, graph, capture, true, network)
	private := capture["entry"].(map[string]any)["external"].(map[string]any)["openvpn"].(map[string]any)
	private["config"] = strings.Replace(private["config"].(string), "remote 2001:db8::24 443\n", "", 1)
	native, err := nativeopenvpn.CompileEndpoint(private["config"].(string), private["username"].(string), private["password"].(string), "external-entry", "")
	if err != nil {
		t.Fatal(err)
	}
	graph["endpoints"] = []any{startObject(t, native)}
	capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
	return graph, capture
}
func TestDesktopExternalOpenVPNEntryExactLinuxScope(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		graph, capture := desktopExternalOpenVPNEntryInput(t, network, "shadowsocks")
		original := externalDesktopCompile(t, graph, capture)
		for _, target := range []string{"linux", "darwin", "windows"} {
			p, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, target)
			if target != "linux" {
				if err == nil {
					t.Fatal("entry acquired unimplemented target", target)
				}
				continue
			}
			if err != nil || p.ValidateLinuxControlledAdmission() != nil {
				t.Fatal("exact Linux OpenVPN/SS pair rejected", err)
			}
			c, err := p.Capture()
			if err != nil || c.EntryID != "saved-entry" || len(c.PhysicalRoots) != 1 || c.PhysicalRoots[0].Type != "openvpn-client" || len(c.PhysicalRoots[0].Destinations) != 1 || c.PhysicalRoots[0].Destinations[0].Network != network || c.SelectedDNS.Physical || c.SelectedDNS.Detour != ExternalFinalTag {
				t.Fatal("composition changed root/DNS authority", err, c)
			}
			source, lower := externalTestRead(t, original.Config()), externalTestRead(t, p.Config())
			if !reflect.DeepEqual(externalTestFind(t, source, ExternalFinalTag), externalTestFind(t, lower, ExternalFinalTag)) {
				t.Fatal("SS final changed while deriving physical root")
			}
		}
	}
	for _, final := range []string{"http-connect", "https-connect", "hysteria2", "socks5"} {
		graph, capture := desktopExternalOpenVPNEntryInput(t, "tcp", final)
		original := externalDesktopCompile(t, graph, capture)
		if _, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, "linux"); err == nil {
			t.Fatal("unproved OpenVPN entry final admitted", final)
		}
	}
	graph, capture := externalTestFixture(t, "shadowsocks", "wireguard")
	externalOpenVPNReplace(t, graph, capture, true, "tcp")
	capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
	if _, err := NewDesktopExternalPolicy(externalDesktopCompile(t, graph, capture), desktopExternalTestSession, "linux"); err == nil {
		t.Fatal("multi-remote entry crossed single-remote native gate")
	}
}
