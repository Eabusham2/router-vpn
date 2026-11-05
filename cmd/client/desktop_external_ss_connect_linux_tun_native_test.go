//go:build linux && routervpn_controller_privileged

package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"strings"
	"testing"
)

// Six original entry/final families, both retained protection lifecycles, and
// independently observed original entry authentication and final CONNECT TLS.
var linuxHostTUNExternalSSCONNECTCases = func() []string {
	var cases []string
	for _, method := range []string{"128", "256", "chacha"} {
		for _, protocol := range []string{"http", "https"} {
			cases = append(cases, "external-ss"+method+protocol+"-on-connect")
		}
	}
	for _, protocol := range []string{"http", "https"} {
		for _, action := range []string{"always", "always-off"} {
			cases = append(cases, "external-ss256"+protocol+"-"+action)
		}
	}
	for _, action := range []string{"public", "cancelled", "source", "entry-source", "replacement", "wrong-entry-public", "wrong-entry-key", "wrong-entry-method", "wrong-proxy-username", "wrong-proxy-password", "wrong-proxy-sni", "wrong-proxy-trust", "dns-failure"} {
		cases = append(cases, "external-ss256https-"+action)
	}
	return cases
}()

func linuxHostTUNExternalSSCONNECT(scenario string) bool {
	for _, candidate := range linuxHostTUNExternalSSCONNECTCases {
		if scenario == candidate {
			return true
		}
	}
	return false
}
func linuxHostTUNSSCONNECTProtocol(scenario string) string {
	if !linuxHostTUNExternalSSCONNECT(scenario) {
		return ""
	}
	token, _, _ := strings.Cut(strings.TrimPrefix(scenario, "external-ss"), "-")
	if strings.HasSuffix(token, "https") {
		return "https-connect"
	}
	return "http-connect"
}
func linuxHostTUNPrepareSSCONNECTPeer(t *testing.T, peer *linuxExternalTUNPeer, scenario string) {
	t.Helper()
	token, _, _ := strings.Cut(strings.TrimPrefix(scenario, "external-ss"), "-")
	token = strings.TrimSuffix(strings.TrimSuffix(token, "https"), "http")
	method := linuxHostTUNSSMethod(token)
	if method == "" || peer.protocol != linuxHostTUNSSCONNECTProtocol(scenario) {
		t.Fatal("unknown original SS CONNECT pair")
	}
	peer.ssEntry = &linuxExternalTUNSSPair{entryMethod: method, entryPassword: linuxHostTUNSSKey(t, method)}
}
func linuxHostTUNExternalSSCONNECTAuthority(native *desktopNodeLaunch) error {
	bad := errors.New("Linux SS CONNECT lost original TCP-only entry or final policy")
	if native == nil || native.external == nil || !desktopExternalSSEntryOwner(native.external) || native.external.physical == nil {
		return bad
	}
	o := native.external
	protocol := o.profile.External.Protocol
	if protocol != "http-connect" && protocol != "https-connect" {
		return bad
	}
	c, err := o.physical.Capture()
	if err != nil || c.Protocol != protocol || c.EntryID != o.entry.ID || c.StartLayer != "" || c.UDPAvailable || len(c.PhysicalRoots) != 1 || c.SelectedDNS.Physical || c.SelectedDNS.Type != "tcp" || c.SelectedDNS.Detour != mobilemultihop.ExternalFinalTag {
		return bad
	}
	root := c.PhysicalRoots[0]
	entry := o.entry.External.Shadowsocks
	if root.Type != "shadowsocks" || root.Tag != "external-entry" || len(root.Networks) != 1 || root.Networks[0] != "tcp" || len(root.Destinations) != 1 {
		return bad
	}
	d := root.Destinations[0]
	if d.Network != "tcp" || d.Host != entry.Server || d.Port != entry.Port {
		return bad
	}
	final := o.profile.External.HTTPConnect
	if protocol == "https-connect" {
		final = o.profile.External.HTTPSConnect
	}
	if final == nil {
		return bad
	}
	var original, derived map[string]any
	if json.Unmarshal([]byte(o.physical.OriginalPolicy().Config()), &original) != nil || json.Unmarshal([]byte(o.physical.Config()), &derived) != nil {
		return bad
	}
	old, _ := original["outbounds"].([]any)
	current, _ := derived["outbounds"].([]any)
	if len(current) != 3 {
		return bad
	}
	e, f := taggedRuntimeItem(current, "external-entry"), taggedRuntimeItem(current, mobilemultihop.ExternalFinalTag)
	if e == nil || f == nil || e["detour"] != mobilemultihop.DesktopExternalPhysicalTag || e["server"] != entry.Server || e["server_port"] != float64(entry.Port) || e["method"] != entry.Method || e["password"] != entry.Password || f["detour"] != "external-entry" || f["server"] != final.Host || f["server_port"] != float64(final.Port) || f["username"] != final.Username || f["password"] != final.Password || !reflect.DeepEqual(f, taggedRuntimeItem(old, mobilemultihop.ExternalFinalTag)) {
		return bad
	}
	if protocol == "https-connect" {
		tls, ok := f["tls"].(map[string]any)
		if !ok || tls["enabled"] != true || tls["server_name"] != final.TLSServerName {
			return bad
		}
	}
	delete(e, "detour")
	if !reflect.DeepEqual(e, taggedRuntimeItem(old, "external-entry")) {
		return bad
	}
	return nil
}
func TestDesktopLinuxInstalledSSCONNECTFixtureKeepsCompiledAuthority(t *testing.T) {
	for _, method := range desktopSSEntryMethods {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			t.Run(method+"/"+protocol, func(t *testing.T) {
				_, _, launch := desktopSSCONNECTFixture(t, "always", method, protocol)
				if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
					t.Fatal(err)
				}
				if err := linuxHostTUNExternalSSCONNECTAuthority(launch); err != nil {
					t.Fatal("actual compiled SS CONNECT lost original authority", err)
				}
				entry, final := launch.external.entry, launch.external.profile
				for _, fault := range []string{"entry-key", "entry-host", "final-key", "final-user", "final-host", "final-tls", "layer", "udp-dns"} {
					launch.external.entry, launch.external.profile = cloneRouterProfile(entry), cloneRouterProfile(final)
					p := &launch.external.profile
					e := &launch.external.entry
					switch fault {
					case "entry-key":
						e.External.Shadowsocks.Password = desktopSSEntryKey(method, 'z')
					case "entry-host":
						e.External.Shadowsocks.Server = "192.0.2.99"
					case "final-key":
						mutateSSCONNECTFinal(p, "password")
					case "final-user":
						mutateSSCONNECTFinal(p, "username")
					case "final-host":
						mutateSSCONNECTFinal(p, "host")
					case "final-tls":
						if protocol != "https-connect" {
							continue
						}
						mutateSSCONNECTFinal(p, "tls")
					case "layer":
						p.StartLayer = common.StartLayerAES256GCM
					case "udp-dns":
						p.DNSProtocol = "udp"
					}
					if fault == "udp-dns" {
						if validateDesktopLinuxExternalSource(*p, launch, *e) == nil {
							t.Fatal("changed selected DNS admitted")
						}
					} else if linuxHostTUNExternalSSCONNECTAuthority(launch) == nil {
						t.Fatal("CONNECT authority accepted changed source", fault)
					}
				}
				launch.external.entry, launch.external.profile = entry, final
				if err := linuxHostTUNExternalSSCONNECTAuthority(launch); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
