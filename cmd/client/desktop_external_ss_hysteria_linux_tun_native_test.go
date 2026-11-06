//go:build linux && routervpn_controller_privileged

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"strings"
	"testing"
)

// Six original entry/final families, both retained protection lifecycles, and
// independently observed original entry authentication and final HY2 TLS.
var linuxHostTUNExternalSSHysteriaCases = append([]string{
	"external-ss128hy2-on-connect",
	"external-ss256hy2-on-connect",
	"external-sschachahy2-on-connect",
	"external-ss256hy2-always",
	"external-ss256hy2-always-off",
	"external-ss256hy2-public",
	"external-ss256hy2-cancelled",
	"external-ss256hy2-source",
	"external-ss256hy2-entry-source",
	"external-ss256hy2-replacement",
	"external-ss256hy2-wrong-entry-public",
	"external-ss256hy2-wrong-entry-key",
	"external-ss256hy2-wrong-entry-method",
	"external-ss256hy2-wrong-key",
	"external-ss256hy2-wrong-ca",
	"external-ss256hy2-wrong-trust",
	"external-ss256hy2-dns-failure",
}, linuxHostTUNSSHysteriaLayerCases...)

var linuxHostTUNSSHysteriaLayerCases = func() []string {
	var result []string
	for a := 0; a < 3; a++ {
		for b := 0; b < 3; b++ {
			result = append(result, fmt.Sprintf("external-ss256hy2l%d%d-on-connect", a, b))
		}
	}
	for _, action := range []string{"always", "always-off", "cancelled", "source", "entry-source", "replacement", "dns-failure", "wrong-entry-public", "wrong-entry-layer", "wrong-final-layer", "entry-whitening", "final-whitening"} {
		result = append(result, "external-ss256hy2l22-"+action)
	}
	return result
}()

func linuxHostTUNExternalSSHysteria(scenario string) bool {
	for _, candidate := range linuxHostTUNExternalSSHysteriaCases {
		if scenario == candidate {
			return true
		}
	}
	return false
}
func linuxHostTUNPrepareSSHysteriaPeer(t *testing.T, peer *linuxExternalTUNPeer, scenario string) {
	t.Helper()
	token, _, _ := strings.Cut(strings.TrimPrefix(scenario, "external-ss"), "-")
	token, a, b, layered := linuxHostTUNSSLayerToken(token)
	token = strings.TrimSuffix(token, "hy2")
	method := linuxHostTUNSSMethod(token)
	if method == "" || peer.protocol != "hysteria2" {
		t.Fatal("unknown original SS HY2 pair")
	}
	peer.ssEntry = &linuxExternalTUNSSPair{entryMethod: method, entryPassword: linuxHostTUNSSKey(t, method)}
	if layered {
		peer.ssEntry.entryLayer = linuxSSLayerSelection{mode: linuxHostTUNSSLayerMode(a), key: linuxHostTUNSSKey(t, common.StartLayerAES256GCMTransport)}
		peer.ssEntry.finalLayer = linuxSSLayerSelection{mode: linuxHostTUNSSLayerMode(b), key: linuxHostTUNSSKey(t, common.StartLayerAES256GCMTransport)}
	}
}
func linuxHostTUNExternalSSHysteriaAuthority(native *desktopNodeLaunch) error {
	bad := errors.New("Linux SS HY2 lost original TCP/UDP entry or final policy")
	if native == nil || native.external == nil || !desktopExternalSSEntryOwner(native.external) || native.external.physical == nil {
		return bad
	}
	o := native.external
	if o.entry.External.StartLayer != nil || o.profile.External.StartLayer != nil {
		return linuxHostTUNSSLayerAuthority(native)
	}
	protocol := o.profile.External.Protocol
	if protocol != "hysteria2" {
		return bad
	}
	c, err := o.physical.Capture()
	if err != nil || c.Protocol != protocol || c.EntryID != o.entry.ID || c.StartLayer != "" || !c.UDPAvailable || len(c.PhysicalRoots) != 1 || c.SelectedDNS.Physical || c.SelectedDNS.Type != "udp" || c.SelectedDNS.Detour != mobilemultihop.ExternalFinalTag {
		return bad
	}
	root := c.PhysicalRoots[0]
	entry := o.entry.External.Shadowsocks
	if root.Type != "shadowsocks" || root.Tag != "external-entry" || len(root.Networks) != 2 || len(root.Destinations) != 2 {
		return bad
	}
	seen := map[string]bool{}
	for _, d := range root.Destinations {
		if d.Network != "tcp" && d.Network != "udp" || seen[d.Network] || d.Host != entry.Server || d.Port != entry.Port {
			return bad
		}
		seen[d.Network] = true
	}
	final := o.profile.External.Hysteria2
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
	if e == nil || f == nil || e["detour"] != mobilemultihop.DesktopExternalPhysicalTag || e["server"] != entry.Server || e["server_port"] != float64(entry.Port) || e["method"] != entry.Method || e["password"] != entry.Password || f["detour"] != "external-entry" || f["server"] != final.Server || f["server_port"] != float64(final.Port) || f["password"] != final.Password || !reflect.DeepEqual(f, taggedRuntimeItem(old, mobilemultihop.ExternalFinalTag)) {
		return bad
	}
	if protocol == "hysteria2" {
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
func TestDesktopLinuxInstalledSSHysteriaFixtureKeepsCompiledAuthority(t *testing.T) {
	for a := 0; a < 3; a++ {
		for b := 0; b < 3; b++ {
			t.Run(fmt.Sprintf("layer%d-layer%d", a, b), func(t *testing.T) {
				_, _, launch := desktopSSHysteriaLayerFixture(t, desktopSSEntryMethods[1], "", linuxHostTUNSSLayerMode(a), linuxHostTUNSSLayerMode(b), "always")
				if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
					t.Fatal(err)
				}
				if err := linuxHostTUNExternalSSHysteriaAuthority(launch); err != nil {
					t.Fatal(err)
				}
				original := cloneRouterProfile(launch.external.profile)
				launch.external.profile.External.Hysteria2.Password += "foreign"
				if linuxHostTUNExternalSSHysteriaAuthority(launch) == nil {
					t.Fatal("replacement HY2 credential adopted")
				}
				launch.external.profile = original
				if err := linuxHostTUNExternalSSHysteriaAuthority(launch); err != nil {
					t.Fatal(err)
				}
			})
		}
	}

	for _, method := range desktopSSEntryMethods {
		for _, protocol := range []string{"hysteria2"} {
			t.Run(method+"/"+protocol, func(t *testing.T) {
				_, _, launch := desktopWindowsSSFinalFixture(t, "always", method, protocol)
				if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
					t.Fatal(err)
				}
				if err := linuxHostTUNExternalSSHysteriaAuthority(launch); err != nil {
					t.Fatal("actual compiled SS HY2 lost original authority", err)
				}
				entry, final := launch.external.entry, launch.external.profile
				for _, fault := range []string{"entry-key", "entry-host", "final-key", "final-host", "final-tls", "layer", "tcp-dns"} {
					launch.external.entry, launch.external.profile = cloneRouterProfile(entry), cloneRouterProfile(final)
					p := &launch.external.profile
					e := &launch.external.entry
					switch fault {
					case "entry-key":
						e.External.Shadowsocks.Password = desktopSSEntryKey(method, 'z')
					case "entry-host":
						e.External.Shadowsocks.Server = "192.0.2.99"
					case "final-key":
						mutateWindowsSSFinal(p, "password")
					case "final-host":
						mutateWindowsSSFinal(p, "host")
					case "final-tls":
						if protocol != "hysteria2" {
							continue
						}
						mutateWindowsSSFinal(p, "tls")
					case "layer":
						p.StartLayer = common.StartLayerAES256GCM
					case "tcp-dns":
						p.DNSProtocol = "tcp"
					}
					if fault == "tcp-dns" {
						if validateDesktopLinuxExternalSource(*p, launch, *e) == nil {
							t.Fatal("changed selected DNS admitted")
						}
					} else if linuxHostTUNExternalSSHysteriaAuthority(launch) == nil {
						t.Fatal("HY2 authority accepted changed source", fault)
					}
				}
				launch.external.entry, launch.external.profile = entry, final
				if err := linuxHostTUNExternalSSHysteriaAuthority(launch); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
