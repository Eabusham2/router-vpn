//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"strconv"
	"testing"
)

// This extends only the Linux Local ordinary WireGuard entry and authenticated
// final HY2 layer. All old plain/direct/other-platform inventories remain intact.
var linuxHostTUNExternalWGHysteriaLayerCases = func() []string {
	var cases []string
	for _, mode := range []string{"wghy2aes", "wghy2xor"} {
		for _, action := range []string{"on-connect", "always", "public", "cancelled", "wrong-entry-public", "wrong-layer-key", "wrong-key", "wrong-trust", "wrong-ca", "dns-failure", "source", "replacement"} {
			cases = append(cases, "external-"+mode+"-"+action)
		}
	}
	return append(cases, "external-wghy2xor-wrong-whitening")
}()

func linuxHostTUNExternalWGHysteriaLayerCase(scenario string) bool {
	for _, value := range linuxHostTUNExternalWGHysteriaLayerCases {
		if value == scenario {
			return true
		}
	}
	return false
}
func linuxHostTUNExternalWGHysteriaLayerRead(t *testing.T, peer *linuxExternalTUNPeer, reply linuxExternalTUNPeerReply) {
	t.Helper()
	layer := reply.Layer
	if layer == nil || reply.PacketEntry == nil || peer.protocol != "hysteria2" {
		t.Fatal("layered entry lost independent original peers")
	}
	inner, err := netip.ParseAddrPort(layer.InnerAddress)
	expectedPort := uint16(8388)
	if peer.layerMode == common.StartLayerAES256GCMXOR {
		expectedPort = 8389
	}
	if err != nil || inner.Addr() != netip.MustParseAddr("127.0.0.1") || inner.Port() == 0 || peer.address != netip.AddrPortFrom(netip.MustParseAddr("198.51.100.240"), expectedPort) || layer.Mode != peer.layerMode || peer.innerAddress.IsValid() && peer.innerAddress != inner || layer.Raw < 0 || layer.Authenticated < 0 || layer.Forwarded < 0 || layer.Rejected < 0 || layer.Raw != reply.PhysicalUDP {
		t.Fatal("layered entry changed its original routed layer/private HY2 tuples", err)
	}
	peer.innerAddress = inner
}
func linuxHostTUNExternalWGHysteriaLayerAuthority(native *desktopNodeLaunch) error {
	bad := errors.New("installed layered WG entry lost original sole physical root or exact private final graph")
	if native == nil || native.external == nil || !desktopExternalLinuxEntryOwner(native.external) || native.external.physical == nil {
		return bad
	}
	profile, entry := native.external.profile, native.external.entry
	if profile.External == nil || profile.External.Hysteria2 == nil || profile.External.StartLayer == nil || entry.External == nil || entry.External.WireGuard == nil {
		return bad
	}
	policy := native.external.physical
	capture, err := policy.Capture()
	meta := policy.Metadata()
	if err != nil || capture.StartLayer != profile.StartLayer || meta.RootTag != "external-entry" || meta.RootType != "wireguard" || len(capture.PhysicalRoots) != 1 || len(capture.PhysicalRoots[0].Destinations) != 1 || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != mobilemultihop.ExternalFinalTag {
		return bad
	}
	root := capture.PhysicalRoots[0].Destinations[0]
	ep, err := netip.ParseAddrPort(entry.External.WireGuard.Endpoint)
	if err != nil || root.Network != "udp" || root.Host != ep.Addr().String() || root.Port != int(ep.Port()) {
		return bad
	}
	var original, physical map[string]any
	if json.Unmarshal([]byte(policy.OriginalPolicy().Config()), &original) != nil || json.Unmarshal([]byte(policy.Config()), &physical) != nil {
		return bad
	}
	before, _ := original["outbounds"].([]any)
	after, _ := physical["outbounds"].([]any)
	const layerTag = "routervpn-exit-start-layer"
	inner, layer := taggedRuntimeItem(after, mobilemultihop.ExternalFinalTag), taggedRuntimeItem(after, layerTag)
	port, err := strconv.Atoi(fmt.Sprint(profile.External.StartLayer.Transport["server_port"]))
	if err != nil || inner == nil || layer == nil || !reflect.DeepEqual(inner, taggedRuntimeItem(before, mobilemultihop.ExternalFinalTag)) || !reflect.DeepEqual(layer, taggedRuntimeItem(before, layerTag)) || inner["server"] != "10.93.0.1" || inner["server_port"] != float64(profile.External.Hysteria2.Port) || inner["password"] != profile.External.Hysteria2.Password || inner["detour"] != layerTag || layer["server"] != "198.51.100.240" || layer["server_port"] != float64(port) || layer["password"] != profile.External.StartLayer.Transport["password"] || layer["detour"] != "external-entry" || profile.External.StartLayer.API != "http://10.93.0.1:8787" || profile.External.StartLayer.Transport["server"] != "198.51.100.240" {
		return bad
	}
	return nil
}

func TestDesktopLinuxInstalledLayeredEntryFixtureKeepsCompiledAuthority(t *testing.T) {
	for _, mode := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		t.Run(mode, func(t *testing.T) {
			profile, entry, _ := desktopExternalPacketEntryLayerExitFixture(t, "always", "wireguard", "hysteria2", mode)
			profile.External.Hysteria2.Server, profile.External.Hysteria2.Port = "198.51.100.240", 10443
			profile.Endpoint = "198.51.100.240"
			profile.External.ResponseProbe.URL = "https://198.51.100.240/node-response"
			profile.External.StartLayer.API = "http://10.93.0.1:8787"
			port := 8388
			if mode == common.StartLayerAES256GCMXOR {
				port = 8389
			}
			profile.External.StartLayer.Transport["server"], profile.External.StartLayer.Transport["server_port"] = "198.51.100.240", port
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
				t.Fatal(err)
			}
			if err = linuxHostTUNExternalLayerAuthority(launch); err != nil {
				t.Fatal("actual compiled layered entry lost its exact authority", err)
			}
			originalProfile, originalEntry := launch.external.profile, launch.external.entry
			for _, fault := range []string{"entry-root", "inner-key", "outer-key", "outer-port", "outer-address", "private-peer", "layer-mode"} {
				t.Run(fault, func(t *testing.T) {
					launch.external.profile, launch.external.entry = cloneRouterProfile(originalProfile), cloneRouterProfile(originalEntry)
					switch fault {
					case "entry-root":
						launch.external.entry.External.WireGuard.Endpoint = "198.51.100.91:8443"
					case "inner-key":
						launch.external.profile.External.Hysteria2.Password += "-changed"
					case "outer-key":
						launch.external.profile.External.StartLayer.Transport["password"] = testWGKey('q')
					case "outer-port":
						launch.external.profile.External.StartLayer.Transport["server_port"] = 8390
					case "outer-address":
						launch.external.profile.External.StartLayer.Transport["server"] = "198.51.100.241"
					case "private-peer":
						launch.external.profile.External.StartLayer.API = "http://10.93.0.2:8787"
					case "layer-mode":
						launch.external.profile.StartLayer = common.StartLayerOff
					}
					if linuxHostTUNExternalWGHysteriaLayerAuthority(launch) == nil {
						t.Fatal("replaced original authority accepted", fault)
					}
					launch.external.profile, launch.external.entry = originalProfile, originalEntry
					if err := linuxHostTUNExternalLayerAuthority(launch); err != nil {
						t.Fatal("negative check changed original authority", err)
					}
				})
			}
		})
	}
}
