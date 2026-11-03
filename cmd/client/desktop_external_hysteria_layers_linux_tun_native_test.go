//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

var linuxHostTUNExternalLayerCases = func() []string {
	var cases []string
	for _, mode := range []string{"hy2aes", "hy2xor"} {
		for _, action := range []string{"on-connect", "always", "public", "cancelled", "wrong-key", "wrong-trust", "dns-failure", "wrong-layer-key", "source", "replacement"} {
			cases = append(cases, "external-"+mode+"-"+action)
		}
	}
	return append(cases, "external-hy2xor-wrong-whitening")
}()

func linuxHostTUNExternalLayerMode(scenario string) string {
	if strings.HasPrefix(scenario, "external-hy2aes-") {
		return common.StartLayerAES256GCM
	}
	if strings.HasPrefix(scenario, "external-hy2xor-") {
		return common.StartLayerAES256GCMXOR
	}
	return ""
}

type linuxExternalTUNLayerReceipt struct {
	Mode          string `json:"mode"`
	InnerAddress  string `json:"inner_address"`
	Raw           int64  `json:"raw"`
	Authenticated int64  `json:"authenticated"`
	Forwarded     int64  `json:"forwarded"`
	Rejected      int64  `json:"rejected"`
}

func linuxHostTUNExternalLayerRead(t *testing.T, peer *linuxExternalTUNPeer, reply linuxExternalTUNPeerReply) {
	t.Helper()
	if peer.layerMode == "" {
		if reply.Layer != nil {
			t.Fatal("ordinary peer acquired an unrequested layer")
		}
		return
	}
	if peer.protocol != "hysteria2" || reply.Layer == nil {
		t.Fatal("installed layer lost its selected HY2 provider")
	}
	layer := reply.Layer
	inner, err := netip.ParseAddrPort(layer.InnerAddress)
	if err != nil || inner.Addr() != peer.address.Addr() || inner.Port() == 0 || inner == peer.address ||
		layer.Mode != peer.layerMode || peer.innerAddress.IsValid() && peer.innerAddress != inner ||
		peer.layerMode == common.StartLayerAES256GCMXOR && peer.address.Port() != 8389 ||
		layer.Raw < 0 || layer.Authenticated < 0 || layer.Forwarded < 0 || layer.Rejected < 0 || layer.Raw != reply.PhysicalUDP {
		t.Fatal("installed layer changed its captured physical/private tuple or typed counters", err)
	}
	peer.innerAddress = inner
}
func linuxHostTUNExternalLayerObserved(t *testing.T, peer *linuxExternalTUNPeer, action string, reply linuxExternalTUNPeerReply) {
	t.Helper()
	if peer.layerMode == "" {
		return
	}
	if reply.Layer == nil {
		t.Fatal("layer observation absent")
	}
	layer := reply.Layer
	if action == "source" {
		if layer.Raw != 0 || layer.Authenticated != 0 || layer.Forwarded != 0 || layer.Rejected != 0 || reply.PhysicalUDP != 0 {
			t.Fatal("changed private layer source reached its physical peer", reply)
		}
	} else if action == "wrong-layer-key" || action == "wrong-whitening" {
		if layer.Raw == 0 || layer.Rejected == 0 || layer.Authenticated != 0 || layer.Forwarded != 0 ||
			reply.Streams != 0 || reply.Packets != 0 || reply.DNSQueries != 0 || reply.PublicAttempts != 0 {
			t.Fatal("invalid layer credential bypassed actual outer authentication", reply)
		}
	} else if layer.Raw == 0 || layer.Authenticated == 0 || layer.Forwarded == 0 || layer.Rejected != 0 {
		t.Fatal("installed HY2 path bypassed its actual authenticated outer carrier", reply)
	}
}
func linuxHostTUNExternalLayerAuthority(native *desktopNodeLaunch) error {
	profile := native.external.profile
	if profile.StartLayer == "" || profile.StartLayer == common.StartLayerOff {
		return nil
	}
	bad := errors.New("installed HY2 layer changed its exact original keys, inner graph or physical root")
	if profile.External == nil || profile.External.Protocol != "hysteria2" || profile.External.Hysteria2 == nil || profile.External.StartLayer == nil {
		return bad
	}
	policy := native.external.physical
	captured, err := policy.Capture()
	meta := policy.Metadata()
	if err != nil || captured.StartLayer != profile.StartLayer || meta.RootTag != "routervpn-exit-start-layer" ||
		len(captured.PhysicalRoots) != 1 || len(captured.PhysicalRoots[0].Destinations) != 1 {
		return bad
	}
	outerPort, err := strconv.Atoi(fmt.Sprint(profile.External.StartLayer.Transport["server_port"]))
	destination := captured.PhysicalRoots[0].Destinations[0]
	if err != nil || destination.Host != "11.77.0.2" || destination.Port != outerPort || destination.Network != "udp" ||
		outerPort == profile.External.Hysteria2.Port || profile.External.StartLayer.API != "http://10.93.0.1:8787" {
		return bad
	}
	var original, physical map[string]any
	if json.Unmarshal([]byte(policy.OriginalPolicy().Config()), &original) != nil || json.Unmarshal([]byte(policy.Config()), &physical) != nil {
		return bad
	}
	before, ok := original["outbounds"].([]any)
	after, nextOK := physical["outbounds"].([]any)
	if !ok || !nextOK {
		return bad
	}
	inner := taggedRuntimeItem(before, mobilemultihop.ExternalFinalTag)
	outer := taggedRuntimeItem(after, meta.RootTag)
	if inner == nil || outer == nil || !reflect.DeepEqual(inner, taggedRuntimeItem(after, mobilemultihop.ExternalFinalTag)) ||
		inner["server"] != "10.93.0.1" || inner["server_port"] != float64(profile.External.Hysteria2.Port) ||
		inner["password"] != profile.External.Hysteria2.Password || inner["detour"] != meta.RootTag ||
		outer["server"] != "11.77.0.2" || outer["server_port"] != float64(outerPort) ||
		outer["password"] != profile.External.StartLayer.Transport["password"] || outer["detour"] != mobilemultihop.DesktopExternalPhysicalTag {
		return bad
	}
	return nil
}

func TestDesktopLinuxInstalledLayerFixtureKeepsCompiledAuthority(t *testing.T) {
	for _, mode := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		t.Run(mode, func(t *testing.T) {
			profile := desktopLayerProfile(t, "hysteria2", mode)
			profile.External.Hysteria2.Server, profile.External.Hysteria2.Port = "11.77.0.2", 10443
			profile.Endpoint = "11.77.0.2"
			profile.External.ResponseProbe.URL = "https://11.77.0.2/node-response"
			profile.KillSwitch, profile.KillSwitchPolicy, profile.MultihopExecution = true, "always", "local"
			profile.External.StartLayer.API = "http://10.93.0.1:8787"
			profile.External.StartLayer.Transport["server"], profile.External.StartLayer.Transport["server_port"] = "11.77.0.2", 8389
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
				t.Fatal(err)
			}
			if err = linuxHostTUNExternalLayerAuthority(launch); err != nil {
				t.Fatal("installed authority witness rejects the actual compiled layered graph", err)
			}
			original := launch.external.profile
			for _, fault := range []string{"inner-key", "outer-key", "outer-port", "private-peer"} {
				changed := cloneRouterProfile(original)
				switch fault {
				case "inner-key":
					changed.External.Hysteria2.Password += "-changed"
				case "outer-key":
					changed.External.StartLayer.Transport["password"] = testWGKey('q')
				case "outer-port":
					changed.External.StartLayer.Transport["server_port"] = 8390
				case "private-peer":
					changed.External.StartLayer.API = "http://10.93.0.2:8787"
				}
				launch.external.profile = changed
				if linuxHostTUNExternalLayerAuthority(launch) == nil {
					t.Fatal("installed authority witness lost captured private identity", fault)
				}
			}
			launch.external.profile = original
			if err = linuxHostTUNExternalLayerAuthority(launch); err != nil {
				t.Fatal("negative check changed original authority", err)
			}
		})
	}
}
