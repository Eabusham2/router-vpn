package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/nativeopenvpn"
)

func TestDesktopExternalCompiledPhysicalTuplesReachOwnedStage(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			profile, exit := desktopExternalNativeFixture(t, protocol)
			launch, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if protocol == "socks5" {
				if len(launch.external.physicalEgress) != 0 {
					t.Fatal("negotiated SOCKS UDP relay was replaced by an invented static port")
				}
				return
			}
			network := "tcp"
			if protocol == "wireguard" || protocol == "amneziawg" || protocol == "hysteria2" {
				network = "udp"
			}
			want := []nativeopenvpn.LayerEgress{{Host: exit.Server, Port: exit.ServerPort, Network: network}}
			if protocol == "shadowsocks" {
				want = append(want, nativeopenvpn.LayerEgress{Host: exit.Server, Port: exit.ServerPort, Network: "udp"})
			}
			if !reflect.DeepEqual(launch.external.physicalEgress, want) {
				t.Fatal("compiled provider path did not retain its actual transport port", launch.external.physicalEgress, want)
			}
			root := t.TempDir()
			t.Setenv("HOMEVPN_ROOT", root)
			t.Setenv("HOMEVPN_NATIVE_EGRESS_JSON", "foreign")
			launch.root, launch.external.network = root, physicalNetworkIdentity()
			a := &app{cfg: common.ClientConfig{ScriptsDir: filepath.Join(root, "modes")}}
			if err := stageDesktopNodeLaunch(a, launch); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := cleanupDesktopNodeLaunch(launch); err != nil {
					t.Error(err)
				}
			}()
			encoded, _ := json.Marshal(want)
			environment := strings.Join(launch.command.Env, "\n")
			if !strings.Contains(environment, "HOMEVPN_NATIVE_EGRESS_JSON="+string(encoded)) || strings.Contains(environment, "foreign") {
				t.Fatal("native stage lost the provider physical capture")
			}
		})
	}
}

func TestDesktopMappedLayerPhysicalEgressOwnership(t *testing.T) {
	for _, mode := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		request := desktopOpenVPNMappedLayerCreateFixture(t, mode)
		profile, err := externalProfileFromCreateRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		want := []nativeopenvpn.LayerEgress{{Host: "203.0.113.20", Port: 8388, Network: "udp"}, {Host: "203.0.113.21", Port: 8390, Network: "tcp"}}
		if mode == common.StartLayerAES256GCMXOR {
			want[0].Port, want[1].Port = 8389, 8389
		}
		actual, err := desktopExternalPhysicalEgress(profile, common.RouterProfile{}, true)
		if err != nil || !reflect.DeepEqual(actual, want) {
			t.Fatal("physical layer used original OpenVPN ports or changed transports", actual, err)
		}
		if hopped, err := desktopExternalPhysicalEgress(profile, common.RouterProfile{ID: "entry", NodeKind: "router-vpn", Endpoint: "198.51.100.7"}, false); err != nil || hopped != nil {
			t.Fatal("hopped exit opened physical provider exceptions", hopped, err)
		}
		if entry, err := desktopExternalPhysicalEgress(common.RouterProfile{}, profile, false); err != nil || !reflect.DeepEqual(entry, want) {
			t.Fatal("mapped external predecessor lost its exact physical outer ports", entry, err)
		}
		changed := common.CloneRouterProfile(profile)
		delete(changed.External.OpenVPNStartLayers, "203.0.113.21")
		if _, err := desktopExternalPhysicalEgress(changed, common.RouterProfile{}, true); err == nil {
			t.Fatal("partial layer map fabricated a physical exception")
		}
	}
	legacy := common.RouterProfile{NodeKind: "external", External: &common.ExternalNodeConfig{Protocol: "openvpn"}}
	if actual, err := desktopExternalPhysicalEgress(legacy, common.RouterProfile{}, true); err != nil || actual != nil {
		t.Fatal("legacy transport acquired a fabricated mapped-layer policy", actual, err)
	}
}

func TestDesktopMappedLayerPhysicalEgressStaging(t *testing.T) {
	for _, mode := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		t.Run(mode, func(t *testing.T) {
			profile, _, launch := desktopOpenVPNCompileFixture(t, desktopOpenVPNMappedLayerCreateFixture(t, mode))
			want, err := desktopExternalPhysicalEgress(profile, common.RouterProfile{}, true)
			if err != nil || !reflect.DeepEqual(launch.external.physicalEgress, want) {
				t.Fatal("shipping compiler did not capture the validated physical tuples", err)
			}
			root := t.TempDir()
			t.Setenv("HOMEVPN_ROOT", root)
			t.Setenv("HOMEVPN_NATIVE_EGRESS_JSON", `[{"host":"8.8.8.8","port":443,"network":"tcp"}]`)
			launch.root, launch.external.network = root, physicalNetworkIdentity()
			a := &app{cfg: common.ClientConfig{ScriptsDir: filepath.Join(root, "modes")}}
			if err := stageDesktopNodeLaunch(a, launch); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := cleanupDesktopNodeLaunch(launch); err != nil {
					t.Error(err)
				}
			}()
			count := 0
			for _, item := range launch.command.Env {
				name, raw, _ := strings.Cut(item, "=")
				if !strings.EqualFold(name, "HOMEVPN_NATIVE_EGRESS_JSON") {
					continue
				}
				var actual []nativeopenvpn.LayerEgress
				if json.Unmarshal([]byte(raw), &actual) != nil || !reflect.DeepEqual(actual, want) {
					t.Fatal("inherited or changed physical exceptions crossed native staging")
				}
				count++
			}
			if count != 1 {
				t.Fatal("native stage did not publish one exact owned tuple list", count)
			}
		})
	}
}

func TestDesktopMappedLayerPhysicalEgressEnvironmentCannotBeInherited(t *testing.T) {
	environment := []string{"SAFE=value", "HOMEVPN_NATIVE_EGRESS_JSON=[]", "homevpn_native_egress_json=foreign"}
	for _, captured := range [][]string{
		desktopNativeEnvironment(environment, t.TempDir(), "entry", "203.0.113.7"),
		desktopSelectedStandardEngineEnvironment(environment, "openvpn"),
	} {
		for _, item := range captured {
			if strings.HasPrefix(strings.ToUpper(item), "HOMEVPN_NATIVE_EGRESS_JSON=") {
				t.Fatal("another native owner's physical exceptions were inherited")
			}
		}
	}
}
