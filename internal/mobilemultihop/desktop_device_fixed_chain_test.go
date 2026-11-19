package mobilemultihop

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDesktopDeviceFixedOrderedAndImportedReplay(t *testing.T) {
	revision := strings.Repeat("b", 32)
	const value = 1300
	chain := desktopChainFixture(t, 3, "", nil)
	before, _ := chain.LaunchInput()
	for _, os := range []string{"windows", "linux", "darwin"} {
		t.Run(os, func(t *testing.T) {
			p, err := NewDesktopNodeChainPolicyWithDevicePreference(chain, desktopNodeTestSession, os, 0, revision, value)
			if err != nil {
				t.Fatal("ordered", err)
			}
			launch, err := p.NodeChain().LaunchInput()
			rebuilt, parseErr := ParseDesktopNodeChainLaunchInput(launch)
			if err != nil || parseErr != nil {
				t.Fatal("child parser", err, parseErr)
			}
			config, meta, capture, err := rebuilt.PhysicalReadValidated()
			if err != nil || meta.DeviceFixedMTU != value || capture.ConfiguredMTU == value || meta.RestoredMTU != 0 || startObject(t, config)["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(value) {
				t.Fatal("provenance or client TUN", err)
			}
			if _, err := ParseDesktopNodeChainLaunchInput(strings.ReplaceAll(launch, revision, strings.Repeat("c", 32))); err == nil {
				t.Fatal("altered generation replayed")
			}
			name := "router-vpn"
			if os == "darwin" {
				name = "utun7"
			}
			ready := DesktopNodeChainReadyRecord{Schema: 1, Kind: "routervpn-node-chain-ready-v1", TransferSHA256: strings.Repeat("f", 64), SourceSHA256: meta.SourceSHA256, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, Identity: NodeChainIdentity{EngineID: "original-engine", NetworkID: "original-network", SessionID: meta.SessionID, SourceSHA256: chain.SourceSHA256(), ConfigSHA256: meta.ConfigSHA256}, Generation: 1, Reader: 1, InterfaceName: name, InterfaceIndex: 7, MTU: value, ObservedAt: 1}
			if err := ready.Validate(rebuilt, ready.TransferSHA256); err != nil {
				t.Fatal("readback", err)
			}
			ready.MTU = capture.ConfiguredMTU
			if err := ready.Validate(rebuilt, ready.TransferSHA256); err == nil {
				t.Fatal("default readback substituted for fixed MTU")
			}
			if os == "darwin" {
				return
			}
			sourceRows := importedSOCKSFixture(t, "shadowsocks")
			if os == "linux" {
				sourceRows = importedPacketFixture(t, "wireguard", "shadowsocks", "", "")
			}
			original := desktopImportedOriginal(t, sourceRows, "always")
			defer original.Close()
			source := original.Config()
			imported, err := NewDesktopImportedPolicyWithDevicePreference(original, desktopNodeTestSession, os, 0, revision, value)
			if err != nil {
				t.Fatal("imported", err)
			}
			m := imported.Metadata()
			raw, _ := json.Marshal(m)
			replay, err := RebuildDesktopImportedDevicePreference(original, desktopNodeTestSession, os, m.SourceSHA256, m.ConfigSHA256, raw)
			if err != nil || original.Config() != source || replay.Metadata().DeviceFixedMTU != value || replay.Metadata().DeviceRevision != revision {
				t.Fatal("imported replay", err)
			}
		})
	}
	after, _ := chain.LaunchInput()
	if before != after {
		t.Fatal("device policy rewrote original captured ordered source")
	}
}

func TestDesktopDeviceFixedTypedOrderedReplay(t *testing.T) {
	revision := strings.Repeat("b", 32)
	socks, _ := desktopSOCKSPolicyFixture(t, "wg", "", "linux", 0)
	socksPolicy, err := NewDesktopNodeChainSOCKSPolicyWithDevicePreference(socks, desktopNodeTestSession, "linux", 0, revision, 1280)
	if err != nil {
		t.Fatal("SOCKS", err)
	}
	socksInput, err := socksPolicy.LaunchInput()
	socksReplay, parseErr := ParseDesktopNodeChainSOCKSLaunchInput(socksInput)
	if err != nil || parseErr != nil || socksReplay.metadata.DeviceRevision != revision {
		t.Fatal("SOCKS replay", err, parseErr)
	}
	connect, _ := desktopCONNECTPolicyFixture(t, "wg", "", "linux", 0)
	connectPolicy, err := NewDesktopNodeChainCONNECTPolicyWithDevicePreference(connect, desktopNodeTestSession, "linux", 0, revision, 1280)
	if err != nil {
		t.Fatal("CONNECT", err)
	}
	connectInput, err := connectPolicy.LaunchInput()
	connectReplay, parseErr := ParseDesktopNodeChainCONNECTLaunchInput(connectInput)
	if err != nil || parseErr != nil || connectReplay.metadata.DeviceRevision != revision {
		t.Fatal("CONNECT replay", err, parseErr)
	}
	if _, err := NewDesktopNodeChainCONNECTPolicyWithDevicePreference(connect, desktopNodeTestSession, "linux", 0, revision, 9000); err == nil {
		t.Fatal("exceeded retained packet prefix capacity")
	}
}
