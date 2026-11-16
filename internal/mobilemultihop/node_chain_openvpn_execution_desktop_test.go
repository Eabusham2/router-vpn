package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func desktopOpenVPNExecutionFixture(t *testing.T, count int, mode, network, layer, target, execution string, mtu int) (*DesktopNodeChainPolicy, *NodeChainExecutionPreparation, NodeChainExecutionSource) {
	t.Helper()
	local, _, request := openVPNExecutionFixture(t, count, mode, network, layer, execution, "")
	original, err := NewDesktopNodeChainPolicy(local, strings.Repeat("c", 32), target, mtu)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := NewDesktopNodeChainOpenVPNExecutionPreparation(original, execution)
	if err != nil {
		t.Fatal("typed desktop preparation", err)
	}
	return original, prep, request
}
func TestDesktopOpenVPNExecutionOriginalPhysicalLinux(t *testing.T) {
	testDesktopOpenVPNExecutionOriginalPhysical(t, "linux", 0)
}
func TestDesktopOpenVPNExecutionOriginalPhysicalWindows(t *testing.T) {
	testDesktopOpenVPNExecutionOriginalPhysical(t, "windows", 1)
}
func TestDesktopOpenVPNExecutionOriginalPhysicalDarwin(t *testing.T) {
	testDesktopOpenVPNExecutionOriginalPhysical(t, "darwin", 2)
}
func testDesktopOpenVPNExecutionOriginalPhysical(t *testing.T, target string, offset int) {
	for count := 1; count <= NodeChainMaximumNodes-2; count++ {
		for ci, choice := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count+2, choice), func(t *testing.T) {
				mode := []string{"wg", "awg2-fast", "awg2-strong"}[(count+ci+offset)%3]
				network := []string{"tcp", "udp"}[ci]
				layer := []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"}[(count+ci+offset)%3]
				original, prep, request := desktopOpenVPNExecutionFixture(t, count, mode, network, layer, target, choice, 0)
				physical, err := prep.OpenVPNDesktopPhysicalPolicy()
				if err != nil {
					t.Fatal(err)
				}
				retained, err := physical.OriginalDesktopOpenVPNPolicy()
				if err != nil || retained != original {
					t.Fatal("original physical policy replaced", err)
				}
				local, err := prep.OriginalOpenVPNSource()
				if err != nil || local != original.original || prep.local != local || prep.openvpn.desktop.native != original.chain || !prep.RequiresDesktopOpenVPNExecutionObserver() {
					t.Fatal("original Local/private pair or native chain replaced", err)
				}
				config, meta, capture, err := ReadDesktopPhysicalPolicy(physical)
				_, _, prior, priorErr := original.PhysicalReadValidated()
				if err != nil || priorErr != nil || config != prep.Config() || meta.Kind != "node-chain-openvpn-execution" || meta.TargetOS != target || meta.SessionID != original.inputs.sessionID || meta.SourceSHA256 != original.metadata.SourceSHA256 || meta.ConfigSHA256 != prep.ConfigSHA256() || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != SelectorTag || !reflect.DeepEqual(capture.PhysicalRoots, prior.PhysicalRoots) || !reflect.DeepEqual(capture.PrivateDestinations, prior.PrivateDestinations) || capture.ConfiguredMTU != prior.ConfiguredMTU {
					t.Fatal("original physical roots/DNS/MTU changed", err, priorErr)
				}
				policy, err := NewNodeChainOpenVPNExecutionPolicy(prep, startJSON(t, request))
				if err != nil {
					t.Fatal("typed desktop execution policy", err)
				}
				projection, err := prep.BindExecution(policy)
				if err != nil {
					t.Fatal("original desktop transition", err)
				}
				adopted, err := projection.OpenVPNDesktopPhysicalPolicy()
				if err != nil || adopted != physical {
					t.Fatal("transition changed physical authority", err)
				}
				before, after := externalTestRead(t, prep.Config()), externalTestRead(t, projection.Config())
				native := externalTestRead(t, original.chain.Config())
				if before["route"].(map[string]any)["final"] != NodeChainExecutionGateTag || after["route"].(map[string]any)["final"] != NodeChainExecutionGateTag || !reflect.DeepEqual(before["services"], native["services"]) || !reflect.DeepEqual(before["services"], after["services"]) || !reflect.DeepEqual(native["inbounds"], after["inbounds"]) {
					t.Fatal("transition opened gate or changed original service/TUN")
				}
				for _, proof := range local.proofs {
					if !reflect.DeepEqual(externalTestFind(t, before, proof.Tag), externalTestFind(t, after, proof.Tag)) || !reflect.DeepEqual(externalTestFind(t, native, proof.Tag), externalTestFind(t, after, proof.Tag)) {
						t.Fatal("original native member changed", proof.Position)
					}
				}
				middle := externalTestFind(t, after, local.proofs[count].Tag)
				final := externalTestFind(t, after, local.proofs[count+1].Tag)
				if middle["type"] != "openvpn-client" || final["detour"] != middle["tag"] || final["udp_over_tcp"] != nil {
					t.Fatal("original OpenVPN packet transport replaced")
				}
				bound, err := projection.MTUPlan()
				want, wantErr := original.chain.MTUPlan()
				if err != nil || wantErr != nil || !reflect.DeepEqual(bound, want) {
					t.Fatal("original native MTU envelope changed", err, wantErr)
				}
				for _, parser := range []func(string) (*NodeChainExecutionPreparation, error){ParseNodeChainExecutionPreparation, ParseNodeChainOpenVPNExecutionPreparation, ParseDesktopNodeChainCONNECTExecutionPreparation, ParseDesktopNodeChainSOCKSExecutionPreparation} {
					if _, err := parser(prep.Source()); err == nil {
						t.Fatal("foreign/mobile parser accepted desktop OpenVPN")
					}
				}
				if _, err := NewNodeChainOpenVPNExecutionPreparation(original.chain, choice); err == nil {
					t.Fatal("mobile preparation adopted original desktop physical chain")
				}
				if _, err := NewDesktopNodeChainExecutionPreparation(original, choice); err == nil {
					t.Fatal("generic desktop execution admitted OpenVPN")
				}
				if _, err := prep.DesktopPhysicalPolicy(); err == nil {
					t.Fatal("typed OpenVPN borrowed generic physical wrapper")
				}
				reopened, err := ParseDesktopNodeChainOpenVPNExecutionPreparation(prep.Source())
				if err != nil || reopened.Source() != prep.Source() || reopened.Config() != prep.Config() || reopened.openvpn.source == local || reopened.openvpn.desktop.original == original {
					t.Fatal("independent child reconstruction changed graph or borrowed owner", err)
				}
				if _, err := reopened.BindExecution(policy); err == nil {
					t.Fatal("equal-content child borrowed original binding")
				}
			})
		}
	}
}

func TestDesktopOpenVPNExecutionOriginalOwnerRefusals(t *testing.T) {
	t.Run("unpaired-original", func(t *testing.T) {
		local, err := NewNodeChain(startJSON(t, nodeChainOpenVPNPrefixFixture(t, 1, "wg", "tcp", "")))
		if err != nil {
			t.Fatal(err)
		}
		ordinary, err := NewDesktopNodeChainPolicy(local, strings.Repeat("c", 32), "linux", 0)
		if err != nil || ordinary.Validate() != nil {
			t.Fatal("existing Local unpaired source changed", err)
		}
		if _, err := NewDesktopNodeChainOpenVPNExecutionPreparation(ordinary, "server"); err == nil {
			t.Fatal("unpaired Local provider acquired Server authority")
		}
	})
	for _, fault := range []string{"original", "nil-preparation", "equal-preparation", "copied-preparation", "copied-physical", "copied-adjunct", "copied-policy", "copied-native", "equal-policy", "equal-source", "equal-native", "source", "source-config", "source-metadata", "native-source", "native-metadata", "native-source-identity", "native-proof", "native-dns", "native-physical", "native-original-config", "native-projection", "policy", "capture", "physical-dns", "metadata", "pair", "native-config", "preparation-source", "preparation-config", "local-source", "sealed-launch", "saved-record"} {
		t.Run(fault, func(t *testing.T) {
			original, prep, _ := desktopOpenVPNExecutionFixture(t, 1, "wg", "tcp", "", "linux", "auto", 0)
			physical, err := prep.OpenVPNDesktopPhysicalPolicy()
			if err != nil {
				t.Fatal(err)
			}
			requested := prep
			switch fault {
			case "nil-preparation":
				requested = nil
			case "equal-preparation":
				requested, err = NewDesktopNodeChainOpenVPNExecutionPreparation(original, "auto")
				if err != nil || requested.Source() != prep.Source() {
					t.Fatal("equal-source fixture", err)
				}
			case "copied-preparation":
				copy := *prep
				requested = &copy
			case "copied-physical":
				copy := *physical
				physical = &copy
			case "copied-adjunct":
				copy := *prep.openvpn.desktop
				prep.openvpn.desktop = &copy
			case "copied-policy":
				copy := *original
				prep.openvpn.desktop.original = &copy
			case "copied-native":
				copy := *original.chain
				prep.openvpn.desktop.native = &copy
			case "equal-policy", "equal-native":
				equal, equalErr := NewDesktopNodeChainPolicy(original.original, original.inputs.sessionID, original.inputs.targetOS, original.inputs.restoredMTU)
				if equalErr != nil || equal.Config() != original.Config() {
					t.Fatal("equal original policy fixture", equalErr)
				}
				if fault == "equal-policy" {
					prep.openvpn.desktop.original = equal
				} else {
					prep.openvpn.desktop.native = equal.chain
				}
			case "equal-source":
				equal, equalErr := ParseNodeChainLaunchInput(prep.source.OpenVPNLocalLaunch)
				if equalErr != nil || equal.Config() != original.original.Config() {
					t.Fatal("equal original source fixture", equalErr)
				}
				prep.openvpn.desktop.source = equal
			case "source":
				original.original.sourceJSON += " "
			case "source-config":
				original.original.config += " "
			case "source-metadata":
				original.original.metadata += " "
			case "native-source":
				original.chain.sourceJSON += " "
			case "native-metadata":
				original.chain.metadata += " "
			case "native-source-identity":
				original.chain.sourceSHA = strings.Repeat("a", 64)
			case "native-proof":
				original.chain.proofs[0].Tag += "-foreign"
			case "native-dns":
				original.chain.dns.ConfigSHA256 = strings.Repeat("a", 64)
			case "native-physical":
				original.chain.physical[0].Port++
			case "native-original-config":
				original.chain.originalConfigSHA = strings.Repeat("a", 64)
			case "native-projection":
				original.chain.projection.RestoredMTU++
			case "policy":
				original.inputs.restoredMTU = 1300
			case "capture":
				physical.owner.capture.ConfiguredMTU = 1300
			case "physical-dns":
				physical.owner.capture.SelectedDNS.Detour = "direct"
			case "metadata":
				prep.source.DesktopOpenVPN.Roots[0].Tag = "foreign"
			case "pair":
				prep.openvpn.pairSHA = strings.Repeat("a", 64)
			case "native-config":
				original.chain.config += " "
			case "preparation-source":
				prep.sourceJSON += " "
			case "preparation-config":
				prep.config += " "
			case "local-source":
				prep.source.LocalSource += " "
			case "sealed-launch":
				prep.source.OpenVPNLocalLaunch += " "
			case "saved-record":
				prep.source.DesktopLast = "foreign"
			}
			owner, metadata, err := physical.ReadOriginalValidated(requested)
			if fault != "original" {
				if err == nil || owner != nil || !reflect.DeepEqual(metadata, DesktopNodeChainMetadata{}) {
					t.Fatal("foreign physical authority admitted", fault, err)
				}
				return
			}
			if err != nil || owner != original || !reflect.DeepEqual(metadata, original.metadata) {
				t.Fatal("original owner lost", err)
			}
			hybrid := *prep
			hybrid.mobile = &nodeChainExecutionMobileProjection{chain: prep.local}
			if hybrid.captureSeal() != "" {
				t.Fatal("mixed mobile projection retained a desktop seal")
			}
			metadata.Roots[0].Tag = "caller"
			metadata.Prefixes[0].ProfileID = "caller"
			_, again, err := physical.ReadOriginalValidated(prep)
			if err != nil || !reflect.DeepEqual(again, original.metadata) {
				t.Fatal("returned metadata aliased original", err)
			}
			_, _, capture, err := physical.PhysicalReadValidated()
			if err != nil {
				t.Fatal(err)
			}
			capture.PhysicalRoots[0].Tag = "caller"
			_, _, next, err := physical.PhysicalReadValidated()
			if err != nil || next.PhysicalRoots[0].Tag == "caller" {
				t.Fatal("returned physical capture aliased original", err)
			}
		})
	}
}
func TestDesktopOpenVPNExecutionCanonicalParserRefusals(t *testing.T) {
	_, prep, _ := desktopOpenVPNExecutionFixture(t, 1, "wg", "tcp", "", "linux", "server", 0)
	for _, fault := range []string{"schema", "ordinary-metadata", "missing-launch", "changed-launch", "session", "target", "source", "native-config", "root", "prefix", "mtu", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			var source NodeChainExecutionPreparationSource
			if json.Unmarshal([]byte(prep.Source()), &source) != nil {
				t.Fatal("fixture")
			}
			switch fault {
			case "schema":
				source.Schema = 4
			case "ordinary-metadata":
				source.Desktop = source.DesktopOpenVPN
			case "missing-launch":
				source.OpenVPNLocalLaunch = ""
			case "changed-launch":
				source.OpenVPNLocalLaunch += " "
			case "session":
				source.DesktopOpenVPN.SessionID = strings.Repeat("d", 32)
			case "target":
				source.DesktopOpenVPN.TargetOS = "darwin"
			case "source":
				source.DesktopOpenVPN.SourceSHA256 = strings.Repeat("a", 64)
			case "native-config":
				source.DesktopOpenVPN.ConfigSHA256 = strings.Repeat("b", 64)
			case "root":
				source.DesktopOpenVPN.Roots[0].OriginalSHA256 = strings.Repeat("a", 64)
			case "prefix":
				source.DesktopOpenVPN.Prefixes[1].SourceSHA256 = strings.Repeat("a", 64)
			case "mtu":
				source.DesktopOpenVPN.RestoredMTU = 1400
			}
			raw := startJSON(t, source)
			if fault == "unknown" {
				object := startObject(t, raw)
				object["native_owner"] = true
				raw = startJSON(t, object)
			}
			if _, err := ParseDesktopNodeChainOpenVPNExecutionPreparation(raw); err == nil {
				t.Fatal("altered typed child metadata admitted", fault)
			}
		})
	}
}

type desktopOpenVPNForeignPhysicalWrapper struct{ DesktopPhysicalPolicy }

func TestDesktopOpenVPNExecutionConcretePhysicalAndCover(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			_, prep, _ := desktopOpenVPNExecutionFixture(t, 1, "wg", "tcp", "", target, "server", 1400)
			physical, err := prep.OpenVPNDesktopPhysicalPolicy()
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := ReadDesktopPhysicalPolicy(desktopOpenVPNForeignPhysicalWrapper{physical}); err == nil {
				t.Fatal("foreign interface wrapper admitted")
			}
			if _, _, err := ReadDesktopPhysicalCoverPolicy(desktopOpenVPNForeignPhysicalWrapper{physical}); err == nil {
				t.Fatal("foreign cover wrapper admitted")
			}
			profile, err := ReadDesktopProtectionProfileID(physical)
			if err != nil || profile != physical.owner.metadata.ProfileID {
				t.Fatal("original protection attribution changed", err)
			}
			cover, digest, err := ReadDesktopPhysicalCoverPolicy(physical)
			wantCover, wantDigest, wantErr := ReadDesktopPhysicalCoverPolicy(physical.original)
			if err != nil || wantErr != nil || digest != wantDigest || !reflect.DeepEqual(cover, wantCover) {
				t.Fatal("original final cover owner changed", err)
			}
			config, metadata, capture, err := physical.PhysicalReadValidated()
			_, _, originalCapture, originalErr := physical.original.PhysicalReadValidated()
			graph := externalTestRead(t, config)
			tun := graph["inbounds"].([]any)[0].(map[string]any)
			if err != nil || originalErr != nil || capture.ConfiguredMTU != originalCapture.ConfiguredMTU || metadata.RestoredMTU != 1400 || tun["mtu"] != float64(1400) {
				t.Fatal("original configured ceiling or actual restored TUN MTU changed", err, originalErr)
			}
		})
	}
}
