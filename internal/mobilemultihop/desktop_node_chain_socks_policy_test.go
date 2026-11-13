package mobilemultihop

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func desktopSOCKSPolicyFixture(t *testing.T, mode, layer, target string, restore int) (*NodeChainSOCKSSource, *DesktopNodeChainSOCKSPolicy) {
	t.Helper()
	source, err := NewNodeChainSOCKSSource(startJSON(t, nodeChainSOCKSFixture(t, mode, layer, "password")))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewDesktopNodeChainSOCKSPolicy(source, strings.Repeat("a", 32), target, restore)
	if err != nil {
		t.Fatal("original typed desktop policy", err)
	}
	return source, policy
}

func TestDesktopNodeChainSOCKSPolicyKeepsOriginalGraph(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, target := range []string{"linux", "windows", "darwin"} {
			for _, layer := range []string{"", "aes-256-gcm+xor-whitening"} {
				t.Run(mode+"/"+target+"/"+layer, func(t *testing.T) {
					source, policy := desktopSOCKSPolicyFixture(t, mode, layer, target, 0)
					original, originalMeta, err := source.ReadValidated()
					if err != nil {
						t.Fatal(err)
					}
					config, meta, capture, err := policy.ReadValidated()
					if err != nil || meta.Kind != "routervpn-desktop-node-chain-socks" ||
						meta.OriginalSourceSHA256 != originalMeta.SourceSHA256 ||
						meta.OriginalConfigSHA256 != originalMeta.ConfigSHA256 ||
						meta.ConfigSHA256 != externalDigest([]byte(config)) ||
						meta.SourceSHA256 == meta.OriginalSourceSHA256 ||
						!reflect.DeepEqual(meta.Prefixes, originalMeta.Proofs) ||
						meta.TargetOS != target || meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "off" || meta.HomeLANAccess {
						t.Fatal("typed desktop receipt changed original path or device policy", err)
					}
					sharedConfig, shared, physical, err := ReadDesktopPhysicalPolicy(policy)
					control, controlErr := ReadDesktopProtectionProfileID(policy)
					cover, coverHash, coverErr := ReadDesktopPhysicalCoverPolicy(policy)
					if err != nil || sharedConfig != config || shared.Kind != "node-chain-socks" ||
						shared.SourceSHA256 != meta.SourceSHA256 || !reflect.DeepEqual(physical, capture) ||
						controlErr != nil || control != meta.ProfileID || coverErr != nil || len(cover) != 0 || coverHash != "" {
						t.Fatal("closed physical reader lost the original typed graph or final control", err, controlErr, coverErr)
					}
					if _, _, _, err := ReadDesktopPhysicalPolicy(desktopPhysicalWrapper{policy}); err == nil {
						t.Fatal("caller wrapper replaced typed physical authority")
					}
					var missing *DesktopNodeChainSOCKSPolicy
					if _, _, _, err := ReadDesktopPhysicalPolicy(missing); err == nil {
						t.Fatal("typed nil acquired desktop physical authority")
					}
					before, after := externalTestRead(t, original), externalTestRead(t, config)
					for _, position := range []int{1, 2} {
						if !reflect.DeepEqual(externalTestFind(t, before, meta.Prefixes[position].Tag), externalTestFind(t, after, meta.Prefixes[position].Tag)) {
							t.Fatal("desktop projection changed SOCKS credentials, final or predecessor detour")
						}
					}
					tun := after["inbounds"].([]any)[0].(map[string]any)
					if target == "darwin" {
						if _, supplied := tun["interface_name"]; supplied {
							t.Fatal("Darwin source guessed a native utun owner")
						}
					} else if tun["interface_name"] != "router-vpn" {
						t.Fatal("desktop source lost its captured system TUN name")
					}
					if !reflect.DeepEqual(before["dns"], after["dns"]) {
						t.Fatal("desktop SOCKS projection changed original selected final DNS")
					}
					if len(capture.PhysicalRoots) == 0 || len(meta.Roots) != len(capture.PhysicalRoots) {
						t.Fatal("typed desktop lost original physical root inventory")
					}
					for _, root := range capture.PhysicalRoots {
						if root.Type == "socks" || root.DynamicSOCKSUDP {
							t.Fatal("SOCKS relay acquired physical bypass authority")
						}
						for _, tuple := range root.Destinations {
							found := false
							for _, original := range originalMeta.Physical {
								found = found || tuple == original
							}
							if !found {
								t.Fatal("desktop root adopted a non-original physical tuple")
							}
						}
					}
					native, err := policy.NativeSource()
					if err != nil || native == source || native.desktop.original != source ||
						native.pair != source.pair || native.middle != source.middle {
						t.Fatal("desktop projection replaced original typed member ownership", err)
					}
					nativeConfig, nativeMeta, err := native.ReadValidated()
					if err != nil || nativeConfig != config || nativeMeta.SourceSHA256 != originalMeta.SourceSHA256 ||
						nativeMeta.DNS.ResolverSHA256 != originalMeta.DNS.ResolverSHA256 ||
						nativeMeta.ConfigSHA256 != meta.ConfigSHA256 || nativeMeta.DNS.ConfigSHA256 != meta.ConfigSHA256 {
						t.Fatal("native typed source relabeled original graph identity", err)
					}
					runtime, err := NewNodeChainSOCKSRuntime(native)
					if err != nil || runtime.chain.projection != native.desktop.projection ||
						runtime.chain.originalConfigSHA != originalMeta.ConfigSHA256 {
						t.Fatal("original projected runtime missing", err)
					}
					plan, err := runtime.MTUPlan()
					if err != nil || !reflect.DeepEqual(plan, nativeMeta.MTU) ||
						runtime.Progress().Ready || runtime.HealthyContext(context.Background()) == nil {
						t.Fatal("configured desktop graph claimed proof or lost original MTU bounds", err)
					}
					if _, err := runtime.chain.LaunchInput(); err == nil {
						t.Fatal("typed desktop source escaped through generic chain launch")
					}
					launch, err := policy.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					reopened, err := ParseDesktopNodeChainSOCKSLaunchInput(launch)
					if err != nil {
						t.Fatal("actual typed desktop reopener", err)
					}
					again, receipt, physical, err := reopened.ReadValidated()
					if err != nil || again != config || !reflect.DeepEqual(receipt, meta) || !reflect.DeepEqual(physical, capture) {
						t.Fatal("typed child changed original projected policy", err)
					}
					if _, err := ParseNodeChainLaunchInput(launch); err == nil {
						t.Fatal("generic child accepted typed SOCKS policy")
					}
					afterSource, afterMeta, err := source.ReadValidated()
					if err != nil || original != afterSource || !reflect.DeepEqual(originalMeta, afterMeta) {
						t.Fatal("desktop projection mutated original source", err)
					}
				})
			}
		}
	}
}

func TestDesktopNodeChainSOCKSPolicyStrictChildReceipt(t *testing.T) {
	for _, fault := range []string{"session", "target", "source-hash", "config-hash", "original-hash", "root", "dns-tun", "kind", "unknown", "whitespace", "schema", "source"} {
		t.Run(fault, func(t *testing.T) {
			_, policy := desktopSOCKSPolicyFixture(t, "wg", "", "linux", 0)
			launch, err := policy.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			var wire desktopNodeChainSOCKSLaunch
			if json.Unmarshal([]byte(launch), &wire) != nil {
				t.Fatal("fixture receipt missing")
			}
			switch fault {
			case "session":
				wire.Metadata.SessionID = strings.Repeat("d", 32)
			case "target":
				wire.Metadata.TargetOS = "windows"
			case "source-hash":
				wire.Metadata.SourceSHA256 = strings.Repeat("a", 64)
			case "config-hash":
				wire.Metadata.ConfigSHA256 = strings.Repeat("b", 64)
			case "original-hash":
				wire.Metadata.OriginalCaptureSHA256 = strings.Repeat("c", 64)
			case "root":
				wire.Metadata.Roots[0].OriginalSHA256 = strings.Repeat("d", 64)
			case "dns-tun":
				wire.Metadata.TUNTag = "foreign-tun"
			case "kind":
				wire.Metadata.Kind = "routervpn-desktop-node-chain"
			case "schema":
				wire.Schema = 2
			case "source":
				wire.OriginalSource += "\n"
			}
			changed := startJSON(t, wire)
			if fault == "unknown" {
				var value map[string]any
				_ = json.Unmarshal([]byte(changed), &value)
				value["caller_graph"] = policy.native.config
				changed = startJSON(t, value)
			} else if fault == "whitespace" {
				changed += "\n"
			}
			if changed == launch {
				t.Fatal("receipt fault made no change")
			}
			if _, err := ParseDesktopNodeChainSOCKSLaunchInput(changed); err == nil {
				t.Fatal("changed typed desktop receipt was accepted")
			}
		})
	}
}

func TestDesktopNodeChainSOCKSPolicyRetainsSourceAndPhysicalBinding(t *testing.T) {
	for _, fault := range []string{"native-source", "native-graph", "native-mtu", "native-proof", "physical-session", "physical-hash", "original-source", "policy-receipt"} {
		t.Run(fault, func(t *testing.T) {
			source, policy := desktopSOCKSPolicyFixture(t, "awg2-fast", "", "linux", 0)
			switch fault {
			case "native-source":
				policy.native.sourceJSON += "\n"
			case "native-graph":
				policy.native.config += "\n"
			case "native-mtu":
				policy.native.metadata.MTU.Original++
			case "native-proof":
				policy.native.metadata.Proofs[1].Tag = "foreign-middle"
			case "physical-session":
				policy.native.desktop.projection.SessionID += "-foreign"
			case "physical-hash":
				policy.native.desktop.projection.PhysicalSourceSHA256 = strings.Repeat("a", 64)
			case "original-source":
				source.sourceJSON += "\n"
			case "policy-receipt":
				policy.metadata.HomeLANAccess = true
			}
			if policy.Validate() == nil {
				t.Fatal("changed original typed desktop owner retained physical authority")
			}
		})
	}
}

func TestDesktopNodeChainSOCKSPolicyRestoreRequiresOriginalFinalPolicy(t *testing.T) {
	for _, fault := range []string{"linux", "windows", "darwin", "bad-target", "bad-session", "fixed", "projected-again"} {
		t.Run(fault, func(t *testing.T) {
			source, _ := desktopSOCKSPolicyFixture(t, "wg", "", "linux", 0)
			session, target, restore := strings.Repeat("b", 32), fault, 1300
			switch fault {
			case "bad-target":
				target = "freebsd"
			case "bad-session":
				target, session = "linux", "../foreign"
			case "fixed":
				wire := nodeChainSOCKSFixture(t, "wg", "", "password")
				// Use the original node constructor; a receipt-only profile
				// edit is not authority to change its configured Fixed TUN.
				node, err := ParseNodeLaunchInput(wire.Nodes[2])
				if err != nil {
					t.Fatal(err)
				}
				profile := predecessorCopy(node.profile)
				profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(1380)
				recompiled, err := NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
				if err != nil {
					t.Fatal(err)
				}
				wire.Nodes[2], err = recompiled.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				source, err = NewNodeChainSOCKSSource(startJSON(t, wire))
				if err != nil {
					t.Fatal(err)
				}
				target = "linux"
			case "projected-again":
				_, previous := desktopSOCKSPolicyFixture(t, "wg", "", "linux", 0)
				source, target = previous.native, "linux"
			}
			policy, err := NewDesktopNodeChainSOCKSPolicy(source, session, target, restore)
			if fault == "linux" || fault == "windows" || fault == "darwin" {
				if err != nil || policy.native.metadata.MTU.Original != restore ||
					policy.native.metadata.MTU.Prefixes[0] != source.metadata.MTU.Prefixes[0] {
					t.Fatal("desktop restore lost its exact source-owned TUN or prefix ceiling", err)
				}
			} else if err == nil {
				t.Fatal("unsupported desktop restore acquired typed native source")
			}
		})
	}
}

// This is the original shared HTTP/TLS proof fixture with explicit native
// owner doubles. It proves the typed projected identity reaches every proof,
// not that any platform TUN/kernel or encrypted association has been accepted.
func TestDesktopNodeChainSOCKSPolicyRunsOriginalProofs(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			unprojected, engine := newNodeChainSOCKSRuntimeFixture(t, "wg")
			policy, err := NewDesktopNodeChainSOCKSPolicy(unprojected.source, strings.Repeat("c", 32), target, 0)
			if err != nil {
				t.Fatal(err)
			}
			native, err := policy.NativeSource()
			if err != nil {
				t.Fatal(err)
			}
			runtime, err := NewNodeChainSOCKSRuntime(native)
			if err != nil {
				t.Fatal("original projected runtime missing", err)
			}
			runtime.chain.runtime.testTLS = unprojected.chain.runtime.testTLS
			engine.source, engine.config, engine.meta = native, native.config, native.metadata
			engine.chain = runtime.chain
			engine.identity.SourceSHA256, engine.identity.ConfigSHA256 = runtime.chain.SourceSHA256(), runtime.chain.ConfigSHA256()
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := runtime.CloseContext(ctx); err != nil {
					t.Error("original projected proof did not join", err)
				}
			})
			if runtime.Progress().Ready || runtime.HealthyContext(context.Background()) == nil {
				t.Fatal("desktop projection fabricated complete proof")
			}
			if err := runtime.Run(context.Background(), engine); err != nil {
				t.Fatal("projected source failed original complete proofs", err)
			}
			progress := runtime.Progress()
			if !progress.Ready || !progress.Complete || !progress.DNSProven || !progress.PublicProven || len(progress.Prefixes) != 3 {
				t.Fatal("projected runtime skipped original complete proof")
			}
			for _, prefix := range progress.Prefixes {
				if !prefix.Proven || prefix.ResponseMS <= 0 {
					t.Fatal("projected runtime invented an unmeasured prefix")
				}
			}
			engine.ownerMu.Lock()
			engine.source = unprojected.source
			engine.ownerMu.Unlock()
			if runtime.HealthyContext(context.Background()) == nil || runtime.Progress().Ready {
				t.Fatal("projected proof adopted a different source object")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := runtime.CloseContext(ctx); err != nil || engine.nativeClosed.Load() {
				t.Fatal("projected shared Close failed or fabricated native DOWN", err)
			}
		})
	}
}
