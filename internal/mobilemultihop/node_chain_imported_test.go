package mobilemultihop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func nodeChainImportedFixture(t *testing.T, mode, layer string) NodeChainSource {
	t.Helper()
	nodes := nodeChainModeFixtureNodes(t, []string{mode, "wg", "shadowsocks"}, []string{layer, "", layer})
	ids := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg"}, []string{"", "", ""})
	config, capture, _, _ := importedEntryFixture(t, "", "")
	middle, err := NodeChainImportedMemberInput(config, capture)
	if err != nil {
		t.Fatal(err)
	}
	source := nodeChainFixtureSource(t, nodes)
	source.Schema = 2
	source.Nodes[1] = middle
	source.IdentitySources = []string{ids[0].inputs.Files, "", ids[2].inputs.Files}
	if mode == "wg" {
		source.IdentitySources[0] = nodes[0].inputs.Files
	}
	return source
}
func TestNodeChainImportedMiddleSourceAndNativeProjection(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				source := nodeChainImportedFixture(t, mode, layer)
				chain, err := NewNodeChain(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				p := chain.ProofInventory()[1]
				if p.NodeKind != "external" || p.Kind != "public-path" || p.NodeID != "" || chain.nodes[1] != nil || p.ProfileID != "saved-exit" {
					t.Fatal("external middle acquired private authority", p)
				}
				original := externalTestRead(t, chain.importedMiddle.input)
				if original["capture"] == "" || !strings.Contains(original["capture"].(string), `"dns_mode":"home"`) {
					t.Fatal("original standalone source lost")
				}
				graph := externalTestRead(t, chain.Config())
				middle := externalTestFind(t, graph, p.Tag)
				if middle["detour"] != chain.proofs[0].Tag || middle["method"] != NativeStartLayerMethod {
					t.Fatal("middle routing/source changed", middle)
				}
				final := externalTestFind(t, graph, chain.FinalTag())
				if final["detour"] != p.Tag {
					t.Fatal("final bypassed custom middle", final)
				}
				for _, row := range graph["dns"].(map[string]any)["servers"].([]any) {
					dns := row.(map[string]any)
					if strings.Contains(dns["tag"].(string), "routervpn-chain-1-") {
						t.Fatal("standalone middle DNS became application or physical policy")
					}
					if dns["tag"] == chain.DNSCapture().ResolverTag && (dns["detour"] != chain.FinalTag() || dns["server"] != "10.82.0.53") {
						t.Fatal("selected final DNS changed", dns)
					}
				}
				for _, target := range []string{"", "android", "ios", "linux", "darwin", "windows"} {
					derived := chain
					if target != "" {
						derived, err = ProjectNodeChain(chain, target, 1280)
						if err != nil {
							t.Fatal(target, err)
						}
					}
					launch, err := derived.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					reopened, err := ParseNodeChainLaunchInput(launch)
					if err != nil || reopened.Config() != derived.Config() || reopened.Metadata() != derived.Metadata() {
						t.Fatal("source replay failed", target, err)
					}
					var record nodeChainLaunchRecord
					_ = json.Unmarshal([]byte(launch), &record)
					if record.Schema != 2 || !reflect.DeepEqual(record.Nodes, source.Nodes) || !reflect.DeepEqual(record.IdentitySources, source.IdentitySources) {
						t.Fatal("original typed sources changed")
					}
				}
			})
		}
	}
}
func TestNodeChainImportedMiddleRejectsUncapturedAuthority(t *testing.T) {
	source := nodeChainImportedFixture(t, "wg", "")
	for _, fault := range []string{"schema1", "unknown-schema", "two", "four", "missing-identities", "middle-identity", "missing-first-identity", "missing-final-identity", "reorder", "paired-middle", "double-imported", "canonical-middle", "duplicate-middle-key", "fake-api", "fake-proof", "layer", "hostname", "wrong-credential", "legacy-method", "identity-chain", "changed-expected-ip", "extra-route"} {
		t.Run(fault, func(t *testing.T) {
			bad := source
			bad.Nodes = append([]string(nil), source.Nodes...)
			bad.IdentitySources = append([]string(nil), source.IdentitySources...)
			var record nodeChainImportedInput
			_ = json.Unmarshal([]byte(bad.Nodes[1]), &record)
			capture := externalTestRead(t, record.Capture)
			profile := capture["profile"].(map[string]any)
			graph := externalTestRead(t, record.Config)
			out := externalTestFind(t, graph, ExternalFinalTag)
			ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
			switch fault {
			case "schema1":
				bad.Schema = 1
			case "unknown-schema":
				bad.Schema = 3
			case "two":
				bad.Nodes = bad.Nodes[:2]
			case "four":
				bad.Nodes = append(bad.Nodes, bad.Nodes[0])
			case "missing-identities":
				bad.IdentitySources = nil
			case "middle-identity":
				bad.IdentitySources[1] = bad.IdentitySources[0]
			case "missing-first-identity":
				bad.IdentitySources[0] = ""
			case "missing-final-identity":
				bad.IdentitySources[2] = ""
			case "reorder":
				bad.Nodes[0], bad.Nodes[1] = bad.Nodes[1], bad.Nodes[0]
			case "paired-middle":
				bad.Nodes[1] = bad.Nodes[0]
			case "double-imported":
				bad.Nodes[0] = bad.Nodes[1]
			case "canonical-middle":
				bad.Nodes[1] += " "
			case "duplicate-middle-key":
				bad.Nodes[1] = strings.Replace(bad.Nodes[1], `"schema":1`, `"schema":1,"schema":1`, 1)
			default:
				switch fault {
				case "fake-api":
					profile["router_api"] = "http://10.0.0.1:8787"
					profile["api_token"] = "invented"
				case "fake-proof":
					profile["node_proof_id"] = strings.Repeat("a", 64)
				case "layer":
					profile["start_layer"] = "aes-256-gcm"
				case "hostname":
					out["server"] = "middle.invalid"
					ss["server"] = "middle.invalid"
				case "wrong-credential":
					out["password"] = "different"
				case "legacy-method":
					out["method"] = "aes-256-gcm"
					ss["method"] = "aes-256-gcm"
				case "identity-chain":
					out["password"] = out["password"].(string) + ":" + out["password"].(string)
					ss["password"] = out["password"]
				case "changed-expected-ip":
					capture["expected_public_ip"] = "198.51.100.243"
				case "extra-route":
					graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": "escape"})
				}
				record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
				bad.Nodes[1] = startJSON(t, record)
			}
			if _, err := NewNodeChain(startJSON(t, bad)); err == nil {
				t.Fatal("uncaptured custom middle accepted")
			}
		})
	}
}
func TestNodeChainImportedMiddleRequiresPublicProof(t *testing.T) {
	for _, fault := range []string{"", "middle-stopped", "wrong-public-ip", "changed-source"} {
		t.Run(fault, func(t *testing.T) {
			chain, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, "wg", "")))
			if err != nil {
				t.Fatal(err)
			}
			engine := newNodeChainTestEngine(t, chain)
			switch fault {
			case "middle-stopped":
				engine.dead = 1
			case "wrong-public-ip":
				engine.publicBody = "ip=198.51.100.7\n"
			case "changed-source":
				chain.importedMiddle.selection.Profile["node_kind"] = "router-vpn"
			}
			err = chain.Run(context.Background(), engine)
			if fault != "" {
				if err == nil || chain.Progress().Ready {
					t.Fatal("unproved middle became ready")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			progress := chain.Progress()
			if !progress.Ready || len(progress.Prefixes) != 3 || progress.Prefixes[1].Kind != "public-path" || progress.Prefixes[1].Label == "" {
				t.Fatal("public prefix lost distinction", progress)
			}
			owner := &nodeChainMeasurementFixture{chain: chain}
			service, err := chain.NewHopMeasurementContext(context.Background(), owner)
			if err != nil {
				t.Fatal(err)
			}
			if err = service.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeChainImportedMiddleDesktopPolicyRetainsPhysicalOwner(t *testing.T) {
	source := nodeChainImportedFixture(t, "wg", "")
	var member nodeChainImportedInput
	_ = json.Unmarshal([]byte(source.Nodes[1]), &member)
	capture := externalTestRead(t, member.Capture)
	profile := capture["profile"].(map[string]any)
	profile["kill_switch_policy"], profile["home_lan_access"], profile["ipv6_mode"] = "always", false, "off"
	var err error
	source.Nodes[1], err = NodeChainImportedMemberInput(member.Config, startJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	original, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux", "darwin", "windows"} {
		t.Run(target, func(t *testing.T) {
			policy, err := NewDesktopNodeChainPolicy(original, desktopNodeTestSession, target, 1280)
			if err != nil {
				t.Fatal(err)
			}
			_, meta, physical, err := policy.ReadValidated()
			chain := policy.NodeChain()
			if err != nil {
				t.Fatal(err)
			}
			if meta.KillSwitchPolicy != "always" || meta.HomeLANAccess || meta.IPv6Mode != "off" || physical.SelectedDNS.Detour != chain.FinalTag() || physical.SelectedDNS.Physical {
				t.Fatal("custom policy or final DNS ownership lost")
			}
			for _, root := range physical.PhysicalRoots {
				if !strings.HasPrefix(root.Tag, "routervpn-chain-0-") {
					t.Fatal("middle escaped original physical owner", root)
				}
			}
			launch, err := chain.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := ParseNodeChainLaunchInput(launch)
			if err != nil || reopened.Config() != chain.Config() {
				t.Fatal("physical source replay changed", err)
			}
		})
	}
	original.importedMiddle.selection.Profile["kill_switch_policy"] = "off"
	if _, err := NewDesktopNodeChainPolicy(original, desktopNodeTestSession, "linux", 1280); err == nil {
		t.Fatal("mutated imported protection acquired owner")
	}
}

func TestNodeChainImportedMiddleCiphersAndCompleteFinalDNS(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		for _, protocol := range []string{"https", "h3"} {
			t.Run(method+"/"+protocol, func(t *testing.T) {
				source := nodeChainImportedFixture(t, "wg", "")
				var member nodeChainImportedInput
				_ = json.Unmarshal([]byte(source.Nodes[1]), &member)
				capture := externalTestRead(t, member.Capture)
				graph := externalTestRead(t, member.Config)
				out := externalTestFind(t, graph, ExternalFinalTag)
				ss := capture["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
				size := 32
				if method == "2022-blake3-aes-128-gcm" {
					size = 16
				}
				key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{81}, size))
				out["method"], out["password"], ss["method"], ss["password"] = method, key, method, key
				var err error
				source.Nodes[1], err = NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, capture))
				if err != nil {
					t.Fatal(err)
				}
				final, err := ParseNodeLaunchInput(source.Nodes[2])
				if err != nil {
					t.Fatal(err)
				}
				profile := predecessorCopy(final.profile)
				profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = "doh", protocol, "resolver.example.net"
				profile["dns_port"], profile["dns_server_name"], profile["dns_path"] = float64(8443), "resolver.example.net", "/owned-query"
				bootstrap := map[string]any{"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": "10.82.0.54", "server_port": float64(5354), "detour": "proxy"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "timeout": "3s", "disable_cache": true, "disable_optimistic_cache": true, "rewrite_ttl": float64(42), "client_subnet": "192.0.2.0/24"}}
				final, err = NewNodeProfile(final.inputs.Mode, final.inputs.Files, startJSON(t, profile), final.inputs.Start, startJSON(t, bootstrap))
				if err != nil {
					t.Fatal(err)
				}
				source.Nodes[2], err = final.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				chain, err := NewNodeChain(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				expected := externalTestRead(t, final.Config())["dns"].(map[string]any)["servers"].([]any)
				actual := externalTestRead(t, chain.Config())["dns"].(map[string]any)["servers"].([]any)
				names := map[string]string{}
				for _, raw := range expected {
					row := raw.(map[string]any)
					names[row["tag"].(string)] = nodeChainNamespace(2, final.source, "dns", row["tag"].(string))
				}
				found := 0
				for _, raw := range actual {
					row := raw.(map[string]any)
					if strings.HasPrefix(row["tag"].(string), "routervpn-chain-1-") {
						t.Fatal("middle standalone resolver escaped")
					}
					for _, original := range expected {
						wanted := predecessorCopy(original.(map[string]any))
						wanted["tag"] = names[wanted["tag"].(string)]
						wanted["detour"] = chain.FinalTag()
						if err := predecessorRelabelResolver(wanted, names); err != nil {
							t.Fatal(err)
						}
						if row["tag"] == wanted["tag"] {
							found++
							if !reflect.DeepEqual(row, wanted) {
								t.Fatal("selected DNS/explicit bootstrap fields changed", row, wanted)
							}
						}
					}
				}
				if found != 2 || chain.importedMiddle.input != source.Nodes[1] {
					t.Fatal("complete original resolver/source capture lost")
				}
			})
		}
	}
}

func TestNodeChainImportedMiddleCancellationJoinsOriginalPublicSocket(t *testing.T) {
	chain, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, "wg", "")))
	if err != nil {
		t.Fatal(err)
	}
	engine := newNodeChainTestEngine(t, chain)
	entered, drained := make(chan struct{}), make(chan struct{})
	engine.beforeDial = func(ctx context.Context, tag string) (net.Conn, bool) {
		if tag != chain.proofs[1].Tag {
			return nil, false
		}
		client, server := net.Pipe()
		go func() { defer close(drained); defer server.Close(); close(entered); _, _ = io.Copy(io.Discard, server) }()
		return client, true
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- chain.Run(ctx, engine) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("custom public proof not reached")
	}
	cancel()
	closeCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := chain.CloseContext(closeCtx); err != nil {
		t.Fatal("original custom proof did not drain", err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled public middle succeeded")
		}
	case <-closeCtx.Done():
		t.Fatal("original start owner not joined")
	}
	select {
	case <-drained:
	case <-closeCtx.Done():
		t.Fatal("custom public socket not joined")
	}
	if chain.Progress().Ready {
		t.Fatal("cancelled custom source remains ready")
	}
}
