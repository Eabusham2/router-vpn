package mobilemultihop

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func nodeChainServerSourceFixture(t *testing.T, count int, layer string) NodeChainServerSource {
	t.Helper()
	modes, layers := make([]string, count), make([]string, count)
	identityModes, identityLayers := make([]string, count), make([]string, count)
	for i := range modes {
		modes[i], layers[i], identityModes[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3], layer, "wg"
	}
	modes[count-1] = "shadowsocks"
	nodes := nodeChainModeFixtureNodes(t, modes, layers)
	identities := nodeChainModeFixtureNodes(t, identityModes, identityLayers)
	if count == 8 && layer != "" {
		// Seven real nested packet envelopes need a larger original budget.
		// Supply that budget in both captured assets; never relax the compiler's
		// fixed/dual-stack ceiling check to make a long fixture fit.
		for _, group := range [][]*NodeProfile{nodes, identities} {
			for i, node := range group {
				if !NodeChainPrefixMode(node.mode) {
					continue
				}
				var assets map[string]string
				if err := json.Unmarshal([]byte(node.inputs.Files), &assets); err != nil {
					t.Fatal(err)
				}
				name := "wg.conf"
				if node.mode != "wg" {
					name = "awg.conf"
				}
				raw := string(mustDecodeChainAsset(t, assets[name]))
				if !strings.Contains(raw, "MTU = 2000") {
					t.Fatal("fixture lost its original packet budget")
				}
				assets[name] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(raw, "MTU = 2000", "MTU = 4096", 1)))
				var err error
				group[i], err = NewNodeProfile(node.mode, startJSON(t, assets), node.inputs.ProfileJSON, node.inputs.Start, node.inputs.DNSBootstrap)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	first := nodes[0]
	source := NodeChainServerSource{Schema: 1, EntryID: predecessorText(first.profile, "id"),
		EntryNodeID: predecessorText(first.profile, "node_proof_id"), EntryMode: first.mode}
	for i := 1; i < count; i++ {
		launch, err := nodes[i].LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
		source.Nodes = append(source.Nodes, launch)
		source.IdentitySources = append(source.IdentitySources, identities[i].inputs.Files)
	}
	return source
}

func nodeChainServerCaptureFixture(t *testing.T, policy *NodeChainServerPolicy) multihoprelay.NodeChainCapture {
	t.Helper()
	descriptor := policy.Descriptor()
	digest, err := descriptor.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := multihoprelay.NodeChainRequest{Schema: descriptor.Schema, SessionID: strings.Repeat("1", 32), EntryNodeID: descriptor.EntryNodeID,
		SourceSHA256: descriptor.SourceSHA256, DescriptorSHA256: digest, DNSPolicySHA256: descriptor.DNSPolicySHA256,
		Epoch: strings.Repeat("2", 64), Peer: "10.77.0.2", AcquireExpiresAt: 1794484810, Port: 26240}
	for i := range descriptor.Members {
		key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{byte(181 + i)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if descriptor.Schema == 1 || i == 0 {
			request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()))
			if descriptor.Schema == 2 {
				request.LocalPacketPositions = append(request.LocalPacketPositions, 0)
			}
		}
		request.Users = append(request.Users, multihoprelay.NodeChainUser{Position: i + 1,
			Username: fmt.Sprintf("%048x", 101+i*2), Password: fmt.Sprintf("%048x", 102+i*2)})
	}
	capture := multihoprelay.NodeChainCapture{Schema: 1, Request: request, Source: descriptor,
		RegistrySHA256: digest, OwnerID: strings.Repeat("3", 64), Peer: request.Peer, Host: "10.77.0.1", BootstrapDeadline: time.Unix(1794484890, 0).UTC()}
	if err := capture.Validate(); err != nil {
		t.Fatal(err)
	}
	return capture
}

func nodeChainServerFixture(t *testing.T, count int, layer string) (*NodeChainServerPolicy, multihoprelay.NodeChainCapture) {
	t.Helper()
	policy, err := NewNodeChainServerPolicy(startJSON(t, nodeChainServerSourceFixture(t, count, layer)))
	if err != nil {
		t.Fatal("complete captured server suffix", err)
	}
	return policy, nodeChainServerCaptureFixture(t, policy)
}

func TestNodeChainServerCompleteSuffixAndListenerSeparation(t *testing.T) {
	for _, count := range []int{2, 3, 4, 8} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(fmt.Sprintf("%d/%s", count, layer), func(t *testing.T) {
				policy, capture := nodeChainServerFixture(t, count, layer)
				config, err := policy.NativeConfig(capture)
				if err != nil {
					t.Fatal(err)
				}
				graph := importedPQGraph(t, config)
				if len(graph["inbounds"].([]any)) != 0 || len(graph["endpoints"].([]any)) != count-2 {
					t.Fatal("server suffix created a listener/TUN or lost its packet owners")
				}
				inventory, targets := policy.ProofInventory(), policy.proofTargets
				if len(inventory) != count-1 || len(targets) != count-1 {
					t.Fatal("server did not retain every suffix proof")
				}
				final := inventory[len(inventory)-1].Tag
				if graph["route"].(map[string]any)["final"] != final {
					t.Fatal("server graph does not have its one final captured route")
				}
				all := map[string]map[string]any{}
				for _, family := range []string{"endpoints", "outbounds"} {
					for _, raw := range graph[family].([]any) {
						row := raw.(map[string]any)
						if row["type"] == "selector" || row["type"] == "direct" || row["type"] == "socks" {
							t.Fatal("suffix added an unowned alternate route or front")
						}
						all[row["tag"].(string)] = row
					}
				}
				for i, proof := range inventory {
					if proof.Position != i+1 || proof.ProfileID != policy.descriptor.Members[i].ProfileID || proof.NodeID != policy.descriptor.Members[i].NodeID || proof.Kind != "" || proof.NodeKind != "" {
						t.Fatal("public suffix position or exact Router identity changed")
					}
					outer := all[proof.Tag]
					if layer != "" && i < len(inventory)-1 {
						outer = all[outer["detour"].(string)]
					}
					if i == 0 && outer["detour"] != nil || i > 0 && outer["detour"] != inventory[i-1].Tag {
						t.Fatal("suffix omitted a previous encrypted position", i, outer)
					}
				}
				dns, err := policy.DNSCapture(capture)
				if err != nil || dns.FinalTag != final || externalDigest([]byte(dns.PolicyJSON)) != capture.Source.DNSPolicySHA256 {
					t.Fatal("DNS identity differs from its original final selected policy", err)
				}
				dnsGraph := importedPQGraph(t, dns.RouterJSON)
				matched := false
				for _, value := range dnsGraph["servers"].([]any) {
					row := value.(map[string]any)
					if row["tag"] == dns.ResolverTag {
						encoded, _ := json.Marshal(row)
						matched = row["detour"] == final && externalDigest(encoded) == dns.ResolverSHA256
					}
				}
				if !matched {
					t.Fatal("selected resolver escaped the exact final suffix")
				}
				routes, err := policy.FrontRoutes(capture)
				if err != nil {
					t.Fatal(err)
				}
				captureDigest, _ := capture.Digest()
				for i, route := range routes {
					if route.Binding.CaptureSHA256 != captureDigest || route.Binding.ConfigSHA256 != externalDigest([]byte(config)) ||
						route.Binding.SourceSHA256 != policy.SourceSHA256() || route.Position != i+1 || route.Username != capture.Request.Users[i].Username ||
						route.Password != capture.Request.Users[i].Password || route.Tag != inventory[i].Tag || route.Final != (i == len(routes)-1) ||
						!route.AllowsDestination("tcp", targets[i].Address) {
						t.Fatal("positional front does not bind the exact worker and proof route")
					}
					if route.Final && route.UDPOverTCPVersion != 2 || !route.Final && route.UDPOverTCPVersion != 0 {
						t.Fatal("positional front changed captured UoT version or gave UDP to a prefix")
					}
					if i < len(routes)-1 && (route.AllowsDestination("udp", targets[i].Address) || route.AllowsDestination("tcp", "1.1.1.1:443") || route.AllowsDestination("udp", "1.1.1.1:53") ||
						route.AllowsDestination("tcp", targets[len(targets)-1].Address)) {
						t.Fatal("prefix credential became general application/final traffic authority")
					}
				}
				if !routes[len(routes)-1].AllowsDestination("tcp", "1.1.1.1:443") || !routes[len(routes)-1].AllowsDestination("udp", "1.1.1.1:443") {
					t.Fatal("final captured front lost a payload network")
				}
				reopened, err := NewNodeChainServerPolicy(policy.Source())
				if err != nil || reopened.config != config || reopened.SourceSHA256() != policy.SourceSHA256() || !reflect.DeepEqual(reopened.Descriptor(), capture.Source) {
					t.Fatal("operator source could not reproduce the original no-inbound graph", err)
				}
			})
		}
	}
}

func TestNodeChainServerOriginalIdentityAndSourceRejection(t *testing.T) {
	local := nodeChainIdentityFixture(t)
	entry, err := ParseNodeLaunchInput(local.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	source := NodeChainServerSource{Schema: 1, EntryID: predecessorText(entry.profile, "id"), EntryNodeID: predecessorText(entry.profile, "node_proof_id"),
		EntryMode: entry.mode, Nodes: append([]string(nil), local.Nodes[1:]...), IdentitySources: append([]string(nil), local.IdentitySources[1:]...)}
	policy, err := NewNodeChainServerPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal("independent AWG key must preserve its standard-WG Router identity", err)
	}
	capture := nodeChainServerCaptureFixture(t, policy)
	if _, err := policy.NativeConfig(capture); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*NodeChainServerSource){
		"empty-suffix":     func(s *NodeChainServerSource) { s.Nodes = nil; s.IdentitySources = nil },
		"oversized-source": func(s *NodeChainServerSource) { s.IdentitySources[0] = strings.Repeat(" ", NodeChainInputLimit) },
		"wrong-schema":     func(s *NodeChainServerSource) { s.Schema = 2 },
		"missing-identity": func(s *NodeChainServerSource) { s.IdentitySources = nil },
		"empty-identity":   func(s *NodeChainServerSource) { s.IdentitySources[0] = "" },
		"reordered-identity": func(s *NodeChainServerSource) {
			s.IdentitySources[0], s.IdentitySources[1] = s.IdentitySources[1], s.IdentitySources[0]
		},
		"duplicate-position":      func(s *NodeChainServerSource) { s.Nodes[1] = s.Nodes[0]; s.IdentitySources[1] = s.IdentitySources[0] },
		"wrong-final":             func(s *NodeChainServerSource) { s.Nodes[2] = s.Nodes[1]; s.IdentitySources[2] = s.IdentitySources[1] },
		"imported-middle":         func(s *NodeChainServerSource) { s.Nodes[1] = `{"kind":"external","mode":"shadowsocks"}` },
		"entry-proof-collision":   func(s *NodeChainServerSource) { s.EntryNodeID = policy.descriptor.Members[0].NodeID },
		"entry-profile-collision": func(s *NodeChainServerSource) { s.EntryID = policy.descriptor.Members[0].ProfileID },
		"unsupported-entry":       func(s *NodeChainServerSource) { s.EntryMode = "max" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := source
			changed.Nodes, changed.IdentitySources = append([]string(nil), source.Nodes...), append([]string(nil), source.IdentitySources...)
			mutate(&changed)
			if _, err := NewNodeChainServerPolicy(startJSON(t, changed)); err == nil {
				t.Fatal("incomplete or changed ordered server source passed")
			}
		})
	}
	for name, raw := range map[string]string{
		"unknown-native-config": strings.Replace(policy.Source(), `"schema":1`, `"native_config":{},"schema":1`, 1),
		"duplicate-source-key":  strings.Replace(policy.Source(), `"schema":1`, `"schema":1,"schema":1`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewNodeChainServerPolicy(raw); err == nil {
				t.Fatal("client-like arbitrary configuration or duplicate source field passed")
			}
		})
	}
}

func TestNodeChainServerWorkerCaptureRejectsReplacementAndAliasing(t *testing.T) {
	policy, capture := nodeChainServerFixture(t, 4, "")
	for name, mutate := range map[string]func(*multihoprelay.NodeChainCapture){
		"registry":     func(c *multihoprelay.NodeChainCapture) { c.RegistrySHA256 = strings.Repeat("a", 64) },
		"missing-user": func(c *multihoprelay.NodeChainCapture) { c.Request.Users = c.Request.Users[1:] },
		"source-rebound": func(c *multihoprelay.NodeChainCapture) {
			c.Source.SourceSHA256 = strings.Repeat("a", 64)
			c.Request.SourceSHA256 = c.Source.SourceSHA256
			c.RegistrySHA256, _ = c.Source.Digest()
			c.Request.DescriptorSHA256 = c.RegistrySHA256
		},
		"dns-rebound": func(c *multihoprelay.NodeChainCapture) {
			c.Source.DNSPolicySHA256 = strings.Repeat("a", 64)
			c.Request.DNSPolicySHA256 = c.Source.DNSPolicySHA256
			c.RegistrySHA256, _ = c.Source.Digest()
			c.Request.DescriptorSHA256 = c.RegistrySHA256
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := capture.Clone()
			mutate(&changed)
			if _, err := policy.NativeConfig(changed); err == nil {
				t.Fatal("foreign capture received native config")
			}
			if _, err := policy.ProofTargets(changed); err == nil {
				t.Fatal("foreign capture received private proof authority")
			}
			if _, err := policy.DNSCapture(changed); err == nil {
				t.Fatal("foreign capture received DNS authority")
			}
			if _, err := policy.FrontRoutes(changed); err == nil {
				t.Fatal("foreign capture received positional front authority")
			}
		})
	}
	descriptor := policy.Descriptor()
	descriptor.Members[0].ProfileID = "replacement"
	proofs := policy.ProofInventory()
	proofs[0].Tag = "replacement"
	targets, _ := policy.ProofTargets(capture)
	targets[0].Token = "replacement"
	dns, _ := policy.DNSCapture(capture)
	dns.Destinations[0].Address = "replacement"
	routes, _ := policy.FrontRoutes(capture)
	routes[0].Destinations[0].Address = "replacement"
	if _, err := policy.NativeConfig(capture); err != nil || policy.descriptor.Members[0].ProfileID == "replacement" || policy.proofs[0].Tag == "replacement" || policy.proofTargets[0].Token == "replacement" || policy.dns.Destinations[0].Address == "replacement" {
		t.Fatal("returned worker capture aliases original source", err)
	}
	for name, mutate := range map[string]func(*NodeChainServerPolicy){
		"native-config":  func(p *NodeChainServerPolicy) { p.config += " " },
		"proof-token":    func(p *NodeChainServerPolicy) { p.proofTargets[0].Token += "x" },
		"resolver":       func(p *NodeChainServerPolicy) { p.dns.RouterJSON += " " },
		"profile-source": func(p *NodeChainServerPolicy) { p.nodes[0].profile["api_token"] = "replacement" },
	} {
		t.Run(name, func(t *testing.T) {
			changed, err := NewNodeChainServerPolicy(policy.Source())
			if err != nil {
				t.Fatal(err)
			}
			mutate(changed)
			if _, err := changed.FrontRoutes(capture); err == nil {
				t.Fatal("mutated internal owner passed its capture seal")
			}
		})
	}
}

func TestNodeChainServerFinalFrontRetainsOriginalDeviceRestrictions(t *testing.T) {
	source := nodeChainServerSourceFixture(t, 4, "")
	node, err := ParseNodeLaunchInput(source.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	profile := predecessorCopy(node.profile)
	profile["ipv6_mode"], profile["home_lan_access"], profile["home_lan_cidrs"] = "off", false, []string{"10.12.0.0/16"}
	node, err = NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	source.Nodes[0], err = node.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewNodeChainServerPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	capture := nodeChainServerCaptureFixture(t, policy)
	routes, err := policy.FrontRoutes(capture)
	if err != nil {
		t.Fatal(err)
	}
	final := routes[len(routes)-1]
	if !final.BlockIPv6 || !reflect.DeepEqual(final.BlockedCIDRs, []string{"10.12.0.0/16"}) {
		t.Fatal("middle policy was discarded")
	}
	for _, address := range []string{"10.12.1.1:443", "[2001:db8::1]:443", "[::ffff:10.12.1.1]:443", "example.com:443", "1.1.1.1:0", "1.1.1.1:0443"} {
		if final.AllowsDestination("tcp", address) || final.AllowsDestination("udp", address) {
			t.Fatal("captured final restrictions bypassed", address)
		}
	}
	if !final.AllowsDestination("tcp", "1.1.1.1:443") || !final.AllowsDestination("udp", "1.1.1.1:443") {
		t.Fatal("public TCP/UDP was lost")
	}
	for _, destination := range final.Destinations {
		if !final.AllowsDestination(destination.Network, destination.Address) {
			t.Fatal("exact captured control/DNS exception was lost")
		}
	}
	final.BlockedCIDRs[0] = "0.0.0.0/0"
	fresh, _ := policy.FrontRoutes(capture)
	if fresh[len(fresh)-1].BlockedCIDRs[0] != "10.12.0.0/16" {
		t.Fatal("front policy alias changed a later worker capture")
	}
}

func TestNodeChainServerSelectedDNSRetainsOriginalTransportAndBootstrap(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
		for _, bootstrapProtocol := range []string{"", "udp", "h3"} {
			t.Run(protocol+"/"+bootstrapProtocol, func(t *testing.T) {
				source := nodeChainServerSourceFixture(t, 3, "aes-256-gcm+xor-whitening")
				last := len(source.Nodes) - 1
				node, err := ParseNodeLaunchInput(source.Nodes[last])
				if err != nil {
					t.Fatal(err)
				}
				profile := predecessorCopy(node.profile)
				profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", protocol, "9.9.9.9", float64(5443)
				profile["dns_server_name"], profile["dns_path"] = "captured-resolver.example", "/owned-query"
				bootstrap := ""
				if bootstrapProtocol != "" {
					profile["dns_host"] = "captured-resolver.example"
					server := map[string]any{"type": bootstrapProtocol, "tag": "external-dns-bootstrap", "server": "1.1.1.1", "server_port": 5553, "detour": "proxy"}
					if bootstrapProtocol == "h3" {
						server["tls"], server["path"] = map[string]any{"enabled": true, "server_name": "captured-bootstrap.example"}, "/owned-bootstrap"
					}
					bootstrap = startJSON(t, map[string]any{"server": server, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "disable_cache": true}})
				}
				node, err = NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, bootstrap)
				if err != nil {
					t.Fatal(err)
				}
				source.Nodes[last], err = node.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				policy, err := NewNodeChainServerPolicy(startJSON(t, source))
				if err != nil {
					t.Fatal("complete selected resolver tree", err)
				}
				capture := nodeChainServerCaptureFixture(t, policy)
				dns, err := policy.DNSCapture(capture)
				if err != nil {
					t.Fatal(err)
				}
				original := importedPQGraph(t, node.Config())["dns"]
				encoded, _ := json.Marshal(original)
				if dns.PolicyJSON != string(encoded) || dns.PolicySHA256 != externalDigest(encoded) || capture.Request.DNSPolicySHA256 != dns.PolicySHA256 {
					t.Fatal("server selected DNS policy was substituted")
				}
				graph := importedPQGraph(t, dns.RouterJSON)
				var selected map[string]any
				for _, value := range graph["servers"].([]any) {
					row := value.(map[string]any)
					if row["tag"] == dns.ResolverTag {
						selected = row
					}
				}
				if selected == nil || selected["type"] != protocol || selected["server"] != profile["dns_host"] || selected["server_port"] != float64(5443) || selected["detour"] != dns.FinalTag {
					t.Fatal("selected DNS escaped the final ordered suffix")
				}
				if protocol == "tls" || protocol == "https" || protocol == "h3" {
					if selected["tls"].(map[string]any)["server_name"] != "captured-resolver.example" {
						t.Fatal("selected TLS identity changed")
					}
				}
				if protocol == "https" || protocol == "h3" {
					if selected["path"] != "/owned-query" {
						t.Fatal("selected HTTP path changed")
					}
				}
				routes, _ := policy.FrontRoutes(capture)
				front := routes[len(routes)-1]
				for _, destination := range dns.Destinations {
					if !front.AllowsDestination(destination.Network, destination.Address) {
						t.Fatal("selected resolver lost its final front authority")
					}
				}
				if bootstrapProtocol != "" {
					query := selected["domain_resolver"].(map[string]any)
					found := false
					for _, value := range graph["servers"].([]any) {
						row := value.(map[string]any)
						if row["tag"] != query["server"] {
							continue
						}
						found = row["type"] == bootstrapProtocol && row["server"] == "1.1.1.1" && row["server_port"] == float64(5553) && row["detour"] == dns.FinalTag && query["strategy"] == "ipv4_only" && query["disable_cache"] == true
						if bootstrapProtocol == "h3" {
							found = found && row["path"] == "/owned-bootstrap" && row["tls"].(map[string]any)["server_name"] == "captured-bootstrap.example"
						}
					}
					if !found || len(dns.Destinations) != 2 {
						t.Fatal("explicit original bootstrap changed or became physical")
					}
				}
			})
		}
	}
}

func TestNodeChainServerSourceReplacementCannotAdoptPriorLease(t *testing.T) {
	policy, capture := nodeChainServerFixture(t, 3, "")
	var source NodeChainServerSource
	if err := json.Unmarshal([]byte(policy.Source()), &source); err != nil {
		t.Fatal(err)
	}
	node, err := ParseNodeLaunchInput(source.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	profile := predecessorCopy(node.profile)
	profile["api_token"] = "replacement-current-catalog-token"
	changed, err := NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	source.Nodes[0], err = changed.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := NewNodeChainServerPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	if replacement.SourceSHA256() == policy.SourceSHA256() {
		t.Fatal("private authentication replacement did not change source identity")
	}
	if _, err := replacement.NativeConfig(capture); err == nil {
		t.Fatal("old lease adopted replacement private authentication")
	}
	raw, err := json.Marshal(policy.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{policy.nodes[0].inputs.Files, policy.proofTargets[0].API, policy.proofTargets[0].Token} {
		if strings.Contains(string(raw), private) {
			t.Fatal("public descriptor disclosed private source or authentication")
		}
	}
}
