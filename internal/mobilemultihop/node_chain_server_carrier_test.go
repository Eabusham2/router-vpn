package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func serverCarrierPolicyFixture(t *testing.T, mode, layer string, fixed int, count int) *NodeChainServerPolicy {
	t.Helper()
	modes, layers, identities := make([]string, count), make([]string, count), make([]string, count)
	for i := range modes {
		modes[i], layers[i], identities[i] = "wg", layer, "wg"
	}
	modes[0], modes[count-1] = mode, "shadowsocks"
	nodes := nodeChainModeFixtureNodes(t, modes, layers)
	identity := nodeChainModeFixtureNodes(t, identities, make([]string, count))
	if fixed > 0 {
		first := nodes[0]
		profile := predecessorCopy(first.profile)
		profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(fixed)
		var err error
		nodes[0], err = NewNodeProfile(first.mode, first.inputs.Files, startJSON(t, profile), first.inputs.Start, first.inputs.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
	}
	source := NodeChainServerSource{Schema: 1, EntryID: "original-entry", EntryNodeID: strings.Repeat("a", 64), EntryMode: "wg"}
	for i, node := range nodes {
		launch, err := node.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
		source.Nodes = append(source.Nodes, launch)
		source.IdentitySources = append(source.IdentitySources, identity[i].inputs.Files)
	}
	policy, err := NewNodeChainServerPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
func serverCarrierSnapshotFixture() nodeChainServerCarrierSnapshot {
	return nodeChainServerCarrierSnapshot{NamespaceDevice: 4, NamespaceInode: 9, InterfaceIndex: 3, InterfaceMTU: 1500, InterfaceName: "original-uplink", InterfaceAddress: "00:11:22:33:44:55", SourceAddress: "192.0.2.2", RouteSHA256: strings.Repeat("d", 64)}
}
func serverCarrierCaptureFixture(t *testing.T, p *NodeChainServerPolicy, snapshot *nodeChainServerCarrierSnapshot) *NodeChainServerCarrier {
	t.Helper()
	carrier, err := captureNodeChainServerCarrier(context.Background(), p, func(ctx context.Context) (nodeChainServerCarrierSnapshot, error) { return *snapshot, ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	return carrier
}
func serverCarrierEndpointMTUs(t *testing.T, p *NodeChainServerPolicy) []int {
	t.Helper()
	var graph map[string]any
	if json.Unmarshal([]byte(p.config), &graph) != nil {
		t.Fatal("projected graph")
	}
	var values []int
	for _, raw := range graph["endpoints"].([]any) {
		value, err := mtuNumber(raw.(map[string]any)["mtu"])
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
	return values
}
func TestNodeChainServerCarrierProjectsOriginalAllLayers(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				original := serverCarrierPolicyFixture(t, mode, layer, 0, 2)
				source, config := original.sourceJSON, original.config
				snapshot := serverCarrierSnapshotFixture()
				carrier := serverCarrierCaptureFixture(t, original, &snapshot)
				projected, err := carrier.ProjectContext(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if original.sourceJSON != source || original.config != config || projected.sourceJSON != source || projected.sourceSHA != original.sourceSHA || projected.configSHA == original.configSHA || !reflect.DeepEqual(projected.proofs, original.proofs) {
					t.Fatal("projection rewrote original source/proof identity or retained unbounded config")
				}
				mtu := serverCarrierEndpointMTUs(t, projected)[0]
				if mtu < 1280 || mtu >= 1500 || mtu >= serverCarrierEndpointMTUs(t, original)[0] {
					t.Fatal("first endpoint did not derive original carrier bound", mtu)
				}
				if projected.validateCapture() != nil || projected.carrier != carrier {
					t.Fatal("projection lost sealed carrier")
				}
			})
		}
	}
}
func TestNodeChainServerCarrierRecomputesDownstreamAndFixedRefuses(t *testing.T) {
	original := serverCarrierPolicyFixture(t, "wg", "", 0, 3)
	snapshot := serverCarrierSnapshotFixture()
	projected, err := serverCarrierCaptureFixture(t, original, &snapshot).ProjectContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mtus := serverCarrierEndpointMTUs(t, projected)
	if len(mtus) != 2 || mtus[0] != 1440 || mtus[1] != 1376 {
		t.Fatal("downstream did not recompute from derived first endpoint", mtus)
	}
	fixed := serverCarrierPolicyFixture(t, "wg", "", 2000, 2)
	if _, err := serverCarrierCaptureFixture(t, fixed, &snapshot).ProjectContext(context.Background()); err == nil {
		t.Fatal("oversized Fixed silently clamped")
	}
	fitting := serverCarrierPolicyFixture(t, "wg", "", 1400, 2)
	projected, err = serverCarrierCaptureFixture(t, fitting, &snapshot).ProjectContext(context.Background())
	if err != nil || serverCarrierEndpointMTUs(t, projected)[0] != 1400 {
		t.Fatal("fitting Fixed changed", err)
	}
	snapshot.RouteMTU = 1400
	if _, err := serverCarrierCaptureFixture(t, original, &snapshot).ProjectContext(context.Background()); err == nil {
		t.Fatal("unviable complete downstream graph accepted")
	}
}
func TestNodeChainServerCarrierOriginalRouteLossNeverRevives(t *testing.T) {
	original := serverCarrierPolicyFixture(t, "wg", "", 0, 2)
	mutations := map[string]func(*nodeChainServerCarrierSnapshot){
		"namespace": func(s *nodeChainServerCarrierSnapshot) { s.NamespaceInode++ }, "index": func(s *nodeChainServerCarrierSnapshot) { s.InterfaceIndex++ },
		"source": func(s *nodeChainServerCarrierSnapshot) { s.SourceAddress = "192.0.2.3" }, "route": func(s *nodeChainServerCarrierSnapshot) { s.RouteSHA256 = strings.Repeat("e", 64) },
		"interface mtu": func(s *nodeChainServerCarrierSnapshot) { s.InterfaceMTU = 1400 }, "kernel route mtu": func(s *nodeChainServerCarrierSnapshot) { s.RouteMTU = 1400 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			snapshot := serverCarrierSnapshotFixture()
			before := snapshot
			carrier := serverCarrierCaptureFixture(t, original, &snapshot)
			projected, err := carrier.ProjectContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			mutate(&snapshot)
			if carrier.CurrentContext(context.Background()) == nil {
				t.Fatal("changed original route retained authority")
			}
			snapshot = before
			if carrier.CurrentContext(context.Background()) == nil || projected.validateCapture() == nil {
				t.Fatal("restored values revived retired route/proof projection")
			}
		})
	}
}
func TestNodeChainServerCarrierRejectsUnownedAdmissionAndCanceledCaller(t *testing.T) {
	original := serverCarrierPolicyFixture(t, "wg", "", 0, 2)
	snapshot := serverCarrierSnapshotFixture()
	carrier := serverCarrierCaptureFixture(t, original, &snapshot)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		calls := 0
		_, err := captureNodeChainServerCarrier(ctx, original, func(context.Context) (nodeChainServerCarrierSnapshot, error) { calls++; return snapshot, nil })
		if err == nil || calls != 0 {
			t.Fatal("invalid caller dispatched native observation")
		}
		if _, err := carrier.ProjectContext(ctx); err == nil {
			t.Fatal("invalid caller projected policy")
		}
	}
	foreign := serverCarrierPolicyFixture(t, "awg2-fast", "", 0, 2)
	if _, err := newNodeChainServerPolicy(foreign.sourceJSON, carrier); err == nil {
		t.Fatal("foreign source borrowed native observation")
	}
	carrier.snapshot.InterfaceMTU = 9000
	if carrier.CurrentContext(context.Background()) == nil {
		t.Fatal("tampered numeric observation accepted")
	}
	var empty NodeChainServerCarrier
	if _, err := empty.ProjectContext(context.Background()); err == nil {
		t.Fatal("caller allocated carrier authority")
	}
}

func TestNodeChainServerCarrierBindsOnlyOriginalOuterTransport(t *testing.T) {
	for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(layer, func(t *testing.T) {
			original := serverCarrierPolicyFixture(t, "awg2-fast", layer, 0, 2)
			snapshot := serverCarrierSnapshotFixture()
			carrier := serverCarrierCaptureFixture(t, original, &snapshot)
			projected, err := carrier.ProjectContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var graph map[string]any
			_ = json.Unmarshal([]byte(projected.config), &graph)
			nodes := map[string]map[string]any{}
			for _, family := range []string{"endpoints", "outbounds"} {
				for _, raw := range graph[family].([]any) {
					node := raw.(map[string]any)
					nodes[node["tag"].(string)] = node
				}
			}
			first := nodes[projected.proofs[0].Tag]
			outer := first
			if layer != "" {
				outer = nodes[predecessorText(first, "detour")]
				if outer == nil || outer["type"] == "direct" {
					t.Fatal("captured Start Layer bypassed")
				}
			}
			bound := nodes[predecessorText(outer, "detour")]
			if bound == nil || bound["type"] != "direct" || bound["bind_interface"] != snapshot.InterfaceName || bound["inet4_bind_address"] != snapshot.SourceAddress || bound["detour"] != nil {
				t.Fatal("physical transport lost captured interface/source")
			}
			for _, proof := range projected.proofs[1:] {
				if nodes[proof.Tag]["detour"] == bound["tag"] {
					t.Fatal("later member bypassed prefix")
				}
			}
			snapshot.NamespaceInode++
			other, err := serverCarrierCaptureFixture(t, original, &snapshot).ProjectContext(context.Background())
			if err != nil || other.configSHA == projected.configSHA {
				t.Fatal("equal MTUs across different route owners reused config binding", err)
			}
		})
	}
}

func TestNodeChainServerCarrierIPv6OuterEnvelopeAndBinding(t *testing.T) {
	for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(layer, func(t *testing.T) {
			original := serverCarrierPolicyFixture(t, "wg", layer, 0, 2)
			var source NodeChainServerSource
			_ = json.Unmarshal([]byte(original.sourceJSON), &source)
			first, err := ParseNodeLaunchInput(source.Nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			replaceFiles := func(raw string) string {
				var assets map[string]string
				if json.Unmarshal([]byte(raw), &assets) != nil {
					t.Fatal("fixture assets")
				}
				for name, value := range assets {
					decoded, err := base64.StdEncoding.DecodeString(value)
					if err != nil {
						t.Fatal(err)
					}
					text := strings.ReplaceAll(string(decoded), "198.51.100.10:51820", "[2001:db8:1::10]:51820")
					text = strings.ReplaceAll(text, "198.51.100.10", "2001:db8:1::10")
					assets[name] = base64.StdEncoding.EncodeToString([]byte(text))
				}
				return startJSON(t, assets)
			}
			files := replaceFiles(first.inputs.Files)
			start := first.inputs.Start
			if start != "" {
				start = replaceFiles(start)
			}
			profile := predecessorCopy(first.profile)
			profile["endpoint"] = "2001:db8:1::10"
			first, err = NewNodeProfile("wg", files, startJSON(t, profile), start, first.inputs.DNSBootstrap)
			if err != nil {
				t.Fatal(err)
			}
			source.Nodes[0], err = first.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			source.IdentitySources[0] = replaceFiles(source.IdentitySources[0])
			original, err = NewNodeChainServerPolicy(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			snapshot := serverCarrierSnapshotFixture()
			snapshot.SourceAddress = "2001:db8::2"
			projected, err := serverCarrierCaptureFixture(t, original, &snapshot).ProjectContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			mtu := serverCarrierEndpointMTUs(t, projected)[0]
			if layer == "" && mtu != 1408 || layer != "" && mtu >= 1408 {
				t.Fatal("IPv6/layer envelope lost its outer bound", mtu)
			}
			var graph map[string]any
			_ = json.Unmarshal([]byte(projected.config), &graph)
			found := false
			for _, raw := range graph["outbounds"].([]any) {
				node := raw.(map[string]any)
				if node["type"] == "direct" {
					found = node["inet6_bind_address"] == snapshot.SourceAddress && node["inet4_bind_address"] == nil
				}
			}
			if !found {
				t.Fatal("IPv6 route acquired IPv4 or unbound physical dialer")
			}
		})
	}
}
