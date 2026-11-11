package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNodeChainProjectionReopensExactSystemTUN(t *testing.T) {
	original := nodeChainFixture(t, 4, "")
	before, source := original.Config(), original.SourceSHA256()
	for _, target := range []string{"windows", "linux", "darwin", "ios", "android"} {
		for _, mtu := range []int{0, 1280, 1400} {
			projected, err := ProjectNodeChain(original, target, mtu)
			if err != nil {
				t.Fatal(target, mtu, err)
			}
			graph := importedPQGraph(t, projected.Config())
			tun := graph["inbounds"].([]any)[0].(map[string]any)
			want := 1280
			if mtu != 0 {
				want = mtu
			}
			if tun["mtu"] != float64(want) || target == "darwin" && tun["interface_name"] != nil ||
				(target == "windows" || target == "linux") && tun["interface_name"] != "router-vpn" {
				t.Fatal("projection did not own exact TUN naming/restore", target, mtu, tun)
			}
			base := importedPQGraph(t, before)
			for _, key := range []string{"outbounds", "endpoints", "route", "dns"} {
				if !reflect.DeepEqual(graph[key], base[key]) {
					t.Fatal("TUN projection changed a captured path", key)
				}
			}
			if original.Config() != before || original.SourceSHA256() != source || projected.SourceSHA256() != source ||
				projected.OriginalConfigSHA256() != original.ConfigSHA256() || projected.TargetOS() != target ||
				projected.RestoredMTU() != mtu || projected.DNSCapture().ConfigSHA256 != projected.ConfigSHA256() {
				t.Fatal("derived TUN lost original or derived source binding")
			}
			input, err := projected.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			opened, err := ParseNodeChainLaunchInput(input)
			if err != nil || opened.Config() != projected.Config() || opened.Metadata() != projected.Metadata() ||
				opened.OriginalConfigSHA256() != original.ConfigSHA256() {
				t.Fatal("independent child changed or lost exact projection", err)
			}
			for _, fault := range []string{"target", "mtu", "original-digest"} {
				var changed nodeChainLaunchRecord
				_ = json.Unmarshal([]byte(input), &changed)
				switch fault {
				case "target":
					changed.TargetOS = "unknown-os"
				case "mtu":
					changed.RestoredMTU = want + 1
				case "original-digest":
					changed.OriginalConfigSHA256 = strings.Repeat("a", 64)
				}
				if _, err := ParseNodeChainLaunchInput(startJSON(t, changed)); err == nil {
					t.Fatal("child adopted foreign projection", fault)
				}
			}
		}
	}
	if _, err := ProjectNodeChain(original, "", 1280); err == nil {
		t.Fatal("restore had no explicit platform scope")
	}
}

func TestNodeChainMTURequiresEveryMiddleEnvelope(t *testing.T) {
	nodes := nodeChainFixtureNodes(t, 4, "")
	input := nodes[1].inputs
	profile := predecessorCopy(nodes[1].profile)
	profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(1408)
	middle, err := NewNodeProfile(input.Mode, input.Files, startJSON(t, profile), input.Start, input.DNSBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	nodes[1] = middle
	chain, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes)))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := chain.MTUPlan()
	if err != nil || plan.Ceiling != 1344 || len(plan.Prefixes) != 4 || plan.Prefixes[2].Ceiling != 1344 {
		t.Fatal("middle packet envelope did not constrain whole path", plan, err)
	}
	if _, err := ProjectNodeChain(chain, "linux", 1400); err == nil {
		t.Fatal("restore skipped the middle packet ceiling")
	}
	for _, fault := range []string{"omitted-middle", "bypassed-middle", "wrong-selector", "two-choices", "foreign-tag"} {
		graph := importedPQGraph(t, chain.Config())
		endpoints := graph["endpoints"].([]any)
		switch fault {
		case "omitted-middle":
			graph["endpoints"] = append(endpoints[:1], endpoints[2:]...)
		case "bypassed-middle":
			endpoints[2].(map[string]any)["detour"] = chain.PrefixTags()[0]
		default:
			rows := graph["outbounds"].([]any)
			for _, raw := range rows {
				node := raw.(map[string]any)
				if node["tag"] != SelectorTag {
					continue
				}
				switch fault {
				case "wrong-selector":
					node["default"] = chain.PrefixTags()[0]
				case "two-choices":
					node["outbounds"] = []any{chain.FinalTag(), chain.PrefixTags()[0]}
				case "foreign-tag":
					node["tag"] = "foreign-selector"
				}
			}
		}
		if _, err := nodeChainMTUPlan(startJSON(t, graph), chain.ProofInventory()); err == nil {
			t.Fatal("altered chain kept a complete MTU plan", fault)
		}
	}
}

func TestNodeChainProjectionRetainsFixedAndSourcePolicy(t *testing.T) {
	nodes := nodeChainFixtureNodes(t, 3, "")
	for index, change := range []map[string]any{
		{"home_lan_access": false, "home_lan_cidrs": []any{"10.12.0.0/16"}},
		{"ipv6_mode": "off"},
		{"mtu_policy": "manual", "manual_mtu": float64(1280)},
	} {
		input := nodes[index].inputs
		profile := predecessorCopy(nodes[index].profile)
		for key, value := range change {
			profile[key] = value
		}
		node, err := NewNodeProfile(input.Mode, input.Files, startJSON(t, profile), input.Start, input.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
		nodes[index] = node
	}
	chain, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProjectNodeChain(chain, "linux", 1400); err == nil {
		t.Fatal("Auto restore overrode captured final Fixed policy")
	}
	graph := importedPQGraph(t, chain.Config())
	ipv6, lan := false, false
	for _, raw := range graph["route"].(map[string]any)["rules"].([]any) {
		rule := raw.(map[string]any)
		ipv6 = ipv6 || rule["action"] == "reject" && rule["ip_version"] == float64(6)
		ranges, _ := rule["ip_cidr"].([]any)
		for _, cidr := range ranges {
			lan = lan || rule["action"] == "reject" && cidr == "10.12.0.0/16"
		}
	}
	if !ipv6 || !lan {
		t.Fatal("middle IPv6 or first LAN refusal was dropped")
	}
}
