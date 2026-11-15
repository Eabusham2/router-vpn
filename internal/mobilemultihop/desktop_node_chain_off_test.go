package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"testing"
)

func desktopChainOffSource(t *testing.T, family, protected string) NodeChainSource {
	t.Helper()
	var source NodeChainSource
	switch family {
	case "connect":
		source = nodeChainCONNECTFixture(t, "wg", "https-connect", "", NativeStartLayerMethod, "password")
	case "socks":
		source = nodeChainSOCKSFixture(t, "wg", "", "password")
	default:
		source = nodeChainFixtureSource(t, nodeChainFixtureNodes(t, 3, ""))
	}
	for i, input := range source.Nodes {
		policy := "off"
		if i == 1 && protected != "" {
			policy = protected
		}
		if i == 1 && family != "ordinary" {
			var record nodeChainImportedInput
			if err := json.Unmarshal([]byte(input), &record); err != nil {
				t.Fatal(err)
			}
			capture := externalTestRead(t, record.Capture)
			capture["profile"].(map[string]any)["kill_switch_policy"] = policy
			record.Capture = startJSON(t, capture)
			source.Nodes[i] = startJSON(t, record)
			continue
		}
		node, err := ParseNodeLaunchInput(input)
		if err != nil {
			t.Fatal(err)
		}
		profile := predecessorCopy(node.profile)
		profile["kill_switch_policy"] = policy
		node, err = NewNodeProfile(node.inputs.Mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
		source.Nodes[i], err = node.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
	}
	return source
}

func TestDesktopNodeChainLinuxOffRetainsFullCapture(t *testing.T) {
	for _, family := range []string{"ordinary", "socks", "connect"} {
		for _, protected := range []string{"", "on-connect", "always"} {
			t.Run(family+"/"+protected, func(t *testing.T) {
				source := desktopChainOffSource(t, family, protected)
				raw := startJSON(t, source)
				want := protected
				if want == "" {
					want = "off"
				}
				for _, target := range []string{"linux", "windows", "darwin"} {
					var p DesktopPhysicalPolicy
					var err error
					switch family {
					case "connect":
						original, e := NewNodeChainCONNECTSource(raw)
						if e != nil {
							t.Fatal(e)
						}
						p, err = NewDesktopNodeChainCONNECTPolicy(original, desktopNodeTestSession, target, 1392)
					case "socks":
						original, e := NewNodeChainSOCKSSource(raw)
						if e != nil {
							t.Fatal(e)
						}
						p, err = NewDesktopNodeChainSOCKSPolicy(original, desktopNodeTestSession, target, 1392)
					default:
						original, e := NewNodeChain(raw)
						if e != nil {
							t.Fatal(e)
						}
						p, err = NewDesktopNodeChainPolicy(original, desktopNodeTestSession, target, 1392)
					}
					if want == "off" && target != "linux" {
						if err == nil {
							t.Fatal("unimplemented native Off target accepted", target)
						}
						continue
					}
					if err != nil {
						t.Fatal(family, target, err)
					}
					_, meta, capture, err := ReadDesktopPhysicalPolicy(p)
					if err != nil || meta.KillSwitchPolicy != want || meta.RestoredMTU != 1392 || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour == "" {
						t.Fatal("Off/mixed capture changed policy, MTU or original DNS", meta, err)
					}
					_, again, physical, err := ReadDesktopPhysicalPolicy(p)
					if err != nil || !reflect.DeepEqual(meta, again) || !reflect.DeepEqual(capture, physical) {
						t.Fatal("original policy changed on revalidation", err)
					}
				}
			})
		}
	}
}
