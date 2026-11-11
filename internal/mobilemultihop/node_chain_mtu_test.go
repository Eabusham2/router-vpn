package mobilemultihop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	"router-vpn/internal/mobilemtu"
)

type nodeChainMTUOwnerFixture struct{ state mobilemtu.State }

func (o *nodeChainMTUOwnerFixture) Capture() (mobilemtu.State, error) { return o.state, nil }
func (o *nodeChainMTUOwnerFixture) CaptureContext(ctx context.Context) (mobilemtu.State, error) {
	return o.state, ctx.Err()
}
func (*nodeChainMTUOwnerFixture) ChangeMTU(context.Context, mobilemtu.State, int) (mobilemtu.State, error) {
	return mobilemtu.State{}, errors.New("construction fixture cannot change a native TUN")
}
func (*nodeChainMTUOwnerFixture) DialThroughTunnel(context.Context, mobilemtu.State, string, string) (net.Conn, error) {
	return nil, errors.New("construction fixture cannot measure a path")
}

func nodeChainMTUControllerFixture(t *testing.T, count int) *NodeChain {
	t.Helper()
	nodes := nodeChainFixtureNodes(t, count, "")
	last := nodes[len(nodes)-1]
	profile := predecessorCopy(last.profile)
	api, _ := url.Parse(profile["router_api"].(string))
	profile["daita_host"], profile["daita_port"] = api.Hostname(), float64(mobilemtu.ProbePort)
	var err error
	nodes[len(nodes)-1], err = NewNodeProfile(last.inputs.Mode, last.inputs.Files, startJSON(t, profile), last.inputs.Start, last.inputs.DNSBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes)))
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

func TestNodeChainMTUControllerRetainsCompleteCapturedPath(t *testing.T) {
	for _, count := range []int{3, 4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			chain := nodeChainMTUControllerFixture(t, count)
			bound, err := chain.MTUPlan()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := mobilemtu.NewPlan(chain.Config(), bound.Original); err == nil {
				t.Fatal("ordinary selector path acquired chain authority")
			}
			plan, err := chain.PlanForMTU(chain.Config(), bound.Original)
			if err != nil || plan.Ceiling != bound.Ceiling || plan.TunTag != bound.TUNTag {
				t.Fatal("complete every-prefix controller plan", err)
			}
			for _, mtu := range plan.Candidates(bound.Ceiling) {
				candidate, err := plan.Config(mtu)
				if err != nil {
					t.Fatal(err)
				}
				again, err := chain.PlanForMTU(candidate, mtu)
				if err != nil || again.Ceiling != bound.Ceiling {
					t.Fatal("retained reader replacement lost a prefix envelope", err)
				}
				before, after := importedPQGraph(t, chain.Config()), importedPQGraph(t, candidate)
				for _, key := range []string{"route", "dns", "outbounds", "endpoints"} {
					if startJSON(t, before[key]) != startJSON(t, after[key]) {
						t.Fatal("TUN planner rewrote captured policy", key)
					}
				}
			}
			profile, err := mobilemtu.ReadProfile(chain.MTUProfile())
			last := chain.nodes[count-1].profile
			if err != nil || profile.ID != last["id"] || profile.Proof != last["node_proof_id"] || profile.Token != last["api_token"] {
				t.Fatal("final private probe identity was replaced", err)
			}
			owner := &nodeChainMTUOwnerFixture{mobilemtu.State{Session: "chain-session", Path: "chain-network", Interface: "chain-tun", MTU: bound.Original}}
			controller, err := chain.NewMTUControllerContext(context.Background(), owner, nil)
			if err != nil || !controller.Requested() {
				t.Fatal("original Auto policy has no captured controller", err)
			}
			if err := controller.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeChainMTUControllerRejectsChangedMiddleAndAuthority(t *testing.T) {
	chain := nodeChainMTUControllerFixture(t, 4)
	for _, fault := range []string{"middle-key", "middle-mtu", "dns", "route", "tun-owner", "new-setting", "readback"} {
		t.Run(fault, func(t *testing.T) {
			graph := importedPQGraph(t, chain.Config())
			actual := 1280
			switch fault {
			case "middle-key":
				graph["endpoints"].([]any)[1].(map[string]any)["private_key"] = "substituted"
			case "middle-mtu":
				graph["endpoints"].([]any)[1].(map[string]any)["mtu"] = float64(9000)
			case "dns":
				graph["dns"].(map[string]any)["final"] = "ambient"
			case "route":
				graph["route"].(map[string]any)["final"] = chain.PrefixTags()[0]
			case "tun-owner":
				graph["inbounds"].([]any)[0].(map[string]any)["tag"] = "replacement-tun"
			case "new-setting":
				graph["new_unowned_policy"] = true
			case "readback":
				actual = 1400
			}
			if _, err := chain.PlanForMTU(startJSON(t, graph), actual); err == nil {
				t.Fatal("altered graph acquired original chain MTU authority", fault)
			}
		})
	}
	chain.nodes[1].profile["api_token"] = "replaced-middle-authority"
	if chain.MTUProfile() != "" {
		t.Fatal("replaced middle authority retained final probe authority")
	}
	if _, err := chain.PlanForMTU(chain.Config(), 1280); err == nil {
		t.Fatal("changed middle source retained a planner")
	}
}

func TestNodeChainMTUControllerRetainsSealedDesktopPhysicalOwner(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			original := desktopChainFixture(t, 4, "", func(position int, profile map[string]any) {
				if position == 3 {
					api, _ := url.Parse(profile["router_api"].(string))
					profile["daita_host"], profile["daita_port"] = api.Hostname(), float64(mobilemtu.ProbePort)
				}
			})
			policy, err := NewDesktopNodeChainPolicy(original, strings.Repeat("a", 32), target, 0)
			if err != nil {
				t.Fatal(err)
			}
			chain := policy.NodeChain()
			bound, err := chain.MTUPlan()
			if err != nil {
				t.Fatal(err)
			}
			plan, err := chain.PlanForMTU(chain.Config(), bound.Original)
			if err != nil || plan.Ceiling != bound.Ceiling {
				t.Fatal("physical chain lost typed prefix bounds", err)
			}
			for _, mtu := range plan.Candidates(1400) {
				config, err := plan.Config(mtu)
				if err != nil {
					t.Fatal(err)
				}
				current, err := chain.PlanForMTU(config, mtu)
				if err != nil || current.Ceiling != bound.Ceiling {
					t.Fatal("native reader replacement rewrote sealed physical source", err)
				}
				before, after := importedPQGraph(t, chain.Config()), importedPQGraph(t, config)
				for _, name := range []string{"services", "endpoints", "outbounds", "dns", "route"} {
					if startJSON(t, before[name]) != startJSON(t, after[name]) {
						t.Fatal("MTU changed physical policy", name)
					}
				}
			}
			graph := importedPQGraph(t, chain.Config())
			graph["services"].([]any)[0].(map[string]any)["source_sha256"] = strings.Repeat("f", 64)
			if _, err := chain.PlanForMTU(startJSON(t, graph), bound.Original); err == nil {
				t.Fatal("foreign native physical source acquired MTU")
			}
		})
	}
}
