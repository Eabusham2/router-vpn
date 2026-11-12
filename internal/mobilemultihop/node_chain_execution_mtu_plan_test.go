package mobilemultihop

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"testing"

	"router-vpn/internal/mobilemtu"
)

func nodeChainExecutionMTUSource(t *testing.T, count int, fixedMiddle, fixedFinal bool) NodeChainExecutionSource {
	t.Helper()
	modes, ids, layers := make([]string, count), make([]string, count), make([]string, count)
	for i := range modes {
		modes[i], ids[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3], "wg"
	}
	modes[count-1] = "shadowsocks"
	nodes := nodeChainModeFixtureNodes(t, modes, layers)
	identities := nodeChainModeFixtureNodes(t, ids, layers)
	for i, node := range nodes {
		profile := predecessorCopy(node.profile)
		profile["kill_switch_policy"] = "on-connect"
		if fixedMiddle && i == 1 && i != count-1 {
			profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(1408)
		}
		if i == count-1 {
			api, _ := url.Parse(predecessorText(profile, "router_api"))
			profile["daita_host"], profile["daita_port"] = api.Hostname(), float64(mobilemtu.ProbePort)
			if fixedFinal {
				profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(1280)
			}
		}
		var err error
		nodes[i], err = NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
	}
	return nodeChainExecutionFixtureFromNodes(t, nodes, identities, "auto")
}

func nodeChainExecutionMTUProjection(t *testing.T, source NodeChainExecutionSource) *NodeChainExecutionProjection {
	t.Helper()
	prep, err := NewNodeChainExecutionPreparation(source.LocalSource, source.Execution)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := prep.BindExecution(policy)
	if err != nil {
		t.Fatal(err)
	}
	return projection
}

func TestNodeChainExecutionMTUPlanKeepsBothChoicesAndEveryPacketBound(t *testing.T) {
	for _, count := range []int{2, 4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			source := nodeChainExecutionMTUSource(t, count, count == 4, false)
			if count == 2 {
				source.Execution = "server"
			}
			p := nodeChainExecutionMTUProjection(t, source)
			bound, err := p.MTUPlan()
			local, localErr := p.policy.local.MTUPlan()
			if err != nil || localErr != nil || !reflect.DeepEqual(bound, local) || len(bound.Prefixes) != count {
				t.Fatal("execution ceiling lost an original Local prefix", bound, err, localErr)
			}
			if count == 4 && bound.Ceiling >= 1408 {
				t.Fatal("fixed middle packet envelope did not constrain shared execution TUN", bound)
			}
			plan, err := p.PlanForMTU(p.Config(), bound.Original)
			if err != nil || plan.Ceiling != bound.Ceiling || plan.TunTag != bound.TUNTag {
				t.Fatal("actual gated execution graph has no complete plan", err)
			}
			for _, mtu := range plan.Candidates(bound.Ceiling) {
				config, err := plan.Config(mtu)
				if err != nil {
					t.Fatal(err)
				}
				again, err := p.PlanForMTU(config, mtu)
				if err != nil || again.Ceiling != bound.Ceiling {
					t.Fatal("actual MTU readback lost the captured execution envelope", err)
				}
				before, after := startObject(t, p.Config()), startObject(t, config)
				for _, family := range []string{"route", "dns", "outbounds", "endpoints", "services"} {
					if !reflect.DeepEqual(before[family], after[family]) {
						t.Fatal("MTU replaced captured execution policy", family)
					}
				}
			}
			if _, err := p.PlanForMTU(p.Config(), 9000); err == nil {
				t.Fatal("caller substituted a jumbo execution ceiling")
			}
			profile, err := mobilemtu.ReadProfile(p.MTUProfile())
			last := p.policy.local.nodes[count-1].profile
			if err != nil || profile.ID != last["id"] || profile.Token != last["api_token"] || profile.Proof != last["node_proof_id"] {
				t.Fatal("execution MTU substituted final private probe authority", err)
			}
			owner := &nodeChainMTUOwnerFixture{mobilemtu.State{Session: "execution-session", Path: "original-network", Interface: "original-tun", MTU: bound.Original}}
			controller, err := p.NewMTUControllerContext(context.Background(), owner, nil)
			if err != nil || !controller.Requested() {
				t.Fatal("execution Auto policy did not retain its captured planner", err)
			}
			if err := controller.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeChainExecutionMTUPlanRetainsActualPhysicalProjection(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			source := nodeChainExecutionMTUSource(t, 3, false, false)
			original, _, p := desktopExecutionProjection(t, source, target, desktopNodeTestSession, 1320)
			bound, err := p.MTUPlan()
			local, localErr := original.chain.MTUPlan()
			if err != nil || localErr != nil || !reflect.DeepEqual(bound, local) || bound.Original != 1320 {
				t.Fatal("execution MTU plan relabeled a generic graph as physical", bound, err, localErr)
			}
			plan, err := p.PlanForMTU(p.Config(), 1320)
			if err != nil {
				t.Fatal(err)
			}
			config, err := plan.Config(1280)
			if err != nil {
				t.Fatal(err)
			}
			before, after := startObject(t, p.Config()), startObject(t, config)
			for _, family := range []string{"route", "dns", "outbounds", "endpoints", "services"} {
				if !reflect.DeepEqual(before[family], after[family]) {
					t.Fatal("execution MTU replaced original physical owner", family)
				}
			}
			if _, err := p.PlanForMTU(config, 1280); err != nil {
				t.Fatal("actual physical readback refused", err)
			}
			generic := nodeChainExecutionMTUProjection(t, source)
			if _, err := p.PlanForMTU(generic.Config(), 1280); err == nil {
				t.Fatal("generic execution graph acquired physical MTU authority")
			}
		})
	}
}

func TestNodeChainExecutionMTUPlanRejectsChangedGraphAndForgedBounds(t *testing.T) {
	p := nodeChainExecutionMTUProjection(t, nodeChainExecutionMTUSource(t, 4, true, false))
	for _, fault := range []string{"middle-key", "middle-mtu", "dns", "gate", "selector", "server-uot", "server-host", "tun-owner", "readback", "extra-setting"} {
		t.Run(fault, func(t *testing.T) {
			graph := startObject(t, p.Config())
			actual := 1280
			switch fault {
			case "middle-key":
				graph["endpoints"].([]any)[1].(map[string]any)["private_key"] = "replaced"
			case "middle-mtu":
				graph["endpoints"].([]any)[1].(map[string]any)["mtu"] = float64(9000)
			case "dns":
				graph["dns"].(map[string]any)["final"] = "ambient"
			case "gate":
				graph["route"].(map[string]any)["final"] = SelectorTag
			case "selector":
				desktopNodeObject(t, graph, "outbounds", SelectorTag)["default"] = p.policy.serverProofs[len(p.policy.serverProofs)-1].Tag
			case "server-uot":
				desktopNodeObject(t, graph, "outbounds", p.policy.serverProofs[len(p.policy.serverProofs)-1].Tag)["udp_over_tcp"] = map[string]any{"enabled": true, "version": float64(1)}
			case "server-host":
				desktopNodeObject(t, graph, "outbounds", p.policy.serverProofs[1].Tag)["server"] = "10.99.0.1"
			case "tun-owner":
				graph["inbounds"].([]any)[0].(map[string]any)["tag"] = "replacement"
			case "readback":
				actual = 1320
			case "extra-setting":
				graph["unowned"] = true
			}
			if _, err := p.PlanForMTU(startJSON(t, graph), actual); err == nil {
				t.Fatal("altered graph acquired original execution MTU authority", fault)
			}
		})
	}
	graph := startObject(t, p.Config())
	var plans []*mobilemtu.Plan
	for _, proof := range p.policy.local.proofs {
		graph["route"].(map[string]any)["final"] = proof.Tag
		plan, err := mobilemtu.NewPlan(startJSON(t, graph), 1280)
		if err != nil {
			t.Fatal(err)
		}
		plans = append(plans, plan)
	}
	if _, err := mobilemtu.CombineExecutionPlans(p.Config(), 1280, plans); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"omit-middle", "repeat", "reorder", "invented"} {
		changed := append([]*mobilemtu.Plan(nil), plans...)
		switch fault {
		case "omit-middle":
			changed = append(changed[:1], changed[2:]...)
		case "repeat":
			changed[1] = changed[0]
		case "reorder":
			changed[1], changed[2] = changed[2], changed[1]
		case "invented":
			changed[1] = &mobilemtu.Plan{Original: 1280, Ceiling: 9000, TunTag: plans[0].TunTag}
		}
		if _, err := mobilemtu.CombineExecutionPlans(p.Config(), 1280, changed); err == nil {
			t.Fatal("incomplete original execution prefix inventory admitted", fault)
		}
	}
	plans[1].Ceiling = 9000
	if _, err := mobilemtu.CombineExecutionPlans(p.Config(), 1280, plans); err == nil {
		t.Fatal("caller forged a prefix packet ceiling")
	}
	p.policy.local.nodes[1].profile["api_token"] = "retired-original-middle"
	if p.MTUProfile() != "" {
		t.Fatal("retired member source retained execution probe authority")
	}
	if _, err := p.MTUPlan(); err == nil {
		t.Fatal("retired member source retained execution MTU authority")
	}
}

func TestNodeChainExecutionMTUPlanKeepsFinalFixedPolicy(t *testing.T) {
	p := nodeChainExecutionMTUProjection(t, nodeChainExecutionMTUSource(t, 4, true, true))
	bound, err := p.MTUPlan()
	if err != nil {
		t.Fatal(err)
	}
	owner := &nodeChainMTUOwnerFixture{mobilemtu.State{Session: "fixed-execution", Path: "original-network", Interface: "original-tun", MTU: bound.Original}}
	controller, err := p.NewMTUControllerContext(context.Background(), owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	if controller.Requested() {
		t.Fatal("middle or Server preference replaced original Fixed final policy")
	}
}
