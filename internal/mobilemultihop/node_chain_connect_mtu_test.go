package mobilemultihop

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	"router-vpn/internal/mobilemtu"
)

// The original compiler and complete-prefix MTU planner execute. Source
// ceilings are configured bounds; this shared fixture is not native PMTU,
// encrypted transport, platform TUN readback or reader-retirement acceptance.
func nodeChainCONNECTMTUFixture(t *testing.T, mode string, fixed bool) (*NodeChainCONNECTRuntime, *nodeChainCONNECTTestEngine) {
	t.Helper()
	input := nodeChainCONNECTFixture(t, mode, "https-connect", "", NativeStartLayerMethod, "password")
	final, err := ParseNodeLaunchInput(input.Nodes[2])
	if err != nil {
		t.Fatal(err)
	}
	profile := predecessorCopy(final.profile)
	api, err := url.Parse(predecessorText(profile, "router_api"))
	if err != nil {
		t.Fatal(err)
	}
	profile["daita_host"], profile["daita_port"] = api.Hostname(), float64(mobilemtu.ProbePort)
	if fixed {
		profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(1280)
	}
	final, err = NewNodeProfile(final.inputs.Mode, final.inputs.Files, startJSON(t, profile), final.inputs.Start, final.inputs.DNSBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	input.Nodes[2], err = final.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewNodeChainCONNECTSource(startJSON(t, input))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewNodeChainCONNECTRuntime(source)
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the original authenticated HTTP/TLS peers through the already-
	// compiled actual positional tags, as in the shared runtime fixture.
	base := newNodeChainTestEngine(t, source.pair)
	originalFinal, actualFinal := source.pair.FinalTag(), runtime.chain.FinalTag()
	base.peers[actualFinal], base.expected[actualFinal] = base.peers[originalFinal], base.expected[originalFinal]
	delete(base.peers, originalFinal)
	delete(base.expected, originalFinal)
	base.chain = runtime.chain
	base.identity.SourceSHA256, base.identity.ConfigSHA256 = runtime.chain.SourceSHA256(), runtime.chain.ConfigSHA256()
	runtime.chain.runtime.testTLS = source.pair.runtime.testTLS
	config, meta, err := source.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	engine := &nodeChainCONNECTTestEngine{nodeChainTestEngine: base, source: source, config: config, meta: meta,
		manager: new(int), middle: new(int), lower: new(int), carrier: new(int), middlePeer: base.publicPeer}
	engine.originalManager, engine.originalMiddle, engine.originalLower, engine.originalCarrier = engine.manager, engine.middle, engine.lower, engine.carrier
	t.Cleanup(func() {
		if err := runtime.CloseContext(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return runtime, engine
}

func TestNodeChainCONNECTMTUUsesOriginalPrefixPlanner(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, policy := range []string{"auto", "fixed"} {
			t.Run(mode+"/"+policy, func(t *testing.T) {
				runtime, _ := nodeChainCONNECTMTUFixture(t, mode, policy == "fixed")
				config, meta, err := runtime.source.ReadValidated()
				if err != nil {
					t.Fatal(err)
				}
				bounds, err := runtime.MTUPlan()
				if err != nil || !reflect.DeepEqual(bounds, meta.MTU) || len(bounds.Prefixes) != 3 {
					t.Fatal("typed adapter changed original configured prefix bounds", err)
				}
				if _, err := mobilemtu.NewPlan(config, bounds.Original); err == nil {
					t.Fatal("ordinary selector planner acquired typed ordered authority")
				}
				plan, err := runtime.PlanForMTU(config, bounds.Original)
				if err != nil || plan.Ceiling != bounds.Ceiling || plan.TunTag != bounds.TUNTag {
					t.Fatal("typed adapter did not use complete original planner", err)
				}
				for _, mtu := range plan.Candidates(bounds.Ceiling) {
					candidate, err := plan.Config(mtu)
					if err != nil {
						t.Fatal(err)
					}
					again, err := runtime.PlanForMTU(candidate, mtu)
					if err != nil || again.Ceiling != bounds.Ceiling {
						t.Fatal("valid original readback lost a captured prefix", err)
					}
					before, after := externalTestRead(t, config), externalTestRead(t, candidate)
					for _, key := range []string{"route", "dns", "outbounds", "endpoints"} {
						if !reflect.DeepEqual(before[key], after[key]) {
							t.Fatal("MTU planner rewrote original CONNECT or final DNS", key)
						}
					}
				}
				probe, err := mobilemtu.ReadProfile(runtime.MTUProfile())
				final := runtime.source.pair.nodes[1].profile
				if err != nil || probe.ID != final["id"] || probe.Proof != final["node_proof_id"] || probe.Token != final["api_token"] {
					t.Fatal("CONNECT middle replaced final private MTU identity", err)
				}
				if runtime.Progress().Ready {
					t.Fatal("configured bounds fabricated native path proof")
				}
			})
		}
	}
}

func TestNodeChainCONNECTMTURejectsGraphAndReadbackSubstitution(t *testing.T) {
	runtime, _ := nodeChainCONNECTMTUFixture(t, "wg", false)
	config, meta, err := runtime.source.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"middle-key", "middle-detour", "middle-relay", "dns", "route", "tun-owner", "new-setting", "readback", "ceiling"} {
		t.Run(fault, func(t *testing.T) {
			graph := externalTestRead(t, config)
			middle := externalTestFind(t, graph, meta.Proofs[1].Tag)
			actual := meta.MTU.Original
			switch fault {
			case "middle-key":
				middle["password"] = "foreign"
			case "middle-detour":
				delete(middle, "detour")
			case "middle-relay":
				middle["server"] = "198.51.100.44"
			case "dns":
				graph["dns"].(map[string]any)["final"] = "ambient"
			case "route":
				graph["route"].(map[string]any)["final"] = meta.Proofs[0].Tag
			case "tun-owner":
				graph["inbounds"].([]any)[0].(map[string]any)["tag"] = "replacement-tun"
			case "new-setting":
				graph["unowned_policy"] = true
			case "readback":
				actual = 1400
			case "ceiling":
				actual = meta.MTU.Ceiling + 1
				graph["inbounds"].([]any)[0].(map[string]any)["mtu"] = float64(actual)
			}
			if _, err := runtime.PlanForMTU(startJSON(t, graph), actual); err == nil {
				t.Fatal("altered CONNECT graph acquired original MTU authority", fault)
			}
		})
	}
}

type nodeChainCONNECTMTUOwner struct {
	nodeChainMTUOwnerFixture
	captures     atomic.Int32
	afterCapture func()
}

func (o *nodeChainCONNECTMTUOwner) CaptureContext(ctx context.Context) (mobilemtu.State, error) {
	o.captures.Add(1)
	if o.afterCapture != nil {
		o.afterCapture()
	}
	return o.state, ctx.Err()
}

func TestNodeChainCONNECTMTUControllerRequiresFreshOwner(t *testing.T) {
	for _, fault := range []string{"healthy", "unproved", "cancelled", "owner-change", "retired"} {
		t.Run(fault, func(t *testing.T) {
			runtime, engine := nodeChainCONNECTMTUFixture(t, "wg", false)
			bounds, err := runtime.MTUPlan()
			if err != nil {
				t.Fatal(err)
			}
			owner := &nodeChainCONNECTMTUOwner{nodeChainMTUOwnerFixture: nodeChainMTUOwnerFixture{
				mobilemtu.State{Session: "original-connect-session", Path: "original-connect-network", Interface: "original-connect-tun", MTU: bounds.Original}}}
			if fault != "unproved" {
				if err := runtime.Run(context.Background(), engine); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "cancelled":
				cancel()
			case "owner-change":
				owner.afterCapture = func() {
					engine.ownerMu.Lock()
					engine.retired = true
					engine.ownerMu.Unlock()
				}
			case "retired":
				if err := runtime.CloseContext(ctx); err != nil {
					t.Fatal(err)
				}
			}
			controller, err := runtime.NewMTUControllerContext(ctx, owner, nil)
			if fault == "healthy" {
				if err != nil || controller == nil || !controller.Requested() || owner.captures.Load() == 0 {
					t.Fatal("current typed owner did not create original MTU controller", err)
				}
				if err := controller.Close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || controller != nil {
				t.Fatal("unproved or changed CONNECT owner acquired MTU controller", fault, err)
			}
			if fault == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("original cancelled MTU constructor lost its context", err)
			}
			if fault != "owner-change" && owner.captures.Load() != 0 {
				t.Fatal("unproved or retired runtime reached MTU owner", fault)
			}
		})
	}
}

func TestNodeChainCONNECTMTUDoesNotLendGenericAuthority(t *testing.T) {
	runtime, _ := nodeChainCONNECTMTUFixture(t, "wg", false)
	if _, ok := any(runtime).(DesktopPhysicalPolicy); ok {
		t.Fatal("MTU adapter lent standalone physical authority")
	}
	for _, name := range []string{"LaunchInput", "NodeChain", "PhysicalReadValidated", "CaptureRestoreContext", "NativeClosed"} {
		if _, exists := reflect.TypeOf(runtime).MethodByName(name); exists {
			t.Fatal("MTU adapter exposed generic or native admission", name)
		}
	}
	runtime.source.middle.selection.Profile["kill_switch_policy"] = "off"
	if runtime.MTUProfile() != "" {
		t.Fatal("changed original source retained private MTU credentials")
	}
	if _, err := runtime.MTUPlan(); err == nil {
		t.Fatal("changed original source retained configured MTU bounds")
	}
}

// The same measurement service must reacquire the current typed proof after
// an authorized reader continuation. This shared test uses the original
// paired proof peers; native TUN transactions are tested in the Box suite.
func TestNodeChainCONNECTMTUMeasurementRetainsServiceAndFiveFieldIdentity(t *testing.T) {
	runtime, engine := newNodeChainCONNECTRuntimeFixture(t, "wg", "http-connect")
	if err := runtime.Run(t.Context(), engine); err != nil {
		t.Fatal(err)
	}
	owner := &nodeChainCONNECTMeasurementFixture{runtime: runtime}
	service, err := runtime.NewHopMeasurementContext(t.Context(), owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	retained := service
	measured := &nodeChainMeasurementEngine{source: runtime.chain, owner: nodeChainCONNECTMeasurementOwner{runtime.source, owner}, identity: engine.identity}
	if err = runtime.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = measured.current(t.Context()); err == nil {
		t.Fatal("paused CONNECT proof retained measurement authority")
	}
	next, err := NewNodeChainCONNECTRuntime(runtime.source)
	if err != nil {
		t.Fatal(err)
	}
	next.chain.runtime.testTLS = runtime.chain.runtime.testTLS
	t.Cleanup(func() {
		if err := next.CloseContext(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err = next.Run(t.Context(), engine); err != nil {
		t.Fatal(err)
	}
	owner.runtime = next
	if current, err := measured.current(t.Context()); err != nil || current != next.chain || service != retained {
		t.Fatal("retained CONNECT measurement did not reacquire original current owner", err)
	}
	request := "1234567890abcdef1234567890abcdef"
	if err = retained.Start(request, 65536); err != nil {
		t.Fatal("original retained measurement rejected reproved runtime", err)
	}
	retained.Cancel(request)
	if err = retained.Drain(request); err != nil {
		t.Fatal("original measurement worker did not drain", err)
	}
	if owner.active.Load() || owner.released.Load() != 1 {
		t.Fatal("original measurement lost activity drain")
	}
	// Corrupt only the retained identity expected by this measurement adapter.
	// Every real source/engine remains unchanged, so each field comparison is
	// independently causal instead of failing an unrelated source guard first.
	for _, field := range []string{"EngineID", "SessionID", "NetworkID", "SourceSHA256", "ConfigSHA256"} {
		t.Run(field, func(t *testing.T) {
			original := measured.identity
			reflect.ValueOf(&measured.identity).Elem().FieldByName(field).SetString("replacement")
			if _, err := measured.current(t.Context()); err == nil {
				t.Fatal("CONNECT measurement accepted substituted identity", field)
			}
			measured.identity = original
			if _, err := measured.current(t.Context()); err != nil {
				t.Fatal("restored exact measurement identity refused", err)
			}
		})
	}
}
