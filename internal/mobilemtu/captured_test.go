package mobilemtu

import (
	"context"
	"errors"
	"testing"
	"time"
)

type capturedPlannerFixture struct {
	plan func(string, int) (*Plan, error)
}

func (p capturedPlannerFixture) PlanForMTU(config string, actual int) (*Plan, error) {
	return p.plan(config, actual)
}

func TestCapturedPlannerRejectsForeignOrForgedPlans(t *testing.T) {
	config := encoded(fixtureGraph())
	for _, fault := range []string{"valid", "source", "readback", "ceiling", "tag", "nil", "error"} {
		t.Run(fault, func(t *testing.T) {
			owner := &contextTestOwner{externalTestOwner: &externalTestOwner{testOwner: &testOwner{state: State{Session: "original", Path: "physical", Interface: "tun-1", MTU: 1380}}}}
			planner := capturedPlannerFixture{func(source string, actual int) (*Plan, error) {
				plan, err := NewPlan(source, actual)
				if err != nil {
					return nil, err
				}
				switch fault {
				case "source":
					plan.source += " "
				case "readback":
					plan.Original++
				case "ceiling":
					plan.Ceiling = MaxMTU
				case "tag":
					plan.TunTag = ""
				case "nil":
					return nil, nil
				case "error":
					return plan, errors.New("captured planner retired")
				}
				return plan, nil
			}}
			controller, err := NewCapturedContext(context.Background(), owner, config, encoded(fixtureProfile()), nil, planner)
			if fault == "valid" {
				if err != nil || !controller.bounded || controller.frozenConfig != config {
					t.Fatal("valid captured plan changed ownership", err)
				}
				_ = controller.Close()
			} else if err == nil || controller != nil {
				t.Fatal("foreign plan became a controller", fault)
			}
		})
	}
}

func TestCapturedControllerKeepsOriginalConstructionDeadline(t *testing.T) {
	owner := &contextTestOwner{capture: func(ctx context.Context) (State, error) {
		<-ctx.Done()
		return State{Session: "late", Path: "late", Interface: "late", MTU: 1380}, nil
	}}
	planned := false
	planner := capturedPlannerFixture{func(string, int) (*Plan, error) { planned = true; return nil, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if value, err := NewCapturedContext(ctx, owner, encoded(fixtureGraph()), encoded(fixtureProfile()), nil, planner); value != nil || !errors.Is(err, context.DeadlineExceeded) || planned {
		t.Fatal("late native read became captured MTU authority", err)
	}
}

func TestCombinedPlansKeepEachOriginalPrefixAndExecutableSelector(t *testing.T) {
	graph := fixtureGraph()
	graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "shadowsocks", "tag": "entry", "server": "198.51.100.2", "server_port": 8388},
		map[string]any{"type": "selector", "tag": "selected", "outbounds": []any{"proxy"}, "default": "proxy", "interrupt_exist_connections": true})
	graph["route"].(map[string]any)["final"] = "selected"
	config := encoded(graph)
	var plans []*Plan
	for _, tag := range []string{"entry", "proxy"} {
		graph["route"].(map[string]any)["final"] = tag
		plan, err := NewPlan(encoded(graph), 1380)
		if err != nil {
			t.Fatal(err)
		}
		plans = append(plans, plan)
	}
	combined, err := CombinePlans(config, 1380, plans)
	if err != nil || combined.source != config || combined.Ceiling != 1500 {
		t.Fatal("complete prefix projections lost executable source", err)
	}
	for _, fault := range []string{"omit", "repeat", "reorder", "field-forgery", "source-forgery", "metadata-only"} {
		changed := []*Plan{plans[0], plans[1]}
		switch fault {
		case "omit":
			changed = changed[:1]
		case "repeat":
			changed[1] = changed[0]
		case "reorder":
			changed[0], changed[1] = changed[1], changed[0]
		case "field-forgery":
			value := *changed[0]
			value.Ceiling = 9000
			changed[0] = &value
		case "source-forgery":
			graph["dns"].(map[string]any)["final"] = "ambient"
			value, err := NewPlan(encoded(graph), 1380)
			if err != nil {
				t.Fatal(err)
			}
			changed[0] = value
		case "metadata-only":
			changed[0] = &Plan{Original: 1380, Ceiling: 9000, TunTag: "tun-in"}
		}
		if _, err := CombinePlans(config, 1380, changed); err == nil {
			t.Fatal("unowned prefix projection accepted", fault)
		}
	}
}
