package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"router-vpn/internal/mobilemtu"
)

// MTUPlan reports a configured bound, not measured path MTU. Both executions
// retain the same TUN and complete original Local packet graph. Server adds a
// captured TCP/UoT2 front over the entry and cannot enlarge that shared ceiling.
func (p *NodeChainExecutionProjection) MTUPlan() (NodeChainMTUPlan, error) {
	if p.validateCapture() != nil {
		return NodeChainMTUPlan{}, nodeChainExecutionError
	}
	local := p.policy.local
	if p.preparation.desktop != nil {
		local = p.preparation.desktop.chain
	} else if p.preparation.mobile != nil {
		local = p.preparation.mobile.chain
	}
	bound, err := local.MTUPlan()
	if err != nil {
		return NodeChainMTUPlan{}, err
	}
	var actual, original map[string]any
	if exactJSON([]byte(p.config), &actual, 4<<20) != nil || exactJSON([]byte(local.config), &original, 4<<20) != nil ||
		!reflect.DeepEqual(actual["inbounds"], original["inbounds"]) || bound.TUNTag != p.transition.TUNTag {
		return NodeChainMTUPlan{}, nodeChainExecutionError
	}
	return bound, nil
}

func (p *NodeChainExecutionProjection) MTUProfile() string {
	if p.validateCapture() != nil {
		return ""
	}
	return p.policy.local.MTUProfile()
}

// PlanForMTU preserves the actual preparation/adoption graph and original
// physical owner. Only the one captured TUN's actual MTU readback may differ;
// neither a generic graph nor caller-supplied ceiling can replace this source.
func (p *NodeChainExecutionProjection) PlanForMTU(config string, actual int) (*mobilemtu.Plan, error) {
	bound, err := p.MTUPlan()
	if err != nil || actual < mobilemtu.MinMTU || actual > bound.Ceiling {
		return nil, errors.Join(err, nodeChainExecutionError)
	}
	var original, current map[string]any
	if exactJSON([]byte(p.config), &original, 4<<20) != nil || exactJSON([]byte(config), &current, 4<<20) != nil {
		return nil, nodeChainExecutionError
	}
	inbounds, ok := original["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return nil, nodeChainExecutionError
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["tag"] != bound.TUNTag {
		return nil, nodeChainExecutionError
	}
	tun["mtu"] = float64(actual)
	if !reflect.DeepEqual(original, current) {
		return nil, errors.New("ordered execution MTU source changed beyond original TUN readback")
	}
	route := current["route"].(map[string]any)
	var plans []*mobilemtu.Plan
	for _, proof := range p.policy.local.proofs {
		route["final"] = proof.Tag
		raw, err := json.Marshal(current)
		if err != nil {
			return nil, err
		}
		plan, err := mobilemtu.NewPlan(string(raw), actual)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	combined, err := mobilemtu.CombineExecutionPlans(config, actual, plans)
	if err != nil || combined.Ceiling != bound.Ceiling || combined.TunTag != bound.TUNTag {
		return nil, errors.Join(err, nodeChainExecutionError)
	}
	return combined, nil
}

func (p *NodeChainExecutionProjection) NewMTUControllerContext(ctx context.Context, owner mobilemtu.Owner, cache mobilemtu.Cache) (*mobilemtu.Controller, error) {
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return mobilemtu.NewCapturedContext(ctx, owner, p.config, p.MTUProfile(), cache, p)
}
