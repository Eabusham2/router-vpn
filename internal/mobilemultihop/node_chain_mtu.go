package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"router-vpn/internal/mobilemtu"
)

// MTUProfile retains the final node's private probe identity and policy. It
// never substitutes a middle node, saved measurement, or public test service.
func (c *NodeChain) MTUProfile() string {
	if c == nil || c.validateCapture() != nil {
		return ""
	}
	raw, err := json.Marshal(c.nodes[len(c.nodes)-1].profile)
	if err != nil {
		return ""
	}
	return string(raw)
}

// PlanForMTU keeps the original mobile or sealed desktop physical graph. A TUN
// reader replacement changes only actual MTU; all physical owner objects,
// endpoints, keys, routes and DNS stay exactly as the captured source.
func (c *NodeChain) PlanForMTU(config string, actual int) (*mobilemtu.Plan, error) {
	if c == nil || c.validateCapture() != nil {
		return nil, nodeChainError
	}
	if _, err := mtuNumber(float64(actual)); err != nil {
		return nil, err
	}
	var original, current map[string]any
	if exactJSON([]byte(c.config), &original, 4<<20) != nil || exactJSON([]byte(config), &current, 4<<20) != nil {
		return nil, nodeChainError
	}
	inbounds, ok := original["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return nil, nodeChainError
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || tun["type"] != "tun" {
		return nil, nodeChainError
	}
	tun["mtu"] = float64(actual)
	if !reflect.DeepEqual(original, current) {
		return nil, errors.New("ordered MTU source changed beyond its captured TUN readback")
	}
	// The sealed original projection supplies every prefix bound. Actual MTU
	// readback changes no endpoint envelope or physical policy source identity.
	bound, err := c.MTUPlan()
	if err != nil || actual > bound.Ceiling || len(bound.Prefixes) != len(c.proofs) {
		return nil, errors.Join(err, nodeChainError)
	}
	route := current["route"].(map[string]any)
	var plans []*mobilemtu.Plan
	for _, prefix := range c.proofs {
		route["final"] = prefix.Tag
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
	combined, err := mobilemtu.CombinePlans(config, actual, plans)
	if err != nil || combined.Ceiling != bound.Ceiling || combined.TunTag != bound.TUNTag {
		return nil, errors.Join(err, nodeChainError)
	}
	return combined, nil
}

func (c *NodeChain) NewMTUControllerContext(ctx context.Context, owner mobilemtu.Owner, cache mobilemtu.Cache) (*mobilemtu.Controller, error) {
	if c == nil || c.validateCapture() != nil {
		return nil, nodeChainError
	}
	return mobilemtu.NewCapturedContext(ctx, owner, c.config, c.MTUProfile(), cache, c)
}
