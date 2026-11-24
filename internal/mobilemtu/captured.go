package mobilemtu

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"router-vpn/internal/hopmeasure"
)

// CapturedPlanner is supplied by a retained graph compiler. Native entrypoints
// must retain their concrete compiled source; caller JSON cannot select this
// capability. The ordinary NewPlan selector contract remains unchanged.
type CapturedPlanner interface {
	PlanForMTU(config string, actual int) (*Plan, error)
}

func NewCapturedContext(ctx context.Context, owner Owner, config, profile string, cache Cache, planner CapturedPlanner) (*Controller, error) {
	if planner == nil {
		return nil, errors.New("captured MTU requires its original graph planner")
	}
	policy, err := ReadProfile(profile)
	if err != nil {
		return nil, err
	}
	state, err := captureContext(ctx, owner)
	if err != nil {
		return nil, err
	}
	controller, err := newControllerStateCaptured(owner, config, policy, cache, state, planner)
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	controller.bounded = true
	return controller, nil
}

func (c *Controller) planFor(config string, actual int) (*Plan, error) {
	if c.planner == nil {
		return NewPlan(config, actual)
	}
	plan, err := c.planner.PlanForMTU(config, actual)
	if err != nil || plan == nil || plan.source != config || plan.Original != actual ||
		plan.Ceiling < actual || actual < MinMTU || plan.Ceiling > MaxMTU || !idPattern.MatchString(plan.TunTag) ||
		plan.captured != plan.captureDigest() {
		return nil, errors.Join(err, errors.New("captured MTU planner returned another graph or envelope"))
	}
	return plan, nil
}

func (p *Plan) captureDigest() [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("routervpn-mtu-plan-v1\x00%d\x00%d\x00%s\x00%s", p.Original, p.Ceiling, p.TunTag, p.source)))
}

func capturePlan(plan *Plan) *Plan {
	plan.captured = plan.captureDigest()
	return plan
}

// CombinePlans retains the executable graph byte for byte. Every supplied
// read-only prefix projection must differ only in route.final, and is parsed
// again by NewPlan; public Plan fields cannot forge a packet envelope. The
// concrete captured compiler supplies its complete ordered prefix inventory.
func CombinePlans(config string, actual int, prefixes []*Plan) (*Plan, error) {
	return combinePlans(config, actual, prefixes, nil, 0, false)
}

var extendedLocalMTUTag = regexp.MustCompile(`^routervpn-chain-(0|[1-9][0-9]*)-[0-9a-f]{12}-node-[0-9a-f]{12}$`)

// CombineExtendedImportedLocalPlans binds all private read-only projections to
// the captured tag order, with one WG physical entry followed by SS streams.
func CombineExtendedImportedLocalPlans(config string, actual int, prefixes []*Plan, originalTags []string) (*Plan, error) {
	if len(prefixes) <= 8 || len(prefixes) > hopmeasure.PhysicalTraversalDepth || len(prefixes) != len(originalTags) {
		return nil, errors.New("extended imported MTU needs every original prefix")
	}
	return combinePlans(config, actual, prefixes, originalTags, 1, false)
}

// CombineExtendedPairedLocalPlans verifies the exact WG endpoint detour
// at every prefix and the original paired Shadowsocks final.
func CombineExtendedPairedLocalPlans(config string, actual int, prefixes []*Plan, originalTags []string) (*Plan, error) {
	if len(prefixes) <= 8 || len(prefixes) > hopmeasure.PhysicalTraversalDepth || len(prefixes) != len(originalTags) {
		return nil, errors.New("extended paired MTU needs every original prefix")
	}
	return combinePlans(config, actual, prefixes, originalTags, len(prefixes)-1, false)
}

// CombineExtendedMixedLocalPlans binds a captured packet prefix and stream
// suffix to each actual immediate detour and original TUN projection.
func CombineExtendedMixedLocalPlans(config string, actual int, prefixes []*Plan, originalTags []string, packets int) (*Plan, error) {
	if len(prefixes) <= 8 || len(prefixes) > hopmeasure.PhysicalTraversalDepth || len(prefixes) != len(originalTags) || packets < 1 || packets > len(prefixes)-2 {
		return nil, errors.New("mixed Local MTU lost its original packet and stream inventory")
	}
	return combinePlans(config, actual, prefixes, originalTags, packets, true)
}

func combinePlans(config string, actual int, prefixes []*Plan, originalTags []string, packets int, mixed bool) (*Plan, error) {
	bad := errors.New("captured MTU needs complete matching prefix plans")
	if len(prefixes) < 2 || len(prefixes) > 8 && originalTags == nil {
		return nil, bad
	}
	var original map[string]any
	if strictJSON(config, &original, 4<<20) != nil {
		return nil, bad
	}
	route, ok := original["route"].(map[string]any)
	if !ok {
		return nil, bad
	}
	selected, err := stringField(route, "final", "")
	if err != nil || !idPattern.MatchString(selected) {
		return nil, bad
	}
	var selector map[string]any
	rows, ok := original["outbounds"].([]any)
	if !ok {
		return nil, bad
	}
	for _, raw := range rows {
		value, ok := raw.(map[string]any)
		if !ok {
			return nil, bad
		}
		if value["tag"] == selected {
			if selector != nil {
				return nil, bad
			}
			selector = value
		}
	}
	if selector == nil || len(selector) != 5 || selector["type"] != "selector" || selector["interrupt_exist_connections"] != true {
		return nil, bad
	}
	choices, ok := selector["outbounds"].([]any)
	if !ok || len(choices) != 1 || selector["default"] != choices[0] {
		return nil, bad
	}
	var extendedNodes map[string]map[string]any
	if originalTags != nil {
		extendedNodes = extendedMTUNodes(original)
		if extendedNodes == nil {
			return nil, bad
		}
	}
	result := &Plan{Original: actual, Ceiling: MaxMTU, source: config}
	seen := map[string]bool{}
	for i, prefix := range prefixes {
		if prefix == nil {
			return nil, bad
		}
		checked, err := NewPlan(prefix.source, actual)
		if err != nil || *checked != *prefix {
			return nil, errors.Join(err, bad)
		}
		var projection map[string]any
		if strictJSON(prefix.source, &projection, 4<<20) != nil {
			return nil, bad
		}
		projectedRoute, ok := projection["route"].(map[string]any)
		if !ok {
			return nil, bad
		}
		tag, err := stringField(projectedRoute, "final", "")
		if err != nil || tag == selected || seen[tag] || i == len(prefixes)-1 && tag != choices[0] {
			return nil, bad
		}
		if originalTags != nil && !extendedMTUPrefix(extendedNodes, originalTags, tag, i, packets, mixed) {
			return nil, bad
		}
		seen[tag] = true
		projectedRoute["final"] = selected
		if !reflect.DeepEqual(original, projection) || i != 0 && result.TunTag != checked.TunTag {
			return nil, bad
		}
		result.TunTag, result.Ceiling = checked.TunTag, min(result.Ceiling, checked.Ceiling)
	}
	if actual < MinMTU || actual > result.Ceiling {
		return nil, bad
	}
	return capturePlan(result), nil
}

func extendedMTUNodes(graph map[string]any) map[string]map[string]any {
	nodes := make(map[string]map[string]any)
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, ok := graph[family].([]any)
		if !ok {
			return nil
		}
		for _, item := range rows {
			node, ok := item.(map[string]any)
			if !ok {
				return nil
			}
			tag, err := stringField(node, "tag", "")
			if err != nil || tag == "" || nodes[tag] != nil {
				return nil
			}
			nodes[tag] = node
		}
	}
	return nodes
}

func extendedMTUPrefix(nodes map[string]map[string]any, tags []string, tag string, i, packets int, mixed bool) bool {
	node := nodes[tag]
	if node == nil || tag != tags[i] || !extendedLocalMTUTag.MatchString(tag) || !strings.HasPrefix(tag, "routervpn-chain-"+strconv.Itoa(i)+"-") {
		return false
	}
	if i < packets {
		kind := node["type"]
		if kind != "wireguard" && (!mixed || kind != "routervpn-amneziawg") {
			return false
		}
		if i == 0 {
			return node["detour"] == nil || node["detour"] == "routervpn-node-physical-egress"
		}
		return node["detour"] == tags[i-1]
	}
	return node["type"] == "shadowsocks" && node["detour"] == tags[i-1]
}
