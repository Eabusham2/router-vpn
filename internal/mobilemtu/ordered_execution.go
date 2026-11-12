package mobilemtu

import (
	"errors"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var executionLocalMTUTag = regexp.MustCompile(`^routervpn-chain-[0-7]-[0-9a-f]{12}-node-[0-9a-f]{12}$`)
var executionServerMTUTag = regexp.MustCompile(`^routervpn-chain-server-[1-7]-[0-9a-f]{16}$`)

// CombineExecutionPlans captures the actual gated, two-choice graph supplied
// by the retained ordered compiler. The same TUN must fit every original Local
// prefix even when Server won. Server UoT2 is a TCP stream over that original
// entry; it never grants a larger packet envelope. Private server path MTUs are
// not inferred here. Native probing and actual interface readback remain required.
func CombineExecutionPlans(config string, actual int, prefixes []*Plan) (*Plan, error) {
	bad := errors.New("ordered execution MTU requires its original gated graph and complete prefix plans")
	if len(prefixes) < 2 || len(prefixes) > 8 {
		return nil, bad
	}
	var original map[string]any
	if strictJSON(config, &original, 4<<20) != nil {
		return nil, bad
	}
	route, ok := original["route"].(map[string]any)
	if !ok || route["final"] != "routervpn-chain-application" {
		return nil, bad
	}
	rows, ok := original["outbounds"].([]any)
	if !ok {
		return nil, bad
	}
	all := map[string]map[string]any{}
	for _, raw := range rows {
		value, ok := raw.(map[string]any)
		if !ok {
			return nil, bad
		}
		tag, err := stringField(value, "tag", "")
		if err != nil || !idPattern.MatchString(tag) || all[tag] != nil {
			return nil, bad
		}
		all[tag] = value
	}
	gate, selector := all["routervpn-chain-application"], all["proxy"]
	if len(gate) != 3 || gate["type"] != "routervpn-node-chain-gate" || gate["detour"] != "proxy" ||
		len(selector) != 5 || selector["type"] != "selector" || selector["interrupt_exist_connections"] != true {
		return nil, bad
	}
	choices, ok := selector["outbounds"].([]any)
	if !ok || len(choices) != 2 {
		return nil, bad
	}
	local, localOK := choices[0].(string)
	server, serverOK := choices[1].(string)
	if !localOK || !serverOK || local == server || selector["default"] != local && selector["default"] != server ||
		!executionLocalMTUTag.MatchString(local) || !executionServerMTUTag.MatchString(server) ||
		!strings.HasPrefix(server, "routervpn-chain-server-"+strconv.Itoa(len(prefixes)-1)+"-") {
		return nil, bad
	}
	final := all[server]
	uot, ok := final["udp_over_tcp"].(map[string]any)
	version, versionErr := intField(uot, "version", 0)
	if final["type"] != "socks" || final["version"] != "5" || !ok || len(uot) != 2 || uot["enabled"] != true || versionErr != nil || version != 2 {
		return nil, bad
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
		if err != nil || !executionLocalMTUTag.MatchString(tag) || !strings.HasPrefix(tag, "routervpn-chain-"+strconv.Itoa(i)+"-") ||
			seen[tag] || i == len(prefixes)-1 && tag != local || i == 0 && final["detour"] != tag {
			return nil, bad
		}
		seen[tag] = true
		projectedRoute["final"] = "routervpn-chain-application"
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
