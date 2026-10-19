package multihoprelay

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

const MAXRelayPrefix = "routervpn-relay-max-"

// MAXRelayTags names only the private relay's complete captured chain. The
// authenticated listener routes to its PQ endpoint, never to an outer helper.
func MAXRelayTags() MAXTags {
	return MAXTags{Root: "exit", Middle: MAXRelayPrefix + "ss", Outer: MAXRelayPrefix + "outer", Start: MAXRelayPrefix + "start"}
}

// PairMAXChain serializes an offline compiler's complete, unwrapped source for
// the private operator registry. It neither starts the chain nor adds a route.
// The optional selected Start Layer is separately bound to that same node.
func PairMAXChain(base map[string]any, outputs []any, mode, node string, from MAXTags) ([]byte, error) {
	// Marshal first to reject cycles and bound recursive string validation.
	source := map[string]any{"endpoint": base, "outbounds": outputs}
	if _, err := boundedMAXCopy(source); err != nil {
		return nil, err
	}
	endpoint, outbounds, err := RelabelMAXChain(base, outputs, mode, node, "", from, MAXRelayTags(), "", "")
	if err != nil {
		return nil, err
	}
	return MAXChainBytes(endpoint, outbounds)
}

func boundedMAXCopy(source map[string]any) (map[string]any, error) {
	bad := errors.New("invalid bounded private MAX chain")
	raw, err := json.Marshal(source)
	if err != nil || len(raw) == 0 || len(raw) > 4<<20 || !maxPrivateText(source, 0) {
		return nil, bad
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil || result == nil {
		return nil, bad
	}
	return result, nil
}

func maxPrivateText(value any, depth int) bool {
	if depth > 32 {
		return false
	}
	switch value := value.(type) {
	case nil, bool, float64, int:
		return true
	case string:
		return utf8.ValidString(value)
	case map[string]any:
		for key, child := range value {
			if !utf8.ValidString(key) || !maxPrivateText(child, depth+1) {
				return false
			}
		}
	case []any:
		for _, child := range value {
			if !maxPrivateText(child, depth+1) {
				return false
			}
		}
	default:
		return false
	}
	return true
}

func validateMAXTransport(exit Exit) (map[string]any, error) {
	bad := errors.New("paired MAX lost its complete captured encryption chain")
	if !CompleteMAXMode(exit.Mode) || len(exit.Transport) != 2 || !maxFields(exit.Transport, "endpoint", "outbounds") {
		return nil, bad
	}
	plan, err := boundedMAXCopy(exit.Transport)
	if err != nil {
		return nil, err
	}
	base, ok := plan["endpoint"].(map[string]any)
	if !ok {
		return nil, bad
	}
	outputs, ok := plan["outbounds"].([]any)
	if !ok || ValidateMAXChain(base, outputs, exit.Mode, exit.NodeID, "", MAXRelayTags(), "") != nil {
		return nil, bad
	}
	return plan, nil
}

func maxRelayChain(exit Exit) (map[string]any, []any, error) {
	plan, err := validateMAXTransport(exit)
	if err != nil {
		return nil, nil, err
	}
	base := plan["endpoint"].(map[string]any)
	outputs := plan["outbounds"].([]any)
	if exit.StartLayer == nil {
		return base, outputs, nil
	}
	tags := MAXRelayTags()
	outerMode := "hysteria2"
	if strings.HasPrefix(exit.Mode, "max-tls-") {
		outerMode = "reality-xhttp"
	}
	for index, value := range outputs {
		outer := value.(map[string]any)
		if outer["tag"] != tags.Outer {
			continue
		}
		inner, start, err := WrapStartLayer(outer, outerMode, exit.StartLayer, tags.Start, "")
		if err != nil {
			return nil, nil, err
		}
		outputs[index] = inner
		outputs = append(outputs, start)
		break
	}
	// Normalize only the freshly owned maps (including a generated port), then
	// prove that the outermost layer matches the original middle AES key and
	// private service. Neither the PQ peer nor its exchange may bypass the chain.
	plan, err = boundedMAXCopy(map[string]any{"endpoint": base, "outbounds": outputs})
	if err != nil {
		return nil, nil, err
	}
	base, outputs = plan["endpoint"].(map[string]any), plan["outbounds"].([]any)
	if err = ValidateMAXChain(base, outputs, exit.Mode, exit.NodeID, LayerMode(exit.StartLayer), tags, ""); err != nil {
		return nil, nil, err
	}
	return base, outputs, nil
}
