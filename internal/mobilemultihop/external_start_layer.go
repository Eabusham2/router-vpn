package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"router-vpn/internal/multihoprelay"
)

const ExternalEntryStartLayerTag = "routervpn-external-entry-start-layer"

// SS2022 UDP wraps the already-accounted packet datagram. Include the larger
// of request/response authenticated headers plus every EIH key, and the private
// destination's SOCKS address. XOR preserves length. This is an overhead bound,
// not a claim of measured physical path MTU.
func externalPacketLayerOverhead(profile map[string]any) (int, error) {
	ext, _ := profile["external"].(map[string]any)
	protocol, _ := ext["protocol"].(string)
	layer, err := externalCapturedStartLayer(externalPolicyCapture{Profile: profile, Protocol: protocol})
	if err != nil || layer == nil {
		return 0, err
	}
	transport, err := multihoprelay.ExternalTransport(protocol, ext)
	if err != nil {
		return 0, err
	}
	if _, _, err = multihoprelay.WrapStartLayer(transport, protocol, layer, multihoprelay.ExitStartLayerTag, ""); err != nil {
		return 0, err
	}
	api, _ := url.Parse(layer.API)
	addressBytes := 7
	if strings.Contains(api.Hostname(), ":") {
		addressBytes = 19
	}
	keys := len(strings.Split(layer.Transport["password"].(string), ":"))
	request := 43 + addressBytes + 16*(keys-1)
	response := 51 + addressBytes
	if response > request {
		return response, nil
	}
	return request, nil
}

// The selected mode and operator-provisioned transport are separate captured
// values. Neither can implicitly enable, disable or replace the other. The
// transport stays in the private external profile used by both native paths
// and the paired server registry.
func externalCapturedStartLayer(selected externalPolicyCapture) (*multihoprelay.StartLayer, error) {
	if selected.Profile["node_kind"] != "external" {
		return nil, nil
	}
	bad := errors.New("external Start Layer requires its exact selected mode and private provisioned transport")
	mode, err := externalOptionalString(selected.Profile, "start_layer")
	if err != nil {
		return nil, err
	}
	if mode == "off" {
		mode = ""
	}
	external, ok := selected.Profile["external"].(map[string]any)
	if !ok {
		return nil, bad
	}
	raw, present := external["start_layer"]
	if mode == "" {
		if present {
			return nil, bad
		}
		return nil, nil
	}
	if !present || !multihoprelay.ValidLayerMode(mode) || !multihoprelay.ExternalMode(selected.Protocol) {
		return nil, bad
	}
	body, err := json.Marshal(raw)
	if err != nil {
		return nil, bad
	}
	var layer multihoprelay.StartLayer
	if exactJSON(body, &layer, 16<<10) != nil || layer.Mode != mode || layer.Transport == nil {
		return nil, bad
	}
	return &layer, nil
}

// The hosts provide the original native external transport. The shared policy
// compiler owns the wrapper so Local, Server and Compare cannot accidentally
// apply different layers or silently ignore the selected exit encryption.
func externalApplyStartLayer(graph, exit map[string]any, selected externalPolicyCapture) (string, error) {
	return externalApplyOwnedStartLayer(graph, exit, selected, multihoprelay.ExitStartLayerTag, selected.EntryTag)
}

// An ordinary external predecessor owns its independent physical wrapper.
// Reusing the exit's tag or detour would either bypass its selected layer or
// send the entry back through itself. Both captured inner transports retain
// their own protocol, credentials and proof tags.
func externalApplyEntryStartLayer(graph, entry map[string]any, selected externalPolicyCapture, protocol string) (string, error) {
	if selected.Entry["node_kind"] != "external" {
		return "", nil
	}
	return externalApplyOwnedStartLayer(graph, entry, externalPolicyCapture{Profile: selected.Entry, Protocol: protocol}, ExternalEntryStartLayerTag, "")
}

func externalApplyOwnedStartLayer(graph, transport map[string]any, selected externalPolicyCapture, tag, via string) (string, error) {
	layer, err := externalCapturedStartLayer(selected)
	if err != nil || layer == nil {
		return "", err
	}
	for _, family := range []string{"endpoints", "outbounds"} {
		values, _ := graph[family].([]any)
		for _, raw := range values {
			value, ok := raw.(map[string]any)
			if !ok || value["tag"] == tag {
				return "", errors.New("external Start Layer tag belongs to another captured transport")
			}
		}
	}
	original := predecessorCopy(transport)
	delete(original, "detour")
	inside, outer, err := multihoprelay.WrapStartLayer(original, selected.Protocol, layer, tag, via)
	if err != nil {
		return "", err
	}
	for field := range transport {
		delete(transport, field)
	}
	for field, value := range inside {
		transport[field] = value
	}
	values, _ := graph["outbounds"].([]any)
	graph["outbounds"] = append(values, outer)
	return layer.Mode, nil
}
