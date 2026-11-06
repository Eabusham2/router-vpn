package mobilemultihop

import (
	"encoding/json"
	"errors"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

// ExternalPolicy has already verified the entire standalone source and layer.
// Preserve its public OpenVPN remote identity while mapping only the actual
// transport to the separately provisioned private service. The original source
// is retained unchanged in the imported-controller fingerprint.
func importedOpenVPNLayerGraph(graph map[string]any, selected externalPolicyCapture) error {
	external, _ := selected.Profile["external"].(map[string]any)
	if _, mapped := external["openvpn_start_layers"]; mapped {
		return nil
	}
	mode, err := externalOptionalString(selected.Profile, "start_layer")
	if err != nil {
		return err
	}
	if mode == "" || mode == "off" {
		return nil
	}
	bad := errors.New("imported OpenVPN layer lost its exact original public remote mapping")
	raw, err := json.Marshal(external["start_layer"])
	var layer nativeopenvpn.StartLayer
	if err != nil || json.Unmarshal(raw, &layer) != nil {
		return bad
	}
	transport, err := multihoprelay.ExternalTransport("openvpn", external)
	if err != nil {
		return bad
	}
	remotes, err := nativeopenvpn.Remotes(transport)
	if err != nil {
		return bad
	}
	layers := nativeopenvpn.StartLayers{}
	for _, remote := range remotes {
		if layer.Validate(remote.Host, mode) != nil {
			return bad
		}
		layers[remote.Host] = layer
	}
	mapping := nativeopenvpn.LayerMap{Mode: mode, Remotes: remotes, Layers: layers}
	if mapping.Validate() != nil {
		return bad
	}
	encoded, err := json.Marshal(mapping)
	outer := map[string]any{}
	if err != nil || json.Unmarshal(encoded, &outer) != nil {
		return bad
	}
	const tag = multihoprelay.OpenVPNStartLayerMapTag
	outer["tag"], outer["type"] = tag, nativeopenvpn.LayerMapType
	var previous map[string]any
	endpoints, _ := graph["endpoints"].([]any)
	for _, item := range endpoints {
		node, ok := item.(map[string]any)
		if !ok {
			return bad
		}
		if node["tag"] == ExternalFinalTag {
			previous = node
		}
	}
	if previous == nil || previous["type"] != externalOpenVPNType {
		return bad
	}
	oldLayer, ok := previous["detour"].(string)
	if !ok || oldLayer == "" {
		return bad
	}
	values, _ := graph["outbounds"].([]any)
	retained := make([]any, 0, len(values))
	removed := 0
	for _, item := range values {
		node, ok := item.(map[string]any)
		if !ok || node["tag"] == tag {
			return bad
		}
		if node["tag"] == oldLayer {
			removed++
			continue
		}
		retained = append(retained, item)
	}
	if removed != 1 {
		return bad
	}
	transport["tag"], transport["detour"] = ExternalFinalTag, tag
	for key := range previous {
		delete(previous, key)
	}
	for key, value := range transport {
		previous[key] = value
	}
	graph["outbounds"] = append(retained, outer)
	return nil
}
