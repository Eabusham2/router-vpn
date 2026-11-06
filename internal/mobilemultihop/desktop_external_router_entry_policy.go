package mobilemultihop

import (
	"reflect"

	"router-vpn/internal/multihoprelay"
)

// Rebuild only the original predecessor's namespace and captured MTU rewrite.
// The candidate graph supplies no credentials, layer selection or expected row.
// The same validated merger used by NewExternalPolicy preserves resolver names
// and every WG/outer field while assigning the entry's role in the full graph.
func desktopExternalRouterEntryExpected(original externalPolicyCapture, capture ExternalDesktopCapture) (map[string]any, map[string]any, error) {
	bad := desktopExternalPolicyError
	layer, err := externalOptionalString(original.Entry, "start_layer")
	if layer == "off" {
		layer = ""
	}
	if err != nil || layer != capture.EntryStartLayer || layer != "" && !multihoprelay.ValidLayerMode(layer) ||
		capture.EntryTag != externalEntryTag || capture.EntryNodeID != original.Entry["node_proof_id"] || capture.EntryMTU <= 0 {
		return nil, nil, bad
	}
	predecessor, err := newExternalPredecessor(original)
	if err != nil || predecessor == nil || predecessor.final["type"] != "wireguard" {
		return nil, nil, bad
	}
	predecessor.final["mtu"] = float64(capture.EntryMTU)
	graph := map[string]any{
		"endpoints": []any{}, "outbounds": []any{},
		"dns": map[string]any{"servers": []any{}}, "route": map[string]any{"rules": []any{}},
	}
	if predecessor.merge(graph, map[string]any{"tag": capture.TUNTag}, map[string]any{}) != nil {
		return nil, nil, bad
	}
	endpoints, ok := graph["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return nil, nil, bad
	}
	inner, ok := endpoints[0].(map[string]any)
	if !ok || inner["type"] != "wireguard" || inner["tag"] != externalEntryTag {
		return nil, nil, bad
	}
	rows, ok := graph["outbounds"].([]any)
	if !ok {
		return nil, nil, bad
	}
	if layer == "" {
		if len(rows) != 0 || inner["detour"] != nil {
			return nil, nil, bad
		}
		return inner, nil, nil
	}
	tag := predecessorNamespace("node", NativeStartLayerTag)
	if len(rows) != 1 || inner["detour"] != tag {
		return nil, nil, bad
	}
	outer, ok := rows[0].(map[string]any)
	if !ok || outer["tag"] != tag || outer["type"] != desktopExternalLayerKind(layer) || outer["method"] != NativeStartLayerMethod || outer["detour"] != nil {
		return nil, nil, bad
	}
	return inner, outer, nil
}

func desktopExternalRouterEntryEndpoint(rows []any, original externalPolicyCapture, capture ExternalDesktopCapture) (map[string]any, error) {
	expected, _, err := desktopExternalRouterEntryExpected(original, capture)
	if err != nil || len(rows) != 1 {
		return nil, desktopExternalPolicyError
	}
	inner, ok := rows[0].(map[string]any)
	if !ok || !reflect.DeepEqual(inner, expected) {
		return nil, desktopExternalPolicyError
	}
	return inner, nil
}

// StartupSocketRequired describes the endpoint's need for its already-owned
// lower transport during Start. It grants neither TUN nor proof readiness.
// A layered Router WG endpoint is separately sealed from its SS/XOR physical
// root; an ordinary lazy SS graph cannot manufacture this phase from its type.
func (p *DesktopExternalPolicy) StartupSocketRequired(targetOS string) (bool, error) {
	if p == nil || p.Validate() != nil || p.metadata.TargetOS != targetOS ||
		(targetOS != "windows" && targetOS != "linux" && targetOS != "darwin") {
		return false, desktopExternalPolicyError
	}
	meta := p.metadata
	if meta.StartupEndpointTag == "" && meta.StartupEndpointType == "" && meta.StartupEndpointSHA256 == "" {
		return meta.RootType == "wireguard" || meta.RootType == AmneziaType || meta.RootType == "openvpn-client", nil
	}
	capture, err := p.Capture()
	if err != nil || targetOS != "windows" || meta.StartupEndpointTag != externalEntryTag || meta.StartupEndpointTag != capture.EntryTag ||
		meta.StartupEndpointType != "wireguard" || !proofID.MatchString(meta.StartupEndpointSHA256) ||
		meta.RootTag != predecessorNamespace("node", NativeStartLayerTag) || meta.RootTag == meta.StartupEndpointTag ||
		!multihoprelay.ValidLayerMode(capture.EntryStartLayer) || meta.RootType != desktopExternalLayerKind(capture.EntryStartLayer) ||
		capture.EntryNodeID == "" || capture.PredecessorSHA256 == "" {
		return false, desktopExternalPolicyError
	}
	return true, nil
}
