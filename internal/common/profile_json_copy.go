package common

import (
	"maps"
	"slices"
)

func copyProfileJSONPointer[T any](source *T) *T {
	if source == nil {
		return nil
	}
	value := *source
	return &value
}

// CloneRouterProfile captures private node credentials and policy without
// normalization or JSON conversion. Later edits cannot mutate this session's
// WireGuard/AWG parameters, Start Layer provision or response endpoint.
func CloneRouterProfile(source RouterProfile) RouterProfile {
	return copyProfileForJSON(source)
}

// JSON output normalizes a detached copy. A value receiver alone is not a
// copy of its slices/pointers: encoding a store or nested external node must
// never change live routing policy or partially normalize it on an error.
func copyProfileForJSON(source RouterProfile) RouterProfile {
	out := source
	out.CustomLayers = slices.Clone(source.CustomLayers)
	out.HomeLANCIDRs = slices.Clone(source.HomeLANCIDRs)
	out.DNSResults = slices.Clone(source.DNSResults)
	out.External = copyProfileJSONPointer(source.External)
	if out.External == nil {
		return out
	}
	e := out.External
	e.ResponseProbe = copyProfileJSONPointer(e.ResponseProbe)
	if e.OpenVPNResponseProbes != nil {
		probes := make(ExternalOpenVPNResponseProbes, len(e.OpenVPNResponseProbes))
		for host, probe := range e.OpenVPNResponseProbes { probes[host] = probe }
		e.OpenVPNResponseProbes = probes
	}
	if e.OpenVPNStartLayers != nil {
		layers := make(ExternalOpenVPNStartLayers, len(e.OpenVPNStartLayers))
		for host, layer := range e.OpenVPNStartLayers {
			layer.Transport = copyProfileJSONMap(layer.Transport)
			layers[host] = layer
		}
		e.OpenVPNStartLayers = layers
	}
	e.OpenVPNPairing = copyProfileJSONPointer(e.OpenVPNPairing)
	if e.OpenVPNPairing != nil { e.OpenVPNPairing.Server.Transport = copyProfileJSONMap(e.OpenVPNPairing.Server.Transport) }
	e.ServerPeer = copyProfileJSONPointer(e.ServerPeer)
	if e.ServerPeer != nil {
		e.ServerPeer.Addresses = slices.Clone(e.ServerPeer.Addresses)
	}
	e.StartLayer = copyProfileJSONPointer(e.StartLayer)
	if e.StartLayer != nil {
		e.StartLayer.Transport = copyProfileJSONMap(e.StartLayer.Transport)
	}
	e.WireGuard = copyProfileJSONPointer(e.WireGuard)
	if w := e.WireGuard; w != nil {
		w.Addresses = slices.Clone(w.Addresses)
		w.AllowedIPs = slices.Clone(w.AllowedIPs)
		w.DNS = slices.Clone(w.DNS)
	}
	e.AmneziaWG = copyProfileJSONPointer(e.AmneziaWG)
	if a := e.AmneziaWG; a != nil {
		a.Addresses = slices.Clone(a.Addresses)
		a.AllowedIPs = slices.Clone(a.AllowedIPs)
		a.DNS = slices.Clone(a.DNS)
		a.Parameters = maps.Clone(a.Parameters)
	}
	e.OpenVPN = copyProfileJSONPointer(e.OpenVPN)
	e.Shadowsocks = copyProfileJSONPointer(e.Shadowsocks)
	e.SOCKS5 = copyProfileJSONPointer(e.SOCKS5)
	e.HTTPConnect = copyProfileJSONPointer(e.HTTPConnect)
	e.HTTPSConnect = copyProfileJSONPointer(e.HTTPSConnect)
	e.Hysteria2 = copyProfileJSONPointer(e.Hysteria2)
	e.TorBridge = copyProfileJSONPointer(e.TorBridge)
	if e.TorBridge != nil {
		e.TorBridge.Bridges = slices.Clone(e.TorBridge.Bridges)
	}
	return out
}

func copyProfileJSONMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	out := make(map[string]any, len(source))
	for key, value := range source {
		out[key] = copyProfileJSONValue(value)
	}
	return out
}

func copyProfileJSONValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return copyProfileJSONMap(value)
	case []any:
		out := make([]any, len(value))
		for i := range value {
			out[i] = copyProfileJSONValue(value[i])
		}
		return out
	case []string:
		return slices.Clone(value)
	default:
		return value
	}
}

func copyProfileStoreForJSON(source RouterProfileStore) RouterProfileStore {
	out := source
	out.Profiles = slices.Clone(source.Profiles)
	for i := range out.Profiles {
		out.Profiles[i] = copyProfileForJSON(out.Profiles[i])
	}
	return out
}
