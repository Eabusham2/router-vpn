package common

import "slices"

func copyProfileJSONPointer[T any](source *T) *T {
	if source == nil {
		return nil
	}
	value := *source
	return &value
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
	e.WireGuard = copyProfileJSONPointer(e.WireGuard)
	if w := e.WireGuard; w != nil {
		w.Addresses = slices.Clone(w.Addresses)
		w.AllowedIPs = slices.Clone(w.AllowedIPs)
		w.DNS = slices.Clone(w.DNS)
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

func copyProfileStoreForJSON(source RouterProfileStore) RouterProfileStore {
	out := source
	out.Profiles = slices.Clone(source.Profiles)
	for i := range out.Profiles {
		out.Profiles[i] = copyProfileForJSON(out.Profiles[i])
	}
	return out
}
