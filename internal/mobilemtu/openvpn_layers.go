package mobilemtu

import (
	"encoding/json"
	"errors"
	"reflect"
	"router-vpn/internal/nativeopenvpn"
)

func openVPNMappedCeiling(endpoint, outbound map[string]any, all map[string]map[string]any) (int, error) {
	bad := errors.New("OpenVPN MTU mapper differs from its complete captured remote envelope")
	options := map[string]any{}
	for key, value := range outbound {
		if key != "type" && key != "tag" {
			options[key] = value
		}
	}
	raw, err := json.Marshal(options)
	var mapping nativeopenvpn.LayerMap
	if err != nil || json.Unmarshal(raw, &mapping) != nil {
		return 0, bad
	}
	// MTU's strict parser keeps json.Number for every interface setting; the
	// shared native compiler deliberately uses standard JSON number values.
	// Convert only a detached endpoint for its full transport validation.
	encodedEndpoint, err := json.Marshal(endpoint)
	var nativeEndpoint map[string]any
	if err != nil || json.Unmarshal(encodedEndpoint, &nativeEndpoint) != nil {
		return 0, bad
	}
	if _, err := nativeopenvpn.ValidateEndpoint(nativeEndpoint); err != nil {
		return 0, bad
	}
	remotes, err := nativeopenvpn.Remotes(nativeEndpoint)
	if err != nil || !reflect.DeepEqual(remotes, mapping.Remotes) {
		return 0, bad
	}
	mtu, err := intField(endpoint, "mtu", 1500)
	if err != nil || mtu < MinMTU || mtu > MaxMTU {
		return 0, bad
	}
	overhead, err := mapping.Layers.DatagramOverhead()
	if err != nil {
		return 0, bad
	}
	if mapping.Detour != "" {
		entry := all[mapping.Detour]
		if entry == nil {
			return 0, bad
		}
		switch entry["type"] {
		case "wireguard", "routervpn-amneziawg", "routervpn-pq", "openvpn-client":
			outer, err := intField(entry, "mtu", 0)
			if err != nil || outer < MinMTU || outer > MaxMTU {
				return 0, bad
			}
			for _, remote := range remotes {
				if remote.Network != "udp" {
					continue
				}
				fragment, err := intField(endpoint, "fragment", 0)
				if err != nil || fragment < 0 {
					return 0, bad
				}
				if fragment > 0 {
					if fragment > outer-48-overhead {
						return 0, bad
					}
				} else {
					mtu = min(mtu, outer-160-overhead)
				}
			}
		}
	}
	if mtu < MinMTU {
		return 0, bad
	}
	return mtu, nil
}
