package main

import (
	"encoding/json"
	"errors"
	"net/netip"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativeopenvpn"
)

func desktopExternalCompiledPhysical(policy *mobilemultihop.ExternalPolicy) ([]nativeopenvpn.LayerEgress, error) {
	tuples, err := policy.PhysicalEgress()
	if errors.Is(err, mobilemultihop.ErrDynamicPhysicalEgress) {
		// The legacy dynamic SOCKS path has no fixed relay tuple. Do not
		// fabricate one or silently disable its negotiated UDP transport.
		// Its per-socket protection migration remains explicit unfinished work.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]nativeopenvpn.LayerEgress, len(tuples))
	for i, tuple := range tuples {
		result[i] = nativeopenvpn.LayerEgress{Host: tuple.Host, Port: tuple.Port, Network: tuple.Network}
	}
	return result, nil
}

func desktopExternalEgressEndpoints(endpoint string, tuples []nativeopenvpn.LayerEgress) ([]string, error) {
	hosts, seen := []string{endpoint}, map[string]bool{endpoint: true}
	found := false
	for _, tuple := range tuples {
		if tuple.Host == endpoint {
			found = true
		}
		if !seen[tuple.Host] {
			seen[tuple.Host] = true
			hosts = append(hosts, tuple.Host)
		}
	}
	if !found || len(hosts) > 16 {
		return nil, errors.New("external physical primary is not part of its compiled socket capture")
	}
	return hosts, nil
}

// Only validated native layer compilation can supply restricted physical
// tuples. An exit behind a predecessor never opens its own provider ports on
// the device's physical network; the captured predecessor is the owner.
func desktopExternalPhysicalEgress(profile, entry common.RouterProfile, direct bool) ([]nativeopenvpn.LayerEgress, error) {
	physical := profile
	if !direct {
		physical = entry
	}
	if physical.External == nil || physical.External.OpenVPNStartLayers == nil {
		return nil, nil
	}
	if physical.External.Protocol != "openvpn" || physical.External.OpenVPN == nil {
		return nil, errors.New("mapped layer physical owner has no captured OpenVPN profile")
	}
	profileJSON, err := json.Marshal(physical.External.OpenVPN)
	if err != nil {
		return nil, err
	}
	probesJSON, err := json.Marshal(physical.External.OpenVPNResponseProbes)
	if err != nil {
		return nil, err
	}
	layersJSON, err := json.Marshal(physical.External.OpenVPNStartLayers)
	if err != nil {
		return nil, err
	}
	return nativeopenvpn.StartLayerEgress(string(profileJSON), string(probesJSON), string(layersJSON), physical.StartLayer)
}

// Only the physically dialed node contributes firewall exceptions. A final
// exit behind an entry never adds its provider remotes to the physical allow
// list. OpenVPN failover retains every captured literal remote, in order.
func desktopExternalPhysicalEndpoints(profile, entry common.RouterProfile, direct bool, endpoint string) ([]string, error) {
	physical := profile
	if !direct {
		physical = entry
	}
	addresses := []string{endpoint}
	if physical.External != nil && physical.External.Protocol == "openvpn" && physical.External.StartLayer == nil {
		if physical.External.OpenVPN == nil {
			return nil, errors.New("OpenVPN physical owner has no captured profile")
		}
		compiled, err := nativeopenvpn.CompileProfile(*physical.External.OpenVPN, "physical-owner", "")
		if err != nil {
			return nil, err
		}
		if remotes, ok := compiled["servers"].([]any); ok {
			addresses = nil
			for _, value := range remotes {
				remote, ok := value.(map[string]any)
				if !ok {
					return nil, errors.New("OpenVPN physical remote is invalid")
				}
				host, _ := remote["server"].(string)
				addresses = append(addresses, host)
			}
		}
	}
	if len(addresses) == 0 || len(addresses) > 16 || addresses[0] != endpoint {
		return nil, errors.New("external physical endpoint capture changed")
	}
	result := make([]string, 0, len(addresses))
	seen := map[string]bool{}
	for _, value := range addresses {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() || address.String() != value {
			return nil, errors.New("external physical remotes require canonical literal unicast addresses")
		}
		if !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	return result, nil
}
