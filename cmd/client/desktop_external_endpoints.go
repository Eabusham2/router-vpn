package main

import (
	"errors"
	"net/netip"

	"router-vpn/internal/common"
	"router-vpn/internal/nativeopenvpn"
)

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
