package common

import "router-vpn/internal/awgpolicy"

// Imported AmneziaWG keeps the same peer/address grammar as WireGuard, while
// retaining its entire separately validated native obfuscation policy. This
// normalization does not turn an imported policy into a Fast/Strong preset.
func normalizeExternalAmnezia(a *ExternalAmneziaWGConfig, expectedPublicIP string) error {
	if _, err := awgpolicy.ParametersUAPI(a.Parameters); err != nil {
		return err
	}
	ordinary := ExternalNodeConfig{Protocol: "wireguard", ExpectedPublicIP: expectedPublicIP, WireGuard: &a.ExternalWireGuardConfig}
	return normalizeExternalNode(&ordinary)
}
