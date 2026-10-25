// This adapter keeps the established Java/Swift API inside the existing Go runtime.
package libbox

import "router-vpn/internal/nativeopenvpn"

const routerOpenVPNMaxBytes = nativeopenvpn.MaxProfileBytes

// RouterOpenVPNEndpoint compiles the captured inline profile with the same
// strict implementation used to validate its external routing graph.
func RouterOpenVPNEndpoint(config, username, password, tag, detour string) (string, error) {
	return nativeopenvpn.CompileEndpoint(config, username, password, tag, detour)
}

// RouterValidateExternalOpenVPNPairing validates raw external.openvpn and raw
// external.openvpn_pairing before native editor JSON conversions. No socket is
// opened and no private descriptor or executable configuration is returned.
func RouterValidateExternalOpenVPNPairing(profileJSON, pairingJSON string) error {
	return nativeopenvpn.ValidatePairingJSON(profileJSON, pairingJSON)
}

// RouterValidatePrivateNodeJSON validates raw object structure before native
// bundle decoding. Typed schema and captured policy validation follow it.
func RouterValidatePrivateNodeJSON(raw string) error {
	return nativeopenvpn.ValidatePrivateNodeJSON(raw)
}
