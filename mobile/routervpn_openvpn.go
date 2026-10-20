// This adapter keeps the established Java/Swift API inside the existing Go runtime.
package libbox

import "router-vpn/internal/nativeopenvpn"

const routerOpenVPNMaxBytes = nativeopenvpn.MaxProfileBytes

// RouterOpenVPNEndpoint compiles the captured inline profile with the same
// strict implementation used to validate its external routing graph.
func RouterOpenVPNEndpoint(config, username, password, tag, detour string) (string, error) {
	return nativeopenvpn.CompileEndpoint(config, username, password, tag, detour)
}
