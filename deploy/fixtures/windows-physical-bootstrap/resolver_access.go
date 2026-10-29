//go:build windows && routervpn_windows_physical_composition

package routervpndesktoppt

import (
	"context"
	"net/netip"
)

// Test-only compile-time access to the identical shipping PT resolver callback.
// No alternative resolver, socket, policy, metadata or lifetime is supplied.
func DesktopWindowsCompositionResolve(owner *Owner, ctx context.Context, network, host string) ([]netip.Addr, error) {
	return owner.resolve(ctx, network, host)
}
