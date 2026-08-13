//go:build android

package libbox

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	xray "github.com/xtls/libxray"
)

// RouterXrayDialerController is deliberately defined in libbox so gomobile
// generates the controller interface in the same AAR/Go runtime as sing-box.
// This avoids loading two independent gomobile runtimes into one Android app.
type RouterXrayDialerController interface {
	ProtectFd(fd int64) bool
}

type routerXrayDialerAdapter struct {
	controller RouterXrayDialerController
}

func (a *routerXrayDialerAdapter) ProtectFd(fd int) bool {
	if a == nil || a.controller == nil {
		return false
	}
	return a.controller.ProtectFd(int64(fd))
}

// RouterXrayRegisterDialerController installs Android VpnService socket
// protection for Xray outbound dials.
func RouterXrayRegisterDialerController(controller RouterXrayDialerController) {
	if controller == nil {
		return
	}
	xray.RegisterDialerController(&routerXrayDialerAdapter{controller: controller})
}

// RouterXrayRegisterListenerController protects listener sockets created by
// Xray before they can recurse into the VPN TUN.
func RouterXrayRegisterListenerController(controller RouterXrayDialerController) {
	if controller == nil {
		return
	}
	xray.RegisterListenerController(&routerXrayDialerAdapter{controller: controller})
}

var (
	routerXrayResolverMu     sync.Mutex
	routerXrayResolverActive bool
	routerXraySavedResolver  *net.Resolver
)

// RouterXraySetDNS installs a temporary process resolver for Xray hostname
// bootstrap. The DNS server must already have been validated by the Android
// profile policy as a literal address. Every resolver socket is protected from
// the VPN TUN before it is used, avoiding DDNS bootstrap recursion.
// It returns an empty string on success or a bounded human-readable error.
func RouterXraySetDNS(controller RouterXrayDialerController, server string) string {
	if controller == nil {
		return "missing Android VPN socket protector"
	}
	ip := net.ParseIP(strings.TrimSpace(server))
	if ip == nil {
		return "Xray bootstrap DNS must be a literal IP address"
	}
	endpoint := net.JoinHostPort(ip.String(), "53")
	isV4 := ip.To4() != nil
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			base := "udp"
			if strings.HasPrefix(strings.ToLower(network), "tcp") {
				base = "tcp"
			}
			if isV4 {
				base += "4"
			} else {
				base += "6"
			}
			dialer := net.Dialer{
				Timeout: 5 * time.Second,
				Control: func(_, _ string, raw syscall.RawConn) error {
					var protectErr error
					if err := raw.Control(func(fd uintptr) {
						if !controller.ProtectFd(int64(fd)) {
							protectErr = errors.New("Android VpnService refused to protect Xray DNS socket")
						}
					}); err != nil {
						return err
					}
					return protectErr
				},
			}
			return dialer.DialContext(ctx, base, endpoint)
		},
	}

	routerXrayResolverMu.Lock()
	defer routerXrayResolverMu.Unlock()
	if !routerXrayResolverActive {
		routerXraySavedResolver = net.DefaultResolver
	}
	net.DefaultResolver = resolver
	routerXrayResolverActive = true
	return ""
}

// RouterXrayResetDNS restores the resolver that existed before native Xray
// started. Router VPN never leaves the process-global resolver modified after
// the Xray core stops or fails.
func RouterXrayResetDNS() {
	routerXrayResolverMu.Lock()
	defer routerXrayResolverMu.Unlock()
	if !routerXrayResolverActive {
		return
	}
	if routerXraySavedResolver != nil {
		net.DefaultResolver = routerXraySavedResolver
	} else {
		net.DefaultResolver = &net.Resolver{}
	}
	routerXraySavedResolver = nil
	routerXrayResolverActive = false
}

// RouterXrayInvoke exposes libXray's bounded JSON command API without binding a
// second Go package/AAR. libXray itself caps requests/responses at 16 MiB.
func RouterXrayInvoke(requestJSON string) string {
	return xray.Invoke(requestJSON)
}

// RouterXrayBridgeRevision is a runtime/debug trust marker for the exact
// libXray source revision copied into the pinned combined mobile build.
func RouterXrayBridgeRevision() string {
	return "294fb37343205b9b0cb7b7b1b423d3d4b60d9998"
}
