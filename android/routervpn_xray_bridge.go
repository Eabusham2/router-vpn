//go:build android

package libbox

import xray "github.com/xtls/libxray"

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
