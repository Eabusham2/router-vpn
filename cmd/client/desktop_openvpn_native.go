package main

import (
	"errors"
	"runtime"

	"router-vpn/internal/nativeopenvpn"
)

// Keep the original inline profile as the credential authority. The displayed
// first remote does not replace its native failover list, TLS policy or keys.
func normalizeNativeOpenVPNStandardExit(exit *standardExit) error {
	endpoint, err := nativeopenvpn.CompileProfile(nativeopenvpn.Profile{Config: exit.OpenVPNConfig, Username: exit.Username, Password: exit.Password}, "custom-exit", "")
	if err != nil {
		return err
	}
	remote := endpoint
	if values, ok := endpoint["servers"].([]any); ok && len(values) != 0 {
		remote, _ = values[0].(map[string]any)
	}
	host, _ := remote["server"].(string)
	port, _ := remote["server_port"].(float64)
	network, _ := remote["network"].(string)
	if host == "" || port < 1 || port > 65535 || port != float64(int(port)) || network == "" {
		return errors.New("native OpenVPN compiler returned an invalid captured remote")
	}
	exit.Server, exit.ServerPort, exit.Method = host, int(port), network
	return nil
}

func desktopOpenVPNEndpoint(exit standardExit, detour string) (map[string]any, error) {
	return nativeopenvpn.CompileProfile(nativeopenvpn.Profile{Config: exit.OpenVPNConfig, Username: exit.Username, Password: exit.Password}, "custom-exit", detour)
}

func desktopNativeOpenVPNCapability() standardExitCapability {
	capability := standardExitCapability{Protocol: "openvpn", Implemented: true}
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		capability.Reason = "the desktop native OpenVPN host runs on Windows, macOS and Linux"
		return capability
	}
	if _, err := verifyBundledNative(desktopAmneziaPackageRoot()); err != nil {
		capability.Reason = err.Error()
		return capability
	}
	capability.Supported = true
	return capability
}
