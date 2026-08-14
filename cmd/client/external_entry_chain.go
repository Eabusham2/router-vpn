package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"router-vpn/internal/common"
)

// externalEntryGraph converts a validated external node into a single
// controlled upstream hop. OpenVPN is intentionally excluded here: a native
// OpenVPN TUN cannot safely act as a sing-box detour without a separate
// route-owned entry adapter, so we fail closed rather than create competing
// default tunnels.
func externalEntryGraph(entry standardExit) ([]any, []any, string, error) {
	if err := validateStandardExit(&entry); err != nil {
		return nil, nil, "", err
	}
	if entry.Protocol == "openvpn" {
		return nil, nil, "", errors.New("external OpenVPN is supported as a direct/final exit, but not yet as an upstream hop; refusing competing default-tunnel ownership")
	}
	endpoint, outbound, err := directStandardExitRuntimeParts(entry)
	if err != nil {
		return nil, nil, "", err
	}
	endpoints := []any{}
	outbounds := []any{}
	if endpoint != nil {
		endpoint["tag"] = "external-entry"
		endpoints = append(endpoints, endpoint)
	}
	if outbound != nil {
		outbound["tag"] = "external-entry"
		outbounds = append(outbounds, outbound)
	}
	if len(endpoints)+len(outbounds) != 1 {
		return nil, nil, "", errors.New("external entry must resolve to exactly one runtime hop")
	}
	return endpoints, outbounds, "external-entry", nil
}

func buildExternalEntryStandardExitConfig(control common.RouterProfile, entry, exit standardExit) (map[string]any, error) {
	entryEndpoints, entryOutbounds, entryTag, err := externalEntryGraph(entry)
	if err != nil {
		return nil, err
	}
	exitEndpoint, exitOutbound, err := standardExitRuntimeParts(exit, entryTag)
	if err != nil {
		return nil, err
	}
	// Neither hop is a Router VPN home, so Home AdGuard must not be fabricated
	// as reachable. The selected external-node DNS policy is forced through the
	// final custom exit just like a direct external-node connection.
	dnsServer, err := selectedStandardExitDNS(control, true)
	if err != nil {
		return nil, err
	}
	endpoints := append([]any{}, entryEndpoints...)
	outbounds := append([]any{}, entryOutbounds...)
	if exitEndpoint != nil {
		endpoints = append(endpoints, exitEndpoint)
	}
	if exitOutbound != nil {
		outbounds = append(outbounds, exitOutbound)
	}
	return standardExitConfig(control, dnsServer, endpoints, outbounds), nil
}

func prepareExternalEntryStandardExit(root string, control, entryProfile common.RouterProfile, exit standardExit) (string, string, error) {
	entry, err := standardExitFromExternalProfile(entryProfile)
	if err != nil {
		return "", "", err
	}
	cfg, err := buildExternalEntryStandardExitConfig(control, entry, exit)
	if err != nil {
		return "", "", err
	}
	return writeStandardExitRuntime(root, cfg)
}

func nativeExternalEntryStandardExitCommand(a *app, control, entry common.RouterProfile, exit standardExit) (*exec.Cmd, error) {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	entryExit, err := standardExitFromExternalProfile(entry)
	if err != nil {
		return nil, err
	}
	if entryExit.Protocol == "openvpn" {
		return nil, errors.New("external OpenVPN cannot currently be used as an upstream hop; use it as the final exit")
	}
	runtimeDir, tunAlias, err := prepareExternalEntryStandardExit(root, control, entry, exit)
	if err != nil {
		return nil, err
	}
	endpoint := entry.Endpoint
	if endpoint == "" {
		endpoint = entryExit.Server
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		helper := filepath.Join(root, "client", "native-multihop-windows.ps1")
		if _, err = os.Stat(helper); err != nil {
			helper = filepath.Join(filepath.Dir(a.cfg.ScriptsDir), "client", "native-multihop-windows.ps1")
		}
		if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
			return nil, errors.New("native Windows external-entry helper is missing")
		}
		cmd = exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper, "-Action", "up", "-RuntimeDir", runtimeDir, "-Endpoint", endpoint, "-TunnelAlias", tunAlias)
	case "darwin":
		helper := filepath.Join(root, "modes", "native-multihop-darwin.sh")
		if _, err = os.Stat(helper); err != nil {
			helper = filepath.Join(a.cfg.ScriptsDir, "native-multihop-darwin.sh")
		}
		if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
			return nil, errors.New("native macOS external-entry helper is missing")
		}
		cmd = exec.Command("bash", helper, "up", runtimeDir, endpoint, tunAlias)
	case "linux":
		helper := filepath.Join(root, "modes", "native-standard-exit-linux.sh")
		if _, err = os.Stat(helper); err != nil {
			helper = filepath.Join(a.cfg.ScriptsDir, "native-standard-exit-linux.sh")
		}
		if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
			return nil, errors.New("native Linux external-entry helper is missing")
		}
		cmd = exec.Command("bash", helper, "up", runtimeDir, endpoint, tunAlias)
	default:
		return nil, errors.New("external-node chaining is implemented on Windows, macOS and Linux only")
	}
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "HOMEVPN_ROOT="+root, "HOMEVPN_PROFILE_ID="+entry.ID, "HOMEVPN_POLICY_PROFILE_ID="+control.ID, "HOMEVPN_ENDPOINT="+endpoint)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

// externalEntryBridgeConfig creates a loopback-only proxy through an external
// entry. It is used when the final hop is native OpenVPN/TCP, whose socks-proxy
// option can consume this bridge without letting the entry own the OS default
// route.
func externalEntryBridgeConfig(entry standardExit, listenPort int) (map[string]any, error) {
	endpoints, outbounds, entryTag, err := externalEntryGraph(entry)
	if err != nil {
		return nil, err
	}
	final := entryTag
	if len(endpoints) == 1 && len(outbounds) == 0 {
		// A WireGuard endpoint is a dialer target rather than a route-final
		// outbound, so provide one narrow direct outbound detoured through it.
		final = "external-entry-egress"
		outbounds = append(outbounds, map[string]any{"type": "direct", "tag": final, "detour": entryTag})
	}
	return map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"inbounds": []any{map[string]any{"type": "mixed", "tag": "openvpn-entry-socks", "listen": "127.0.0.1", "listen_port": listenPort}},
		"endpoints": endpoints,
		"outbounds": outbounds,
		"route": map[string]any{"final": final, "auto_detect_interface": true},
	}, nil
}
