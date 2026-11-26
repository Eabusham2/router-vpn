package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"router-vpn/internal/common"
)

func (a *app) standardExitStopFailure(cmd *exec.Cmd, cause string) (string, bool) {
	if cleanupErr := a.stopOwnedConnectionRuntime(cmd); cleanupErr != nil {
		return cause + "; runtime cleanup failed: " + cleanupErr.Error(), true
	}
	return cause, false
}

type standardExitConnectRequest struct {
	EntryID        string `json:"entry_id"`
	StandardExitID string `json:"standard_exit_id"`
	Base           string `json:"base"`
	Direct         bool   `json:"direct"`
}

func selectedStandardExitDNS(control common.RouterProfile, direct bool) (map[string]any, error) {
	mode := strings.ToLower(strings.TrimSpace(control.DNSMode))
	protocol := strings.ToLower(strings.TrimSpace(control.DNSProtocol))
	host := strings.TrimSpace(control.DNSHost)
	port := control.DNSPort
	serverName := strings.TrimSpace(control.DNSServerName)
	path := strings.TrimSpace(control.DNSPath)
	detour := "custom-exit"
	if path == "" {
		path = "/dns-query"
	}
	switch mode {
	case "", "home":
		if direct {
			return nil, errors.New("Home AdGuard DNS requires a Router VPN entry; choose Fastest, Custom, DoH, DoT, DoH3 or Rescue for a direct external node")
		}
		if host == "" {
			host = strings.TrimSpace(control.AdGuardIPv4)
		}
		if host == "" {
			host = strings.TrimSpace(control.AdGuardIPv6)
		}
		if protocol == "" {
			protocol = "udp"
		}
		if port == 0 {
			port = 53
		}
		detour = "entry-wg"
	case "fastest":
		host = strings.TrimSpace(control.FastestDNSHost)
		protocol = "udp"
		port = 53
		serverName = ""
	case "doh":
		protocol = "https"
		if port == 0 {
			port = 443
		}
	case "dot":
		protocol = "tls"
		if port == 0 {
			port = 853
		}
	case "doh3":
		protocol = "h3"
		if port == 0 {
			port = 443
		}
	case "rescue":
		protocol = "https"
		if port == 0 {
			port = 443
		}
		if host == "" {
			host = "1.1.1.1"
		}
		if serverName == "" {
			serverName = "cloudflare-dns.com"
		}
	case "custom":
	default:
		return nil, fmt.Errorf("unsupported DNS mode %q for standard exit", mode)
	}
	if host == "" {
		return nil, errors.New("selected DNS policy has no resolver address; configure or measure the selected resolver before connecting")
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) == nil {
		return nil, errors.New("custom standard exit currently requires a literal DNS server address so DNS cannot escape through an implicit system resolver")
	}
	if port == 0 {
		port = 53
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("selected DNS port is invalid")
	}
	switch protocol {
	case "udp", "tcp":
	case "tls", "https", "h3":
		if serverName == "" {
			return nil, errors.New("selected encrypted DNS requires a TLS server name")
		}
	default:
		return nil, fmt.Errorf("unsupported DNS protocol %q for standard exit", protocol)
	}
	server := map[string]any{"type": protocol, "tag": "selected-dns", "server": host, "server_port": port, "detour": detour}
	if protocol == "tls" || protocol == "https" || protocol == "h3" {
		server["tls"] = map[string]any{"enabled": true, "server_name": serverName}
		if protocol == "https" || protocol == "h3" {
			server["path"] = path
		}
	}
	return server, nil
}

func buildNativeStandardExitConfig(control common.RouterProfile, entryWG nativeWG, exit standardExit) (map[string]any, error) {
	endpoint, outbound, err := standardExitRuntimeParts(exit, "entry-wg")
	if err != nil {
		return nil, err
	}
	dnsServer, err := selectedStandardExitDNS(control, false)
	if err != nil {
		return nil, err
	}
	endpoints := []any{nativeWGEndpoint(entryWG)}
	if endpoint != nil {
		endpoints = append(endpoints, endpoint)
	}
	outbounds := []any{}
	if outbound != nil {
		outbounds = append(outbounds, outbound)
	}
	return standardExitConfig(control, dnsServer, endpoints, outbounds), nil
}

func directStandardExitRuntimeParts(e standardExit) (map[string]any, map[string]any, error) {
	if err := validateStandardExit(&e); err != nil {
		return nil, nil, err
	}
	if e.Protocol == "openvpn" {
		endpoint, err := desktopOpenVPNEndpoint(e, "")
		return endpoint, nil, err
	}
	if e.Protocol == "amneziawg" {
		endpoint, err := desktopAmneziaEndpoint(e, "")
		return endpoint, nil, err
	}
	if e.Protocol == "wireguard" {
		peer := map[string]any{"address": e.Server, "port": e.ServerPort, "public_key": e.WGPeerPublicKey, "allowed_ips": e.WGAllowedIPs, "persistent_keepalive_interval": e.WGKeepalive}
		if e.WGPreSharedKey != "" {
			peer["pre_shared_key"] = e.WGPreSharedKey
		}
		endpoint := map[string]any{"type": "wireguard", "tag": "custom-exit", "address": e.WGAddresses, "private_key": e.WGPrivateKey, "peers": []any{peer}}
		if e.WGMTU != 0 {
			endpoint["mtu"] = e.WGMTU
		}
		return endpoint, nil, nil
	}
	out := map[string]any{"tag": "custom-exit", "server": e.Server, "server_port": e.ServerPort}
	switch e.Protocol {
	case "socks5":
		out["type"] = "socks"
		out["version"] = "5"
		if e.Username != "" {
			out["username"] = e.Username
			out["password"] = e.Password
		}
	case "http-connect", "https-connect":
		out["type"] = "http"
		if e.Username != "" {
			out["username"] = e.Username
			out["password"] = e.Password
		}
		if e.Protocol == "https-connect" {
			out["tls"] = map[string]any{"enabled": true, "server_name": e.TLSServerName}
		}
	case "shadowsocks":
		out["type"] = "shadowsocks"
		out["method"] = e.Method
		out["password"] = e.Secret
	case "hysteria2":
		out["type"] = "hysteria2"
		out["password"] = e.Secret
		out["tls"] = map[string]any{"enabled": true, "server_name": e.TLSServerName}
	default:
		return nil, nil, fmt.Errorf("unsupported direct standard-node protocol %q", e.Protocol)
	}
	return nil, out, nil
}

func buildDirectStandardExitConfig(control common.RouterProfile, exit standardExit) (map[string]any, error) {
	endpoint, outbound, err := directStandardExitRuntimeParts(exit)
	if err != nil {
		return nil, err
	}
	dnsServer, err := selectedStandardExitDNS(control, true)
	if err != nil {
		return nil, err
	}
	endpoints := []any{}
	outbounds := []any{}
	if endpoint != nil {
		endpoints = append(endpoints, endpoint)
	}
	if outbound != nil {
		outbounds = append(outbounds, outbound)
	}
	return standardExitConfig(control, dnsServer, endpoints, outbounds), nil
}

func standardExitConfig(_ common.RouterProfile, dnsServer map[string]any, endpoints, outbounds []any) map[string]any {
	// This is only the transport seed. The shared captured-policy compiler
	// applies Fixed/Jumbo and per-hop bounds before a runnable file is written.
	// A saved effective value is not a measurement of this new path.
	return map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"dns": map[string]any{"servers": []any{dnsServer}, "final": "selected-dns"},
		"inbounds": []any{
			map[string]any{"type": "tun", "tag": "tun-in", "interface_name": "router-vpn", "address": []any{"172.29.91.1/30", "fd29:91::1/126"}, "mtu": 1280, "auto_route": true, "strict_route": true, "stack": "system"},
			map[string]any{"type": "mixed", "tag": "standard-exit-proof", "listen": "127.0.0.1", "listen_port": 1099},
		},
		"endpoints": endpoints, "outbounds": outbounds,
		"route": map[string]any{"rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}, "final": "custom-exit", "auto_detect_interface": true},
	}
}

func writeStandardExitRuntime(root string, cfg map[string]any) (string, string, error) {
	runtimeDir, err := newPrivateRuntimeDir(root, "native-standard-exit")
	if err != nil {
		return "", "", err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		_ = os.RemoveAll(runtimeDir)
		return "", "", err
	}
	if len(raw) > 4<<20 {
		_ = os.RemoveAll(runtimeDir)
		return "", "", errors.New("prepared standard exit config exceeds safety limit")
	}
	if err = writePrivateRuntimeFile(filepath.Join(runtimeDir, "sing-box.json"), append(raw, '\n')); err != nil {
		_ = os.RemoveAll(runtimeDir)
		return "", "", err
	}
	return runtimeDir, "router-vpn", nil
}

func nativeStandardExitCommand(a *app, control, entry common.RouterProfile, exit standardExit, direct bool) (*exec.Cmd, error) {
	return nativeStandardExitCommandWithBootstrap(a, control, entry, exit, direct, standardExitSystemBootstrap())
}

func nativeStandardExitCommandWithBootstrap(a *app, control, entry common.RouterProfile, exit standardExit, direct bool, bootstrap standardExitBootstrap) (*exec.Cmd, error) {
	return nativeStandardExitCommandContext(a.connectionOperationContextOrBackground(), a, control, entry, exit, direct, bootstrap)
}

func nativeStandardExitCommandContext(operation context.Context, a *app, control, entry common.RouterProfile, exit standardExit, direct bool, bootstrap standardExitBootstrap) (*exec.Cmd, error) {
	return nativeStandardExitCommandOwnedContext(operation, a, control, entry, exit, direct, bootstrap, nil)
}

func nativeStandardExitCommandOwnedContext(operation context.Context, a *app, control, entry common.RouterProfile, exit standardExit, direct bool, bootstrap standardExitBootstrap, owner **desktopNodeLaunch) (_ *exec.Cmd, failure error) {
	if desktopTorProtocol(exit.Protocol) {
		// The fixed-exit store excludes Tor. External Connect and Speed Lab
		// dispatch it to the owned adapter with dynamic Tor proof before reaching
		// this builder; a generic command must never discard its workspace owner.
		return nil, errors.New("Tor bridge requires its owned external connection adapter")
	}
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	useNative := exit.StartLayer != nil
	if useNative {
		if _, err := verifyBundledNative(desktopAmneziaPackageRoot()); err != nil {
			return nil, err
		}
	} else if exit.Protocol == "amneziawg" {
		if _, err := verifyBundledAmnezia(desktopAmneziaPackageRoot()); err != nil {
			return nil, err
		}
	}
	prepared, err := prepareCapturedStandardExit(operation, root, control, entry, exit, direct, bootstrap)
	if err != nil {
		return nil, err
	}
	workspace := &desktopNodeLaunch{}
	if err := captureDesktopRuntimeDirectory(workspace, prepared.directory); err != nil {
		return nil, err
	}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, cleanupDesktopNodeLaunch(workspace))
		} else if owner != nil {
			*owner = workspace
		} else {
			_ = workspace.directoryRoot.Close()
		}
	}()
	runtimeDir, tunAlias, endpoint := prepared.directory, prepared.alias, prepared.endpoint
	var runtimeProfileID string
	if direct {
		runtimeProfileID = control.ID
	} else {
		runtimeProfileID = entry.ID
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		helper := filepath.Join(root, "client", "native-multihop-windows.ps1")
		if _, err = os.Stat(helper); err != nil {
			helper = filepath.Join(filepath.Dir(a.cfg.ScriptsDir), "client", "native-multihop-windows.ps1")
		}
		if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
			return nil, errors.New("native Windows standard-exit helper is missing")
		}
		cmd = exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper, "-Action", "up", "-RuntimeDir", runtimeDir, "-Endpoint", endpoint, "-TunnelAlias", tunAlias)
	case "darwin":
		helper := filepath.Join(root, "modes", "native-multihop-darwin.sh")
		if _, err = os.Stat(helper); err != nil {
			helper = filepath.Join(a.cfg.ScriptsDir, "native-multihop-darwin.sh")
		}
		if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
			return nil, errors.New("native macOS standard-exit helper is missing")
		}
		cmd = exec.Command("bash", helper, "up", runtimeDir, endpoint, tunAlias)
	case "linux":
		helper := filepath.Join(root, "modes", "native-standard-exit-linux.sh")
		if _, err = os.Stat(helper); err != nil {
			helper = filepath.Join(a.cfg.ScriptsDir, "native-standard-exit-linux.sh")
		}
		if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
			return nil, errors.New("native Linux standard-exit helper is missing")
		}
		cmd = exec.Command("bash", helper, "up", runtimeDir, endpoint, tunAlias)
	default:
		return nil, errors.New("native standard exit runtime is implemented on Windows, macOS and Linux only")
	}
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "HOMEVPN_ROOT="+root, "HOMEVPN_PROFILE_ID="+runtimeProfileID, "HOMEVPN_POLICY_PROFILE_ID="+control.ID, "HOMEVPN_ENDPOINT="+endpoint)
	cmd.Env = desktopExternalEngineEnvironment(cmd.Env, useNative, exit.Protocol == "amneziawg")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}
