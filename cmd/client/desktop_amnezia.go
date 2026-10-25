package main

import (
	"encoding/json"
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Import validation can accept a bounded outer hostname while checking every
// actual AWG parameter and peer field. This disposable address is never saved
// or executed; only the captured bootstrap path may produce a runnable literal
// endpoint, and desktopAmneziaEndpoint still rejects unresolved hostnames.
func validateDesktopAmneziaProfile(e standardExit) error {
	if net.ParseIP(e.Server) == nil {
		if !applexray.ValidNodeHostname(e.Server) {
			return errors.New("AmneziaWG outer hostname is invalid")
		}
		e.Server = "192.0.2.254"
	}
	_, err := desktopAmneziaEndpoint(e, "")
	return err
}

// An imported AWG policy contains the peer's actual obfuscation parameters.
// Never infer Fast/Strong, strip them, or route this through the stock WG core.
func desktopAmneziaEndpoint(e standardExit, detour string) (map[string]any, error) {
	mtu := e.WGMTU
	if mtu == 0 {
		mtu = 1280
	}
	peer := map[string]any{"address": e.Server, "port": e.ServerPort, "public_key": e.WGPeerPublicKey, "allowed_ips": append([]string(nil), e.WGAllowedIPs...), "persistent_keepalive_interval": e.WGKeepalive}
	if e.WGPreSharedKey != "" {
		peer["pre_shared_key"] = e.WGPreSharedKey
	}
	endpoint := map[string]any{"type": mobilemultihop.AmneziaType, "tag": "custom-exit", "system": false, "mtu": mtu, "address": append([]string(nil), e.WGAddresses...), "private_key": e.WGPrivateKey, "peers": []any{peer}, "amnezia": maps.Clone(e.AWGParameters)}
	if detour != "" {
		endpoint["detour"] = detour
	}
	encoded, err := json.Marshal(endpoint)
	if err != nil {
		return nil, err
	}
	if _, err := mobilemultihop.AmneziaRuntimeConfig(string(encoded)); err != nil {
		return nil, err
	}
	return endpoint, nil
}

// Capture the complete external peer independently of the control profile's
// selected DNS/device policy. Legacy standard exits and unified nodes share
// this native compiler; neither may substitute a standard WireGuard endpoint.
func desktopExternalCapture(control common.RouterProfile, e standardExit) (common.RouterProfile, error) {
	if err := validateStandardExit(&e); err != nil {
		return common.RouterProfile{}, err
	}
	return desktopExternalCaptureUnchecked(control, e)
}

func desktopExternalCaptureUnchecked(control common.RouterProfile, e standardExit) (common.RouterProfile, error) {
	profile := control
	profile.ID, profile.Name, profile.NodeKind, profile.Endpoint = e.ID, e.Name, "external", e.Server
	profile.External = &common.ExternalNodeConfig{Protocol: e.Protocol, ExpectedPublicIP: e.ExpectedPublicIP, ResponseProbe: e.ResponseProbe, StartLayer: e.StartLayer}
	profile.StartLayer = common.StartLayerOff
	if e.StartLayer != nil {
		profile.StartLayer = e.StartLayer.Mode
	}
	wireGuard := common.ExternalWireGuardConfig{PrivateKey: e.WGPrivateKey, Addresses: append([]string(nil), e.WGAddresses...), PeerPublicKey: e.WGPeerPublicKey, PresharedKey: e.WGPreSharedKey, Endpoint: net.JoinHostPort(e.Server, strconv.Itoa(e.ServerPort)), AllowedIPs: append([]string(nil), e.WGAllowedIPs...), MTU: e.WGMTU, PersistentKeepalive: e.WGKeepalive}
	switch e.Protocol {
	case "amneziawg":
		profile.External.AmneziaWG = &common.ExternalAmneziaWGConfig{ExternalWireGuardConfig: wireGuard, Parameters: maps.Clone(e.AWGParameters)}
	case "wireguard":
		profile.External.WireGuard = &wireGuard
	case "socks5":
		profile.External.SOCKS5 = &common.ExternalSOCKS5Config{Host: e.Server, Port: e.ServerPort, Username: e.Username, Password: e.Password}
	case "http-connect":
		profile.External.HTTPConnect = &common.ExternalHTTPConnectConfig{Host: e.Server, Port: e.ServerPort, Username: e.Username, Password: e.Password}
	case "https-connect":
		profile.External.HTTPSConnect = &common.ExternalHTTPConnectConfig{Host: e.Server, Port: e.ServerPort, Username: e.Username, Password: e.Password, TLSServerName: e.TLSServerName}
	case "shadowsocks":
		profile.External.Shadowsocks = &common.ExternalShadowsocksConfig{Server: e.Server, Port: e.ServerPort, Method: e.Method, Password: e.Secret}
	case "hysteria2":
		profile.External.Hysteria2 = &common.ExternalHysteria2Config{Server: e.Server, Port: e.ServerPort, Password: e.Secret, TLSServerName: e.TLSServerName}
	case "openvpn":
		profile.External.OpenVPN = &common.ExternalOpenVPNConfig{Config: e.OpenVPNConfig, Username: e.Username, Password: e.Password}
	default:
		return common.RouterProfile{}, errors.New("desktop external policy requires a native ordinary graph")
	}
	return cloneRouterProfile(profile), nil
}

func compileDesktopAmneziaPolicy(graph map[string]any, control common.RouterProfile, entry *common.RouterProfile, exit standardExit) (map[string]any, error) {
	if exit.Protocol != "amneziawg" && exit.StartLayer == nil && (entry == nil || entry.External == nil || entry.External.Protocol != "amneziawg" && entry.External.StartLayer == nil) {
		return graph, nil
	}
	profile, err := desktopExternalCapture(control, exit)
	if err != nil {
		return nil, err
	}
	capture := map[string]any{"schema": 1, "exit_id": exit.ID, "protocol": exit.Protocol, "expected_public_ip": exit.ExpectedPublicIP, "profile": profile}
	if entry != nil {
		capture["entry"] = *entry
		capture["entry_tag"] = "entry-wg"
		if entry.NodeKind == "external" {
			capture["entry_tag"] = "external-entry"
		}
	}
	// Cached effective_mtu is historical. The source starts at the safe
	// dual-stack default and the shared compiler applies only saved Fixed
	// policy and captured per-hop bounds, including native AWG S4 padding.
	for _, raw := range graph["inbounds"].([]any) {
		if in := raw.(map[string]any); in["type"] == "tun" {
			in["mtu"] = 1280
		}
	}
	configJSON, err := json.Marshal(graph)
	if err != nil {
		return nil, err
	}
	captureJSON, err := json.Marshal(capture)
	if err != nil {
		return nil, err
	}
	compiled, err := mobilemultihop.NewExternalPolicy(string(configJSON), string(captureJSON))
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(compiled.Config()), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func desktopStandardEngineEnvironment(environment []string, amnezia bool) []string {
	engine := "stock"
	if amnezia {
		engine = "amnezia"
	}
	return desktopSelectedStandardEngineEnvironment(environment, engine)
}

func desktopExternalEngineEnvironment(environment []string, native, amnezia bool) []string {
	if native {
		return desktopSelectedStandardEngineEnvironment(environment, "native")
	}
	return desktopStandardEngineEnvironment(environment, amnezia)
}

func desktopSelectedStandardEngineEnvironment(environment []string, engine string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, value := range environment {
		upper := strings.ToUpper(value)
		if !strings.HasPrefix(upper, "HOMEVPN_STANDARD_ENGINE=") && !strings.HasPrefix(upper, "HOMEVPN_AMNEZIA_CONTROLLER=") && !strings.HasPrefix(upper, "HOMEVPN_AMNEZIA_PACKAGE=") && !strings.HasPrefix(upper, "HOMEVPN_NATIVE_CONTROLLER=") && !strings.HasPrefix(upper, "HOMEVPN_NATIVE_PACKAGE=") && !strings.HasPrefix(upper, "HOMEVPN_EXTERNAL_SESSION=") && !strings.HasPrefix(upper, "HOMEVPN_NATIVE_ENDPOINTS_JSON=") {
			result = append(result, value)
		}
	}
	result = append(result, "HOMEVPN_STANDARD_ENGINE="+engine)
	if engine == "amnezia" {
		executable, err := os.Executable()
		if err == nil {
			result = append(result, "HOMEVPN_AMNEZIA_CONTROLLER="+executable, "HOMEVPN_AMNEZIA_PACKAGE="+desktopAmneziaPackageRoot())
		}
	}
	if engine == "native" {
		executable, err := os.Executable()
		if err == nil {
			root := desktopAmneziaPackageRoot()
			result = append(result, "HOMEVPN_NATIVE_CONTROLLER="+executable, "HOMEVPN_NATIVE_PACKAGE="+root)
			result = nativeLibraryEnvironment(result, filepath.Join(root, "runtime", "native"))
		}
	}
	return result
}
