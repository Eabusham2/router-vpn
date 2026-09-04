package main

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"router-vpn/internal/common"
)

// standardExitFromExternalProfile is the single translation boundary between
// the unified node/profile model and the existing standard-exit dataplane. It
// intentionally re-runs both profile normalization and standard-exit runtime
// validation so imported external-node data cannot bypass either contract.
// Tor is the only dynamic-exit exception: its profile is fully normalized here,
// but fixed expected-public-IP validation is intentionally replaced later by
// Tor Project IsTor + observed-exit proof on the running circuit.
func standardExitFromExternalProfile(profile common.RouterProfile) (standardExit, error) {
	if err := common.NormalizeRouterProfile(&profile); err != nil { return standardExit{}, err }
	if profile.NodeKind != "external" || profile.External == nil { return standardExit{}, errors.New("profile is not an external custom node") }
	ext := profile.External
	exit := standardExit{ID: profile.ID, Name: profile.Name, Protocol: ext.Protocol, ExpectedPublicIP: ext.ExpectedPublicIP}

	switch ext.Protocol {
	case "wireguard":
		w := ext.WireGuard
		if w == nil { return standardExit{}, errors.New("external WireGuard block is missing") }
		host, port, err := splitExternalEndpoint(w.Endpoint, 51820); if err != nil { return standardExit{}, err }
		exit.Server, exit.ServerPort = host, port
		exit.WGAddresses = append([]string(nil), w.Addresses...)
		exit.WGPrivateKey = w.PrivateKey
		exit.WGPeerPublicKey = w.PeerPublicKey
		exit.WGPreSharedKey = w.PresharedKey
		exit.WGAllowedIPs = append([]string(nil), w.AllowedIPs...)
		exit.WGMTU = w.MTU
	case "openvpn":
		o := ext.OpenVPN
		if o == nil { return standardExit{}, errors.New("external OpenVPN block is missing") }
		exit.OpenVPNConfig = o.Config; exit.Username = o.Username; exit.Password = o.Password
		// validateStandardExit calls normalizeOpenVPNStandardExit, which derives
		// and sanitizes the one allowed remote endpoint from this untrusted text.
	case "shadowsocks":
		s := ext.Shadowsocks
		if s == nil { return standardExit{}, errors.New("external Shadowsocks block is missing") }
		exit.Server, exit.ServerPort, exit.Method, exit.Secret = s.Server, s.Port, s.Method, s.Password
	case "socks5":
		s := ext.SOCKS5
		if s == nil { return standardExit{}, errors.New("external SOCKS5 block is missing") }
		exit.Server, exit.ServerPort, exit.Username, exit.Password = s.Host, s.Port, s.Username, s.Password
	case "hysteria2":
		h := ext.Hysteria2
		if h == nil { return standardExit{}, errors.New("external Hysteria2 block is missing") }
		exit.Server, exit.ServerPort, exit.Secret, exit.TLSServerName = h.Server, h.Port, h.Password, h.TLSServerName
	case "tor-bridge":
		if ext.TorBridge == nil { return standardExit{}, errors.New("external Tor bridge block is missing") }
		if ext.ExpectedPublicIP != "" { return standardExit{}, errors.New("Tor bridge cannot carry a fixed expected public exit IP") }
		if strings.TrimSpace(profile.Endpoint) == "" { return standardExit{}, errors.New("Tor bridge profile has no validated physical bridge relay endpoint") }
		exit.Server = profile.Endpoint
		return exit, nil
	default:
		return standardExit{}, errors.New("external profile protocol has no standard-exit adapter")
	}
	if err := validateStandardExit(&exit); err != nil { return standardExit{}, err }
	return exit, nil
}

func splitExternalEndpoint(value string, defaultPort int) (string, int, error) {
	value = strings.TrimSpace(value)
	if value == "" { return "", 0, errors.New("external endpoint is empty") }
	if host, portText, err := net.SplitHostPort(value); err == nil {
		port, convErr := strconv.Atoi(portText)
		if convErr != nil || port < 1 || port > 65535 { return "", 0, errors.New("external endpoint port is invalid") }
		return strings.Trim(host, "[]"), port, nil
	}
	// An unbracketed IPv6 literal cannot safely carry an optional port here.
	// Treat a bare literal as the host and apply the protocol default.
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil { return ip.String(), defaultPort, nil }
	if strings.Count(value, ":") == 1 {
		parts := strings.SplitN(value, ":", 2)
		port, err := strconv.Atoi(parts[1]); if err != nil || port < 1 || port > 65535 { return "", 0, errors.New("external endpoint port is invalid") }
		if strings.TrimSpace(parts[0]) == "" { return "", 0, errors.New("external endpoint host is empty") }
		return strings.TrimSpace(parts[0]), port, nil
	}
	return value, defaultPort, nil
}
