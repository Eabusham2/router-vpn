package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"router-vpn/internal/mobilemultihop"
)

// The Windows helper receives the compiled physical tuple set, never a fresh
// profile lookup. Keep its immutable encoding after staging clears the graph,
// because multihop then replaces the environment with ENTRY/CONTROL ownership.
type desktopNodePhysicalCapture struct {
	session, configSHA256, primary, endpointsJSON, egressJSON string
}

func captureDesktopNodePhysical(launch *desktopNodeLaunch) (*desktopNodePhysicalCapture, error) {
	failure := errors.New("native Router firewall capture lost its exact graph, session or physical tuples")
	if launch == nil || launch.external != nil || launch.tor != nil || len(launch.config) == 0 ||
		len(launch.mtuSession) != 32 || strings.Trim(launch.mtuSession, "0123456789abcdef") != "" {
		return nil, failure
	}
	digest := sha256.Sum256(launch.config)
	var receipt struct {
		ConfigSHA256 string                          `json:"config_sha256"`
		Physical     []mobilemultihop.PhysicalEgress `json:"physical_egress"`
	}
	if json.Unmarshal(launch.metadata, &receipt) != nil || receipt.ConfigSHA256 != hex.EncodeToString(digest[:]) ||
		launch.configSHA256 != receipt.ConfigSHA256 || len(receipt.Physical) < 1 || len(receipt.Physical) > 16 ||
		!slices.Equal(receipt.Physical, launch.nodePhysicalEgress) {
		return nil, failure
	}
	hosts, seenHosts := []string{}, map[string]bool{}
	seenTuples := map[mobilemultihop.PhysicalEgress]bool{}
	for _, tuple := range receipt.Physical {
		address, err := netip.ParseAddr(tuple.Host)
		if err != nil || !address.IsGlobalUnicast() || address.IsLoopback() || address.Is4In6() ||
			address.Zone() != "" || address.String() != tuple.Host || tuple.Port < 1 || tuple.Port > 65535 ||
			tuple.Network != "tcp" && tuple.Network != "udp" || seenTuples[tuple] {
			return nil, failure
		}
		seenTuples[tuple] = true
		if !seenHosts[tuple.Host] {
			seenHosts[tuple.Host] = true
			hosts = append(hosts, tuple.Host)
		}
	}
	// A Start Layer may physically terminate somewhere other than the saved
	// node endpoint. Do not turn that logical endpoint into an extra exception.
	// Prefer it only when the actual compiler also captured that address.
	if selected := slices.Index(hosts, launch.endpoint); selected > 0 {
		hosts[0], hosts[selected] = hosts[selected], hosts[0]
	}
	endpoints, err := json.Marshal(hosts)
	if err != nil {
		return nil, err
	}
	egress, err := json.Marshal(receipt.Physical)
	if err != nil {
		return nil, err
	}
	return &desktopNodePhysicalCapture{
		session: launch.mtuSession, configSHA256: receipt.ConfigSHA256,
		primary: hosts[0], endpointsJSON: string(endpoints), egressJSON: string(egress),
	}, nil
}

func desktopNodePhysicalEnvironment(environment []string, launch *desktopNodeLaunch) ([]string, error) {
	if launch == nil || launch.external != nil || launch.tor != nil || launch.nodePhysicalCapture == nil {
		return nil, errors.New("native Router firewall environment has no captured owner")
	}
	capture := launch.nodePhysicalCapture
	if len(capture.session) != 32 || len(capture.configSHA256) != 64 || capture.primary == "" ||
		capture.session != launch.mtuSession || capture.configSHA256 != launch.configSHA256 {
		return nil, errors.New("native Router firewall environment belongs to another session or graph")
	}
	clean := make([]string, 0, len(environment)+6)
	for _, value := range environment {
		name, _, _ := strings.Cut(value, "=")
		switch strings.ToUpper(name) {
		case "HOMEVPN_STANDARD_ENGINE", "HOMEVPN_ENDPOINT", "HOMEVPN_EXTERNAL_SESSION",
			"HOMEVPN_NODE_SESSION", "HOMEVPN_NODE_CONFIG_SHA256",
			"HOMEVPN_NATIVE_ENDPOINTS_JSON", "HOMEVPN_NATIVE_EGRESS_JSON":
			continue
		}
		clean = append(clean, value)
	}
	return append(clean, "HOMEVPN_STANDARD_ENGINE=native", "HOMEVPN_ENDPOINT="+capture.primary,
		"HOMEVPN_NODE_SESSION="+capture.session, "HOMEVPN_NODE_CONFIG_SHA256="+capture.configSHA256,
		"HOMEVPN_NATIVE_ENDPOINTS_JSON="+capture.endpointsJSON, "HOMEVPN_NATIVE_EGRESS_JSON="+capture.egressJSON), nil
}
