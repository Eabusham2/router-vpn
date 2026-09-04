package main

import (
	"errors"
	"fmt"
	"strings"

	"router-vpn/internal/common"
)

// Tor exposes a TCP SOCKS circuit. DNS transported through the full-device
// sing-box graph must therefore be connect-oriented too; UDP and QUIC cannot be
// silently relabeled as working through Tor's SOCKS port.
func selectedTorBridgeDNS(policy common.RouterProfile) (map[string]any, error) {
	server, err := selectedStandardExitDNS(policy, true)
	if err != nil {
		return nil, err
	}
	typeName, _ := server["type"].(string)
	typeName = strings.ToLower(strings.TrimSpace(typeName))
	switch typeName {
	case "tcp", "tls", "https":
		return server, nil
	case "udp":
		return nil, errors.New("Tor bridge DNS cannot use UDP/Fastest-UDP through Tor SOCKS; choose Custom TCP, DoT, DoH, or Rescue")
	case "h3":
		return nil, errors.New("Tor bridge DNS cannot use DoH3/QUIC through Tor SOCKS; choose DoH/HTTPS, DoT, Custom TCP, or Rescue")
	default:
		return nil, fmt.Errorf("Tor bridge DNS transport %q is not supported through the Tor SOCKS circuit", typeName)
	}
}
