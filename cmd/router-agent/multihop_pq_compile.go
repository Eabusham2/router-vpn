package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"router-vpn/internal/mobilemultihop"
)

const maxPQPairingBytes = 12 << 20

// Compile captured assets as data with the shipping mobile compiler. This
// command opens no files, sockets, native protocol handles or VPN interfaces.
func compilePQRelayProfile(input io.Reader, output io.Writer, mode, node, server string) error {
	bad := errors.New("invalid captured PQ relay profile")
	address, err := netip.ParseAddr(server)
	if !mobilemultihop.IsPQMode(mode) || !validNodeID(node) || err != nil || address.String() != server || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return bad
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxPQPairingBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxPQPairingBytes {
		return bad
	}
	defer clear(raw)
	var assets map[string]string
	if json.Unmarshal(raw, &assets) != nil {
		return bad
	}
	allowed := map[string]bool{"rosenpass.env": true, "rosenpass.toml": true, "rosenpass-client-secret": true, "rosenpass-client-public": true, "rosenpass-server-public": true, "stack.json": true}
	if mode == "wg-pq" {
		allowed["wg.conf"] = true
	} else {
		allowed["awg.conf"] = true
	}
	for name := range assets {
		if !allowed[name] {
			return bad
		}
	}
	// The compiler also rejects duplicate JSON members, unbound peer keys,
	// unknown env/TOML directives, changed modes and missing secret material.
	compiled, err := mobilemultihop.CompilePQProfile(mode, string(raw), node)
	if err != nil {
		return bad
	}
	var graph struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if json.Unmarshal([]byte(compiled), &graph) != nil || len(graph.Endpoints) != 1 {
		return bad
	}
	endpoint := graph.Endpoints[0]
	serialized, err := json.Marshal(endpoint)
	if err != nil {
		return bad
	}
	defer clear(serialized)
	runtime, err := mobilemultihop.PQRuntimeConfig(string(serialized))
	if err != nil {
		return bad
	}
	defer runtime.PQ.Erase()
	pqEndpoint, err := netip.ParseAddrPort(runtime.PQ.Endpoint)
	if err != nil || pqEndpoint.Addr() != address || runtime.Mode != mode || endpoint["node_id"] != node || endpoint["tag"] != "proxy" {
		return bad
	}
	if value, ok := endpoint["system"]; ok && value != false {
		return bad
	}
	if value, ok := endpoint["listen_port"]; ok && value != float64(0) {
		return bad
	}
	if _, ok := endpoint["detour"]; ok {
		return bad
	}
	// Server transport records have no OS-interface owner or fixed local port.
	// These were checked false/zero, not silently discarded from an import.
	delete(endpoint, "system")
	delete(endpoint, "listen_port")
	endpoint["tag"] = "exit"
	result, err := json.Marshal(endpoint)
	if err != nil || len(result) > maxPQPairingBytes {
		return bad
	}
	defer clear(result)
	n, err := output.Write(result)
	if err == nil && n != len(result) {
		return io.ErrShortWrite
	}
	return err
}
