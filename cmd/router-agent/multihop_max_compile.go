package main

import (
	"encoding/json"
	"errors"
	"io"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

const maxMAXPairingBytes = 16 << 20

// Compile the exact captured PQ base, SS2022 middle and TLS/QUIC outer as data.
// Secrets are read only from bounded stdin. Pairing cannot execute a helper,
// create a protocol owner or start an interface, route, listener or service.
func compileMAXRelayProfile(input io.Reader, output io.Writer, mode, node, server, api string) error {
	bad := errors.New("invalid complete captured MAX relay profile")
	if !multihoprelay.CompleteMAXMode(mode) || !validNodeID(node) {
		return bad
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxMAXPairingBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxMAXPairingBytes {
		return bad
	}
	defer clear(raw)
	metadata, err := json.Marshal(map[string]string{"node_id": node, "node_kind": "router-vpn", "endpoint": server, "router_api": api, "start_layer": "off"})
	if err != nil {
		return bad
	}
	compiled, err := mobilemultihop.CompileMAXProfile(mode, string(raw), string(metadata))
	if err != nil || len(compiled) == 0 || len(compiled) > 4<<20 {
		return bad
	}
	var graph struct {
		Endpoints []map[string]any `json:"endpoints"`
		Outbounds []any            `json:"outbounds"`
	}
	if json.Unmarshal([]byte(compiled), &graph) != nil || len(graph.Endpoints) != 1 || len(graph.Outbounds) != 2 {
		return bad
	}
	tags := multihoprelay.MAXTags{Root: "proxy", Middle: mobilemultihop.MAXShadowsocksTag, Outer: mobilemultihop.MAXOuterTag, Start: mobilemultihop.MAXStartLayerTag}
	plan, err := multihoprelay.PairMAXChain(graph.Endpoints[0], graph.Outbounds, mode, node, tags)
	if err != nil {
		return bad
	}
	encoded := append(plan, '\n')
	defer clear(encoded)
	n, err := output.Write(encoded)
	if err == nil && n != len(encoded) {
		return io.ErrShortWrite
	}
	return err
}
