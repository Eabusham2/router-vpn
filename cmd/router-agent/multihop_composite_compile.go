package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"strconv"

	"router-vpn/internal/nativecomposite"
)

// Compile both transports from captured bundle assets through the same pure
// compiler as the mobile hosts. Private source arrives only on bounded stdin;
// the output is an operator-private plan, never a runnable single-lane proxy.
func compileCompositeRelayProfile(input io.Reader, output io.Writer, mode, node, endpoint, api string) error {
	bad := errors.New("invalid captured composite relay profile")
	server, err := netip.ParseAddr(endpoint)
	if err != nil || !nativecomposite.Mode(mode) || server.Zone() != "" || server.Is4In6() || server.IsLoopback() || server.IsUnspecified() || server.IsMulticast() || server.IsLinkLocalUnicast() {
		return bad
	}
	address, err := url.Parse(api)
	if err != nil || address == nil || (address.Scheme != "http" && address.Scheme != "https") || address.User != nil || address.RawPath != "" || address.RawQuery != "" || address.Fragment != "" || address.Path != "" && address.Path != "/" {
		return bad
	}
	private, err := netip.ParseAddr(address.Hostname())
	if err != nil || private.Zone() != "" || private.Is4In6() || !private.IsPrivate() || private.IsUnspecified() || private.IsLoopback() || private.IsLinkLocalUnicast() {
		return bad
	}
	port, err := strconv.Atoi(address.Port())
	if err != nil || port < 1 || port > 65535 {
		return bad
	}
	raw, err := io.ReadAll(io.LimitReader(input, nativecomposite.MaxSize+1))
	if err != nil || len(raw) == 0 || len(raw) > nativecomposite.MaxSize {
		return bad
	}
	metadata, err := json.Marshal(map[string]any{"node_id": node, "node_kind": "router-vpn", "router_api": api, "start_layer": ""})
	if err != nil {
		return bad
	}
	compiled, err := nativecomposite.Compile(mode, string(raw), string(metadata), "")
	if err != nil {
		return bad
	}
	plan, err := nativecomposite.Plan(compiled, mode, node, "")
	if err != nil {
		return bad
	}
	// Plan has already proved both TCP and UDP belong to this same literal.
	remote, err := netip.ParseAddr(plan["udp"].(map[string]any)["server"].(string))
	if err != nil || remote != server {
		return bad
	}
	body, err := json.Marshal(plan)
	if err != nil || len(body) == 0 || len(body) > nativecomposite.MaxSize {
		return bad
	}
	encoded := append(body, '\n')
	n, err := output.Write(encoded)
	if err == nil && n != len(encoded) {
		return io.ErrShortWrite
	}
	return err
}
