package applexray

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

// Lookup is supplied only by the host application's pre-TUN bootstrap bridge.
// The PacketTunnel adapter never calls it or falls back to a system resolver.
type Lookup func(context.Context, string) ([]netip.Addr, error)

// ResolveAndCompile resolves only the configured node's outer hostname before
// its TUN starts. It never resolves application or encrypted-DNS destinations.
// Certificate names, VLESS keys/flow, path, fragmentation and selected DNS stay
// unchanged; the resulting runtime contains frozen literal outer endpoints.
func ResolveAndCompile(ctx context.Context, mode string, wrapper, raw []byte, lookup Lookup) (map[string][]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("Xray endpoint preparation cancelled")
	}
	plan, err := prepare(mode, raw, true)
	if err != nil {
		return nil, err
	}
	compiled, err := compile(mode, wrapper, raw, true)
	if err != nil {
		return nil, err
	}
	if plan.Server.IsValid() {
		if ctx.Err() != nil {
			return nil, errors.New("Xray endpoint preparation cancelled")
		}
		return map[string][]byte{"sing-box.json": compiled, "xray.json": raw}, nil
	}
	if lookup == nil {
		return nil, errors.New("node hostname requires the owned pre-tunnel resolver")
	}
	candidates, err := lookup(ctx, plan.ServerHost)
	if err != nil || ctx.Err() != nil || len(candidates) == 0 || len(candidates) > 32 {
		return nil, errors.New("node hostname resolution failed or expired")
	}
	var chosen netip.Addr
	for _, ip := range candidates {
		if safeIP(ip) {
			ip = ip.Unmap()
			if !chosen.IsValid() || ip.Is4() {
				chosen = ip
				if ip.Is4() {
					break
				}
			}
		}
	}
	if !chosen.IsValid() {
		return nil, errors.New("node hostname did not resolve to an allowed endpoint")
	}
	xray, _ := Object(raw)
	outbound := xray["outbounds"].([]any)[0].(map[string]any)
	remote := outbound["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	remote["address"] = chosen.String()
	resolved, err := json.Marshal(xray)
	if err != nil {
		return nil, err
	}
	graph, _ := Object(compiled)
	for _, value := range graph["outbounds"].([]any) {
		o := value.(map[string]any)
		if o["type"] == Type {
			o["config_json"] = string(resolved)
		}
		// Split and PQ Dual Transport share the same generated node endpoint. Do not
		// touch TLS server names, DNS hosts, or transports nested behind a detour.
		if o["type"] == "hysteria2" && strings.EqualFold(text(o["server"]), plan.ServerHost) {
			if text(o["detour"]) != "" {
				return nil, errors.New("dual transport has an unexpected outer detour")
			}
			o["server"] = chosen.String()
		}
	}
	normalized, err := json.Marshal(graph)
	if err != nil {
		return nil, err
	}
	normalized, err = Compile(mode, normalized, resolved)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, errors.New("Xray endpoint preparation cancelled")
	}
	return map[string][]byte{"sing-box.json": normalized, "xray.json": resolved}, nil
}
