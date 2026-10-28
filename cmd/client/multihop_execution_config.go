package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativecomposite"
	"runtime"
)

type desktopExecutionDescriptor struct {
	Execution string              `json:"execution"`
	Lease     multihoprelay.Lease `json:"lease"`
}

// Only a copy of the already-validated, session-owned native configuration is
// changed. The original generated node profiles and selected DNS policy survive.
func patchDesktopExecutionConfig(path string, d desktopExecutionDescriptor, sel multihopSelection) error {
	raw, err := readPrivateRegular(path, 4<<20)
	if err != nil {
		return err
	}
	compiled, err := compileDesktopExecutionConfig(raw, d, sel)
	if err != nil {
		return err
	}
	return writePrivateRuntimeFile(path, compiled)
}

func compileDesktopExecutionConfig(raw []byte, d desktopExecutionDescriptor, sel multihopSelection) ([]byte, error) {
	if d.Execution != "server" {
		return nil, errors.New("invalid server execution descriptor")
	}
	ip, err := netip.ParseAddr(d.Lease.Host)
	if err != nil || ip.Zone() != "" || !ip.IsPrivate() || ip.IsLoopback() || d.Lease.Port < 26240 || d.Lease.Port > 26271 || len(d.Lease.Username) != 48 || len(d.Lease.Password) != 48 {
		return nil, errors.New("invalid private server listener")
	}
	for _, secret := range []string{d.Lease.Username, d.Lease.Password} {
		if _, err := hex.DecodeString(secret); err != nil {
			return nil, errors.New("invalid relay credential encoding")
		}
	}
	if d.Lease.Username == d.Lease.Password {
		return nil, errors.New("relay credentials must be independent")
	}
	layer := sel.Exit.StartLayer
	if layer == "off" {
		layer = ""
	}
	if sel.Native == nil || sel.Native.validate(sel) != nil || string(raw) != sel.Native.configs[sel.ExitMode] || d.Lease.ExitMode != sel.ExitMode || d.Lease.ExitStartLayer != layer {
		return nil, errors.New("native server graph differs from the immutable selected source")
	}
	var cfg map[string]any
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	route, ok := cfg["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return nil, errors.New("unowned native multihop final route")
	}
	entryOwners, entrySnapshot, err := nativeMultihopEntrySnapshot(cfg, sel.Native.entryOwners)
	if err != nil {
		return nil, err
	}
	defer clear(entrySnapshot)
	removedExitOwners := map[string]bool{}
	if mobilemultihop.MAXMode(sel.ExitMode) {
		removedExitOwners, err = nativeMAXExitOwners(cfg, sel)
		if err != nil {
			return nil, err
		}
	}
	endpoints, ok := cfg["endpoints"].([]any)
	if cfg["endpoints"] != nil && !ok {
		return nil, errors.New("native server path requires its owned endpoints")
	}
	retainedEndpoints := make([]any, 0, len(endpoints))
	packetExits := 0
	for _, raw := range endpoints {
		endpoint, valid := raw.(map[string]any)
		if !valid {
			return nil, errors.New("invalid native endpoint")
		}
		tag, _ := endpoint["tag"].(string)
		if entryOwners[tag] {
			retainedEndpoints = append(retainedEndpoints, endpoint)
			continue
		}
		switch tag {
		case "proxy":
			wantType := "wireguard"
			if awgpolicy.IsMode(sel.ExitMode) {
				wantType = mobilemultihop.AmneziaType
			} else if nativeMultihopPQExitMode(sel.ExitMode) {
				wantType = mobilemultihop.PQType
			}
			if !nativeMultihopPacketExitMode(sel.ExitMode) || endpoint["type"] != wantType || packetExits != 0 {
				return nil, errors.New("native server path has an unowned packet exit")
			}
			if awgpolicy.IsMode(sel.ExitMode) {
				encoded, _ := json.Marshal(endpoint)
				if _, err := mobilemultihop.AmneziaRuntimeConfig(string(encoded)); err != nil {
					return nil, errors.New("native AWG exit lost its captured parameters")
				}
			}
			if nativeMultihopPQExitMode(sel.ExitMode) {
				baseMode := sel.ExitMode
				if mobilemultihop.MAXMode(baseMode) {
					baseMode = multihoprelay.MAXBaseMode(baseMode)
				}
				encoded, _ := json.Marshal(endpoint)
				captured, err := mobilemultihop.PQRuntimeConfig(string(encoded))
				captured.PQ.Erase()
				if err != nil || endpoint["mode"] != baseMode || endpoint["node_id"] != sel.Exit.NodeProofID {
					return nil, errors.New("native PQ exit lost its captured packet and negotiation owner")
				}
			}
			packetExits++
		default:
			return nil, errors.New("native server path contains an unrelated endpoint")
		}
	}
	if nativeMultihopPacketExitMode(sel.ExitMode) != (packetExits == 1) {
		return nil, errors.New("native server path lost its captured packet exit")
	}
	outbounds, ok := cfg["outbounds"].([]any)
	if !ok {
		return nil, errors.New("native multihop outbounds missing")
	}
	if nativecomposite.Mode(sel.ExitMode) {
		// The lease executes this exact complete paired transport. Validate
		// both local lanes before removing their entire owned closure; merely
		// replacing the dispatcher would leave private dormant exit engines.
		if _, err := nativecomposite.Extract(cfg, sel.ExitMode, sel.Exit.NodeProofID, layer, "proxy", mobilemultihop.CompositeExitPrefix, "entry-wg"); err != nil {
			return nil, err
		}
		removedExitOwners[mobilemultihop.CompositeExitPrefix+"tcp"] = true
		removedExitOwners[mobilemultihop.CompositeExitPrefix+"udp"] = true
		if layer != "" {
			removedExitOwners[mobilemultihop.CompositeExitPrefix+"start"] = true
		}
	}
	found := 0
	removedExitLayer := mobilemultihop.MAXMode(sel.ExitMode) && removedExitOwners[mobilemultihop.MAXExitPrefix+"start"]
	retained := make([]any, 0, len(outbounds))
	serverExit := map[string]any{"type": "socks", "tag": "proxy", "version": "5", "server": d.Lease.Host, "server_port": d.Lease.Port, "username": d.Lease.Username, "password": d.Lease.Password, "detour": "entry-wg"}
	if packetExits == 1 {
		// The independent lease now owns the packet exit. Remove its local
		// endpoint entirely so a dormant local peer cannot roam the server key.
		cfg["endpoints"] = retainedEndpoints
		retained = append(retained, serverExit)
	}
	for _, item := range outbounds {
		out, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid native outbound")
		}
		if tag, _ := out["tag"].(string); entryOwners[tag] {
			retained = append(retained, out)
			continue
		}
		if tag, _ := out["tag"].(string); removedExitOwners[tag] {
			continue
		}
		if out["tag"] == "proxy" {
			if packetExits != 0 {
				return nil, errors.New("native packet exit also contains an ambiguous proxy")
			}
			found++
			out = serverExit
		} else if out["tag"] == mobilemultihop.NativeStartLayerTag {
			// The authenticated lease owns this exact exit layer on the entry
			// server. The namespaced entry layer stays in the local graph.
			if mobilemultihop.MAXMode(sel.ExitMode) || !multihoprelay.ValidLayerMode(d.Lease.ExitStartLayer) || out["detour"] != "entry-wg" {
				return nil, errors.New("server lease does not own the captured exit Start Layer")
			}
			removedExitLayer = true
			removedExitOwners[mobilemultihop.NativeStartLayerTag] = true
			continue
		}
		retained = append(retained, out)
	}
	if found+packetExits != 1 || packetExits == 1 && (layer != "") != removedExitLayer {
		return nil, errors.New("ambiguous exit proxy")
	}
	if len(removedExitOwners) != 0 {
		// A captured resolver can use an exact exit child or AES owner. That
		// owner now lives behind the authenticated Server lease: keep the
		// selected resolver/TLS/port and move only this owned edge to the lease.
		// Other entry, exit and application DNS references remain unchanged.
		dns, ok := cfg["dns"].(map[string]any)
		if !ok {
			return nil, errors.New("native server graph lost its captured DNS")
		}
		servers, ok := dns["servers"].([]any)
		if !ok {
			return nil, errors.New("native server graph lost its captured DNS servers")
		}
		for _, raw := range servers {
			resolver, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("native server graph has invalid captured DNS")
			}
			if tag, _ := resolver["detour"].(string); removedExitOwners[tag] {
				resolver["detour"] = "proxy"
			}
		}
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return nil, errors.New("proof routes missing")
	}
	control := 0
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ins, _ := rule["inbound"].([]any)
		for _, in := range ins {
			if in == "multihop-entry-proof" {
				if len(ins) != 1 {
					return nil, errors.New("control lane cannot carry ordinary traffic")
				}
				control++
				rule["outbound"] = "entry-wg"
			}
		}
	}
	if control != 1 {
		return nil, errors.New("entry control must have exactly one private tunnel route")
	}
	cfg["outbounds"] = retained
	_, afterEntry, err := nativeMultihopEntrySnapshot(cfg, sel.Native.entryOwners)
	defer clear(afterEntry)
	if err != nil || !bytes.Equal(entrySnapshot, afterEntry) {
		return nil, errors.New("Server execution changed the captured entry graph or DNS policy")
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func desktopExecutionCommand(a *app, sel multihopSelection, d *desktopExecutionDescriptor) (*exec.Cmd, string, *desktopNodeLaunch, error) {
	return desktopExecutionCommandContext(a.connectionOperationContextOrBackground(), a, sel, d)
}

func desktopExecutionCommandContext(ctx context.Context, a *app, sel multihopSelection, d *desktopExecutionDescriptor) (*exec.Cmd, string, *desktopNodeLaunch, error) {
	if ctx == nil {
		return nil, "", nil, errors.New("multihop command requires its candidate context")
	}
	if err := ctx.Err(); err != nil {
		return nil, "", nil, err
	}
	if runtime.GOOS == "linux" && sel.Native == nil {
		cmd := multihopCommand(a, sel)
		if d == nil {
			return cmd, "", nil, nil
		}
		// The existing Linux split entry installs a host route for SocksHost. The
		// lease control must use that same tunnel address, not a route guessed via WAN.
		host, err := netip.ParseAddr(sel.Entry.SocksHost)
		target, e := netip.ParseAddr(d.Lease.Host)
		if err != nil || e != nil || host.Unmap() != target.Unmap() {
			return nil, "", nil, errors.New("server execution requires the entry Router API and split-tunnel SOCKS address to match")
		}
		root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
		dir, err := newPrivateRuntimeDir(root, "multihop-execution")
		if err != nil {
			return nil, "", nil, err
		}
		path := filepath.Join(dir, "execution.json")
		body, err := json.Marshal(d)
		if err == nil {
			err = writePrivateRuntimeFile(path, body)
		}
		if err != nil {
			return nil, dir, nil, err
		}
		cmd.Args = append(cmd.Args, path)
		return cmd, dir, nil, nil
	}
	launch, err := prepareOwnedNativeMultihopCommandContext(ctx, a, sel, d)
	if err != nil {
		return nil, "", launch, err
	}
	return launch.command, "", launch, nil
}
