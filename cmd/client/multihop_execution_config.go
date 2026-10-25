package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
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
	endpoints, ok := cfg["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return nil, errors.New("native server path requires one owned entry endpoint")
	}
	entry, ok := endpoints[0].(map[string]any)
	if !ok || entry["tag"] != "entry-wg" || entry["type"] != "wireguard" && entry["type"] != mobilemultihop.AmneziaType {
		return nil, errors.New("native entry endpoint identity changed")
	}
	if entry["type"] == mobilemultihop.AmneziaType {
		encoded, _ := json.Marshal(entry)
		if _, err := mobilemultihop.AmneziaRuntimeConfig(string(encoded)); err != nil {
			return nil, errors.New("native AWG entry lost its captured parameters")
		}
	}
	outbounds, ok := cfg["outbounds"].([]any)
	if !ok {
		return nil, errors.New("native multihop outbounds missing")
	}
	found := 0
	retained := make([]any, 0, len(outbounds))
	for _, item := range outbounds {
		out, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid native outbound")
		}
		if out["tag"] == "proxy" {
			found++
			out = map[string]any{"type": "socks", "tag": "proxy", "version": "5", "server": d.Lease.Host, "server_port": d.Lease.Port, "username": d.Lease.Username, "password": d.Lease.Password, "detour": "entry-wg"}
		} else if out["tag"] == mobilemultihop.NativeStartLayerTag {
			// The authenticated lease owns this exact exit layer on the entry
			// server. The namespaced entry layer stays in the local graph.
			if !multihoprelay.ValidLayerMode(d.Lease.ExitStartLayer) || out["detour"] != "entry-wg" {
				return nil, errors.New("server lease does not own the captured exit Start Layer")
			}
			continue
		}
		retained = append(retained, out)
	}
	if found != 1 {
		return nil, errors.New("ambiguous exit proxy")
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
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func desktopExecutionCommand(a *app, sel multihopSelection, d *desktopExecutionDescriptor) (*exec.Cmd, string, *desktopNodeLaunch, error) {
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
	launch, err := prepareOwnedNativeMultihopCommand(a, sel, d)
	if err != nil {
		return nil, "", launch, err
	}
	return launch.command, "", launch, nil
}
