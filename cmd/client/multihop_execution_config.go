package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/multihoprelay"
	"runtime"
)

type desktopExecutionDescriptor struct {
	Execution string              `json:"execution"`
	Lease     multihoprelay.Lease `json:"lease"`
}

// Only a copy of the already-validated, session-owned native configuration is
// changed. The original generated node profiles and selected DNS policy survive.
func patchDesktopExecutionConfig(path string, d desktopExecutionDescriptor) error {
	if d.Execution != "server" {
		return errors.New("invalid server execution descriptor")
	}
	ip, err := netip.ParseAddr(d.Lease.Host)
	if err != nil || ip.Zone() != "" || !ip.IsPrivate() || ip.IsLoopback() || d.Lease.Port < 26240 || d.Lease.Port > 26271 || len(d.Lease.Username) != 48 || len(d.Lease.Password) != 48 {
		return errors.New("invalid private server listener")
	}
	for _, secret := range []string{d.Lease.Username, d.Lease.Password} {
		if _, err := hex.DecodeString(secret); err != nil {
			return errors.New("invalid relay credential encoding")
		}
	}
	if d.Lease.Username == d.Lease.Password {
		return errors.New("relay credentials must be independent")
	}
	raw, err := readPrivateRegular(path, 4<<20)
	if err != nil {
		return err
	}
	var cfg map[string]any
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	route, ok := cfg["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return errors.New("unowned native multihop final route")
	}
	endpoints, ok := cfg["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return errors.New("native server path requires one owned entry endpoint")
	}
	entry, ok := endpoints[0].(map[string]any)
	if !ok || entry["tag"] != "entry-wg" || entry["type"] != "wireguard" {
		return errors.New("native entry endpoint identity changed")
	}
	outbounds, ok := cfg["outbounds"].([]any)
	if !ok {
		return errors.New("native multihop outbounds missing")
	}
	found := 0
	for i, item := range outbounds {
		out, ok := item.(map[string]any)
		if !ok {
			return errors.New("invalid native outbound")
		}
		if out["tag"] == "proxy" {
			found++
			outbounds[i] = map[string]any{"type": "socks", "tag": "proxy", "version": "5", "server": d.Lease.Host, "server_port": d.Lease.Port, "username": d.Lease.Username, "password": d.Lease.Password, "detour": "entry-wg"}
		}
	}
	if found != 1 {
		return errors.New("ambiguous exit proxy")
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return errors.New("proof routes missing")
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
					return errors.New("control lane cannot carry ordinary traffic")
				}
				control++
				rule["outbound"] = "entry-wg"
			}
		}
	}
	if control != 1 {
		return errors.New("entry control must have exactly one private tunnel route")
	}
	cfg["outbounds"] = outbounds
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateRuntimeFile(path, append(body, '\n'))
}

func desktopExecutionCommand(a *app, sel multihopSelection, d *desktopExecutionDescriptor) (*exec.Cmd, string, error) {
	if runtime.GOOS == "linux" {
		cmd := multihopCommand(a, sel)
		if d == nil {
			return cmd, "", nil
		}
		// The existing Linux split entry installs a host route for SocksHost. The
		// lease control must use that same tunnel address, not a route guessed via WAN.
		host, err := netip.ParseAddr(sel.Entry.SocksHost)
		target, e := netip.ParseAddr(d.Lease.Host)
		if err != nil || e != nil || host.Unmap() != target.Unmap() {
			return nil, "", errors.New("server execution requires the entry Router API and split-tunnel SOCKS address to match")
		}
		root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
		dir, err := newPrivateRuntimeDir(root, "multihop-execution")
		if err != nil {
			return nil, "", err
		}
		path := filepath.Join(dir, "execution.json")
		body, err := json.Marshal(d)
		if err == nil {
			err = writePrivateRuntimeFile(path, body)
		}
		if err != nil {
			return nil, dir, err
		}
		cmd.Args = append(cmd.Args, path)
		return cmd, dir, nil
	}
	cmd, err := nativeMultihopPlatformCommand(a, sel)
	if err != nil {
		return nil, "", err
	}
	if d != nil {
		dir, e := nativeMultihopRuntimeDirFromCommand(cmd)
		if e != nil {
			return nil, "", e
		}
		if err = patchDesktopExecutionConfig(filepath.Join(dir, "sing-box.json"), *d); err != nil {
			return nil, dir, err
		}
	}
	return cmd, "", nil
}
