package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// A comparison and its selected connection share this immutable capture. No
// candidate can re-read a different AWG variant, key, layer or DNS preference.
type nativeMultihopCapture struct {
	root, entryID, exitID, base, entryMode, endpoint, source string
	controlToken, entryToken, exitToken                      string
	configs                                                  map[string]string
	localPacketPublic                                        map[string]string
	failures                                                 map[string]error
	assets                                                   []viaEntryAsset
}

func captureNativeMultihopSelection(ctx context.Context, root string, sel multihopSelection, modes []string, lookup applexray.Lookup) (multihopSelection, error) {
	if ctx == nil || ctx.Err() != nil || (sel.Base != "wg" && sel.Base != "awg") {
		return sel, errors.New("native multihop requires a current captured WG or AWG selection")
	}
	root, err := canonicalBundleRoot(root)
	if err != nil {
		return sel, err
	}
	sel.Control, sel.Entry, sel.Exit = cloneRouterProfile(sel.Control), cloneRouterProfile(sel.Entry), cloneRouterProfile(sel.Exit)
	c := &nativeMultihopCapture{root: root, entryID: sel.Entry.ID, exitID: sel.Exit.ID, base: sel.Base, configs: map[string]string{}, localPacketPublic: map[string]string{}, failures: map[string]error{}, controlToken: liveMeasurementProfileToken(sel.Control), entryToken: liveMeasurementProfileToken(sel.Entry), exitToken: liveMeasurementProfileToken(sel.Exit)}
	c.entryMode, err = viaEntrySourceMode(root, sel.Entry.ID, sel.Base)
	if err != nil {
		return sel, err
	}
	owned := map[string]map[string][]byte{}
	defer func() {
		for _, files := range owned {
			clearViaEntryAssets(files)
		}
	}()
	read := func(id, mode string) (map[string][]byte, error) {
		key := id + "/" + mode
		if files, ok := owned[key]; ok {
			return files, nil
		}
		files, err := readDesktopNodeAssets(root, id, mode)
		if err == nil {
			owned[key] = files
			c.assets = append(c.assets, viaEntryAsset{id, mode, viaEntryAssetDigest(files)})
		} else {
			c.assets = append(c.assets, viaEntryAsset{id, mode, ""})
		}
		return files, err
	}
	// AWG's transport key differs from the stable node identity, which remains
	// anchored to the exact saved standard WireGuard peer for both nodes.
	for _, p := range []common.RouterProfile{sel.Entry, sel.Exit} {
		files, e := read(p.ID, "wg")
		if e != nil {
			return sel, errors.New("native multihop requires both saved node identities")
		}
		base, e := mobilemultihop.NativeBaseSourceForEndpoint("wg", files, p.Endpoint)
		identity, identityErr := nodeProofIDFromWGConfig(base)
		if e != nil || identityErr != nil || identity != p.NodeProofID {
			return sel, errors.New("native multihop node identity differs from its captured standard peer")
		}
	}
	compile := func(p common.RouterProfile, mode string) (*mobilemultihop.NodeProfile, string, error) {
		files, e := read(p.ID, mode)
		if e != nil {
			return nil, "", e
		}
		var start map[string][]byte
		if p.StartLayer != "" && p.StartLayer != "off" && mode != "shadowsocks" {
			start, e = read(p.ID, "shadowsocks")
			if e != nil {
				return nil, "", e
			}
		}
		return compileDesktopNode(ctx, p, mode, files, start, lookup)
	}
	entry, endpoint, err := compile(sel.Entry, c.entryMode)
	if err != nil {
		return sel, err
	}
	c.endpoint = endpoint
	for _, mode := range modes {
		if !mobilemultihop.NodeMultihopExitMode(mode) {
			return sel, errors.New("native multihop exit mode is not supported")
		}
		if _, exists := c.configs[mode]; exists {
			continue
		}
		exit, _, e := compile(sel.Exit, mode)
		if e == nil {
			public := ""
			if mode == "wg" {
				public, e = exit.WireGuardClientPublicKey()
			}
			var config string
			if e == nil {
				config, e = mobilemultihop.NodeMultihopConfig(entry, exit)
			}
			if e == nil {
				config, _, e = nativeMultihopProofConfig(config, sel.Entry)
			}
			if e == nil {
				c.configs[mode] = config
				if public != "" {
					c.localPacketPublic[mode] = public
				}
			}
		}
		if e != nil {
			c.failures[mode] = e
		}
	}
	if len(c.configs) == 0 {
		failures := []error{errors.New("no selected native multihop exit has a complete captured configuration")}
		for _, mode := range modes {
			failures = append(failures, c.failures[mode])
		}
		return sel, errors.Join(failures...)
	}
	assetIDs := make([][]string, 0, len(c.assets))
	for _, asset := range c.assets {
		assetIDs = append(assetIDs, []string{asset.id, asset.mode, asset.digest})
	}
	identity, _ := json.Marshal([]any{c.entryMode, c.endpoint, c.controlToken, c.entryToken, c.exitToken, assetIDs, c.configs, c.localPacketPublic})
	sum := sha256.Sum256(identity)
	clear(identity)
	c.source = hex.EncodeToString(sum[:])
	sel.Native = c
	if err := c.validate(sel); err != nil {
		return sel, err
	}
	return sel, nil
}

func (c *nativeMultihopCapture) validate(sel multihopSelection) error {
	bad := errors.New("captured native multihop source changed; choose the path again")
	if c == nil || sel.Entry.ID != c.entryID || sel.Exit.ID != c.exitID || sel.Base != c.base || liveMeasurementProfileToken(sel.Control) != c.controlToken || liveMeasurementProfileToken(sel.Entry) != c.entryToken || liveMeasurementProfileToken(sel.Exit) != c.exitToken {
		return bad
	}
	if mode, err := viaEntrySourceMode(c.root, c.entryID, c.base); err != nil || mode != c.entryMode {
		return bad
	}
	for _, asset := range c.assets {
		files, err := readDesktopNodeAssets(c.root, asset.id, asset.mode)
		if asset.digest == "" {
			clearViaEntryAssets(files)
			if err == nil {
				return bad
			}
			continue
		}
		if err != nil {
			return bad
		}
		matches := viaEntryAssetDigest(files) == asset.digest
		clearViaEntryAssets(files)
		if !matches {
			return bad
		}
	}
	return nil
}

func captureNativeMultihopForApp(a *app, sel multihopSelection, modes []string) (multihopSelection, error) {
	if _, err := verifyBundledNative(desktopAmneziaPackageRoot()); err != nil {
		return sel, err
	}
	ctx, cancel := context.WithTimeout(a.connectionOperationContextOrBackground(), 20*time.Second)
	defer cancel()
	return captureNativeMultihopSelection(ctx, clientRoot(a), sel, modes, func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	})
}

// AWG transport keys are separate from the paired node's stable WG identity.
// Prove both exact nodes through their distinct captured lanes before treating
// a native local connection (including a temporary Speed Lab path) as ready.
func (a *app) proveNativeMultihop(sel multihopSelection, command *exec.Cmd) error {
	ctx, cancel := context.WithTimeout(a.connectionOperationContextOrBackground(), 20*time.Second)
	defer cancel()
	return proveNativeMultihopCapture(ctx, sel, func() bool { return a.ownsConnectionRuntime(command) }, proveMultihopLaneNodeContext)
}

func proveNativeMultihopCapture(ctx context.Context, sel multihopSelection, owns func() bool, prove func(context.Context, common.RouterProfile, string) error) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !owns() || sel.Native == nil || sel.Native.validate(sel) != nil {
			return errors.New("native multihop lost its captured source or runtime before proof")
		}
		err := prove(ctx, sel.Entry, multihopEntryProofProxy)
		if err == nil {
			if ctx.Err() != nil || !owns() || sel.Native.validate(sel) != nil {
				return errors.New("native multihop entry proof completed for a retired capture")
			}
			err = prove(ctx, sel.Exit, multihopProofProxy)
		}
		if err == nil && ctx.Err() == nil && owns() && sel.Native.validate(sel) == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

func nativeMultihopProofConfig(config string, entry common.RouterProfile) (string, string, error) {
	var graph map[string]any
	// This is the compiler's immutable JSON result, never a request or a
	// separately opened source file. Its ownership was validated before merge.
	if len(config) == 0 || len(config) > 4<<20 || json.Unmarshal([]byte(config), &graph) != nil || graph == nil {
		return "", "", errors.New("captured native multihop graph is invalid")
	}
	ins, ok := graph["inbounds"].([]any)
	if !ok || len(ins) != 1 {
		return "", "", errors.New("native multihop must own one full-device interface")
	}
	tun, ok := ins[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return "", "", errors.New("native multihop interface is not protected")
	}
	alias := nativeMultihopTUNAlias(tun, runtime.GOOS)
	private, err := nativeEntryPrivateOutbound(entry.SocksHost, entry.SocksPort, entry.SocksUsername, entry.SocksPassword)
	if err != nil {
		return "", "", err
	}
	outs, ok := graph["outbounds"].([]any)
	if !ok {
		return "", "", errors.New("native multihop has no exit owner")
	}
	for _, raw := range outs {
		out, ok := raw.(map[string]any)
		if !ok || out["tag"] == "entry-private" {
			return "", "", errors.New("native multihop proof tag is already owned")
		}
	}
	route, ok := graph["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return "", "", errors.New("native multihop final owner is missing")
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return "", "", errors.New("native multihop policy routes are missing")
	}
	graph["outbounds"] = append(outs, private)
	graph["inbounds"] = append(ins,
		map[string]any{"type": "mixed", "tag": "multihop-entry-proof", "listen": "127.0.0.1", "listen_port": nativeMultihopEntryProofPort},
		map[string]any{"type": "mixed", "tag": "multihop-proof", "listen": "127.0.0.1", "listen_port": nativeMultihopExitProofPort},
	)
	route["rules"] = append([]any{
		map[string]any{"inbound": []any{"multihop-entry-proof"}, "outbound": "entry-private"},
		map[string]any{"inbound": []any{"multihop-proof"}, "outbound": "proxy"},
	}, rules...)
	body, err := json.Marshal(graph)
	if err != nil || len(body) > 4<<20 {
		return "", "", errors.New("native multihop graph exceeds its bound")
	}
	return string(body), alias, nil
}

func nativeMultihopTUNAlias(tun map[string]any, platform string) string {
	if platform == "darwin" {
		// The pinned Darwin backend requires a free utunN. Let its native
		// allocator choose one; the existing PF watcher proves ownership from
		// the newly installed route instead of borrowing a fixed interface.
		delete(tun, "interface_name")
		return ""
	}
	alias, _ := tun["interface_name"].(string)
	if alias == "" {
		alias = "router-vpn-multihop"
		tun["interface_name"] = alias
	}
	return alias
}

func nativeMultihopEnvironment(root string, sel multihopSelection) []string {
	env := desktopNativeEnvironment(os.Environ(), root, sel.Entry.ID, sel.Native.endpoint)
	for i, value := range env {
		if strings.HasPrefix(value, "HOMEVPN_POLICY_PROFILE_ID=") {
			env[i] = "HOMEVPN_POLICY_PROFILE_ID=" + sel.Control.ID
		}
	}
	return env
}

func stageNativeMultihopCapture(root string, sel multihopSelection) (string, string, error) {
	root, err := canonicalBundleRoot(root)
	if err != nil || sel.Native == nil || root != sel.Native.root {
		return "", "", errors.New("native multihop requires its captured private source")
	}
	if err := sel.Native.validate(sel); err != nil {
		return "", "", err
	}
	config, ok := sel.Native.configs[sel.ExitMode]
	if !ok {
		if err := sel.Native.failures[sel.ExitMode]; err != nil {
			return "", "", err
		}
		return "", "", errors.New("selected exit mode was unavailable in the captured round")
	}
	var graph map[string]any
	if json.Unmarshal([]byte(config), &graph) != nil {
		return "", "", errors.New("captured native graph is invalid")
	}
	alias, _ := graph["inbounds"].([]any)[0].(map[string]any)["interface_name"].(string)
	dir, err := newPrivateRuntimeDir(root, "native-multihop")
	if err != nil {
		return "", "", err
	}
	if err := writePrivateRuntimeFile(filepath.Join(dir, "sing-box.json"), []byte(config)); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", err
	}
	return dir, alias, nil
}
