package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// The retained node launch owns the full-device TUN for both Local and Server.
// Entry transport MTU and exit-path system-TUN MTU remain distinct quantities.
type nativeMultihopRuntime struct {
	launch    *desktopNodeLaunch
	selection multihopSelection
	graph     activeMultihopGraph
	network   string
}

var nativeMultihopOwners sync.Map // map[*app]*nativeMultihopRuntime

func retainedNativeMultihopSelected() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux" && desktopNodeNativeSelected("wg")
}

func compileRetainedNativeMultihopLaunch(sel multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
	if sel.Native == nil || sel.Native.validate(sel) != nil {
		return nil, errors.New("native multihop launch lost its immutable entry/exit source")
	}
	physical, err := netip.ParseAddr(sel.Native.endpoint)
	if err != nil || !physical.IsGlobalUnicast() || physical.IsLoopback() || physical.Is4In6() || physical.Zone() != "" {
		return nil, errors.New("native multihop has no captured physical entry address")
	}
	raw, exists := sel.Native.configs[sel.ExitMode]
	if !exists {
		return nil, errors.Join(errors.New("captured multihop exit configuration is unavailable"), sel.Native.failures[sel.ExitMode])
	}
	data := []byte(raw)
	execution := "local"
	if descriptor != nil {
		// The exact authenticated Server graph is finalized before staging's
		// source digest/session. No post-staging rewrite can bypass that owner.
		data, err = compileDesktopExecutionConfig(data, *descriptor, sel)
		if err != nil {
			return nil, err
		}
		execution = "server"
	}
	var graph map[string]any
	if json.Unmarshal(data, &graph) != nil {
		return nil, errors.New("captured multihop graph is invalid")
	}
	inbounds, ok := graph["inbounds"].([]any)
	if !ok {
		return nil, errors.New("native multihop has no captured system TUN")
	}
	tunnels := 0
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid captured native inbound")
		}
		if inbound["type"] != "tun" {
			continue
		}
		tunnels++
		if inbound["auto_route"] != true || inbound["strict_route"] != true {
			return nil, errors.New("native multihop TUN lost its protected route")
		}
		if runtime.GOOS == "darwin" {
			delete(inbound, "interface_name")
		} else {
			inbound["interface_name"] = "router-vpn"
		}
	}
	if tunnels != 1 {
		return nil, errors.New("native multihop requires exactly one retained system TUN")
	}
	data, err = json.Marshal(graph)
	if err != nil {
		return nil, err
	}
	if sel.restoreMTU != 0 {
		data, err = restoreDesktopNodeTUNMTU(data, sel.restoreMTU)
		if err != nil {
			return nil, err
		}
	}
	sum := sha256.Sum256(data)
	metadata, err := json.Marshal(map[string]any{
		"schema": 1, "config_sha256": hex.EncodeToString(sum[:]), "graph_source_sha256": sel.Native.source,
		"control_id": sel.Control.ID, "entry_id": sel.Entry.ID, "exit_id": sel.Exit.ID,
		"entry_mode": sel.Native.entryMode, "base": sel.Base, "exit_mode": sel.ExitMode,
		"execution": execution, "mtu_scope": "multihop-exit-path",
	})
	if err != nil {
		clear(data)
		return nil, err
	}
	return &desktopNodeLaunch{root: sel.Native.root, endpoint: physical.String(), profileID: sel.Exit.ID, policyProfileID: sel.Control.ID, mode: sel.ExitMode, config: data, metadata: metadata}, nil
}

func preflightRetainedNativeMultihop(ctx context.Context, binary string, launch *desktopNodeLaunch, run desktopExternalPreflightCommand) (failure error) {
	if ctx == nil || launch == nil || launch.external != nil || len(launch.config) == 0 || run == nil || !filepath.IsAbs(binary) {
		return errors.New("native multihop preflight requires its exact executable and graph")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, err := newPrivateRuntimeDir(launch.root, "native-node")
	if err != nil {
		return err
	}
	workspace := &desktopNodeLaunch{}
	if err := captureDesktopRuntimeDirectory(workspace, directory); err != nil {
		return err
	}
	defer workspace.directoryRoot.Close()
	defer func() { failure = errors.Join(failure, cleanupDesktopNodeLaunch(workspace)) }()
	if err := writeDesktopRuntimeFile(workspace, "sing-box.json", launch.config, false); err != nil {
		return err
	}
	environment := desktopNativeEnvironment(os.Environ(), launch.root, launch.profileID, launch.endpoint)
	if err := run(ctx, binary, []string{"routervpn-node", "--help"}, environment, directory); err != nil {
		return err
	}
	if err := desktopExternalDirectoryCurrent(workspace); err != nil {
		return err
	}
	if err := run(ctx, binary, []string{"check", "-D", directory, "-c", filepath.Join(directory, "sing-box.json")}, environment, directory); err != nil {
		return err
	}
	checked, err := readDesktopRuntimeFile(workspace, "sing-box.json", 4<<20)
	if err != nil || !bytes.Equal(checked, launch.config) {
		return errors.New("native multihop preflight changed its captured configuration")
	}
	return errors.Join(ctx.Err(), desktopExternalDirectoryCurrent(workspace))
}

func prepareOwnedNativeMultihopCommand(a *app, sel multihopSelection, descriptor *desktopExecutionDescriptor) (launch *desktopNodeLaunch, failure error) {
	return prepareOwnedNativeMultihopCommandContext(a.connectionOperationContextOrBackground(), a, sel, descriptor)
}

func prepareOwnedNativeMultihopCommandContext(ctx context.Context, a *app, sel multihopSelection, descriptor *desktopExecutionDescriptor) (launch *desktopNodeLaunch, failure error) {
	launch, failure = preflightOwnedNativeMultihopCommandContext(ctx, a, sel, descriptor)
	if failure != nil {
		return launch, failure
	}
	if failure = ctx.Err(); failure != nil {
		return launch, errors.Join(failure, retireUnstartedNativeMultihop(launch))
	}
	if failure = stageOwnedNativeMultihopCommand(a, sel, launch); failure != nil {
		failure = errors.Join(failure, retireUnstartedNativeMultihop(launch))
	}
	return launch, failure
}

func preflightOwnedNativeMultihopCommand(a *app, sel multihopSelection, descriptor *desktopExecutionDescriptor) (launch *desktopNodeLaunch, failure error) {
	return preflightOwnedNativeMultihopCommandContext(a.connectionOperationContextOrBackground(), a, sel, descriptor)
}

func preflightOwnedNativeMultihopCommandContext(ctx context.Context, a *app, sel multihopSelection, descriptor *desktopExecutionDescriptor) (launch *desktopNodeLaunch, failure error) {
	binary, err := verifyBundledNativeContext(ctx, desktopAmneziaPackageRoot())
	if err != nil {
		return nil, err
	}
	launch, err = compileRetainedNativeMultihopLaunch(sel, descriptor)
	if err != nil {
		return nil, err
	}
	defer func() {
		if failure != nil {
			clear(launch.config)
			clear(launch.metadata)
			failure = errors.Join(failure, retireUnstartedNativeMultihop(launch))
		}
	}()
	if err := preflightRetainedNativeMultihop(ctx, binary, launch, runDesktopExternalPreflightCommand); err != nil {
		return launch, err
	}
	return launch, nil
}

// Called only after the previous runtime has drained. Preflight is separate so
// an invalid native graph never requires stopping a usable connection first.
func stageOwnedNativeMultihopCommand(a *app, sel multihopSelection, launch *desktopNodeLaunch) error {
	if launch == nil || sel.Native == nil || sel.Native.validate(sel) != nil || launch.profileID != sel.Exit.ID || launch.policyProfileID != sel.Control.ID || launch.endpoint != sel.Native.endpoint {
		return errors.New("native multihop source changed before staging")
	}
	if err := stageDesktopNodeLaunch(a, launch); err != nil {
		return err
	}
	// The physical connection and firewall belong to ENTRY and CONTROL,
	// respectively. The shared node launch's profile identity remains EXIT.
	launch.command.Env = nativeNodeMTUEnvironment(nativeMultihopEnvironment(launch.root, sel), launch.mtuSession, launch.configSHA256)
	if err := registerNativeMultihopDNSRuntime(a, sel, launch.command); err != nil {
		return err
	}
	return nil
}

func bindNativeMultihopRuntime(a *app, launch *desktopNodeLaunch, sel multihopSelection, network string) error {
	graph, found := getActiveMultihopGraph(a)
	if launch == nil || launch.command == nil || sel.Native == nil || !found ||
		!a.ownsConnectionRuntime(launch.command) || network == "" || physicalNetworkIdentity() != network ||
		graph.EntryID != sel.Entry.ID || graph.ExitID != sel.Exit.ID || graph.Base != sel.Base || graph.EntryMode != sel.Native.entryMode ||
		graph.SourceSHA != sel.Native.source || graph.ExitMode != sel.ExitMode || graph.Execution != "local" && graph.Execution != "server" {
		return errors.New("native multihop changed before its retained TUN could be adopted")
	}
	if current, ok := desktopNodeOwners.Load(a); !ok || current != launch || launch.profileID != sel.Exit.ID || launch.policyProfileID != sel.Control.ID {
		return errors.New("native multihop TUN belongs to another node owner")
	}
	nativeMultihopOwners.Store(a, &nativeMultihopRuntime{launch: launch, selection: sel, graph: graph, network: network})
	return nil
}

func retireUnstartedNativeMultihop(launch *desktopNodeLaunch) error {
	if launch == nil || launch.command != nil && launch.command.Process != nil {
		return nil
	}
	clear(launch.config)
	clear(launch.metadata)
	if launch.directory == "" {
		return nil
	}
	if _, err := os.Lstat(launch.directory); errors.Is(err, os.ErrNotExist) {
		if launch.directoryRoot != nil {
			_ = launch.directoryRoot.Close()
		}
		launch.directory, launch.directoryRoot, launch.directoryInfo = "", nil, nil
		return nil
	}
	err := cleanupDesktopNodeLaunch(launch)
	if err == nil {
		launch.directory, launch.directoryRoot, launch.directoryInfo = "", nil, nil
	}
	return err
}

func sameMTUMultihopGraph(left, right activeMultihopGraph) bool {
	return sameActiveMultihopGraph(left, right) && left.Execution == right.Execution && left.EntryMode == right.EntryMode && left.SourceSHA == right.SourceSHA
}

func retireNativeMultihopGraph(a *app, launch *desktopNodeLaunch) {
	raw, ok := nativeMultihopOwners.Load(a)
	owner, valid := raw.(*nativeMultihopRuntime)
	if !ok || !valid || owner == nil || owner.launch != launch {
		return
	}
	if nativeMultihopOwners.CompareAndDelete(a, owner) {
		activeMultihopGraphs.CompareAndDelete(a, owner.graph)
	}
}

func capturedNativeMultihopRuntime(a *app, command *exec.Cmd, graph activeMultihopGraph) (*nativeMultihopRuntime, error) {
	raw, found := nativeMultihopOwners.Load(a)
	owner, ok := raw.(*nativeMultihopRuntime)
	if !found || !ok || owner == nil || owner.launch == nil || owner.launch.command != command || !sameMTUMultihopGraph(owner.graph, graph) {
		return nil, errors.New("multihop measurement has no retained active graph owner")
	}
	if current, found := desktopNodeOwners.Load(a); !found || current != owner.launch {
		return nil, errors.New("multihop system TUN owner was replaced")
	}
	if owner.network == "" || physicalNetworkIdentity() != owner.network || owner.selection.Native == nil || owner.selection.Native.validate(owner.selection) != nil {
		return nil, errors.New("multihop source or physical network changed")
	}
	if err := desktopExternalDirectoryCurrent(owner.launch); err != nil {
		return nil, err
	}
	return owner, nil
}
