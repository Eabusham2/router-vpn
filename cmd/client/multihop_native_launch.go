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

	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// The retained node launch owns the full-device TUN for both Local and Server.
// Entry transport MTU and exit-path system-TUN MTU remain distinct quantities.
type nativeMultihopRuntime struct {
	launch    *desktopNodeLaunch
	selection multihopSelection
	graph     activeMultihopGraph
	network   string
	// Bound once to the OS observer by bindNativeMultihopRuntime, alongside
	// the retained launch. Missing observation must fail closed.
	networkIdentityContext func(context.Context) (string, error)
}

func (owner *nativeMultihopRuntime) physicalNetworkContext(ctx context.Context) (string, error) {
	if ctx == nil || owner == nil || owner.networkIdentityContext == nil {
		return "", errors.New("captured multihop has no original physical network observer")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	network, err := owner.networkIdentityContext(ctx)
	return network, errors.Join(err, ctx.Err())
}

var nativeMultihopOwners sync.Map // map[*app]*nativeMultihopRuntime

func retainedNativeMultihopSelected() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux" && desktopNodeNativeSelected("wg")
}

func compileRetainedNativeMultihopLaunch(sel multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
	if sel.Native == nil || sel.Native.validate(sel) != nil {
		return nil, errors.New("native multihop launch lost its immutable entry/exit source")
	}
	if sel.Native.importedHost != nil {
		return nil, errors.New("protected imported capture requires its typed Windows policy owner")
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
		if sel.Native.imported {
			return nil, errors.New("ordinary imported entry cannot authorize Server or Compare execution")
		}
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
		if sel.Native.imported && (sel.EntryMode == "wireguard" || sel.EntryMode == "amneziawg" || sel.EntryMode == "openvpn") {
			if _, err := mobilemtu.NewPlan(string(data), sel.restoreMTU); err != nil {
				return nil, errors.Join(errors.New("restored imported packet TUN exceeds its original captured envelope"), err)
			}
		}
	}
	sum := sha256.Sum256(data)
	metadata, err := json.Marshal(map[string]any{
		"schema": 1, "config_sha256": hex.EncodeToString(sum[:]), "graph_source_sha256": sel.Native.source,
		"control_id": sel.Control.ID, "entry_id": sel.Entry.ID, "exit_id": sel.Exit.ID,
		"entry_mode": sel.Native.entryMode, "base": sel.Base, "exit_mode": sel.ExitMode,
		"execution": execution, "mtu_scope": "multihop-exit-path",
		"physical_egress": sel.Native.entryPhysical,
	})
	if err != nil {
		clear(data)
		return nil, err
	}
	launch := &desktopNodeLaunch{root: sel.Native.root, endpoint: physical.String(), profileID: sel.Exit.ID, policyProfileID: sel.Control.ID, mode: sel.ExitMode, config: data, metadata: metadata, importedEntry: sel.Native.imported,
		nodePhysicalEgress: append([]mobilemultihop.PhysicalEgress(nil), sel.Native.entryPhysical...)}
	if sel.Native.openVPN != nil {
		launch.importedOpenVPN = &desktopImportedOpenVPNRuntime{spec: *sel.Native.openVPN, notBefore: time.Now().UnixMilli()}
	}
	return launch, nil
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
	if failure = stageOwnedNativeMultihopCommandContext(ctx, a, sel, launch); failure != nil {
		failure = errors.Join(failure, retireUnstartedNativeMultihop(launch))
	}
	return launch, failure
}

func preflightOwnedNativeMultihopCommand(a *app, sel multihopSelection, descriptor *desktopExecutionDescriptor) (launch *desktopNodeLaunch, failure error) {
	return preflightOwnedNativeMultihopCommandContext(a.connectionOperationContextOrBackground(), a, sel, descriptor)
}

func preflightOwnedNativeMultihopCommandContext(ctx context.Context, a *app, sel multihopSelection, descriptor *desktopExecutionDescriptor) (launch *desktopNodeLaunch, failure error) {
	var binary string
	var err error
	if sel.Native != nil && sel.Native.importedHost != nil {
		if !sel.Native.imported || descriptor != nil {
			return nil, errors.New("protected imported preflight requires its original Local graph")
		}
		binary, err = verifiedDesktopImportedPackage(ctx, sel.Native.importedHost)
		if err == nil {
			launch, err = prepareDesktopOwnedImportedLaunch(ctx, a, sel)
		}
	} else {
		binary, err = verifyBundledNativeContext(ctx, desktopAmneziaPackageRoot())
		if err == nil {
			launch, err = compileRetainedNativeMultihopLaunch(sel, descriptor)
		}
	}
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
	return stageOwnedNativeMultihopCommandContext(a.connectionOperationContextOrBackground(), a, sel, launch)
}

func stageOwnedNativeMultihopCommandContext(ctx context.Context, a *app, sel multihopSelection, launch *desktopNodeLaunch) error {
	if err := stageOwnedNativeMultihopInputsContext(ctx, a, sel, launch); err != nil {
		return err
	}
	return registerNativeMultihopDNSRuntime(a, sel, launch.command)
}

// A temporary prepared launch publishes DNS only after its captured operation
// wins the final owner check. Private input staging itself grants no live route.
func stageOwnedNativeMultihopInputs(a *app, sel multihopSelection, launch *desktopNodeLaunch) error {
	return stageOwnedNativeMultihopInputsContext(a.connectionOperationContextOrBackground(), a, sel, launch)
}

func stageOwnedNativeMultihopInputsContext(ctx context.Context, a *app, sel multihopSelection, launch *desktopNodeLaunch) error {
	if launch == nil || sel.Native == nil || sel.Native.validate(sel) != nil || launch.profileID != sel.Exit.ID || launch.policyProfileID != sel.Control.ID || launch.endpoint != sel.Native.endpoint || launch.importedEntry != sel.Native.imported {
		return errors.New("native multihop source changed before staging")
	}
	if err := stageDesktopNodeLaunchContext(ctx, a, launch); err != nil {
		return err
	}
	// The physical connection and firewall belong to ENTRY and CONTROL,
	// respectively. The shared node launch's profile identity remains EXIT.
	if launch.ownedNode != nil {
		// The typed child already retained its authenticated package and final
		// policy owner. Its protected sockets do not use helper exceptions.
		launch.command.Env = nativeNodeMTUEnvironment(launch.command.Env, launch.mtuSession, launch.configSHA256)
	} else {
		launch.command.Env = nativeNodeMTUEnvironment(nativeMultihopEnvironment(launch.root, sel), launch.mtuSession, launch.configSHA256)
	}
	if launch.ownedNode == nil && (runtime.GOOS == "windows" || launch.importedEntry) {
		var err error
		launch.command.Env, err = desktopNodePhysicalEnvironment(launch.command.Env, launch)
		if err != nil {
			return err
		}
	}
	return nil
}

func bindNativeMultihopRuntime(a *app, launch *desktopNodeLaunch, sel multihopSelection, network string) error {
	return bindNativeMultihopRuntimeContext(context.Background(), a, launch, sel, network)
}

func bindNativeMultihopRuntimeContext(ctx context.Context, a *app, launch *desktopNodeLaunch, sel multihopSelection, network string) error {
	observe := physicalNetworkIdentityContext
	if launch != nil && launch.ownedNode != nil && launch.ownedNode.imported != nil {
		observe = launch.ownedNode.imported.readNetwork
	}
	if ctx == nil || observe == nil {
		return errors.New("native multihop lost its original network observer")
	}
	actual, err := observe(ctx)
	if err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	graph, found := getActiveMultihopGraph(a)
	if launch == nil || launch.command == nil || sel.Native == nil || !found ||
		!a.ownsConnectionRuntime(launch.command) || network == "" || actual != network ||
		graph.EntryID != sel.Entry.ID || graph.ExitID != sel.Exit.ID || graph.Base != sel.Base || graph.EntryMode != sel.Native.entryMode ||
		graph.SourceSHA != sel.Native.source || graph.ExitMode != sel.ExitMode || graph.Execution != "local" && graph.Execution != "server" {
		return errors.New("native multihop changed before its retained TUN could be adopted")
	}
	if current, ok := desktopNodeOwners.Load(a); !ok || current != launch || launch.profileID != sel.Exit.ID || launch.policyProfileID != sel.Control.ID {
		return errors.New("native multihop TUN belongs to another node owner")
	}
	nativeMultihopOwners.Store(a, &nativeMultihopRuntime{launch: launch, selection: sel, graph: graph, network: network, networkIdentityContext: observe})
	return nil
}

func nativeMultihopLaunchStarted(launch *desktopNodeLaunch) bool {
	return launch != nil && (launch.command != nil && launch.command.Process != nil || desktopOwnedNodeCreated(launch))
}

func retireUnstartedNativeMultihop(launch *desktopNodeLaunch) error {
	if launch == nil || nativeMultihopLaunchStarted(launch) {
		return nil
	}
	if owned := launch.ownedNode; owned != nil && owned.imported != nil {
		if owned.imported.app == nil {
			return errors.New("unstarted protected imported launch lost its original application")
		}
		if launch.directory != "" || owned.attempt != nil || desktopOwnedNodeProcess(launch) != nil {
			return owned.imported.app.discardDesktopOwnedNodeUnstarted(launch)
		}
		if err := owned.imported.app.retireDesktopOwnedNode(context.Background(), launch); err != nil {
			return err
		}
		clear(owned.source)
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
	return sameActiveMultihopGraph(left, right) && left.Execution == right.Execution && left.EntryMode == right.EntryMode && left.SourceSHA == right.SourceSHA && left.ImportedEntry == right.ImportedEntry
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
	return capturedNativeMultihopRuntimeContext(context.Background(), a, command, graph)
}

func capturedNativeMultihopRuntimeContext(ctx context.Context, a *app, command *exec.Cmd, graph activeMultihopGraph) (*nativeMultihopRuntime, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("multihop observation has no live original caller")
	}
	raw, found := nativeMultihopOwners.Load(a)
	owner, ok := raw.(*nativeMultihopRuntime)
	if !found || !ok || owner == nil || owner.launch == nil || owner.launch.command != command || !sameMTUMultihopGraph(owner.graph, graph) {
		return nil, errors.New("multihop measurement has no retained active graph owner")
	}
	if current, found := desktopNodeOwners.Load(a); !found || current != owner.launch {
		return nil, errors.New("multihop system TUN owner was replaced")
	}
	if owner.launch.ownedNode != nil && owner.launch.ownedNode.imported != nil {
		if err := a.desktopOwnedNodeCurrentContext(ctx, owner.launch, true); err != nil {
			return nil, err
		}
	}
	network, err := owner.physicalNetworkContext(ctx)
	if err != nil {
		return nil, err
	}
	if owner.network == "" || network != owner.network || owner.selection.Native == nil || owner.selection.Native.validate(owner.selection) != nil {
		return nil, errors.New("multihop source or physical network changed")
	}
	if err := desktopExternalDirectoryCurrent(owner.launch); err != nil {
		return nil, err
	}
	return owner, ctx.Err()
}
