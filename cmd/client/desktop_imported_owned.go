package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// The imported graph has its own compiler authority and both original node
// sources. Only process, journal and native readiness mechanics are shared
// with an ordinary Router-node runtime; no imported entry becomes a NodeProfile.
type desktopOwnedImportedRuntime struct {
	app         *app
	policy      *mobilemultihop.DesktopImportedPolicy
	selection   multihopSelection
	readNetwork func(context.Context) (string, error)
}

func (owned *desktopOwnedNodeRuntime) physicalPolicy() (mobilemultihop.DesktopPhysicalPolicy, error) {
	if owned != nil && owned.chain != nil {
		if owned.policy != nil || owned.imported != nil || owned.chain.policy == nil {
			return nil, errors.New("native ordered owner mixed its concrete policy family")
		}
		return owned.chain.policy, nil
	}
	if owned == nil || (owned.policy == nil) == (owned.imported == nil) {
		return nil, errors.New("native physical owner requires exactly one captured policy family")
	}
	if owned.imported != nil {
		if owned.imported.policy == nil {
			return nil, errors.New("native imported owner lost its original policy")
		}
		return owned.imported.policy, nil
	}
	return owned.policy, nil
}

func (owned *desktopOwnedNodeRuntime) physicalState() (string, mobilemultihop.DesktopPhysicalMetadata, mobilemultihop.DesktopPhysicalCapture, error) {
	policy, err := owned.physicalPolicy()
	if err != nil {
		return "", mobilemultihop.DesktopPhysicalMetadata{}, mobilemultihop.DesktopPhysicalCapture{}, err
	}
	return mobilemultihop.ReadDesktopPhysicalPolicy(policy)
}

func validateDesktopOwnedImportedSourceContext(ctx context.Context, launch *desktopNodeLaunch, config string, meta mobilemultihop.DesktopPhysicalMetadata) error {
	if ctx == nil || ctx.Err() != nil || launch == nil || launch.ownedNode == nil || launch.ownedNode.imported == nil {
		return errors.New("native imported source has no original caller and typed owner")
	}
	owned := launch.ownedNode
	selection, policy := owned.imported.selection, owned.imported.policy
	capture := selection.Native
	if owned.policy != nil || policy == nil || capture == nil || !capture.imported || capture.validate(selection) != nil ||
		owned.host == nil || owned.host != capture.importedHost || owned.host.capture.dataRoot != launch.root || launch.root != capture.root ||
		!launch.importedEntry || launch.external != nil || launch.tor != nil || launch.profileID != selection.Exit.ID || launch.policyProfileID != selection.Control.ID ||
		launch.mode != selection.ExitMode || launch.endpoint != capture.endpoint || meta.Kind != "imported" || meta.TargetOS != "windows" ||
		meta.ConfigSHA256 != launch.configSHA256 || meta.SessionID != launch.mtuSession || config != policy.Config() {
		return errors.New("native imported source changed its original graph or derived session")
	}
	if err := desktopnetwork.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	retired, source := owned.retired, string(owned.source)
	launch.workspaceMu.Unlock()
	if retired || source != capture.importedInput {
		return errors.New("native imported source lost its exact private envelope")
	}
	metadata := policy.Metadata()
	original := policy.OriginalController()
	if original == nil || original.SourceSHA256() != capture.importedOriginalSource || metadata.OriginalSourceSHA256 != capture.importedOriginalSource ||
		metadata.EntryID != selection.Entry.ID || metadata.ExitID != selection.Exit.ID || metadata.ExitNodeID != selection.Exit.NodeProofID ||
		metadata.EntryMode != selection.EntryMode || metadata.ExitMode != selection.ExitMode {
		return errors.New("native imported source changed its independent entry or paired final")
	}
	envelope, err := original.ImportedLaunchInput()
	if err != nil || envelope != source {
		return errors.Join(err, errors.New("native imported source does not match its original constructor"))
	}
	return ctx.Err()
}

// MTU and other retained-runtime readers compare the actual file bytes with
// the protected derived config while retaining the separate original source.
// Neither equality alone grants process, network or measurement ownership.
func validateDesktopOwnedImportedConfigContext(ctx context.Context, launch *desktopNodeLaunch, actual []byte) error {
	if launch == nil || launch.ownedNode == nil || launch.ownedNode.imported == nil || len(actual) == 0 || len(actual) > 4<<20 {
		return errors.New("native imported config requires its typed bounded runtime")
	}
	config, meta, _, err := launch.ownedNode.physicalState()
	if err != nil || string(actual) != config {
		return errors.Join(err, errors.New("native imported config differs from its original derived policy"))
	}
	return validateDesktopOwnedImportedSourceContext(ctx, launch, config, meta)
}

func (owned *desktopOwnedNodeRuntime) sourceFile() (string, int) {
	if owned != nil && owned.chain != nil {
		return "node-chain-source.json", mobilemultihop.NodeChainInputLimit
	}
	if owned != nil && owned.imported != nil {
		return "imported-source.json", mobilemultihop.ImportedLaunchInputLimit
	}
	return "node-source.json", mobilemultihop.NodeLaunchInputLimit
}

func (owned *desktopOwnedNodeRuntime) networkContext(ctx context.Context) (string, error) {
	if owned != nil && owned.chain != nil {
		if owned.chain.selection.Native == nil || owned.chain.selection.Native.chain == nil ||
			owned.chain.selection.Native.chain.host == nil || owned.chain.selection.Native.chain.host.readNetwork == nil {
			return "", errors.New("ordered owner lost its original network observer")
		}
		return owned.chain.selection.Native.chain.host.readNetwork(ctx)
	}
	if owned != nil && owned.imported != nil {
		if owned.imported.readNetwork == nil {
			return "", errors.New("native imported owner lost its original network observer")
		}
		return owned.imported.readNetwork(ctx)
	}
	return physicalNetworkIdentityContext(ctx)
}

func (owned *desktopOwnedNodeRuntime) importedProtectionSlot(ctx context.Context, a *app) (*desktopNodeProtectionSlot, error) {
	if owned == nil || owned.imported == nil || owned.imported.app != a || owned.host == nil {
		return nil, errors.New("native imported protection lost its captured controller")
	}
	return desktopCapturedNodeProtectionSlot(ctx, a, owned.host)
}

func desktopCapturedNodeProtectionSlot(ctx context.Context, a *app, host *desktopNodeConnectionOwner) (*desktopNodeProtectionSlot, error) {
	if a == nil || host == nil {
		return nil, errors.New("native protection lost its captured controller")
	}
	if err := host.currentContext(ctx); err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	slot := a.nodeProtection
	a.mu.Unlock()
	if slot != nil {
		return slot, host.currentContext(ctx)
	}
	if host.capture.protectionBackend == nil {
		return nil, errors.New("native imported protection lost its original backend")
	}
	backend, err := host.capture.protectionBackend()
	if err != nil {
		return nil, err
	}
	if err := host.currentContext(ctx); err != nil {
		return nil, err
	}
	candidate := &desktopNodeProtectionSlot{backend: backend}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	if a.nodeProtection != nil || a.controllerClosingLocked() {
		a.mu.Unlock()
		return nil, errors.New("native imported protection cannot replace another application slot")
	}
	a.nodeProtection = candidate
	a.mu.Unlock()
	return candidate, host.currentContext(ctx)
}

func (owned *desktopOwnedNodeRuntime) importedSourceCurrentLocked(a *app) bool {
	if owned.imported == nil {
		return true
	}
	selection := owned.imported.selection
	if selection.Native == nil || !selection.Native.imported || a.profiles.SelectedID != selection.Control.ID {
		return false
	}
	for _, captured := range []common.RouterProfile{selection.Control, selection.Entry, selection.Exit} {
		actual, exists := a.profileByIDLocked(captured.ID)
		if !exists || mtuProfileSnapshotToken(actual) != mtuProfileSnapshotToken(captured) {
			return false
		}
	}
	return true
}

func (owned *desktopOwnedNodeRuntime) closeImportedConstructor() error {
	if owned == nil || owned.imported == nil {
		return nil
	}
	if owned.imported.policy == nil {
		return errors.New("native imported retirement lost its exact constructor")
	}
	original := owned.imported.policy.OriginalController()
	if original == nil {
		return errors.New("native imported retirement cannot substitute another constructor")
	}
	return original.Close()
}

func (a *app) desktopOwnedNodeCurrentFor(ctx context.Context, launch *desktopNodeLaunch, processRequired bool) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("native startup lost its original caller")
	}
	if launch != nil && launch.ownedNode != nil && (launch.ownedNode.imported != nil || launch.ownedNode.chain != nil) {
		return a.desktopOwnedNodeCurrentContext(ctx, launch, processRequired)
	}
	if !a.desktopOwnedNodeCurrent(launch, processRequired) {
		return errors.New("native startup lost its captured process or source")
	}
	return ctx.Err()
}

func captureDesktopImportedConnectionOwner(ctx context.Context, a *app, selection multihopSelection) (*desktopNodeConnectionOwner, error) {
	if selection.Entry.NodeKind != "external" || desktopOwnedNodeProtectionPolicy(selection.Control) == "off" {
		return nil, nil
	}
	host, err := a.desktopNodeConnectionHostContext(ctx)
	if err != nil || host == nil {
		return nil, err
	}
	if host.capture == nil || host.verify == nil || host.start == nil {
		return nil, errors.New("protected imported path requires its captured Windows controller")
	}
	capture, err := host.capture(a)
	if err != nil {
		return nil, err
	}
	owner := &desktopNodeConnectionOwner{host: *host, capture: capture}
	if err := owner.currentContext(ctx); err != nil {
		return nil, err
	}
	return owner, nil
}

// This derives the Windows lower path from the frozen private constructor,
// before any old connection is suspended. A restored graph keeps its captured
// controller/package but receives a fresh native session and later acquires
// the latest independently joined predecessor from the protection slot.
func prepareDesktopOwnedImportedLaunch(ctx context.Context, a *app, selection multihopSelection) (*desktopNodeLaunch, error) {
	return prepareDesktopOwnedImportedLaunchWith(ctx, a, selection, physicalNetworkIdentityContext)
}

func prepareDesktopOwnedImportedLaunchWith(ctx context.Context, a *app, selection multihopSelection,
	readNetwork func(context.Context) (string, error)) (_ *desktopNodeLaunch, failure error) {
	if ctx == nil || a == nil || readNetwork == nil || selection.Native == nil || !selection.Native.imported ||
		selection.Native.importedHost == nil || selection.Native.validate(selection) != nil || selection.Control.ID != selection.Exit.ID {
		return nil, errors.New("protected imported launch requires its exact captured entry, final and controller")
	}
	owner := selection.Native.importedHost
	if owner.capture.dataRoot != selection.Native.root {
		return nil, errors.New("protected imported graph belongs to another captured private root")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	operation := a.connectionContext
	a.mu.Unlock()
	current := func() error {
		if err := owner.currentContext(ctx); err != nil {
			return err
		}
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return err
		}
		err := a.checkCapturedConnectionOperationLocked(operation)
		a.mu.Unlock()
		return errors.Join(err, ctx.Err(), selection.Native.validate(selection))
	}
	if err := current(); err != nil {
		return nil, err
	}
	network, err := readNetwork(ctx)
	if err != nil || network == "" {
		return nil, errors.Join(err, errors.New("protected imported graph has no original physical network"))
	}
	original, err := mobilemultihop.ParseImportedLaunchInput(selection.Native.importedInput)
	if err != nil {
		return nil, err
	}
	defer func() {
		if failure != nil {
			_ = original.Close()
		}
	}()
	graph, _, err := nativeMultihopProofConfig(original.Config(), selection.Entry)
	if err != nil || original.SourceSHA256() != selection.Native.importedOriginalSource || graph != selection.Native.configs[selection.ExitMode] {
		return nil, errors.Join(err, errors.New("protected imported replay differs from its exact preflight source"))
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	policy, err := mobilemultihop.NewDesktopImportedPolicyWithMTU(original, session, "windows", selection.restoreMTU)
	if err != nil {
		return nil, err
	}
	meta := policy.Metadata()
	if meta.ProfileID != selection.Control.ID || meta.EntryID != selection.Entry.ID || meta.ExitID != selection.Exit.ID ||
		meta.EntryMode != selection.EntryMode || meta.ExitMode != selection.ExitMode || meta.ExitNodeID != selection.Exit.NodeProofID {
		return nil, errors.New("protected imported policy changed its original entry or paired final identity")
	}
	receipt, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	selection.Control, selection.Entry, selection.Exit = cloneRouterProfile(selection.Control), cloneRouterProfile(selection.Entry), cloneRouterProfile(selection.Exit)
	launch := &desktopNodeLaunch{root: selection.Native.root, endpoint: selection.Native.endpoint, profileID: selection.Exit.ID,
		policyProfileID: selection.Control.ID, mode: selection.ExitMode, config: []byte(policy.Config()), metadata: receipt,
		configSHA256: meta.ConfigSHA256, mtuSession: meta.SessionID, importedEntry: true,
		nodePhysicalEgress: append([]mobilemultihop.PhysicalEgress(nil), selection.Native.entryPhysical...),
		ownedNode: &desktopOwnedNodeRuntime{host: owner, source: []byte(selection.Native.importedInput), network: network,
			profileToken: desktopOwnedNodeProfileToken(selection.Control),
			options:      [3]bool{selection.Control.DAITAEnabled, selection.Control.JumboTUN, selection.Control.SocksEnabled}, operation: operation,
			imported: &desktopOwnedImportedRuntime{app: a, policy: policy, selection: selection, readNetwork: readNetwork}}}
	if selection.Native.openVPN != nil {
		launch.importedOpenVPN = &desktopImportedOpenVPNRuntime{spec: *selection.Native.openVPN, notBefore: time.Now().UnixMilli()}
	}
	after, networkErr := readNetwork(ctx)
	if err := errors.Join(current(), networkErr); err != nil || after != network {
		clear(launch.config)
		clear(launch.metadata)
		clear(launch.ownedNode.source)
		return nil, errors.Join(err, errors.New("protected imported preparation lost its captured network or caller"))
	}
	return launch, nil
}

func verifiedDesktopImportedPackage(ctx context.Context, owner *desktopNodeConnectionOwner) (string, error) {
	if owner == nil || owner.host.verify == nil || owner.currentContext(ctx) != nil {
		return "", errors.New("protected imported path lost its captured native package")
	}
	binary, err := owner.host.verify(ctx, owner.capture.packageRoot)
	if err != nil || filepath.Clean(binary) != filepath.Join(owner.capture.packageRoot, "runtime", "native", nativeBinaryName()) {
		return "", errors.Join(err, errors.New("protected imported path verified another native executable"))
	}
	return binary, owner.currentContext(ctx)
}

func startDesktopOwnedImportedLaunch(ctx, operation context.Context, a *app, launch *desktopNodeLaunch) error {
	if launch == nil || launch.ownedNode == nil || launch.ownedNode.imported == nil || launch.ownedNode.imported.app != a {
		return errors.New("protected imported startup lost its captured typed owner")
	}
	return startDesktopOwnedNodeLaunchFor(ctx, operation, a, launch,
		func(call context.Context, arguments, environment []string, directory string) (desktopNodeProcess, error) {
			owner := launch.ownedNode.host
			if owner == nil {
				return nil, errors.New("protected imported startup lost its captured native controller")
			}
			if err := owner.currentContext(call); err != nil {
				return nil, err
			}
			return owner.host.start(call, a, launch, arguments, environment, directory)
		})
}

// The caller holds a.mu. Register the exact partial native owner before child
// creation, and publish the same complete multihop identity in that transaction.
func (a *app) publishDesktopImportedMultihopStartLocked(operation context.Context, launch *desktopNodeLaunch, selection multihopSelection) error {
	if err := a.checkCapturedConnectionOperationLocked(operation); err != nil {
		return err
	}
	if launch == nil || launch.command == nil || launch.ownedNode == nil || launch.ownedNode.imported == nil || a.cmd != nil {
		return errors.New("protected multihop publication lost its unstarted native owner")
	}
	owned := launch.ownedNode
	if owned.imported.app != a || owned.imported.selection.Native != selection.Native || owned.operation != operation ||
		owned.slot == nil || owned.slot != a.nodeProtection || owned.attempt == nil || !owned.attempt.matchesOwned(owned) ||
		owned.attempt.launch != launch || !owned.importedSourceCurrentLocked(a) {
		return errors.New("protected multihop publication changed its captured source or operation")
	}
	if prior, exists := desktopNodeOwners.LoadOrStore(a, launch); exists && prior != launch {
		return errors.New("protected multihop publication cannot replace another native owner")
	}
	a.cmd = launch.command
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode = "multihop", "multihop", selection.ExitMode
	a.state.Base, a.state.RouterID = selection.Base, selection.Exit.ID
	a.state.Connected, a.state.Phase, a.state.LastError = false, "multihop:proving-local", ""
	a.state.DAITA, a.state.Jumbo, a.state.Socks = owned.options[0], owned.options[1], owned.options[2]
	return nil
}

func validateDesktopOwnedImportedRestore(ctx context.Context, a *app, owner *nativeMultihopRuntime) error {
	if owner == nil || owner.launch == nil || owner.launch.ownedNode == nil || owner.launch.ownedNode.imported == nil {
		return errors.New("protected imported restore lost its exact native owner")
	}
	launch, owned := owner.launch, owner.launch.ownedNode
	if owned.imported.app != a || owned.imported.selection.Native != owner.selection.Native ||
		owner.selection.Native == nil || owner.selection.Native.importedHost != owned.host {
		return errors.New("protected imported restore changed its captured source or controller")
	}
	if _, err := a.readDesktopOwnedNodeReadyContext(ctx, launch, false); err != nil {
		return err
	}
	config, _, _, err := owned.physicalState()
	if err != nil {
		return err
	}
	actualConfig, err := readDesktopRuntimeFileContext(ctx, launch, "sing-box.json", 4<<20)
	if err != nil || string(actualConfig) != config {
		clear(actualConfig)
		return errors.Join(err, errors.New("protected imported restore lost its exact running graph"))
	}
	if err := validateDesktopOwnedImportedConfigContext(ctx, launch, actualConfig); err != nil {
		clear(actualConfig)
		return err
	}
	clear(actualConfig)
	source, err := readDesktopRuntimeFileContext(ctx, launch, "imported-source.json", mobilemultihop.ImportedLaunchInputLimit)
	if err != nil || !bytes.Equal(source, owned.source) || string(source) != owner.selection.Native.importedInput {
		clear(source)
		return errors.Join(err, errors.New("protected imported restore lost its original private inputs"))
	}
	clear(source)
	return a.desktopOwnedNodeCurrentContext(ctx, launch, true)
}
