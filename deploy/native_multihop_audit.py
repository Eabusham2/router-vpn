"""Source-only closure for the public native multihop shipping adapters.

This is a bounded structural guard, not evidence of native runtime execution.
Comments and string contents cannot supply calls; calls must occur in the owned
handler, whose sole public wrapper installs the exact production adapters.
"""
from __future__ import annotations

import re

_TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|`[^`]*`|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z_0-9]*|\d+|[^\s]', re.S)


def _tokens(source: str) -> list[str]:
    return [m.group() for m in _TOKEN.finditer(source)
            if not m.group().startswith(("//", "/*"))]


def _positions(tokens: list[str], fragment: str) -> list[int]:
    wanted = _tokens(fragment)
    return [i for i in range(len(tokens) - len(wanted) + 1)
            if tokens[i:i + len(wanted)] == wanted]


def _function(tokens: list[str], declaration: str) -> list[str] | None:
    positions = _positions(tokens, declaration + " {")
    if len(positions) != 1:
        return None
    start = positions[0] + len(_tokens(declaration)) + 1
    depth = 1
    for end in range(start, len(tokens)):
        depth += (tokens[end] == "{") - (tokens[end] == "}")
        if depth == 0:
            return tokens[start:end]
    return None


def _ordered_once(tokens: list[str] | None, *fragments: str) -> bool:
    if tokens is None:
        return False
    previous = -1
    for fragment in fragments:
        matches = _positions(tokens, fragment)
        if len(matches) != 1 or matches[0] <= previous:
            return False
        previous = matches[0]
    return True


def native_multihop_ordered_owner(read) -> bool:
    """Trace complete source, concrete native owner and fresh typed child proof.

    This is structural source closure only; native accepted traffic is a
    separate required gate. Every dispatched branch keeps its original caller.
    """
    if not callable(read):
        return False
    expected = (
        ('cmd/client/desktop_node_chain_policy_dispatch.go', 'func (c *desktopNodeChainLaunch) hasPolicy() bool', r'''
	if c == nil {
		return false
	}
	return desktopNodeChainConcretePolicyCount(c.policy, c.socksPolicy, c.connectPolicy) == 1
        '''),
        ('cmd/client/desktop_node_chain_policy_dispatch.go', 'func desktopNodeChainConcretePolicyCount(chain *mobilemultihop.DesktopNodeChainPolicy, socks *mobilemultihop.DesktopNodeChainSOCKSPolicy, connect *mobilemultihop.DesktopNodeChainCONNECTPolicy) int', r'''
	count := 0
	for _, present := range []bool{chain != nil, socks != nil, connect != nil} {
		if present {
			count++
		}
	}
	return count
        '''),
        ('cmd/client/desktop_node_chain_policy_dispatch.go', 'func (c *desktopNodeChainLaunch) readPolicy() (string, mobilemultihop.DesktopNodeChainMetadata, mobilemultihop.DesktopPhysicalCapture, error)', r'''
	if !c.hasPolicy() {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, mobilemultihop.DesktopPhysicalCapture{}, errors.New("ordered parent lost its exclusive concrete policy")
	}
	if c.socksPolicy != nil {
		config, meta, capture, err := c.socksPolicy.ReadValidated()
		return config, meta.DesktopNodeChainMetadata, capture, err
	}
	if c.connectPolicy != nil {
		config, meta, capture, err := c.connectPolicy.ReadValidated()
		return config, meta.DesktopNodeChainMetadata, capture, err
	}
	return c.policy.ReadValidated()
        '''),
        ('cmd/client/desktop_node_chain_policy_dispatch.go', 'func (c *desktopNodeChainLaunch) readLaunchPolicy() (string, mobilemultihop.DesktopNodeChainMetadata, string, error)', r'''
	bad := errors.New("ordered launch lost its exact concrete original source")
	if !c.hasPolicy() || c.selection.Native == nil || c.selection.Native.chain == nil {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, "", bad
	}
	original := c.selection.Native.chain
	if c.connectPolicy != nil {
		if original.connect == nil || original.chain != nil || original.socks != nil {
			return "", mobilemultihop.DesktopNodeChainMetadata{}, "", bad
		}
		capture, err := c.connectPolicy.ReadValidatedLaunch()
		if err != nil || capture.Original != original.connect.source {
			return "", mobilemultihop.DesktopNodeChainMetadata{}, "", errors.Join(err, bad)
		}
		return capture.Config, capture.Metadata.DesktopNodeChainMetadata, capture.Input, nil
	}
	if c.socksPolicy != nil {
		if original.socks == nil || original.chain != nil || original.connect != nil {
			return "", mobilemultihop.DesktopNodeChainMetadata{}, "", bad
		}
		capture, err := c.socksPolicy.ReadValidatedLaunch()
		if err != nil || capture.Original != original.socks.source {
			return "", mobilemultihop.DesktopNodeChainMetadata{}, "", errors.Join(err, bad)
		}
		return capture.Config, capture.Metadata.DesktopNodeChainMetadata, capture.Input, nil
	}
	if original.socks != nil || original.connect != nil || original.chain == nil {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, "", bad
	}
	capture, err := c.policy.ReadValidatedLaunch()
	if err != nil || capture.Original != original.chain {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, "", errors.Join(err, bad)
	}
	return capture.Config, capture.Metadata, capture.Input, nil
        '''),
        ('cmd/client/desktop_node_chain_policy_dispatch.go', 'func (c *desktopNodeChainLaunch) policyMetadata() mobilemultihop.DesktopNodeChainMetadata', r'''
	_, meta, _, _ := c.readPolicy()
	return meta
        '''),
        ('cmd/client/desktop_node_chain_dispatch.go', 'func proveDesktopNodeChainContext(ctx context.Context, a *app, selection multihopSelection, command *exec.Cmd) error', r'''
graph, found := getActiveMultihopGraph(a)
	owner, err := capturedNativeMultihopRuntimeContext(ctx, a, command, graph)
	if err != nil || !found || owner == nil || owner.launch.chain == nil || owner.selection.Native != selection.Native ||
		owner.launch.chain.selection.Native != selection.Native || graph.ChainNodes != len(selection.Nodes) || graph.Execution != "local" {
		return errors.Join(err, errors.New("ordered native proof lost its full original runtime"))
	}
	if owner.launch.chain.platform != nil {
		return owner.launch.chain.platform.prove(ctx)
	}
	// The typed child owns all prefix authentication and the selected final DNS
	// proof. Its fresh heartbeat is checked alongside the actual native reader;
	// the legacy pair's loopback proof listeners are not part of this graph.
	if _, err := a.readDesktopOwnedNodeReadyContext(ctx, owner.launch, false); err != nil {
		return err
	}
	return desktopNodeChainCurrent(ctx, a, owner.launch)
        '''),
        ('cmd/client/desktop_node_chain_host.go', 'func desktopNodeChainCurrent(ctx context.Context, a *app, launch *desktopNodeLaunch) error', r'''
if launch == nil || launch.chain == nil {
		return errors.New("ordered observation lost its original launch")
	}
	if launch.chain.platform != nil {
		return launch.chain.platform.current(ctx)
	}
	if a == nil || launch.ownedNode == nil || launch.ownedNode.chain != launch.chain {
		return errors.New("ordered observation changed its original native owner")
	}
	if err := a.desktopOwnedNodeCurrentContext(ctx, launch, true); err != nil {
		return err
	}
	launch.workspaceMu.Lock()
	ready := launch.ownedNode.ready != nil
	launch.workspaceMu.Unlock()
	if ready {
		_, err := a.readDesktopOwnedNodeReadyContext(ctx, launch, false)
		return err
	}
	return nil
        '''),
        ('cmd/client/desktop_node_chain_host.go', 'func (s *desktopNodeChainSources) currentLocked(a *app) error', r'''
if s == nil || a == nil || s.selection.Native == nil || s.selection.Native.chain == nil ||
		s.selected != s.selection.Control.ID || a.profiles.SelectedID != s.selected ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != s.options ||
		s.options != [3]bool{s.selection.Control.DAITAEnabled, s.selection.Control.JumboTUN, s.selection.Control.SocksEnabled} {
		return errors.New("ordered host changed its final control or runtime options")
	}
	if !s.selection.Native.chain.profilesCurrent(s.selection.Control, a.profiles.Profiles) {
		return errors.New("ordered host changed a selected member's complete saved source")
	}
	return nil
        '''),
        ('cmd/client/desktop_node_chain_host.go', 'func (capture *desktopNodeChainHostCapture) current(ctx context.Context) error', r'''
if ctx == nil || ctx.Err() != nil || capture == nil || capture.app == nil || capture.sources == nil ||
		capture.readNetwork == nil || (capture.windows == nil) == (capture.platform == nil) {
		return errors.New("ordered host lost its one concrete original controller")
	}
	var err error
	if capture.windows != nil {
		err = capture.windows.currentContext(ctx)
	} else {
		err = capture.platform.current(ctx)
	}
	if err != nil {
		return err
	}
	network, err := capture.readNetwork(ctx)
	if err != nil || network != capture.network || network == "" {
		return errors.Join(err, errors.New("ordered host changed its original physical network"))
	}
	if err := desktopnetwork.LockContext(ctx, &capture.app.mu); err != nil {
		return err
	}
	defer capture.app.mu.Unlock()
	return capture.sources.currentLocked(capture.app)
        '''),
        ('cmd/client/desktop_node_chain_linux.go', 'func (owner *desktopNodeChainPlatformRuntime) current(ctx context.Context) error', r'''
if owner == nil || owner.session == nil || owner.host == nil {
		return errors.New("Linux ordered observation lost its retained session")
	}
	s, h := owner.session, owner.host
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if s.active != h || s.journal == nil || h.transaction == nil || h.transaction.journal != s.journal {
		return errors.New("Linux ordered observation belongs to a replaced native session")
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.runningPolicyLocked(ctx); err != nil {
		return err
	}
	if h.ready != nil {
		_, _, err := h.readReadyLocked(ctx, false)
		return err
	}
	return nil
        '''),
        ('cmd/client/desktop_node_chain_linux.go', 'func (owner *desktopNodeChainPlatformRuntime) prove(ctx context.Context) error', r'''
if owner == nil || owner.host == nil {
		return errors.New("Linux ordered proof has no original host")
	}
	if err := owner.host.enter(ctx); err != nil {
		return err
	}
	active := owner.host.activation != nil
	owner.host.gate <- struct{}{}
	if active {
		return owner.current(ctx)
	}
	if _, err := owner.host.WaitReady(ctx); err != nil {
		return err
	}
	_, err := owner.host.Prove(ctx)
	return err
        '''),
        ('cmd/client/desktop_node_chain_linux.go', 'func (h *desktopLinuxNodeHost) currentNodeChain(ctx context.Context) error', r'''
if h == nil || ctx == nil || ctx.Err() != nil || h.closing || h.closed || h.operation == nil || h.parent == nil ||
		(h.chain == nil && h.socksChain == nil && h.connectChain == nil) || h.policy != nil || h.imported != nil || h.external != nil || h.launch == nil || h.launch.chain == nil ||
		!h.launch.chain.hasPolicy() || h.launch.chain.policy != h.chain || h.launch.chain.socksPolicy != h.socksChain || h.launch.chain.connectPolicy != h.connectChain || h.launch.chain.platform == nil || h.launch.ownedNode != nil {
		return errors.New("Linux ordered host lost its unique concrete policy")
	}
	runtime := h.launch.chain.platform
	if runtime.host != h || runtime.capture == nil || h.launch.chain.capture != runtime.capture ||
		h.launch.chain.selection.Native.chain.host != runtime.capture || runtime.capture.platform == nil || runtime.capture.platform.parent != h.parent ||
		runtime.capture.app != h.parent.app || runtime.capture.sources == nil ||
		runtime.capture.sources.selection.Native != h.launch.chain.selection.Native {
		return errors.New("Linux ordered host substituted its captured parent or full source")
	}
	if err := runtime.capture.current(ctx); err != nil {
		return err
	}
	if err := validateDesktopNodeChainLaunch(ctx, h.launch); err != nil {
		return err
	}
	meta := h.launch.chain.policyMetadata()
	wanted := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
		ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	if meta.TargetOS != "linux" || h.selection != wanted || string(h.source) != h.launch.chain.input || h.network != runtime.capture.network {
		return errors.New("Linux ordered host changed its native protection or projected source")
	}
	if h.activation != nil {
		if err := h.activation.matches(h); err != nil {
			return err
		}
	} else if h.operation.Err() != nil {
		return errConnectionOperationCancelled
	}
	a := h.parent.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if h.activation == nil {
		if a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.connectionCancelIntent == h.operation {
			return errConnectionOperationCancelled
		}
	} else if h.process == nil || a.cmd != h.process.command || a.state.RouterID != meta.ProfileID || a.state.RuntimeMode != meta.Mode {
		return errors.New("Linux ordered activation belongs to a replaced connection")
	}
	return runtime.capture.sources.currentLocked(a)
        '''),
        ('cmd/client/desktop_node_chain_dispatch.go', 'func desktopMultihopPlatformLaunch(launch *desktopNodeLaunch) bool', r'''
return launch != nil && (launch.importedPlatform != nil || launch.chain != nil && launch.chain.platform != nil)
        '''),
        ('cmd/client/desktop_node_chain_dispatch.go', 'func startDesktopMultihopPlatform(ctx context.Context, a *app, selection multihopSelection, launch *desktopNodeLaunch) error', r'''
if launch == nil || launch.chain == nil {
		return startDesktopImportedPlatform(ctx, a, selection, launch)
	}
	if launch.chain.platform == nil || selection.Native == nil || selection.Native.chain == nil || launch.chain.selection.Native != selection.Native {
		return errors.New("ordered platform startup lost its exact original source")
	}
	budget, err := desktopNodeReadyBudget(launch)
	if err != nil {
		return err
	}
	startup, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if err := launch.chain.platform.start(startup); err != nil {
		return err
	}
	if launch.command == nil {
		return errors.New("ordered platform startup returned no original created command")
	}
	if err := launch.chain.platform.current(ctx); err != nil {
		return err
	}
	return registerActiveDNSRuntimeConfigKind(a, selection.Exit.ID, selection.ExitMode, filepath.Join(launch.directory, "sing-box.json"), true)
        '''),
        ('cmd/client/desktop_node_chain_dispatch.go', 'func (a *app) publishDesktopCapturedMultihopStartLocked(operation context.Context, launch *desktopNodeLaunch, selection multihopSelection) error', r'''
if launch != nil && launch.chain != nil {
		return a.publishDesktopNodeChainStartLocked(operation, launch, selection)
	}
	return a.publishDesktopImportedMultihopStartLocked(operation, launch, selection)
        '''),
        ('cmd/client/desktop_node_chain_dispatch.go', 'func startDesktopCapturedMultihopOwned(ctx, operation context.Context, a *app, launch *desktopNodeLaunch) error', r'''
if launch != nil && launch.chain != nil {
		return startDesktopOwnedNodeChainLaunch(ctx, operation, a, launch)
	}
	return startDesktopOwnedImportedLaunch(ctx, operation, a, launch)
        '''),
        ('cmd/client/desktop_node_chain_dispatch.go', 'func activateDesktopMultihopPlatform(ctx context.Context, launch *desktopNodeLaunch) error', r'''
if launch != nil && launch.chain != nil && launch.chain.platform != nil {
		return launch.chain.platform.activate(ctx)
	}
	if launch == nil || launch.importedPlatform == nil {
		return errors.New("native platform activation lost its original launch")
	}
	return launch.importedPlatform.Activate(ctx)
        '''),
        ('cmd/client/desktop_node_chain_dispatch.go', 'func closeDesktopMultihopPlatform(ctx context.Context, a *app, launch *desktopNodeLaunch) error', r'''
if launch != nil && launch.chain != nil {
		return closeDesktopNodeChainLaunch(ctx, a, launch)
	}
	if launch == nil || launch.importedPlatform == nil {
		return errors.New("native platform retirement lost its original launch")
	}
	return launch.importedPlatform.Close(ctx)
        '''),
    )
    sources = {path: _tokens(read(path)) for path, _, _ in expected}
    return all(_function(sources[path], declaration) == _tokens(body)
               for path, declaration, body in expected)


def native_multihop_platform_chain(read) -> bool:
    """Trace the concrete Linux owner; an arbitrary interface is not proof.

    This is source closure only. It neither opens public Linux admission nor
    awards native execution credit; the installed-host runner owns that gate.
    """
    if not callable(read):
        return False
    def function(path, declaration):
        return _function(_tokens(read("cmd/client/" + path)), declaration)
    start = function("desktop_imported_platform.go", "func startDesktopImportedPlatform(ctx context.Context, a *app, sel multihopSelection, launch *desktopNodeLaunch) error")
    current = function("desktop_imported_linux_lifecycle.go", "func (owner *desktopLinuxImportedConnection) Current(ctx context.Context) error")
    prove = function("desktop_imported_linux_lifecycle.go", "func (owner *desktopLinuxImportedConnection) Prove(ctx context.Context) error")
    native_prove = function("desktop_imported_linux_lifecycle.go", "func (h *desktopLinuxNodeHost) proveImportedLocked(parent context.Context) (elapsed time.Duration, failure error)")
    activate = function("desktop_imported_linux_lifecycle.go", "func (owner *desktopLinuxImportedConnection) Activate(ctx context.Context) error")
    guard = function("desktop_imported_linux_lifecycle.go", "func guardDesktopImportedPlatformTransition(ctx context.Context, a *app, launch *desktopNodeLaunch) error")
    common_guard = function("desktop_node_owned.go", "func (a *app) guardDesktopOwnedNodeTransitionContext(ctx context.Context, next *desktopNodeLaunch) error")
    launch = function("multihop_native_launch.go", "func nativeMultihopLaunchCurrent(ctx context.Context, a *app, launch *desktopNodeLaunch) error")
    prepare = function("desktop_imported_linux_host.go", "func (capture *desktopLinuxImportedCapture) Prepare(ctx context.Context, a *app, sel multihopSelection) (launch *desktopNodeLaunch, failure error)")
    return (
        native_multihop_ordered_owner(read)
        and start == _tokens('''
            if launch == nil || launch.importedPlatform == nil || sel.Native == nil || !sel.Native.imported {
                return errors.New("imported startup lost its original typed host")
            }
            if err := launch.importedPlatform.Start(ctx); err != nil { return err }
            if launch.command == nil { return errors.New("imported startup returned no original created command") }
            if err := launch.importedPlatform.Current(ctx); err != nil { return err }
            return registerActiveDNSRuntimeConfigKind(a, sel.Exit.ID, sel.ExitMode, filepath.Join(launch.directory, "sing-box.json"), true)
        ''')
        and current == _tokens('''
            if owner == nil || owner.session == nil || owner.host == nil { return errors.New("Linux imported observation lost its original session") }
            s, h := owner.session, owner.host
            if err := s.enter(ctx); err != nil { return err }
            defer func() { s.gate <- struct{}{} }()
            if err := s.currentLocked(ctx); err != nil { return err }
            if s.active != h || s.journal == nil || h.transaction == nil || h.transaction.journal != s.journal {
                return errors.New("Linux imported observation belongs to a replaced session")
            }
            if err := h.enter(ctx); err != nil { return err }
            defer func() { h.gate <- struct{}{} }()
            if err := h.runningPolicyLocked(ctx); err != nil { return err }
            if h.ready != nil {
                _, _, err := h.readReadyLocked(ctx, false)
                return err
            }
            return nil
        ''')
        and prove == _tokens('''
            if owner == nil || owner.host == nil { return errors.New("Linux imported proof has no original host") }
            if err := owner.host.enter(ctx); err != nil { return err }
            active := owner.host.activation != nil
            owner.host.gate <- struct{}{}
            if active {
                if err := owner.Current(ctx); err != nil { return err }
                if err := proveNativeMultihopCapture(ctx, owner.selection, func() bool { return owner.Current(ctx) == nil }, proveNativeMultihopLaneContext); err != nil { return err }
                if _, err := owner.host.parent.app.proveImportedNativeDNS(ctx, owner.selection, owner.host.launch.command); err != nil { return err }
                return owner.Current(ctx)
            }
            if _, err := owner.host.WaitReady(ctx); err != nil { return err }
            _, err := owner.host.Prove(ctx)
            return err
        ''')
        and _ordered_once(native_prove,
            'owner, ok := h.launch.importedPlatform.(*desktopLinuxImportedConnection)',
            'if !ok || owner.host != h {',
            'ready, live, err := h.readReadyLocked(parent, false)',
            'ctx, cancel := context.WithTimeout(parent, time.Duration(seconds)*time.Second)',
            'stop := context.AfterFunc(h.operation, cancel)',
            'after, next, err := h.readReadyLocked(call, false)',
            'if err != nil || after != ready || !sameDesktopLinuxNodeProofTUN(live, next) {',
            'if err := proveNativeMultihopCapture(ctx, owner.selection, func() bool { return current(ctx) == nil }, proveNativeMultihopLaneContext); err != nil { return 0, err }',
            'selected, err := expectedDNSSelection(owner.selection.Exit)',
            '''if _, err := exchangeDesktopImportedDNS(ctx, h.launch, func(call context.Context) error {
                if err := current(call); err != nil { return err }
                return verifySingBoxDNSConfigBytes(h.launch.config, selected)
            }); err != nil { return 0, err }''',
            'if err := current(ctx); err != nil { return 0, err }',
            'h.proof = &desktopLinuxNodeProof{ready: ready, live: live, provedAt: time.Now(), elapsed: elapsed}')
        and activate == _tokens('''
            if owner == nil || owner.host == nil || owner.session == nil { return errors.New("Linux imported activation has no original session") }
            if err := owner.host.Activate(ctx); err != nil { return err }
            return owner.session.Monitor(ctx, owner.host)
        ''')
        and _ordered_once(guard,
            'owner, ok := launch.importedPlatform.(*desktopLinuxImportedConnection)',
            '''if !ok || owner == nil || !owner.registered || owner.host == nil || owner.host.launch != launch ||
                owner.session == nil || owner.capture == nil || owner.capture.parent == nil || owner.capture.parent.app != a ||
                owner.host.parent != owner.capture.parent || owner.selection.Native == nil || owner.selection.Native.importedPlatform != owner.capture ||
                launch.ownedNode != nil || launch.external != nil { return errors.New("Linux imported transition changed its concrete original host") }''',
            'if err := s.enter(ctx); err != nil { return err }',
            'if err := s.currentLocked(ctx); err != nil { return err }',
            '_, retained := p.dependents[h]',
            'if !retained { return errors.New("Linux imported transition lost its original parent cleanup registration") }',
            'return h.CheckLegacyTransition(ctx)')
        and _ordered_once(common_guard,
            '''if next != nil && next.importedPlatform != nil { return guardDesktopImportedPlatformTransition(ctx, a, next) }''',
            'if err := a.guardDesktopLinuxNodeLegacyTransitionContext(ctx); err != nil { return err }')
        and launch == _tokens('''
            if launch == nil { return errors.New("multihop observation lost its original launch") }
            if launch.chain != nil {
                if launch.ownedNode != nil && !desktopOwnedNodeCreated(launch) {
                    return a.desktopOwnedNodeCurrentContext(ctx, launch, false)
                }
                return desktopNodeChainCurrent(ctx, a, launch)
            }
            if launch.importedPlatform != nil { return launch.importedPlatform.Current(ctx) }
            if current, found := desktopNodeOwners.Load(a); !found || current != launch { return errors.New("multihop system TUN owner was replaced") }
            return ctx.Err()
        ''')
        and _ordered_once(prepare,
            'sel.Native.importedPlatform != capture',
            'sel.Native.validate(sel) != nil || !desktopLinuxImportedEligible(sel)',
            'capture.sources.currentLocked(a, false)',
            'original, err := mobilemultihop.ParseImportedLaunchInput(sel.Native.importedInput)',
            'policy, err := mobilemultihop.NewDesktopImportedPolicyWithMTU(original, sessionID, "linux", sel.restoreMTU)',
            'p.dependents[h] = struct{}{}',
            'owner.session, err = captureDesktopLinuxNodeSession(ctx, a)',
            'if err := h.CheckLegacyTransition(ctx); err != nil { return launch, err }',
            'return launch, h.current(ctx)')
    )


def native_multihop_proof_lanes(source: str, imported_source: str) -> bool:
    """Source-only closure of both compiler captures and their exact proof routes."""
    tokens, imported = _tokens(source), _tokens(imported_source)
    capture = _function(tokens, "func captureNativeMultihopSelection(ctx context.Context, root string, sel multihopSelection, modes []string, lookup applexray.Lookup) (multihopSelection, error)")
    imported_wrapper = _function(imported, "func captureDesktopImportedMultihop(ctx context.Context, root string, sel multihopSelection, modes []string, lookup applexray.Lookup) (multihopSelection, error)")
    imported_capture = _function(imported, "func captureDesktopImportedMultihopWithHost(ctx context.Context, root string, sel multihopSelection, modes []string, lookup applexray.Lookup, host *desktopNodeConnectionOwner) (multihopSelection, error)")
    protected_capture = _function(tokens, "func captureNativeMultihopForAppContext(parent context.Context, a *app, sel multihopSelection, modes []string) (multihopSelection, error)")
    graph = _function(tokens, "func nativeMultihopProofConfig(config string, entry common.RouterProfile) (string, string, error)")
    return (
        _ordered_once(capture, '''
            if sel.Entry.NodeKind == "external" {
                return captureDesktopImportedMultihop(ctx, root, sel, modes, lookup)
            }
        ''', "config, _, e = nativeMultihopProofConfig(config, sel.Entry)")
        and imported_wrapper == _tokens("return captureDesktopImportedMultihopWithHost(ctx, root, sel, modes, lookup, nil)")
        and _ordered_once(protected_capture,
            "owner, err := captureDesktopImportedConnectionOwner(parent, a, sel)",
            "if owner != nil {",
            "verifiedDesktopImportedPackage(ctx, owner)",
            "captured, err := captureDesktopImportedMultihopWithHost(ctx, owner.capture.dataRoot, sel, modes, owner.host.lookup, owner)",
            "owner.currentContext(ctx)",
            "return captured, nil")
        and _ordered_once(imported_capture,
            "compiled, err := mobilemultihop.NewImportedEntry(source, capture, sel.ExitMode, encodeDesktopNodeAssets(files), string(rawFinal), startJSON, bootstrap)",
            "config, _, err := nativeMultihopProofConfig(compiled.Config(), sel.Entry)",
            "c.configs[sel.ExitMode] = config")
        and graph is not None and graph.count("entryProofTag") == 3
        and _ordered_once(graph, '''
            imported := entry.NodeKind == "external" && entry.External != nil
            if imported && ok && len(ins) == 2 {
                proof, valid := ins[1].(map[string]any)
                if !valid || len(proof) != 4 || proof["type"] != "mixed" || proof["tag"] != "routervpn-proof" || proof["listen"] != "127.0.0.1" || proof["listen_port"] != float64(1099) {
                    return "", "", errors.New("imported final proof listener differs from its compiler owner")
                }
                ins = ins[:1]
            }
        ''', '''
            if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
                return "", "", errors.New("native multihop interface is not protected")
            }
        ''', '''
            entryProofTag := "entry-wg"
            var private map[string]any
            if !imported {
                var err error
                private, err = nativeEntryPrivateOutbound(entry.SocksHost, entry.SocksPort, entry.SocksUsername, entry.SocksPassword)
                if err != nil { return "", "", err }
                entryProofTag = "entry-private"
            }
        ''', '''
            if !ok || route["final"] != "proxy" {
                return "", "", errors.New("native multihop final owner is missing")
            }
        ''', '''
            if !imported { graph["outbounds"] = append(outs, private) }
            graph["inbounds"] = append(ins,
                map[string]any{"type": "mixed", "tag": "multihop-entry-proof", "listen": "127.0.0.1", "listen_port": nativeMultihopEntryProofPort},
                map[string]any{"type": "mixed", "tag": "multihop-proof", "listen": "127.0.0.1", "listen_port": nativeMultihopExitProofPort},
            )
            route["rules"] = append([]any{
                map[string]any{"inbound": []any{"multihop-entry-proof"}, "outbound": entryProofTag},
                map[string]any{"inbound": []any{"multihop-proof"}, "outbound": "proxy"},
            }, rules...)
        ''')
    )


def native_multihop_proof_admission(source: str, imported_source: str, dns_source: str, read=None) -> bool:
    """Bounded source evidence: original owner, both node proofs, then imported DNS.

    These token checks do not earn live traffic or physical acceptance credit.
    Every call is scoped to its shipping function; comments, quoted witnesses,
    and a similarly named helper elsewhere cannot supply a missing branch.
    """
    tokens, imported, dns = _tokens(source), _tokens(imported_source), _tokens(dns_source)
    admission = _function(tokens, "func (a *app) proveNativeMultihop(sel multihopSelection, command *exec.Cmd) error")
    owner = _function(tokens, "func (a *app) nativeMultihopProofOwnerCurrentContext(ctx context.Context, sel multihopSelection, command *exec.Cmd) bool")
    proof = _function(tokens, "func proveNativeMultihopCapture(ctx context.Context, sel multihopSelection, owns func() bool, prove func(context.Context, common.RouterProfile, string) error) error")
    lane = _function(imported, "func proveNativeMultihopLaneContext(ctx context.Context, profile common.RouterProfile, proxy string) error")
    selected_dns = _function(dns, "func (a *app) proveImportedNativeDNS(parent context.Context, selection multihopSelection, command *exec.Cmd) (float64, error)")
    captured_profiles = _function(_tokens(read("cmd/client/multihop_node_chain_selection.go")),
        "func nativeMultihopCapturedProfiles(selection multihopSelection) []common.RouterProfile") if callable(read) else None
    return (
        native_multihop_platform_chain(read)
        and admission == _tokens('''
            ctx, cancel := context.WithTimeout(a.connectionOperationContextOrBackground(), nativeMultihopProofTimeout(sel))
            defer cancel()
            if sel.Native != nil && sel.Native.chain != nil {
                return proveDesktopNodeChainContext(ctx, a, sel, command)
            }
            if sel.Native != nil && sel.Native.importedPlatform != nil {
                graph, found := getActiveMultihopGraph(a)
                owner, err := capturedNativeMultihopRuntimeContext(ctx, a, command, graph)
                if err != nil || !found || owner.selection.Native != sel.Native || owner.launch.importedPlatform == nil {
                    return errors.Join(err, errors.New("Linux imported proof lost its original runtime"))
                }
                return owner.launch.importedPlatform.Prove(ctx)
            }
            current := func() bool { return a.nativeMultihopProofOwnerCurrentContext(ctx, sel, command) && a.observeImportedOpenVPN(ctx, sel, command) == nil }
            if err := proveNativeMultihopCapture(ctx, sel, current, proveNativeMultihopLaneContext); err != nil { return err }
            if sel.Native.imported {
                if _, err := a.proveImportedNativeDNS(ctx, sel, command); err != nil { return err }
            }
            if ctx.Err() != nil || !current() { return errors.New("native multihop proof completed for a retired source or runtime") }
            return nil
        ''')
        and owner == _tokens('''
            if ctx == nil || ctx.Err() != nil || sel.Native == nil || mobilemtu.LockContext(ctx, &a.mu) != nil { return false }
            owned := command != nil && a.cmd == command && !a.closing
            selected := a.profiles.SelectedID == sel.Control.ID
            if sel.Native.imported || sel.Native.chain != nil {
                for _, captured := range nativeMultihopCapturedProfiles(sel) {
                    current, ok := a.profileByIDLocked(captured.ID)
                    owned = owned && ok && mtuProfileSnapshotToken(current) == mtuProfileSnapshotToken(captured)
                }
            }
            a.mu.Unlock()
            if !owned { return false }
            if !sel.Native.imported && sel.Native.chain == nil { return true }
            if sel.Native.chain != nil {
                raw, found := nativeMultihopOwners.Load(a)
                owner, valid := raw.(*nativeMultihopRuntime)
                if !found || !valid || owner == nil || owner.launch == nil || owner.launch.command != command || owner.selection.Native != sel.Native ||
                    owner.launch.chain == nil || desktopNodeChainCurrent(ctx, a, owner.launch) != nil { return false }
            }
            if sel.Native.importedPlatform != nil {
                raw, found := nativeMultihopOwners.Load(a)
                owner, valid := raw.(*nativeMultihopRuntime)
                if !found || !valid || owner == nil || owner.launch == nil || owner.launch.command != command || owner.selection.Native != sel.Native ||
                    owner.launch.importedPlatform == nil || owner.launch.importedPlatform.Current(ctx) != nil {
                    return false
                }
            }
            return selected && sel.Native.validate(sel) == nil && ctx.Err() == nil
        ''')
        # The existing paired capture still checks Control/Entry/Exit. An
        # ordered capture must retain every original profile in order; tracing
        # this helper is separate from the typed native owner and child heartbeat checks.
        and captured_profiles == _tokens('''
            profiles := []common.RouterProfile{selection.Control}
            if len(selection.Nodes) == 0 {
                return append(profiles, selection.Entry, selection.Exit)
            }
            for _, member := range selection.Nodes {
                profiles = append(profiles, member.Profile)
            }
            return profiles
        ''')
        and _ordered_once(proof,
            'if ctx.Err() != nil { return ctx.Err() }',
            '''if !owns() || sel.Native == nil || sel.Native.validate(sel) != nil {
                return errors.New("native multihop lost its captured source or runtime before proof")
            }''',
            'err := prove(ctx, sel.Entry, multihopEntryProofProxy)',
            '''if err == nil {
                if ctx.Err() != nil || !owns() || sel.Native.validate(sel) != nil {
                    return errors.New("native multihop entry proof completed for a retired capture")
                }
                err = prove(ctx, sel.Exit, multihopProofProxy)
            }''',
            'if err == nil && ctx.Err() == nil && owns() && sel.Native.validate(sel) == nil { return nil }')
        and lane == _tokens('''
            if profile.NodeKind != "external" { return proveMultihopLaneNodeContext(ctx, profile, proxy) }
            if profile.External == nil || !desktopImportedEntryProtocol(profile.External.Protocol) || proxy != multihopEntryProofProxy {
                return errors.New("imported entry proof has no exact original entry lane")
            }
            client, closeIdle, err := newMultihopLaneHTTPClient(proxy, 2500*time.Millisecond)
            if err != nil { return err }
            defer closeIdle()
            return proveExpectedPublicExit(ctx, client, publicExitProofProviders, profile.External.ExpectedPublicIP, "imported entry", 3*time.Second)
        ''')
        and selected_dns == _tokens('''
            if selection.Native == nil || !selection.Native.imported {
                return 0, errors.New("selected final DNS has no original imported graph")
            }
            graph, ok := getActiveMultihopGraph(a)
            owner, err := capturedNativeMultihopRuntimeContext(parent, a, command, graph)
            if !ok || err != nil || owner.selection.Native != selection.Native || !owner.launch.importedEntry {
                return 0, errors.New("selected final DNS has no retained original process")
            }
            current := func(ctx context.Context) error {
                if ctx.Err() != nil || !a.nativeMultihopProofOwnerCurrentContext(ctx, selection, command) || desktopNodeProcessExited(owner.launch) {
                    return errors.New("selected final DNS lost its current source or process")
                }
                actual, err := capturedNativeMultihopRuntimeContext(ctx, a, command, graph)
                if err != nil || actual != owner {
                    return errors.New("selected final DNS lost its original network generation")
                }
                selected, err := expectedDNSSelection(selection.Exit)
                if err != nil { return err }
                raw, err := readDesktopRuntimeFileContext(ctx, owner.launch, "sing-box.json", 4<<20)
                if err != nil { return err }
                return verifySingBoxDNSConfigBytes(raw, selected)
            }
            if err := a.observeImportedOpenVPN(parent, selection, command); err != nil { return 0, err }
            elapsed, err := exchangeDesktopImportedDNS(parent, owner.launch, current)
            if err != nil { return 0, err }
            if err := a.observeImportedOpenVPN(parent, selection, command); err != nil { return 0, err }
            return elapsed, parent.Err()
        ''')
    )


def native_multihop_request_admission(read) -> bool:
    """Bind canonical public input to the original complete catalog snapshot.

    This remains a structural source guard. Unique, scoped function bodies keep
    duplicate/comment/string decoys from supplying strict decoding or revision
    ownership; executable HTTP and native-owner gates remain separate evidence.
    """
    if not callable(read):
        return False
    expected = (
        ('cmd/client/multihop_node_chain_request.go', 'func (q multihopConnectRequest) ordered() bool', r'''
return q.nodesPresent || q.Nodes != nil
        '''),
        ('cmd/client/multihop_node_chain_request.go', 'func (q multihopConnectRequest) validateOrdered() error', r'''
if !q.ordered() {
	return nil
}
if q.Execution != "local" || q.EntryID != "" || q.ExitID != "" || q.Base != "" || q.EntryMode != "" || q.ExitMode != "" ||
	q.ExpectedSelectedNodeID == nil || *q.ExpectedSelectedNodeID == "" || q.ExpectedProfileTokens == nil {
	return errors.New("ordered Connect requires one explicit Local path and its complete original node revisions")
}
if err := common.ValidateMultihopNodes(q.Nodes); err != nil {
	return err
}
if q.Nodes[len(q.Nodes)-1].ID != *q.ExpectedSelectedNodeID {
	return errors.New("ordered Connect must end at its original selected node")
}
return nil
        '''),
        ('cmd/client/multihop_node_chain_request.go', 'func (q *multihopConnectRequest) UnmarshalJSON(data []byte) error', r'''
fields, err := externalConnectJSONObject(data)
if err != nil {
	return err
}
capture, err := decodeDesktopProfileExpectations(fields)
if err != nil {
	return err
}
for name := range fields {
	if name != "nodes" && strings.EqualFold(name, "nodes") {
		return errors.New("ordered nodes must use their canonical JSON field")
	}
}
rawNodes, ordered := fields["nodes"]
if ordered {
	for name := range fields {
		switch name {
		case "nodes", "execution", "expected_selected_node_id", "expected_profile_tokens":
		default:
			return errors.New("ordered Connect cannot mix another selection or an unknown field")
		}
	}
	var rows []json.RawMessage
	if json.Unmarshal(rawNodes, &rows) != nil || len(rows) < 2 || len(rows) > common.MultihopMaximumNodes {
		return errors.New("ordered Connect requires a bounded complete node array")
	}
	for _, raw := range rows {
		row, err := externalConnectJSONObject(raw)
		if err != nil || len(row) != 2 || row["id"] == nil || row["mode"] == nil {
			return errors.New("ordered node rows require only canonical identity and mode fields")
		}
	}
}
type wire multihopConnectRequest
var decoded wire
if err := json.Unmarshal(data, &decoded); err != nil {
	return err
}
decoded.desktopProfileExpectations, decoded.nodesPresent = capture, ordered
result := multihopConnectRequest(decoded)
if err := result.validateOrdered(); err != nil {
	return err
}
*q = result
return nil
        '''),
        ('cmd/client/multihop_node_chain_request.go', 'func decodeMultihopConnectRequest(body io.Reader) (multihopConnectRequest, error)', r'''
var q multihopConnectRequest
data, err := io.ReadAll(body)
if err == nil {
	err = json.Unmarshal(data, &q)
}
return q, err
        '''),
        ('cmd/client/multihop_node_chain_request.go', 'func (a *app) resolveNativeMultihopRequestLocked(q multihopConnectRequest) (multihopSelection, error)', r'''
if err := q.validateOrdered(); err != nil {
	return multihopSelection{}, err
}
var required []string
if q.ordered() {
	for _, node := range q.Nodes {
		required = append(required, node.ID)
	}
}
if err := a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, required, q.ordered()); err != nil {
	return multihopSelection{}, err
}
store := cloneRouterProfileStore(a.profiles)
control, ok := profileByID(store.Profiles, store.SelectedID)
if !ok {
	return multihopSelection{}, errors.New("select a Router VPN control profile first")
}
if control.NodeKind == "external" {
	return multihopSelection{}, errors.New("selected node is external; use External Connect for its captured path")
}
selection, err := resolveNativeMultihopSelection(control, store.Profiles, q)
if err == nil && q.present() && !q.ordered() {
	err = a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, []string{selection.Entry.ID, selection.Exit.ID}, false)
}
return selection, err
        '''),
        ('cmd/client/desktop_profile_expectation.go', 'func decodeDesktopProfileExpectations(fields map[string]json.RawMessage) (desktopProfileExpectations, error)', r'''
var capture desktopProfileExpectations
for name := range fields {
	for _, canonical := range []string{"expected_selected_node_id", "expected_profile_tokens"} {
		if name != canonical && strings.EqualFold(name, canonical) {
			return capture, errors.New("source expectation field must use its canonical JSON name")
		}
	}
}
selected, hasSelected := fields["expected_selected_node_id"]
tokens, hasTokens := fields["expected_profile_tokens"]
if hasSelected != hasTokens {
	return capture, errors.New("source expectations require both selected identity and node revisions")
}
if !hasSelected {
	return capture, nil
}
if err := json.Unmarshal(selected, &capture.ExpectedSelectedNodeID); err != nil || capture.ExpectedSelectedNodeID == nil ||
	(*capture.ExpectedSelectedNodeID != "" && !validProfileID(*capture.ExpectedSelectedNodeID)) {
	return desktopProfileExpectations{}, errors.New("expected selection must be a canonical node identity")
}
entries, err := externalConnectJSONObject(tokens)
if err != nil || len(entries) > 64 {
	return desktopProfileExpectations{}, errors.New("expected node revisions must be a bounded unique object")
}
capture.ExpectedProfileTokens = make(map[string]string, len(entries))
for id, raw := range entries {
	var token string
	if json.Unmarshal(raw, &token) != nil || !validProfileID(id) || !validExternalProfileExpectationToken(token) {
		return desktopProfileExpectations{}, errors.New("expected node revision is malformed")
	}
	capture.ExpectedProfileTokens[id] = token
}
return capture, nil
        '''),
        ('cmd/client/desktop_profile_expectation.go', 'func (capture desktopProfileExpectations) present() bool', r'''
return capture.ExpectedSelectedNodeID != nil || capture.ExpectedProfileTokens != nil
        '''),
        ('cmd/client/desktop_profile_expectation.go', 'func (a *app) validateDesktopProfileExpectationsLocked(capture desktopProfileExpectations, requiredIDs []string, exact bool) error', r'''
if !capture.present() {
	return nil
}
if capture.ExpectedSelectedNodeID == nil || capture.ExpectedProfileTokens == nil || len(capture.ExpectedProfileTokens) > 64 ||
	*capture.ExpectedSelectedNodeID != a.profiles.SelectedID {
	return errDesktopProfileSelectionChanged
}
required := make(map[string]bool, len(requiredIDs)+1)
for _, id := range requiredIDs {
	if !validProfileID(id) {
		return errDesktopProfileSelectionChanged
	}
	required[id] = true
}
if selected := *capture.ExpectedSelectedNodeID; selected != "" {
	if !validProfileID(selected) {
		return errDesktopProfileSelectionChanged
	}
	required[selected] = true
}
if exact && len(capture.ExpectedProfileTokens) != len(required) {
	return errDesktopProfileSelectionChanged
}
for id := range required {
	if capture.ExpectedProfileTokens[id] == "" {
		return errDesktopProfileSelectionChanged
	}
}
for id, token := range capture.ExpectedProfileTokens {
	if !validProfileID(id) || !validExternalProfileExpectationToken(token) || (exact && !required[id]) {
		return errDesktopProfileSelectionChanged
	}
	matches := 0
	for _, profile := range a.profiles.Profiles {
		if profile.ID == id {
			matches++
			if token != publicProfileToken(profile) {
				return errDesktopProfileSelectionChanged
			}
		}
	}
	if matches != 1 {
		return errDesktopProfileSelectionChanged
	}
}
return nil
        '''),
        ('cmd/client/external_profile_expectation.go', 'func externalConnectJSONObject(data []byte) (map[string]json.RawMessage, error)', r'''
decoder := json.NewDecoder(bytes.NewReader(data))
open, err := decoder.Token()
if err != nil || open != json.Delim('{') {
	return nil, errors.New("external connection JSON must be an object")
}
fields := map[string]json.RawMessage{}
for decoder.More() {
	key, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	name, ok := key.(string)
	if !ok {
		return nil, errors.New("external connection JSON field is invalid")
	}
	if _, exists := fields[name]; exists {
		return nil, errors.New("external connection JSON contains a duplicate field")
	}
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	fields[name] = raw
}
if close, err := decoder.Token(); err != nil || close != json.Delim('}') {
	return nil, errors.New("external connection JSON object is incomplete")
}
var trailing json.RawMessage
if err := decoder.Decode(&trailing); err != io.EOF {
	return nil, errors.New("external connection JSON contains trailing data")
}
return fields, nil
        '''),
    )
    for path, declaration, body in expected:
        if _function(_tokens(read(path)), declaration) != _tokens(body):
            return False
    return True


def native_multihop_shipping_chain(source: str, read=None) -> bool:
    if not native_multihop_request_admission(read):
        return False
    # Typed source retention is not public native acceptance. Require the
    # exact installed-target gate and complete-node detector, not decoy text.
    support = _function(_tokens(read("cmd/client/desktop_node_chain_policy_dispatch.go")),
                        "func nativeNodeChainSOCKSPlatformSupported() bool")
    detector = _function(_tokens(read("cmd/client/multihop_node_chain_socks_selection.go")),
                         "func desktopNodeChainHasSOCKS(nodes []common.MultihopNodeSelection) bool")
    admission = _tokens(read("cmd/client/desktop_node_chain_socks_admission.go"))
    host = _function(admission, "func nativeNodeChainSOCKSHostSupported() bool")
    target = _function(admission, "func desktopNodeChainSOCKSAdmissionSupported(targetOS, targetArch string, retained bool) bool")
    if (support != _tokens("return nativeNodeChainSOCKSHostSupported()") or
            host != _tokens("return desktopNodeChainSOCKSAdmissionSupported(runtime.GOOS, runtime.GOARCH, retainedNativeMultihopSelected())") or
            target != _tokens('return retained && (targetOS == "linux" || targetOS == "windows") && (targetArch == "amd64" || targetArch == "arm64")')):
        return False
    if detector != _tokens('''
        for _, node := range nodes {
            if node.Mode == "socks5" { return true }
        }
        return false
    '''):
        return False
    connect_support = _function(_tokens(read("cmd/client/desktop_node_chain_policy_dispatch.go")),
                                "func nativeNodeChainCONNECTPlatformSupported() bool")
    connect_detector = _function(_tokens(read("cmd/client/multihop_node_chain_connect_selection.go")),
                                 "func desktopNodeChainHasCONNECT(nodes []common.MultihopNodeSelection) bool")
    if connect_support != _tokens("return false") or connect_detector != _tokens('''
        for _, node := range nodes {
            if node.Mode == "http-connect" || node.Mode == "https-connect" { return true }
        }
        return false
    '''):
        return False
    tokens = _tokens(source)
    public = _function(tokens, "func (a *app) nativeMultihopConnect(w http.ResponseWriter, r *http.Request)")
    expected = _tokens("""
        a.nativeMultihopConnectOwned(w, r, nativeMultihopConnectRuntime{
            capture: captureNativeMultihopForApp, preflight: preflightOwnedNativeMultihopCommand,
            stage: stageOwnedNativeMultihopCommand, proof: (*app).proveNativeMultihop,
        })
    """)
    if public != expected:
        return False
    routes = _function(tokens, "func registerDesktopMultihopRoutes(h *http.ServeMux, a *app)")
    if routes is None or len(_positions(routes, 'h.HandleFunc("/api/multihop/connect", a.nativeMultihopConnect)')) != 1:
        return False
    handler = _function(tokens, "func (a *app) nativeMultihopConnectOwned(w http.ResponseWriter, r *http.Request, driver nativeMultihopConnectRuntime)")
    if not _ordered_once(handler,
            "operation, finish, guardErr := a.beginConnectionOperationContext(r.Context())",
            "defer finish()",
            "if r.Method != http.MethodPost {",
            "if !nativeMultihopPlatformSupported() {",
            "q, err := decodeMultihopConnectRequest(http.MaxBytesReader(w, r.Body, 16<<10))",
            '''if err != nil { http.Error(w, "bad json", http.StatusBadRequest)
                return }''',
            '''if q.ordered() && (!nativeNodeChainPlatformSupported() || desktopNodeChainHasSOCKS(q.Nodes) && !nativeNodeChainSOCKSPlatformSupported() || desktopNodeChainHasCONNECT(q.Nodes) && !nativeNodeChainCONNECTPlatformSupported()) {
                http.Error(w, "this platform has not enabled its protected ordered native host", http.StatusNotImplemented)
                return
            }''',
            '''a.mu.Lock()
            sel, err := a.resolveNativeMultihopRequestLocked(q)
            a.mu.Unlock()''',
            '''if err != nil {
                status := http.StatusBadRequest
                if errors.Is(err, errDesktopProfileSelectionChanged) { status = http.StatusConflict }
                http.Error(w, err.Error(), status)
                return
            }''',
            "if execution, err := routeExecution(q); err != nil {",
            "a.nativeMultihopConnectLocalOwned(w, r, operation, sel, driver)"):
        return False
    owned = _function(tokens, "func (a *app) nativeMultihopConnectLocalOwned(w http.ResponseWriter, r *http.Request, operation context.Context, sel multihopSelection, driver nativeMultihopConnectRuntime)")
    if owned is None or owned.count("driver") != 8:
        return False
    if not _ordered_once(owned, '''if operation == nil || a.checkCapturedConnectionOperation(operation) != nil || driver.capture == nil ||
            driver.preflight == nil || driver.stage == nil || driver.proof == nil {
        http.Error(w, "native Local launch lost its original operation", http.StatusConflict)
        return
    }'''):
        return False
    calls = (
        "sel, err := driver.capture(a, sel, []string{sel.ExitMode})",
        "native, err := driver.preflight(a, sel, nil)",
        "a.stopModeWithIntent(native.ownedNode != nil || desktopMultihopPlatformLaunch(native))",
        "err = driver.stage(a, sel, native)",
        "cmd := native.command",
        '''protected := native.ownedNode != nil || desktopMultihopPlatformLaunch(native)
        if desktopMultihopPlatformLaunch(native) {
            err = startDesktopMultihopPlatform(operation, a, sel, native)
            cmd = native.command
        } else if protected {
            a.mu.Lock()
            err = a.publishDesktopCapturedMultihopStartLocked(operation, native, sel)
            a.mu.Unlock()
        } else {
            err = cmd.Start()
        }''',
        "err = bindNativeMultihopRuntime(a, native, sel, network)",
        '''if protected && !desktopMultihopPlatformLaunch(native) {
            if err := startDesktopCapturedMultihopOwned(operation, operation, a, native); err != nil {
                message, _ := a.multihopStopFailure(cmd, err.Error())
                sessionTrackerFor(a).markRequestFailure(message)
                http.Error(w, message, http.StatusInternalServerError)
                return
            }
        }''',
        "proofErr := driver.proof(a, sel, cmd)",
        '''if proofErr == nil && desktopMultihopPlatformLaunch(native) {
            proofErr = activateDesktopMultihopPlatform(operation, native)
        }''',
    )
    previous = -1
    for call in calls:
        matches = _positions(owned, call)
        if len(matches) != 1 or matches[0] <= previous:
            return False
        previous = matches[0]
    return True
