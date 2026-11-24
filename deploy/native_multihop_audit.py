"""Source-only closure for the public native multihop shipping adapters.

This is a bounded structural guard, not evidence of native runtime execution.
Comments and string contents cannot supply calls; calls must occur in the owned
handler, whose sole public wrapper installs the exact production adapters.
"""
from __future__ import annotations

import re
from functools import lru_cache

_TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|`[^`]*`|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z_0-9]*|\d+|[^\s]', re.S)


@lru_cache(maxsize=128)
def _token_tuple(source: str) -> tuple[str, ...]:
    # The complete source bytes are the key. Mutated fixtures cannot reuse a
    # prior verdict, and callers receive fresh lists below rather than cache
    # authority over any mutable source or parsed token collection.
    return tuple(m.group() for m in _TOKEN.finditer(source)
                 if not m.group().startswith(("//", "/*")))


def _tokens(source: str) -> list[str]:
    return list(_token_tuple(source))


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
	return desktopNodeChainConcretePolicyCount(c.policy, c.socksPolicy, c.connectPolicy) == 1 &&
		(c.execution == nil || (c.policy != nil || c.connectPolicy != nil || c.socksPolicy != nil) && c.execution.original == c && c.preparation == c.execution.draftPurpose &&
            (c.preparation == nil || c.preparation.ownsSelectedDraft(c.preparation.launch, c.execution)))
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
	if c != nil && c.execution != nil {
		return c.execution.readPolicy()
	}
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
	if c != nil && c.execution != nil {
		config, meta, _, err := c.execution.readPolicy()
		if err != nil {
			return "", meta, "", err
		}
		return config, meta, c.execution.preparation.Source(), nil
	}
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
		owner.launch.chain.selection.Native != selection.Native || graph.ChainNodes != len(selection.Nodes) {
		return errors.Join(err, errors.New("ordered native proof lost its full original runtime"))
	}
	if err := owner.execution.currentContext(ctx, owner.launch, graph); err != nil {
		return err
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
        # The execution branch keeps the original physical source and a fresh
        # selected-child proof. Local-only refusal moved into proof.original;
        # accepting the new dispatch without these callees would weaken it.
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func desktopNodeChainLaunchExecution(launch *desktopNodeLaunch) *desktopNodeChainExecutionLaunch', r'''
	if launch == nil || launch.chain == nil {
		return nil
	}
	return launch.chain.execution

        '''),
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func (e *desktopNodeChainExecutionLaunch) validateSource() error', r'''
	_, _, err := e.readSourceValidated()
	return err

        '''),
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func (p *orderedCandidatePreparation) ownsSelectedDraft(launch *desktopNodeLaunch, e *desktopNodeChainExecutionLaunch) bool', r'''
	return p != nil && p.request.Scope == orderedCandidateSelectedDraftScope && orderedCandidateDraftScopeMatches(p.request.Scope, p.request.draft) &&
		p.prefixPreparation == nil && p.launch == launch && launch != nil && launch.chain != nil && launch.chain.preparation == p &&
		launch.chain.execution == e && e != nil && e.original == launch.chain && e.draftPurpose == p && e.operation == p.operation &&
		e.preparation != nil && e.preparation.Execution() == p.request.draft.Execution && p.selection.Native != nil && p.selection.Native == launch.chain.selection.Native
        '''),
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func (e *desktopNodeChainExecutionLaunch) readSourceValidated() (mobilemultihop.DesktopPhysicalPolicy, mobilemultihop.DesktopNodeChainMetadata, error)', r'''
	observed, err := e.readSourceObservation(false)
	return observed.policy, observed.metadata, err

        '''),
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func (e *desktopNodeChainExecutionLaunch) readSourceObservation(physicalRead bool) (desktopExecutionSourceObservation, error)', r'''
	bad := func() (desktopExecutionSourceObservation, error) {
		return desktopExecutionSourceObservation{}, errors.New("execution launch changed its exact original source or physical preparation")
	}
	if e == nil || e.original == nil || e.preparation == nil || desktopNodeChainExecutionPhysicalCountWithMultiple(e.physical, e.connectPhysical, e.socksPhysical, e.openvpnPhysical, e.multiplePhysical) != 1 ||
		!e.original.hasPolicy() || e.original.preparation != e.draftPurpose ||
		e.draftPurpose != nil && !e.draftPurpose.ownsSelectedDraft(e.draftPurpose.launch, e) || e.original.selection.Native == nil ||
		e.original.selection.Native.chain == nil || e.original.selection.Native.validate(e.original.selection) != nil {
		return bad()
	}
	if e.original.execution != nil && e.original.execution != e {
		return bad()
	}
	selected := e.original.selection.Native.chain
	var observed desktopExecutionSourceObservation
	var policy mobilemultihop.DesktopPhysicalPolicy
	var meta mobilemultihop.DesktopNodeChainMetadata
	if e.multiplePhysical != nil {
		if e.original.policy == nil || e.original.connectPolicy != nil || e.original.socksPolicy != nil || selected.chain == nil || selected.connect != nil || selected.socks != nil {
			return bad()
		}
		var original *mobilemultihop.DesktopNodeChainPolicy
		var source *mobilemultihop.NodeChain
		var metadata mobilemultihop.DesktopNodeChainMetadata
		var err error
		if physicalRead {
			original, source, metadata, observed.config, observed.physical, observed.capture, err = e.multiplePhysical.ReadExecutionValidated(e.preparation)
		} else {
			original, source, metadata, err = e.multiplePhysical.ReadOriginalSourceValidated(e.preparation)
		}
		if err != nil || original != e.original.policy || source != selected.chain {
			return bad()
		}
		policy, meta = e.multiplePhysical, metadata
	} else if e.openvpnPhysical != nil {
		if e.original.policy == nil || e.original.connectPolicy != nil || e.original.socksPolicy != nil || selected.chain == nil || selected.connect != nil || selected.socks != nil {
			return bad()
		}
		var original *mobilemultihop.DesktopNodeChainPolicy
		var source *mobilemultihop.NodeChain
		var metadata mobilemultihop.DesktopNodeChainMetadata
		var err error
		if physicalRead {
			original, source, metadata, observed.config, observed.physical, observed.capture, err = e.openvpnPhysical.ReadExecutionValidated(e.preparation)
		} else {
			original, source, metadata, err = e.openvpnPhysical.ReadOriginalSourceValidated(e.preparation)
		}
		if err != nil || original != e.original.policy || source != selected.chain {
			return bad()
		}
		policy, meta = e.openvpnPhysical, metadata
	} else if e.socksPhysical != nil {
		if e.original.socksPolicy == nil || e.original.policy != nil || e.original.connectPolicy != nil || selected.socks == nil || selected.chain != nil || selected.connect != nil {
			return bad()
		}
		var original *mobilemultihop.DesktopNodeChainSOCKSPolicy
		var source *mobilemultihop.NodeChainSOCKSSource
		var metadata mobilemultihop.DesktopNodeChainMetadata
		var err error
		if physicalRead {
			original, source, metadata, observed.config, observed.physical, observed.capture, err = e.socksPhysical.ReadExecutionValidated(e.preparation)
		} else {
			original, source, metadata, err = e.socksPhysical.ReadOriginalSourceValidated(e.preparation)
		}
		if err != nil || original != e.original.socksPolicy || source != selected.socks.source {
			return bad()
		}
		policy, meta = e.socksPhysical, metadata
	} else if e.connectPhysical != nil {
		if e.original.connectPolicy == nil || e.original.policy != nil || selected.connect == nil || selected.chain != nil || selected.socks != nil {
			return bad()
		}
		var original *mobilemultihop.DesktopNodeChainCONNECTPolicy
		var source *mobilemultihop.NodeChainCONNECTSource
		var metadata mobilemultihop.DesktopNodeChainMetadata
		var err error
		if physicalRead {
			original, source, metadata, observed.config, observed.physical, observed.capture, err = e.connectPhysical.ReadExecutionValidated(e.preparation)
		} else {
			original, source, metadata, err = e.connectPhysical.ReadOriginalSourceValidated(e.preparation)
		}
		if err != nil || original != e.original.connectPolicy || source != selected.connect.source {
			return bad()
		}
		policy, meta = e.connectPhysical, metadata
	} else {
		if e.original.policy == nil || e.original.connectPolicy != nil || selected.chain == nil || selected.connect != nil || selected.socks != nil {
			return bad()
		}
		var original *mobilemultihop.DesktopNodeChainPolicy
		var source *mobilemultihop.NodeChain
		var metadata mobilemultihop.DesktopNodeChainMetadata
		var err error
		if physicalRead {
			original, source, metadata, observed.config, observed.physical, observed.capture, err = e.physical.ReadExecutionValidated(e.preparation)
		} else {
			original, source, metadata, err = e.physical.ReadOriginalSourceValidated(e.preparation)
		}
		if err != nil || original != e.original.policy || source != selected.chain {
			return bad()
		}
		policy, meta = e.physical, metadata
	}
	if meta.TargetOS != "linux" && meta.TargetOS != "windows" && meta.TargetOS != "darwin" {
		return bad()
	}
	observed.policy, observed.metadata = policy, meta
	return observed, nil
        '''),
        ('cmd/client/desktop_node_chain_socks_execution.go', 'func desktopNodeChainExecutionPhysicalCount(paired *mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy,\n\tconnect *mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy, socks *mobilemultihop.DesktopNodeChainSOCKSExecutionPhysicalPolicy, openvpn ...*mobilemultihop.DesktopNodeChainOpenVPNExecutionPhysicalPolicy) int', r'''
	count := 0
	if paired != nil {
		count++
	}
	if connect != nil {
		count++
	}
	if socks != nil {
		count++
	}
	for _, policy := range openvpn {
		if policy != nil {
			count++
		}
	}
	return count

        '''),
        ('internal/mobilemultihop/node_chain_openvpn_execution_desktop.go', 'func (p *DesktopNodeChainOpenVPNExecutionPhysicalPolicy) ReadOriginalValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, DesktopNodeChainMetadata, error)', r'''
	original, _, metadata, err := p.ReadOriginalSourceValidated(preparation)
	return original, metadata, err
'''),
        ('internal/mobilemultihop/node_chain_openvpn_execution_desktop.go', 'func (p *DesktopNodeChainOpenVPNExecutionPhysicalPolicy) ReadOriginalSourceValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, *NodeChain, DesktopNodeChainMetadata, error)', r'''
	if p == nil || preparation == nil || p.preparation != preparation || p.Validate() != nil {
		return nil, nil, DesktopNodeChainMetadata{}, nodeChainExecutionError
	}
	metadata := p.owner.metadata
	metadata.Prefixes = append([]NodeChainProof(nil), metadata.Prefixes...)
	metadata.Roots = append([]DesktopNodeRootMetadata(nil), metadata.Roots...)
	return p.original, p.owner.source, metadata, nil
'''),
        ('internal/mobilemultihop/node_chain_openvpn_execution_desktop.go', 'func (p *DesktopNodeChainOpenVPNExecutionPhysicalPolicy) ReadExecutionValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, *NodeChain, DesktopNodeChainMetadata, string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error)', r'''
	original, source, metadata, err := p.ReadOriginalSourceValidated(preparation)
	if err != nil {
		return nil, nil, DesktopNodeChainMetadata{}, "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, err
	}
	config, physical, capture, err := p.physicalReadValidated()
	if err != nil {
		return nil, nil, DesktopNodeChainMetadata{}, "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, err
	}
	return original, source, metadata, config, physical, capture, nil
'''),
        ('internal/mobilemultihop/node_chain_socks_execution_desktop.go', 'func (p *DesktopNodeChainSOCKSExecutionPhysicalPolicy) ReadOriginalValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainSOCKSPolicy, DesktopNodeChainMetadata, error)', r'''
	if p == nil || preparation == nil || p.preparation != preparation || p.Validate() != nil {
		return nil, DesktopNodeChainMetadata{}, nodeChainExecutionError
	}
	_, metadata, _, err := p.original.ReadValidated()
	if err != nil {
		return nil, DesktopNodeChainMetadata{}, err
	}
	return p.original, metadata.DesktopNodeChainMetadata, nil
        '''),
        ('internal/mobilemultihop/node_chain_execution_desktop.go', 'func (p *DesktopNodeChainExecutionPhysicalPolicy) ReadOriginalSourceValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, *NodeChain, DesktopNodeChainMetadata, error)', r'''
	original, metadata, err := p.ReadOriginalValidated(preparation)
	if err != nil {
		return nil, nil, DesktopNodeChainMetadata{}, err
	}
	return original, original.original, metadata, nil

        '''),
        ('internal/mobilemultihop/node_chain_execution_desktop.go', 'func (p *DesktopNodeChainExecutionPhysicalPolicy) ReadExecutionValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, *NodeChain, DesktopNodeChainMetadata, string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error)', r'''
	original, source, metadata, err := p.ReadOriginalSourceValidated(preparation)
	if err != nil {
		return nil, nil, DesktopNodeChainMetadata{}, "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, err
	}
	config, physical, capture, err := p.physicalReadValidated()
	if err != nil {
		return nil, nil, DesktopNodeChainMetadata{}, "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, err
	}
	return original, source, metadata, config, physical, capture, nil

        '''),
        ('internal/mobilemultihop/node_chain_execution_desktop.go', 'func (p *DesktopNodeChainExecutionPhysicalPolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error)', r'''
	if p.Validate() != nil {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, nodeChainExecutionError
	}
	return p.physicalReadValidated()

        '''),
        ('internal/mobilemultihop/node_chain_execution_desktop.go', 'func (p *DesktopNodeChainExecutionPhysicalPolicy) ReadOriginalValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, DesktopNodeChainMetadata, error)', r'''
	if p == nil || preparation == nil || p.preparation != preparation || p.Validate() != nil {
		return nil, DesktopNodeChainMetadata{}, nodeChainExecutionError
	}
	_, metadata, _, err := p.original.ReadValidated()
	if err != nil {
		return nil, DesktopNodeChainMetadata{}, err
	}
	return p.original, metadata, nil
        '''),
        ('internal/mobilemultihop/node_chain_connect_execution_desktop.go', 'func (p *DesktopNodeChainCONNECTExecutionPhysicalPolicy) ReadOriginalValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainCONNECTPolicy, DesktopNodeChainMetadata, error)', r'''
	if p == nil || preparation == nil || p.preparation != preparation || p.Validate() != nil {
		return nil, DesktopNodeChainMetadata{}, nodeChainExecutionError
	}
	_, metadata, _, err := p.original.ReadValidated()
	if err != nil {
		return nil, DesktopNodeChainMetadata{}, err
	}
	return p.original, metadata.DesktopNodeChainMetadata, nil
        '''),
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func desktopNodeChainExecutionOriginalMetadata(original *desktopNodeChainLaunch) (mobilemultihop.DesktopNodeChainMetadata, error)', r'''
	if original == nil || !original.hasPolicy() {
		return mobilemultihop.DesktopNodeChainMetadata{}, errors.New("execution metadata lost its original typed policy")
	}
	if original.socksPolicy != nil {
		_, meta, _, err := original.socksPolicy.ReadValidated()
		return meta.DesktopNodeChainMetadata, err
	}
	if original.connectPolicy != nil {
		_, meta, _, err := original.connectPolicy.ReadValidated()
		return meta.DesktopNodeChainMetadata, err
	}
	_, meta, _, err := original.policy.ReadValidated()
	return meta, err

        '''),
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func (e *desktopNodeChainExecutionLaunch) physicalPolicy() (mobilemultihop.DesktopPhysicalPolicy, error)', r'''
	policy, _, err := e.readSourceValidated()
	return policy, err

        '''),
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func (e *desktopNodeChainExecutionLaunch) readPolicy() (string, mobilemultihop.DesktopNodeChainMetadata, mobilemultihop.DesktopPhysicalCapture, error)', r'''
	observation, err := e.readPolicyCapture()
	return observation.config, observation.metadata, observation.capture, err

        '''),
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func (e *desktopNodeChainExecutionLaunch) readPolicyCapture() (desktopExecutionSourceObservation, error)', r'''
	observed, err := e.readSourceObservation(true)
	if err != nil {
		return desktopExecutionSourceObservation{}, err
	}
	meta, physical := observed.metadata, observed.physical
	kind := "node-chain-execution"
	if e.multiplePhysical != nil {
		kind = "node-chain-multiple-imported-execution"
	} else if e.openvpnPhysical != nil {
		kind = "node-chain-openvpn-execution"
	} else if e.socksPhysical != nil {
		kind = "node-chain-socks-execution"
	} else if e.connectPhysical != nil {
		kind = "node-chain-connect-execution"
	}
	if err != nil || physical.ConfigSHA256 != e.preparation.ConfigSHA256() || physical.SourceSHA256 != meta.SourceSHA256 ||
		physical.SessionID != meta.SessionID || physical.TargetOS != meta.TargetOS || physical.Kind != kind {
		return desktopExecutionSourceObservation{}, errors.New("execution physical capture differs from its original desktop policy")
	}
	observed.metadata.ConfigSHA256, observed.metadata.FinalTag = physical.ConfigSHA256, mobilemultihop.SelectorTag
	return observed, nil
        '''),
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func (e *desktopNodeChainExecutionLaunch) bound(launch *desktopNodeLaunch) error', r'''
	_, meta, err := e.readSourceValidated()
	if err != nil || launch == nil || launch.chain != e.original || launch.chain.execution != e || launch.configSHA256 != e.preparation.ConfigSHA256() ||
		launch.mtuSession != meta.SessionID || e.original.input != e.preparation.Source() {
		return errors.New("execution observation lost its exact staged parent launch")
	}
	return nil

        '''),
        ('cmd/client/desktop_node_chain_execution_graph.go', 'func captureDesktopNodeChainExecutionProofContext(ctx context.Context, launch *desktopNodeLaunch) (*desktopNodeChainExecutionProof, error)', r'''
	if ctx == nil {
		return nil, errors.New("execution proof capture has no caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	e := desktopNodeChainLaunchExecution(launch)
	if e == nil {
		return nil, nil
	}
	if err := e.bound(launch); err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &e.mu); err != nil {
		return nil, err
	}
	defer e.mu.Unlock()
	if e.projection == nil || e.ready == nil || e.ready.Identity != e.identity || e.ready.Progress.Comparison.Winner == nil ||
		!e.ready.Progress.Complete || !e.ready.Progress.Ready || !e.ready.Progress.DNSProven || !e.ready.Progress.PublicProven || e.ready.SelectionEpoch == 0 {
		return nil, errors.New("ordered execution graph preceded its selected native proof")
	}
	return &desktopNodeChainExecutionProof{execution: e, physical: e.physical, connectPhysical: e.connectPhysical, socksPhysical: e.socksPhysical, openvpnPhysical: e.openvpnPhysical, multiplePhysical: e.multiplePhysical, projection: e.projection, identity: e.identity,
		winner: *e.ready.Progress.Comparison.Winner, target: e.ready.Progress.Comparison.Target, epoch: e.ready.SelectionEpoch}, nil
        '''),
        ('cmd/client/desktop_node_chain_execution_graph.go', 'func (proof *desktopNodeChainExecutionProof) currentContext(ctx context.Context, launch *desktopNodeLaunch, graph activeMultihopGraph) error', r'''
	if ctx == nil {
		return errors.New("execution observation has no caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	e, err := proof.original(launch, graph)
	if err != nil || e == nil {
		return errors.Join(err, ctx.Err())
	}
	if err := desktopnetwork.LockContext(ctx, &e.mu); err != nil {
		return err
	}
	defer e.mu.Unlock()
	return errors.Join(proof.currentState(e, graph), ctx.Err())

        '''),
        ('cmd/client/desktop_node_chain_execution_graph.go', 'func (proof *desktopNodeChainExecutionProof) original(launch *desktopNodeLaunch, graph activeMultihopGraph) (*desktopNodeChainExecutionLaunch, error)', r'''
	e := desktopNodeChainLaunchExecution(launch)
	if proof == nil {
		if e != nil || launch != nil && launch.chain != nil && graph.Execution != "local" {
			return nil, errors.New("ordered graph omitted its execution authority")
		}
		return nil, nil
	}
	if e == nil || e != proof.execution || e.bound(launch) != nil || e.physical != proof.physical || e.connectPhysical != proof.connectPhysical || e.socksPhysical != proof.socksPhysical || e.openvpnPhysical != proof.openvpnPhysical || e.multiplePhysical != proof.multiplePhysical || graph.Execution != string(proof.winner.Execution) {
		return nil, errors.New("ordered execution graph replaced its original preparation")
	}
	return e, nil
        '''),
        ('cmd/client/desktop_node_chain_execution_graph.go', 'func (proof *desktopNodeChainExecutionProof) currentState(e *desktopNodeChainExecutionLaunch, graph activeMultihopGraph) error', r'''
	if e.projection != proof.projection || e.identity != proof.identity || e.ready == nil || e.ready.Identity != proof.identity ||
		e.ready.SelectionEpoch < proof.epoch || e.ready.Progress.Comparison.Target != proof.target || e.ready.Progress.Comparison.Winner == nil ||
		*e.ready.Progress.Comparison.Winner != proof.winner || e.ready.Progress.Execution != graph.Execution {
		return errors.New("ordered execution graph replaced its proved winner, target or identity")
	}
	return nil

        '''),
        ('cmd/client/desktop_node_chain_execution_graph.go', 'func (e *desktopNodeChainExecutionLaunch) publicationCurrentLocked(ctx context.Context, a *app, launch *desktopNodeLaunch, selection multihopSelection) error', r'''
	if ctx == nil || ctx.Err() != nil || a == nil || e == nil || e.operation == nil || e.bound(launch) != nil ||
		e.original.capture == nil || e.original.capture.app != a || e.original.capture.sources == nil ||
		e.original.selection.Native != selection.Native || launch.command == nil || a.cmd != launch.command || a.closing ||
		a.connectionContext != e.operation || a.checkCapturedConnectionOperationLocked(e.operation) != nil ||
		e.original.capture.sources.currentLocked(a) != nil {
		return errors.New("ordered execution publication lost its captured operation, source or command")
	}
	return ctx.Err()

        '''),
    )
    expected += (
        ('cmd/client/desktop_node_chain_execution_launch.go', 'func newDesktopNodeChainExecutionSource(original *desktopNodeChainLaunch, requested string) (*desktopNodeChainExecutionLaunch, error)', r'''
	if original == nil || original.preparation != nil || !original.originalPolicyCurrent() {
		return nil, errors.New("execution preparation requires its complete original typed Local source")
	}
	meta, err := desktopNodeChainExecutionOriginalMetadata(original)
	if err != nil {
		return nil, err
	}
	if meta.TargetOS != "linux" && meta.TargetOS != "windows" && meta.TargetOS != "darwin" {
		return nil, errors.New("execution host has no supported native target")
	}
	if desktopNodeChainMultipleImportedExecutionSource(original) {
		prep, err := mobilemultihop.NewDesktopNodeChainMultipleImportedExecutionPreparation(original.policy, requested)
		if err != nil {
			return nil, err
		}
		physical, err := prep.MultipleImportedDesktopPhysicalPolicy()
		if err != nil {
			return nil, err
		}
		result := &desktopNodeChainExecutionLaunch{original: original, preparation: prep, multiplePhysical: physical}
		return result, result.validateSource()
	}
	if desktopNodeChainHasOpenVPN(nodeChainSelectedReferences(original.selection.Nodes)) {
		if original.policy == nil || original.socksPolicy != nil || original.connectPolicy != nil {
			return nil, errors.New("OpenVPN execution requires its original generic Local owner")
		}
		prep, err := mobilemultihop.NewDesktopNodeChainOpenVPNExecutionPreparation(original.policy, requested)
		if err != nil {
			return nil, err
		}
		physical, err := prep.OpenVPNDesktopPhysicalPolicy()
		if err != nil {
			return nil, err
		}
		result := &desktopNodeChainExecutionLaunch{original: original, preparation: prep, openvpnPhysical: physical}
		return result, result.validateSource()
	}
	if original.socksPolicy != nil {
		prep, err := mobilemultihop.NewDesktopNodeChainSOCKSExecutionPreparation(original.socksPolicy, requested)
		if err != nil {
			return nil, err
		}
		physical, err := prep.SOCKSDesktopPhysicalPolicy()
		if err != nil {
			return nil, err
		}
		result := &desktopNodeChainExecutionLaunch{original: original, preparation: prep, socksPhysical: physical}
		return result, result.validateSource()
	}
	if original.connectPolicy != nil {
		prep, err := mobilemultihop.NewDesktopNodeChainCONNECTExecutionPreparation(original.connectPolicy, requested)
		if err != nil {
			return nil, err
		}
		physical, err := prep.CONNECTDesktopPhysicalPolicy()
		if err != nil {
			return nil, err
		}
		result := &desktopNodeChainExecutionLaunch{original: original, preparation: prep, connectPhysical: physical}
		return result, result.validateSource()
	}
	prep, err := mobilemultihop.NewDesktopNodeChainExecutionPreparation(original.policy, requested)
	if err != nil {
		return nil, err
	}
	physical, err := prep.DesktopPhysicalPolicy()
	if err != nil {
		return nil, err
	}
	result := &desktopNodeChainExecutionLaunch{original: original, preparation: prep, physical: physical}
	return result, result.validateSource()
        '''),
        ('cmd/client/desktop_node_chain_multiple_imported_execution.go', 'func desktopNodeChainMultipleImportedExecutionSource(original *desktopNodeChainLaunch) bool', r'''
	if original == nil || original.policy == nil || original.connectPolicy != nil || original.socksPolicy != nil {
		return false
	}
	source := original.policy.OriginalChain()
	if source == nil {
		return false
	}
	input, err := source.LaunchInput()
	if err != nil {
		return false
	}
	var header struct {
		Schema json.RawMessage `json:"schema"`
	}
	return json.Unmarshal([]byte(input), &header) == nil && string(header.Schema) == "6"
        '''),
        ('cmd/client/desktop_node_chain_multiple_imported_execution.go', 'func desktopNodeChainExecutionPhysicalCountWithMultiple(paired *mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy,\n\tconnect *mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy, socks *mobilemultihop.DesktopNodeChainSOCKSExecutionPhysicalPolicy,\n\topenvpn *mobilemultihop.DesktopNodeChainOpenVPNExecutionPhysicalPolicy, multiple *mobilemultihop.DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) int', r'''
	count := desktopNodeChainExecutionPhysicalCount(paired, connect, socks, openvpn)
	if multiple != nil {
		count++
	}
	return count
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
            '''revision, fixed, err := desktopDeviceFixedInput(operation)
            if err != nil { return nil, err }
            policy, err := mobilemultihop.NewDesktopImportedPolicyWithDevicePreference(original, sessionID, "linux", sel.restoreMTU, revision, fixed)''',
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
    retained_launch = _tokens(read("cmd/client/multihop_native_launch.go")) if callable(read) else []
    retained_preflight = _function(retained_launch,
        "func preflightOwnedNativeMultihopCommandForPurpose(ctx context.Context, a *app, sel multihopSelection, descriptor *desktopExecutionDescriptor, purpose *orderedCandidatePreparation) (launch *desktopNodeLaunch, failure error)")
    retained_compile = _function(retained_launch,
        "func compileRetainedNativeMultihopLaunchContext(ctx context.Context, sel multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error)")
    return (
        native_multihop_platform_chain(read)
        and retained_preflight is not None and retained_compile is not None
        and len(_positions(retained_preflight, "launch, err = compileRetainedNativeMultihopLaunchContext(ctx, sel, descriptor)")) == 1
        and len(_positions(retained_compile, "revision, fixed, err := desktopDeviceFixedInput(ctx)")) == 1
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
            if c := deviceMTUForContext(ctx); c != nil && c.policy.FixedMTU != 0 {
                graph, found := getActiveMultihopGraph(a)
                owner, err := capturedNativeMultihopRuntimeContext(ctx, a, command, graph)
                if err != nil || !found || owner.launch.multihopDeviceMTU != c {
                    return errors.Join(err, errDeviceMTUReadback)
                }
                record, err := readDesktopNodeMTUContext(ctx, owner.launch)
                if err != nil || record.Active || record.Failure != "" || record.MTU != c.policy.FixedMTU || c.current() != nil {
                    return errors.Join(err, errDeviceMTUReadback)
                }
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
if !validDesktopOrderedExecution(q.Execution) || q.EntryID != "" || q.ExitID != "" || q.Base != "" || q.EntryMode != "" || q.ExitMode != "" ||
	q.ExpectedSelectedNodeID == nil || *q.ExpectedSelectedNodeID == "" || q.ExpectedProfileTokens == nil {
	return errors.New("ordered Connect requires one explicit execution choice and its complete original node revisions")
}
if err := desktopOrderedExecutionSelection(q.Nodes, q.Execution); err != nil {
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
	if json.Unmarshal(rawNodes, &rows) != nil || len(rows) < 2 || len(rows) > hopmeasure.PhysicalTraversalDepth {
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
if err != nil || len(entries) > hopmeasure.PhysicalTraversalDepth {
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
if capture.ExpectedSelectedNodeID == nil || capture.ExpectedProfileTokens == nil || len(capture.ExpectedProfileTokens) > hopmeasure.PhysicalTraversalDepth ||
        (len(capture.ExpectedProfileTokens) > 64 && (!exact || len(requiredIDs) < len(capture.ExpectedProfileTokens))) ||
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


def native_multihop_execution_product(read) -> bool:
    """Trace the distinct public execution transaction and captured Stop.

    This guard does not establish native execution. It keeps the actual public
    adapter, complete selection, pre-Stop preparation, child-selected proof and
    original retirement owner connected while native tests supply that evidence.
    Ordinary Darwin admission cannot grant this separate capability. Imported
    Darwin trios have their own exact source and Start Layer admission.
    """
    if not callable(read):
        return False
    product_path = "cmd/client/desktop_node_chain_execution_product.go"
    imported_path = "cmd/client/desktop_node_chain_imported_execution.go"
    platform_path = "cmd/client/desktop_node_chain_imported_execution_platform.go"
    product = _tokens(read(product_path))
    expected = (
        (imported_path, "func desktopNodeChainImportedExecutionMiddle(profile common.RouterProfile) bool", '''
if !desktopNodeChainImported(profile, "shadowsocks") { return false }
ss := profile.External.Shadowsocks
address, err := netip.ParseAddr(ss.Server)
if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.String() != ss.Server || profile.Endpoint != ss.Server {
    return false
}
key, err := base64.StdEncoding.Strict().DecodeString(ss.Password)
defer clear(key)
return err == nil && base64.StdEncoding.EncodeToString(key) == ss.Password
        '''),
        (imported_path, "func desktopNodeChainImportedHostnameExecutionMiddle(profile common.RouterProfile) bool", """
_, err := desktopNodeChainImportedHostnameInput(profile)
return err == nil
        """),
        (imported_path, "func desktopOrderedExecutionMembers(members []desktopNodeChainMember, requested string) error", r'''
	bad := errors.New("ordered imported execution requires its original complete SS2022, CONNECT, SOCKS or independently paired OpenVPN path, with a saved hostname resolver after two packet members")
	if !validDesktopOrderedExecution(requested) {
		return bad
	}
	if requested == "local" {
		return nil
	}
	imported := 0
	for _, member := range members {
		if member.Profile.NodeKind == "external" || member.Profile.External != nil {
			imported++
		}
	}
	if imported == 0 {
		if len(members) > 0 && members[len(members)-1].Mode == "hysteria2" && !desktopHysteriaExecutionMembers(members, requested) {
			return bad
		}
		return nil
	}
	if desktopNodeChainMultipleImportedExecutionShape(members) {
		return nil
	}
	if imported != 1 || len(members) < 3 || len(members) > 8 {
		return bad
	}
	middle := len(members) - 2
	if members[len(members)-1].Mode != "shadowsocks" || !(members[middle].Mode == "shadowsocks" && (desktopNodeChainImportedExecutionMiddle(members[middle].Profile) || len(members) >= 4 && desktopNodeChainImportedHostnameExecutionMiddle(members[middle].Profile)) || desktopNodeChainCONNECTExecutionShape(members) || desktopNodeChainSOCKSExecutionShape(members) || desktopNodeChainOpenVPNExecutionShape(members)) {
		return bad
	}
	ids, proofs := map[string]bool{}, map[string]bool{}
	for i, member := range members {
		p := member.Profile
		if !validProfileID(p.ID) || ids[p.ID] {
			return bad
		}
		ids[p.ID] = true
		if i == middle {
			continue
		}
		if i < middle && !mobilemultihop.NodeChainPrefixMode(member.Mode) || p.NodeKind != "" && p.NodeKind != "router-vpn" || p.External != nil || !common.ValidNodeProofID(p.NodeProofID) || proofs[p.NodeProofID] {
			return bad
		}
		proofs[p.NodeProofID] = true
	}
	return nil
        '''),
        ('cmd/client/desktop_node_chain_socks_execution.go', 'func desktopNodeChainSOCKSExecutionShape(members []desktopNodeChainMember) bool', r'''
	if len(members) < 3 || len(members) > mobilemultihop.NodeChainMaximumNodes {
		return false
	}
	middle, final := len(members)-2, len(members)-1
	if members[final].Mode != "shadowsocks" || !desktopNodeChainSOCKSMiddle(members[middle].Profile, members[middle].Mode) ||
		!desktopSOCKSExecutionPairedLayer(members[final].Profile.StartLayer) {
		return false
	}
	for _, member := range members[:middle] {
		layer := member.Profile.StartLayer
		if !mobilemultihop.NodeChainPrefixMode(member.Mode) || !desktopSOCKSExecutionPairedLayer(layer) {
			return false
		}
	}
	return true
        '''),
        ('cmd/client/desktop_node_chain_socks_execution.go', 'func desktopSOCKSExecutionPairedLayer(layer string) bool', r'''
 return layer == "" || layer == "off" || layer == "aes-256-gcm" || layer == "aes-256-gcm+xor-whitening"
        '''),
        ('cmd/client/desktop_node_chain_socks_execution.go', 'func desktopSOCKSTrioExecutionMembers(members []desktopNodeChainMember, requested string) bool', r'''
	return (requested == "server" || requested == "auto") && desktopNodeChainSOCKSExecutionShape(members) && desktopOrderedExecutionMembers(members, requested) == nil
        '''),
        ('cmd/client/desktop_node_chain_socks_execution.go', 'func desktopSOCKSTrioExecutionChoices() []string', r'''
	if nativeDesktopImportedTrioExecutionPlatformSupported() && nativeNodeChainSOCKSHostSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
        '''),
        ('cmd/client/multihop_node_chain_socks_capture.go', 'func desktopNodeChainSOCKSMiddle(profile common.RouterProfile, mode string) bool', r'''
	if mode != "socks5" || profile.NodeKind != "external" || profile.External == nil ||
		profile.External.Protocol != "socks5" || profile.External.SOCKS5 == nil ||
		profile.NodeProofID != "" || profile.APIToken != "" || profile.RouterAPI != "" ||
		profile.StartLayer != "" && profile.StartLayer != "off" {
		return false
	}
	socks := profile.External.SOCKS5
	address, err := netip.ParseAddr(socks.Host)
	return err == nil && address.Zone() == "" && !address.Is4In6() &&
		!address.IsUnspecified() && !address.IsMulticast() &&
		socks.Host == profile.Endpoint && socks.Port >= 1 && socks.Port <= 65535 &&
		len(socks.Username) <= 255 && len(socks.Password) <= 255 &&
		(socks.Username == "") == (socks.Password == "")
        '''),
        ('cmd/client/desktop_node_chain_imported_execution.go', 'func desktopNodeChainCONNECTExecutionShape(members []desktopNodeChainMember) bool', r'''
	if len(members) < 3 || len(members) > mobilemultihop.NodeChainMaximumNodes {
		return false
	}
	middle, final := len(members)-2, len(members)-1
	if members[final].Mode != "shadowsocks" || !desktopNodeChainCONNECTMiddle(members[middle].Profile, members[middle].Mode) ||
		!desktopCONNECTExecutionPairedLayer(members[final].Profile.StartLayer) {
		return false
	}
	for _, member := range members[:middle] {
		layer := member.Profile.StartLayer
		if !mobilemultihop.NodeChainPrefixMode(member.Mode) || !desktopCONNECTExecutionPairedLayer(layer) {
			return false
		}
	}
	return true

        '''),
        ('cmd/client/desktop_node_chain_imported_execution.go', 'func desktopCONNECTExecutionPairedLayer(layer string) bool', r'''
	return layer == "" || layer == "off" || layer == "aes-256-gcm" || layer == "aes-256-gcm+xor-whitening"
        '''),
        ('cmd/client/desktop_node_chain_imported_execution.go', 'func desktopCONNECTTrioExecutionMembers(members []desktopNodeChainMember, requested string) bool', r'''
	return (requested == "server" || requested == "auto") && desktopNodeChainCONNECTExecutionShape(members) && desktopOrderedExecutionMembers(members, requested) == nil
        '''),
        ('cmd/client/desktop_node_chain_imported_execution_platform.go', 'func desktopCONNECTTrioExecutionChoices() []string', r'''
	if nativeDesktopImportedTrioExecutionPlatformSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
        '''),
        ('cmd/client/multihop_node_chain_connect_capture.go', 'func desktopNodeChainCONNECTMiddle(profile common.RouterProfile, mode string) bool', r'''
	if (mode != "http-connect" && mode != "https-connect") || profile.NodeKind != "external" || profile.External == nil ||
		profile.External.Protocol != mode || profile.NodeProofID != "" || profile.APIToken != "" || profile.RouterAPI != "" ||
		profile.StartLayer != "" && profile.StartLayer != "off" {
		return false
	}
	proxy := profile.External.HTTPConnect
	if mode == "https-connect" {
		if profile.External.HTTPConnect != nil {
			return false
		}
		proxy = profile.External.HTTPSConnect
	} else if profile.External.HTTPSConnect != nil {
		return false
	}
	if proxy == nil || (proxy.Username == "") != (proxy.Password == "") ||
		len(proxy.Username) > 4096 || len(proxy.Password) > 4096 || len(proxy.TLSServerName) > 4096 {
		return false
	}
	if mode == "https-connect" {
		if proxy.TLSServerName == "" || strings.ContainsAny(proxy.TLSServerName, " /\\?#@") {
			return false
		}
	} else if proxy.TLSServerName != "" {
		return false
	}
	address, err := netip.ParseAddr(proxy.Host)
	return err == nil && address.Zone() == "" && !address.Is4In6() && !address.IsUnspecified() && !address.IsMulticast() &&
		proxy.Host == profile.Endpoint && proxy.Port >= 1 && proxy.Port <= 65535
        '''),
        ('cmd/client/multihop_node_chain_selection.go', 'func resolveDesktopNodeChainSelection(control common.RouterProfile, profiles []common.RouterProfile, nodes []common.MultihopNodeSelection, execution string) (multihopSelection, error)', r'''
	if err := desktopOrderedExecutionSelection(nodes, execution); err != nil {
		return multihopSelection{}, err
	}
	// The immutable graph describes the same full Local source. Execution is
	// a separate child-owned derivation; never rewrite saved member preferences.
	members, err := resolveDesktopNodeChainMembers(control, profiles, nodes, "local")
	if desktopNodeChainHasSOCKS(nodes) {
		members, err = resolveDesktopNodeChainSOCKSMembers(control, profiles, nodes, "local")
	}
	if desktopNodeChainHasCONNECT(nodes) {
		members, err = resolveDesktopNodeChainCONNECTMembers(control, profiles, nodes, "local")
	}
	if err != nil {
		return multihopSelection{}, err
	}
	if err := desktopOrderedExecutionMembers(members, execution); err != nil {
		return multihopSelection{}, err
	}
	// The concrete physical policy has one final authenticated control source.
	// A third profile cannot supply credentials or a weaker protection policy.
	final := members[len(members)-1]
	if control.ID != final.Profile.ID || liveMeasurementProfileToken(control) != liveMeasurementProfileToken(final.Profile) {
		return multihopSelection{}, errors.New("ordered native control must be its exact final selected node")
	}
	return multihopSelection{Control: common.CloneRouterProfile(control), Entry: common.CloneRouterProfile(members[0].Profile),
		Exit: common.CloneRouterProfile(final.Profile), Base: desktopExternalEntryBase(members[0].Mode), EntryMode: members[0].Mode, ExitMode: final.Mode,
		Nodes: cloneDesktopNodeChainMembers(members)}, nil
        '''),
        (product_path, "func nativeDesktopOrderedExecutionPlatformSupported() bool", '''
return retainedNativeMultihopSelected() && (runtime.GOOS == "linux" || runtime.GOOS == "windows") &&
    (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
        '''),
        (product_path, "func desktopOrderedExecutionChoices() []string", '''
if nativeDesktopOrderedExecutionPlatformSupported() {
    return []string{"local", "server", "auto"}
}
return []string{"local"}
        '''),
        (platform_path, "func nativeDesktopImportedTrioExecutionPlatformSupported() bool", '''
return nativeDesktopOrderedExecutionPlatformSupported() ||
    retainedNativeMultihopSelected() && runtime.GOOS == "darwin" &&
        (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
        '''),
        (platform_path, "func desktopImportedTrioExecutionChoices() []string", '''
if nativeDesktopImportedTrioExecutionPlatformSupported() {
    return []string{"local", "server", "auto"}
}
return []string{"local"}
        '''),
        (platform_path, "func desktopDarwinImportedTrioExecutionMembers(members []desktopNodeChainMember, requested string) bool", r'''
	if requested != "server" && requested != "auto" || len(members) < 3 || len(members) > common.MultihopMaximumNodes ||
		!(desktopNodeChainImportedExecutionMiddle(members[len(members)-2].Profile) || len(members) >= 4 && desktopNodeChainImportedHostnameExecutionMiddle(members[len(members)-2].Profile)) ||
		desktopOrderedExecutionMembers(members, requested) != nil {
		return false
	}
	for index, member := range members {
		if index == len(members)-2 {
			continue
		}
		if member.Profile.NodeKind == "external" || member.Profile.External != nil {
			return false
		}
		layer := member.Profile.StartLayer
		if layer != "" && layer != "off" && layer != "aes-256-gcm" && layer != "aes-256-gcm+xor-whitening" {
			return false
		}
	}
	return true
        '''),
        (platform_path, "func nativeDesktopOrderedExecutionSelectionPlatformSupported(members []desktopNodeChainMember, requested string) bool", r'''
	if nativeDesktopOrderedExecutionPlatformSupported() {
		return true
	}
	if runtime.GOOS == "darwin" && nativeDesktopPairedSSExecutionPlatformSupported() && desktopPairedSSExecutionMembers(members, requested) {
		return true
	}
	if runtime.GOOS == "darwin" && nativeDesktopHysteriaExecutionPlatformSupported() && desktopHysteriaExecutionMembers(members, requested) {
		return true
	}
	return runtime.GOOS == "darwin" && nativeDesktopImportedTrioExecutionPlatformSupported() &&
		(desktopDarwinImportedTrioExecutionMembers(members, requested) || desktopCONNECTTrioExecutionMembers(members, requested) || desktopSOCKSTrioExecutionMembers(members, requested) || desktopOpenVPNExecutionMembers(members, requested) || desktopMultipleImportedExecutionMembers(members, requested))
        '''),
        (product_path, "func validDesktopOrderedExecution(value string) bool", '''
return value == "local" || value == "server" || value == "auto"
        '''),
        (product_path, "func desktopOrderedExecutionSelection(nodes []common.MultihopNodeSelection, requested string) error", '''
	if !validDesktopOrderedExecution(requested) {
		return errors.New("ordered execution requires an explicit Local, Server or Compare choice")
	}
	if err := common.ValidateMultihopNodes(nodes); err != nil {
		return err
	}
	if requested != "local" && (common.ExtendedPairedLocalMultihopSelection(nodes) || common.ExtendedMixedLocalPacketCount(nodes) > 0) {
		return errors.New("extended paired WireGuard routes require Local execution")
	}
	if requested != "local" && nodes[len(nodes)-1].Mode != "shadowsocks" && !desktopHysteriaExecutionNodes(nodes) {
		return errors.New("ordered Server and Compare require their captured Shadowsocks final or wholly paired Hysteria2 path")
	}
	if requested != "local" && desktopNodeChainHasOpenVPN(nodes) {
		if len(nodes) < 3 || len(nodes) > mobilemultihop.NodeChainMaximumNodes || nodes[len(nodes)-2].Mode != "openvpn" {
			return errors.New("OpenVPN execution requires its original paired packet prefix and SS final")
		}
		for _, node := range nodes[:len(nodes)-2] {
			if !mobilemultihop.NodeChainPrefixMode(node.Mode) {
				return errors.New("OpenVPN execution requires only paired packet prefixes")
			}
		}
	}
	if requested != "local" && desktopNodeChainHasSOCKS(nodes) {
		if len(nodes) < 3 || len(nodes) > mobilemultihop.NodeChainMaximumNodes || nodes[len(nodes)-2].Mode != "socks5" {
			return errors.New("SOCKS Server and Compare require their original complete packet prefix and paired final")
		}
		for _, node := range nodes[:len(nodes)-2] {
			if !mobilemultihop.NodeChainPrefixMode(node.Mode) {
				return errors.New("SOCKS Server and Compare require only paired WireGuard or AWG2 prefix members")
			}
		}
	}
	if requested != "local" && desktopNodeChainHasCONNECT(nodes) {
		if len(nodes) < 3 || len(nodes) > mobilemultihop.NodeChainMaximumNodes ||
			(nodes[len(nodes)-2].Mode != "http-connect" && nodes[len(nodes)-2].Mode != "https-connect") {
			return errors.New("CONNECT Server and Compare require their original complete packet prefix and paired final")
		}
		for _, node := range nodes[:len(nodes)-2] {
			if !mobilemultihop.NodeChainPrefixMode(node.Mode) {
				return errors.New("CONNECT Server and Compare require only paired WireGuard or AWG2 prefix members")
			}
		}
	}
	return nil

        '''),
        (product_path, "func prepareDesktopOrderedExecutionSession(ctx context.Context, a *app, selection multihopSelection, requested string) (*desktopNodeChainExecutionSession, error)", '''
return prepareDesktopOrderedExecutionSessionWithLast(ctx, a, selection, requested, "")
        '''),
        (product_path, "func prepareDesktopOrderedExecutionSessionWithLast(ctx context.Context, a *app, selection multihopSelection, requested, saved string) (*desktopNodeChainExecutionSession, error)", '''
launch, image, err := prepareDesktopNodeChainExecutionHostWithLast(ctx, a, selection, requested, saved)
if launch == nil { return nil, err }
s := &desktopNodeChainExecutionSession{app: a, launch: launch, execution: desktopNodeChainLaunchExecution(launch), selection: selection}
if err == nil { err = preflightRetainedNativeMultihop(ctx, image, launch, runDesktopExternalPreflightCommand) }
return s, err
        '''),
        ("cmd/client/desktop_node_chain_execution_product.go", "func (a *app) publishDesktopOrderedExecution(ctx context.Context, s *desktopNodeChainExecutionSession, usage bool) error", r'''
return a.publishDesktopOrderedExecutionWithStartup(ctx, s, usage, nil)
        '''),
        ("cmd/client/startup_selected_compiler.go", "func (c *startupNodeChainCapture) compilerContext(ctx context.Context) context.Context", r'''
if c == nil || c.selectedLast == "" {
		return ctx
	}
	return context.WithValue(ctx, startupSelectedCompilerKey{}, c)
        '''),
        ("cmd/client/startup_selected_compiler.go", "func startupSelectedCompilerProfile(ctx context.Context, profile common.RouterProfile) (common.RouterProfile, error)", r'''
c, ok := ctx.Value(startupSelectedCompilerKey{}).(*startupNodeChainCapture)
	if !ok {
		return profile, nil
	}
	if c == nil || c.last == nil || c.last.NodeChain == nil || c.selectedLast != c.last.NodeChain.SelectedLast {
		return common.RouterProfile{}, errors.New("selected Last lost its original compiler capture")
	}
	for _, member := range c.last.NodeChain.Nodes {
		if member.ID == profile.ID && member.ProfileToken == startupExternalProfileToken(profile) {
			return withStartupCompilerHistory(profile, member.CompilerHistory)
		}
	}
	return common.RouterProfile{}, errors.New("selected Last lost its original member private source")
        '''),
        ("cmd/client/startup_selected_execution.go", "func (d *desktopOrderedExecutionRuntime) startupSelectedCurrent(ctx context.Context, a *app, selection multihopSelection, requested string) error", r'''
if d.startup == nil {
		return nil
	}
	c := d.startup.nodeChain
	if c == nil || requested != c.requested || requested != "server" && requested != "auto" {
		return errors.New("selected startup changed its original execution family")
	}
	return d.startup.nodeChainSelectionCurrent(ctx, a, selection)
        '''),
        ("cmd/client/startup_selected_execution.go", "func (d *desktopOrderedExecutionRuntime) checkPreparedStartup(ctx context.Context, a *app, s *desktopNodeChainExecutionSession, requested string) error", r'''
if d.startup == nil {
		return nil
	}
	if s == nil || s.execution == nil || s.execution.bound(s.launch) != nil || s.execution.preparation.Execution() != requested {
		return errors.New("selected startup prepared a different original family")
	}
	if err := d.startupSelectedCurrent(ctx, a, s.selection, requested); err != nil {
		return err
	}
	e := s.execution
	var last mobilemultihop.NodeChainExecutionLast
	var has bool
	var err error
	switch {
	case e.multiplePhysical != nil:
		last, has, err = e.preparation.MultipleImportedDesktopLast()
	case e.openvpnPhysical != nil:
		last, has, err = e.preparation.OpenVPNDesktopLast()
	case e.socksPhysical != nil:
		last, has, err = e.preparation.SOCKSDesktopLast()
	case e.connectPhysical != nil:
		last, has, err = e.preparation.CONNECTDesktopLast()
	default:
		last, has, err = e.preparation.DesktopLast()
	}
	saved := d.startup.nodeChain.selectedLast
	if err != nil || has != (saved != "") || has && last.JSON() != saved {
		return errors.Join(err, errors.New("selected startup failed to bind its original saved choice"))
	}
	return nil
        '''),
        ("cmd/client/startup_selected_execution.go", "func (d *desktopOrderedExecutionRuntime) checkStartupReady(ctx context.Context, a *app, s *desktopNodeChainExecutionSession, requested string) error", r'''
if err := d.startupSelectedCurrent(ctx, a, s.selection, requested); err != nil {
		return err
	}
	if d.startup == nil || d.startup.nodeChain.selectedLast == "" {
		return nil
	}
	last, err := mobilemultihop.ParseNodeChainExecutionLast(d.startup.nodeChain.selectedLast, s.execution.preparation)
	if err != nil {
		return err
	}
	result, err := s.Result(ctx)
	if err != nil || result.Winner == nil || string(result.Winner.Execution) != last.Execution() || result.Target != last.Target() {
		return errors.Join(err, errors.New("selected startup child changed its original frozen winner or target"))
	}
	return nil
        '''),
        ("cmd/client/strategy_modes.go", "func (a *app) saveStartupSelectionCurrent(selection startupSelection, current func() error) error", r'''
path := a.startupStatePath()
	if path == "" {
		return nil
	}
	if !validStartupProfileToken(selection.ProfileToken) {
		return errors.New("last-good startup state requires one exact profile/path-policy token")
	}
	if err := validateStartupNodeChainSelection(selection); err != nil {
		return err
	}
	body, err := json.MarshalIndent(selection, "", "  ")
	if err != nil {
		return err
	}
	if selection.NodeChain != nil && len(body)+1 > 64<<10 {
		return errors.New("ordered Last exceeds its private startup receipt byte limit")
	}
	_, err = atomicWritePrivateChecked(path, append(body, '\n'), current)
	return err
        '''),
        (product_path, "func (a *app) retireDesktopOrderedExecutionPreparation(ctx context.Context, s *desktopNodeChainExecutionSession) error", '''
if s == nil || s.app != a || s.launch == nil || s.execution == nil || s.launch.command != nil || s.graph != nil || s.native != nil {
    return errors.New("ordered preparation retirement lost its unentered original session")
}
if prior, exists := desktopOrderedExecutionPreparations.LoadOrStore(a, s); exists && prior != s {
    return errors.New("ordered preparation cannot replace an earlier cleanup owner")
}
if err := s.Close(ctx); err != nil { return err }
if !desktopOrderedExecutionPreparations.CompareAndDelete(a, s) {
    return errors.New("ordered preparation cleanup owner changed")
}
return ctx.Err()
        '''),
        (product_path, "func (a *app) retirePendingDesktopOrderedExecutionPreparation(ctx context.Context) error", '''
if ctx == nil { return errors.New("ordered pending retirement requires its original caller") }
if err := ctx.Err(); err != nil { return err }
raw, exists := desktopOrderedExecutionPreparations.Load(a)
if !exists { return nil }
s, ok := raw.(*desktopNodeChainExecutionSession)
if !ok || s == nil { return errors.New("ordered pending preparation lost its original cleanup owner") }
return a.retireDesktopOrderedExecutionPreparation(ctx, s)
        '''),
        (product_path, "func (a *app) connectDesktopOrderedExecution(ctx context.Context, selection multihopSelection, requested string, usage bool) (*desktopNodeChainExecutionSession, error)", '''
return a.connectDesktopOrderedExecutionWithRuntime(ctx, selection, requested, usage, nil)
        '''),
        ("cmd/client/desktop_external_owned_stop.go", "func (a *app) captureDesktopRetainedStopContext(ctx context.Context) (desktopRetainedStopCapture, error)", '''
if err := a.retirePendingDesktopOrderedExecutionPreparation(ctx); err != nil { return nil, err }
if captured, err := a.captureDesktopOrderedExecutionStopContext(ctx); captured != nil || err != nil { return captured, err }
return a.captureDesktopRetainedStopWithoutExecution()
        '''),
        ("cmd/client/desktop_node_owned.go", "func (a *app) releaseCapturedDesktopNodeProtection(slot *desktopNodeProtectionSlot) error", '''
ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()
return a.releaseCapturedDesktopNodeProtectionContext(ctx, slot)
        '''),
        ("cmd/client/desktop_node_owned.go", "func (a *app) releaseCapturedDesktopNodeProtectionContext(ctx context.Context, slot *desktopNodeProtectionSlot) error", '''
if ctx == nil || a == nil || slot == nil {
    return errors.New("native protection release requires its captured caller and slot")
}
if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil { return err }
current := a.nodeProtection == slot
a.mu.Unlock()
if !current { return errors.New("native protection release belongs to a replaced application slot") }
pending, err := slot.pendingOffContext(ctx)
if err != nil { return err }
if pending != nil {
    _, err := a.resumeDesktopProtectionOff(ctx, slot, pending, true)
    return err
}
if err := desktopnetwork.LockContext(ctx, &slot.mu); err != nil { return err }
defer slot.mu.Unlock()
if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil { return err }
current = a.nodeProtection == slot
a.mu.Unlock()
if !current { return errors.New("native protection release belongs to a replaced application slot") }
if err := slot.releaseLocked(ctx); err != nil { return err }
if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil { return err }
defer a.mu.Unlock()
if a.nodeProtection != slot {
    return errors.New("native protection release completed for a replaced application slot")
}
if slot.provedEmptyLocked() { a.nodeProtection = nil }
return ctx.Err()
        '''),
    )
    expected += (
        ("cmd/client/desktop_node_chain_openvpn_execution.go", "func desktopNodeChainOpenVPNExecutionMiddle(profile common.RouterProfile) bool", '''
	if !desktopNodeChainOpenVPNMiddle(profile, "openvpn") || profile.External.OpenVPNPairing == nil {
		return false
	}
	_, err := nativeopenvpn.ValidatePairing(*profile.External.OpenVPN, *profile.External.OpenVPNPairing)
	return err == nil

        '''),
        ("cmd/client/desktop_node_chain_openvpn_execution.go", "func desktopNodeChainOpenVPNExecutionShape(members []desktopNodeChainMember) bool", '''
	if len(members) < 3 || len(members) > mobilemultihop.NodeChainMaximumNodes {
		return false
	}
	middle, final := len(members)-2, len(members)-1
	if members[middle].Mode != "openvpn" || !desktopNodeChainOpenVPNExecutionMiddle(members[middle].Profile) || members[final].Mode != "shadowsocks" || !desktopOpenVPNExecutionPairedLayer(members[final].Profile.StartLayer) {
		return false
	}
	for _, member := range members[:middle] {
		if !mobilemultihop.NodeChainPrefixMode(member.Mode) || !desktopOpenVPNExecutionPairedLayer(member.Profile.StartLayer) {
			return false
		}
	}
	return true

        '''),
        ("cmd/client/desktop_node_chain_openvpn_execution.go", "func desktopOpenVPNExecutionPairedLayer(layer string) bool", '''
	return layer == "" || layer == "off" || layer == "aes-256-gcm" || layer == "aes-256-gcm+xor-whitening"

        '''),
        ("cmd/client/desktop_node_chain_openvpn_execution.go", "func desktopOpenVPNExecutionMembers(members []desktopNodeChainMember, requested string) bool", '''
	return (requested == "server" || requested == "auto") && desktopNodeChainOpenVPNExecutionShape(members) && desktopOrderedExecutionMembers(members, requested) == nil

        '''),
        ("cmd/client/desktop_node_chain_openvpn_execution.go", "func desktopOpenVPNExecutionChoices() []string", '''
	if nativeDesktopImportedTrioExecutionPlatformSupported() && nativeNodeChainOpenVPNPlatformSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}

        '''),
    )
    expected += (
        ("cmd/client/desktop_node_chain_hysteria_execution.go", 'func desktopHysteriaExecutionNodes(nodes []common.MultihopNodeSelection) bool', '\n\tif len(nodes) < 2 || len(nodes) > mobilemultihop.NodeChainMaximumNodes || nodes[len(nodes)-1].Mode != "hysteria2" {\n\t\treturn false\n\t}\n\tfor _, node := range nodes[:len(nodes)-1] {\n\t\tif !mobilemultihop.NodeChainPrefixMode(node.Mode) {\n\t\t\treturn false\n\t\t}\n\t}\n\treturn true\n'),
        ("cmd/client/desktop_node_chain_hysteria_execution.go", 'func desktopHysteriaExecutionMembers(members []desktopNodeChainMember, requested string) bool', '\n\tif (requested != "server" && requested != "auto") || !desktopHysteriaExecutionNodes(nodeChainSelectedReferences(members)) {\n\t\treturn false\n\t}\n\tids, proofs := map[string]bool{}, map[string]bool{}\n\tfor _, member := range members {\n\t\tprofile := member.Profile\n\t\tif !validProfileID(profile.ID) || ids[profile.ID] || profile.External != nil ||\n\t\t\t(profile.NodeKind != "" && profile.NodeKind != "router-vpn") || !common.ValidNodeProofID(profile.NodeProofID) || proofs[profile.NodeProofID] {\n\t\t\treturn false\n\t\t}\n\t\tif profile.StartLayer != "" && profile.StartLayer != "off" && profile.StartLayer != "aes-256-gcm" && profile.StartLayer != "aes-256-gcm+xor-whitening" {\n\t\t\treturn false\n\t\t}\n\t\tids[profile.ID], proofs[profile.NodeProofID] = true, true\n\t}\n\treturn true\n'),
        ("cmd/client/desktop_node_chain_hysteria_execution.go", 'func nativeDesktopHysteriaExecutionPlatformSupported() bool', '\n\treturn nativeNodeChainPlatformSupported() && retainedNativeMultihopSelected() &&\n\t\t(runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin") &&\n\t\t(runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")\n'),
        ("cmd/client/desktop_node_chain_hysteria_execution.go", 'func desktopHysteriaExecutionChoices() []string', '\n\tif nativeDesktopHysteriaExecutionPlatformSupported() {\n\t\treturn []string{"local", "server", "auto"}\n\t}\n\treturn []string{"local"}\n'),
    )
    expected += (
        ('cmd/client/desktop_node_chain_paired_ss_execution.go', 'func desktopPairedSSExecutionNodes(nodes []common.MultihopNodeSelection) bool', 'if len ( nodes ) < 2 | | len ( nodes ) > mobilemultihop . NodeChainMaximumNodes | | nodes [ len ( nodes ) - 1 ] . Mode ! = "shadowsocks" { return false } for _ , node : = range nodes [ : len ( nodes ) - 1 ] { if ! mobilemultihop . NodeChainPrefixMode ( node . Mode ) { return false } } return true'),
        ('cmd/client/desktop_node_chain_paired_ss_execution.go', 'func desktopPairedSSExecutionMembers(members []desktopNodeChainMember, requested string) bool', 'if ( requested ! = "server" & & requested ! = "auto" ) | | ! desktopPairedSSExecutionNodes ( nodeChainSelectedReferences ( members ) ) { return false } ids , proofs : = map [ string ] bool { } , map [ string ] bool { } for _ , member : = range members { profile : = member . Profile if ! validProfileID ( profile . ID ) | | ids [ profile . ID ] | | profile . External ! = nil | | ( profile . NodeKind ! = "" & & profile . NodeKind ! = "router-vpn" ) | | ! common . ValidNodeProofID ( profile . NodeProofID ) | | proofs [ profile . NodeProofID ] { return false } if profile . StartLayer ! = "" & & profile . StartLayer ! = "off" & & profile . StartLayer ! = "aes-256-gcm" & & profile . StartLayer ! = "aes-256-gcm+xor-whitening" { return false } ids [ profile . ID ] , proofs [ profile . NodeProofID ] = true , true } return true'),
        ('cmd/client/desktop_node_chain_paired_ss_execution.go', 'func nativeDesktopPairedSSExecutionPlatformSupported() bool', 'return nativeNodeChainPlatformSupported ( ) & & retainedNativeMultihopSelected ( ) & & runtime . GOOS = = "darwin" & & ( runtime . GOARCH = = "amd64" | | runtime . GOARCH = = "arm64" )'),
        ('cmd/client/desktop_node_chain_paired_ss_execution.go', 'func desktopPairedSSExecutionChoices() []string', 'if nativeDesktopPairedSSExecutionPlatformSupported ( ) { return [ ] string { "local" , "server" , "auto" } } return [ ] string { "local" }'),
    )
    expected += (
        ('cmd/client/desktop_node_chain_multiple_imported_execution.go', 'func desktopNodeChainMultipleImportedExecutionShape(members []desktopNodeChainMember) bool', r'''
	if len(members) < 4 || len(members) > mobilemultihop.NodeChainExtendedLocalMaximumNodes || members[len(members)-1].Mode != "shadowsocks" {
		return false
	}
	if len(members) > mobilemultihop.NodeChainMaximumNodes {
		if schema, err := desktopNodeChainSourceSchema(members); err != nil || schema != 6 {
			return false
		}
	}
	ids, proofs := map[string]bool{}, map[string]bool{}
	public, onlyPosition := 0, -1
	for position, member := range members {
		profile := member.Profile
		if !validProfileID(profile.ID) || ids[profile.ID] {
			return false
		}
		ids[profile.ID] = true
		if profile.NodeKind == "external" || profile.External != nil {
			if position == 0 || position == len(members)-1 || member.Mode != "shadowsocks" || !desktopNodeChainImportedExecutionMiddle(profile) || profile.StartLayer != "" && profile.StartLayer != "off" {
				return false
			}
			public++
			onlyPosition = position
			continue
		}
		if profile.NodeKind != "" && profile.NodeKind != "router-vpn" || !common.ValidNodeProofID(profile.NodeProofID) || proofs[profile.NodeProofID] || position < len(members)-1 && !mobilemultihop.NodeChainPrefixMode(member.Mode) {
			return false
		}
		if layer := profile.StartLayer; layer != "" && layer != "off" && layer != "aes-256-gcm" && layer != "aes-256-gcm+xor-whitening" {
			return false
		}
		proofs[profile.NodeProofID] = true
	}
	return public > 1 || public == 1 && onlyPosition != len(members)-2
        '''),
        ('cmd/client/desktop_node_chain_multiple_imported_execution.go', 'func desktopMultipleImportedExecutionMembers(members []desktopNodeChainMember, requested string) bool', r'''
	return (requested == "server" || requested == "auto") && desktopNodeChainMultipleImportedExecutionShape(members) && desktopOrderedExecutionMembers(members, requested) == nil
        '''),
        ('cmd/client/desktop_node_chain_multiple_imported_execution.go', 'func desktopMultipleImportedExecutionChoices() []string', r'''
	if nativeDesktopImportedTrioExecutionPlatformSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
        '''),
    )
    expected += (("internal/common/profile_node_chain.go", "func ExtendedMixedLocalPacketCount(nodes []MultihopNodeSelection) int", '''
	n := len(nodes)
	if n <= MultihopMaximumNodes || n > MultihopPhysicalTraversalDepth || nodes[n-1].Mode != "shadowsocks" {
		return 0
	}
	p := 0
	for p < n-1 && (nodes[p].Mode == "wg" || nodes[p].Mode == "awg2-fast" || nodes[p].Mode == "awg2-strong") {
		p++
	}
	if p == 0 || p >= n-1 || p == 1 && nodes[0].Mode == "wg" {
		return 0
	}
	for _, node := range nodes[p : n-1] {
		if node.Mode != "shadowsocks" {
			return 0
		}
	}
	return p
    '''),)
    for path, declaration, body in expected:
        if _function(_tokens(read(path)), declaration) != _tokens(body):
            return False

    schema = _function(_tokens(read("cmd/client/multihop_node_chain_imported_nodes.go")), "func desktopNodeChainSourceSchema(members []desktopNodeChainMember) (int, error)")
    if not _ordered_once(schema, r'''bad := errors.New("ordered imports require their complete Local source and supported positions")
	if len(members) < 2 || len(members) > mobilemultihop.NodeChainExtendedLocalMaximumNodes {
		return 0, bad
	}
	if len(members) > mobilemultihop.NodeChainMaximumNodes {
		last := len(members) - 1
		refs := nodeChainSelectedReferences(members)
		packets := common.ExtendedMixedLocalPacketCount(refs)
		paired := common.ExtendedPairedLocalMultihopSelection(refs)
		if paired {
			packets = last
		} else if common.ExtendedLocalMultihopSelection(refs) {
			packets = 1
		} else if packets == 0 {
			return 0, bad
		}
		for position, member := range members {
			p := member.Profile
			if position < packets || position == last {
				if p.External != nil || p.NodeKind != "" && p.NodeKind != "router-vpn" || p.StartLayer != "" && p.StartLayer != "off" {
					return 0, bad
				}
				continue
			}
			if !desktopNodeChainImportedExecutionMiddle(p) || member.Mode != "shadowsocks" || p.StartLayer != "" && p.StartLayer != "off" {
				return 0, bad
			}
			if addr, err := netip.ParseAddr(p.External.Shadowsocks.Server); err != nil || addr.Zone() != "" || addr.Is4In6() {
				return 0, bad
			}
		}
		if paired {
			return 1, nil
		}
		return 6, nil
	}
    '''):
        return False

    compiler = _tokens(read("cmd/client/startup_selected_compiler.go"))
    # Replaying an old presentation or measurement field may reproduce the
    # compiler input. Private profile sources and physical policy remain live.
    if len(_positions(compiler, '''var startupCompilerHistoryFields = [...]string{
        "AutoConnect", "StartupMode", "UseCount", "LastUsedAt",
        "EffectiveMTU", "EffectiveMTUSource", "EffectiveMTUPathKey", "EffectiveUnderlayPMTU",
        "EffectiveMTUTestedAt", "EffectiveMTUNetworkFingerprint", "EffectiveMTUProfileFingerprint",
        "EffectiveMTUMbps", "EffectiveMTUMedianRTTMs", "EffectiveMTUSuccessRatio",
        "LatencySamples", "LatencyMinMs", "LatencyMedianMs", "LatencyTrimmedMeanMs", "LatencyAverageMs",
        "LatencyP90Ms", "LatencyMaxMs", "LatencyLastTest", "LatencyReceipt",
    }''')) != 1:
        return False
    replay = _function(compiler, "func withStartupCompilerHistory(profile common.RouterProfile, raw string) (common.RouterProfile, error)")
    if replay != _tokens('''
        fields, err := startupStrictObject([]byte(raw), startupCompilerHistoryFields[:]...)
        if err != nil { return common.RouterProfile{}, err }
        value := reflect.ValueOf(&profile).Elem()
        for _, name := range startupCompilerHistoryFields {
            field := value.FieldByName(name)
            field.SetZero()
            if encoded, ok := fields[name]; ok {
                if err := json.Unmarshal(encoded, field.Addr().Interface()); err != nil { return common.RouterProfile{}, err }
            }
        }
        canonical, err := startupCompilerHistory(profile)
        if err != nil || canonical != raw { return common.RouterProfile{}, errors.New("ordered Last lost canonical compiler history") }
        return profile, nil
    '''):
        return False
    startup_path = "cmd/client/startup_selected_execution.go"
    startup = _function(_tokens(read(startup_path)), "func (a *app) startSelectedNodeChainStartupOwned(ctx context.Context, capture *startupPolicyCapture, supplied *desktopOrderedExecutionRuntime) error")
    if not _ordered_once(startup,
        'saved := capture.nodeChain.selectedLast',
        'if mode != "auto" && mode != "smart-auto" && mode != "last" || (mode == "last") != (saved != "") || (saved != "") != (capture.nodeChain.last != nil) { return errors.New("selected startup lost its original policy or proved Last") }',
        'driver := desktopOrderedExecutionRuntime{capture: captureNativeMultihopForAppContext, prepare: prepareDesktopOrderedExecutionSession, prepareLast: prepareDesktopOrderedExecutionSessionWithLast}',
        'driver.startup = capture original := capture.nodeChain',
        'if err := driver.startupSelectedCurrent(ctx, a, original.selection, original.requested); err != nil { return err }',
        's, err := a.connectDesktopOrderedExecutionWithRuntime(ctx, original.selection, original.requested, true, &driver)'):
        return False
    ready_last = _function(_tokens(read(startup_path)), "func (a *app) selectedStartupSelectionAtReady(ctx context.Context, s *desktopNodeChainExecutionSession, startup *startupPolicyCapture) (startupSelection, error)")
    if not _ordered_once(ready_last,
        'if s == nil || s.app != a || s.execution == nil || s.execution.draftPurpose != nil || s.selection.Native == nil || s.selection.Native.chain == nil || s.execution.bound(s.launch) != nil {',
        'if err := s.Current(ctx); err != nil { return startupSelection{}, err }',
        'if err := desktopnetwork.LockContext(ctx, &e.mu); err != nil { return startupSelection{}, err }',
        'if e.ready == nil || e.projection == nil { e.mu.Unlock() return startupSelection{}, errors.New("selected Last preceded native readiness") }',
        'ready := *e.ready e.mu.Unlock()',
        'last, err := e.provedLastAtReady(ctx, s.launch, ready) if err != nil { return startupSelection{}, err }',
        'return originalStartupNodeChainReceipt(s.selection, e.preparation.Execution(), last.JSON(), prior)'):
        return False
    private_write = _function(_tokens(read("cmd/client/private_store.go")), "func atomicWritePrivateChecked(path string, data []byte, current func() error) (os.FileInfo, error)")
    if not _ordered_once(private_write,
        'if current != nil { if err := current(); err != nil { return nil, err } } if err := validatePrivateParent(path); err != nil { return nil, err } parent := filepath.Dir(path)',
        'if err := tmp.Chmod(0o600); err != nil { return nil, err }',
        'if err := tmp.Sync(); err != nil { return nil, err }',
        'if err := tmp.Close(); err != nil { return nil, err } if current != nil { if err := current(); err != nil { return nil, err } }',
        'if err := validatePrivateParent(path); err != nil { return nil, err } if err := atomicWritePrivateTargetUnchanged(path, targetBefore); err != nil { return nil, err }',
        'if err := replacePrivateStoreFile(tmpPath, path); err != nil { return nil, err } committed = true'):
        return False

    status = _function(_tokens(read("cmd/client/multihop_native_routes.go")),
        "func (a *app) nativeMultihopStatus(w http.ResponseWriter, r *http.Request)")
    if not _ordered_once(status,
        '"ordered_executions": desktopOrderedExecutionChoices(),',
        '"ordered_imported_trio_executions": desktopImportedTrioExecutionChoices(),',
        '"ordered_connect_trio_executions": desktopCONNECTTrioExecutionChoices(),',
        '"ordered_socks_trio_executions": desktopSOCKSTrioExecutionChoices(),'):
        return False
    if len(_positions(status, '"ordered_paired_ss_executions": desktopPairedSSExecutionChoices(),')) != 1:
        return False
    if len(_positions(status, '"ordered_hysteria_executions": desktopHysteriaExecutionChoices(),')) != 1:
        return False
    if len(_positions(status, '"ordered_multiple_imported_executions": desktopMultipleImportedExecutionChoices(),')) != 1:
        return False
    if len(_positions(_tokens(read("cmd/client/profile_public_view.go")), 'OrderedHostnameExecutionMiddle bool `json:"ordered_hostname_execution_middle_supported"`')) != 1:
        return False
    public_profile = _function(_tokens(read("cmd/client/profile_public_view.go")),
        "func publicProfileForCapabilities(p common.RouterProfile, caps []standardExitCapability) publicProfile")
    if not _ordered_once(public_profile,
        'OrderedSOCKSExecutionMiddle: nativeDesktopImportedTrioExecutionPlatformSupported() && nativeNodeChainSOCKSHostSupported() && desktopNodeChainSOCKSMiddle(p, "socks5"),',
        'OrderedCONNECTExecutionMiddle: nativeDesktopImportedTrioExecutionPlatformSupported() && (desktopNodeChainCONNECTMiddle(p, "http-connect") || desktopNodeChainCONNECTMiddle(p, "https-connect")),',
        'OrderedExecutionMiddle: nativeDesktopImportedTrioExecutionPlatformSupported() && desktopNodeChainImportedExecutionMiddle(p),',
        'OrderedHostnameExecutionMiddle: nativeDesktopImportedTrioExecutionPlatformSupported() && desktopNodeChainImportedHostnameExecutionMiddle(p),'):
        return False

    if len(_positions(public_profile, 'out.External.OrderedMultipleImportedExecution = nativeDesktopImportedTrioExecutionPlatformSupported() && desktopNodeChainImportedExecutionMiddle(p)')) != 1:
        return False

    handler = _function(_tokens(read("cmd/client/multihop_native_routes.go")),
        "func (a *app) nativeMultihopConnectOwned(w http.ResponseWriter, r *http.Request, driver nativeMultihopConnectRuntime)")
    if not _ordered_once(handler,
        "sel, err := a.resolveNativeMultihopRequestLocked(q)",
        '''if execution, err := routeExecution(q); err != nil {
            http.Error(w, err.Error(), 400)
            return
        } else if execution != "local" {
            if q.ordered() {
                a.runDesktopOrderedExecution(w, r, operation, sel, q.Execution, driver.execution)
                return
            }
            a.runMultihopExecution(w, r, sel, q)
            return
        }''',
        "a.nativeMultihopConnectLocalOwned(w, r, operation, sel, driver)"):
        return False
    run = _function(product, "func (a *app) runDesktopOrderedExecution(w http.ResponseWriter, r *http.Request, operation context.Context, selection multihopSelection, requested string, driver *desktopOrderedExecutionRuntime)")
    if not _ordered_once(run,
        "s, err := a.connectDesktopOrderedExecutionWithRuntime(operation, selection, requested, true, driver)",
        '''if err != nil { http.Error(w, err.Error(), http.StatusBadGateway)
return }''',
        "a.startRouterNodeAutomaticMTU()",
        '"requested_execution": requested, "execution": s.graph.Execution, "nodes": nodeChainSelectedReferences(s.selection.Nodes)'):
        return False
    connect = _function(product, "func (a *app) connectDesktopOrderedExecutionWithRuntime(ctx context.Context, selection multihopSelection, requested string, usage bool, modeled *desktopOrderedExecutionRuntime) (*desktopNodeChainExecutionSession, error)")
    if not _ordered_once(connect,
        "driver := desktopOrderedExecutionRuntime{capture: captureNativeMultihopForAppContext, prepare: prepareDesktopOrderedExecutionSession}",
        "if modeled != nil { driver = *modeled }",
        "if driver.capture == nil || driver.prepare == nil { return nil, errors.New(\"ordered execution lost its concrete native adapter\") }",
        '''if ctx == nil || a.checkCapturedConnectionOperation(ctx) != nil || !nativeDesktopOrderedExecutionSelectionPlatformSupported(selection.Nodes, requested) || requested == "local" {
            return nil, errors.New("ordered execution has no original admitted connection operation")
        }''',
        "if err := desktopOrderedExecutionSelection(nodeChainSelectedReferences(selection.Nodes), requested); err != nil { return nil, err }",
        "if err := desktopOrderedExecutionMembers(selection.Nodes, requested); err != nil { return nil, err }",
        '''if _, pending := desktopOrderedExecutionPreparations.Load(a); pending {
            return nil, errors.New("ordered preparation cleanup must finish before another connection")
        }''',
        '''if selection.Native == nil {
            var err error
            captureContext := ctx
            if driver.startup != nil { captureContext = driver.startup.nodeChain.compilerContext(ctx) }
            selection, err = driver.capture(captureContext, a, selection, []string{selection.ExitMode})
            if err != nil { return nil, err }
        }''',
        "if err := driver.startupSelectedCurrent(ctx, a, selection, requested); err != nil { return nil, err }",
        '''if driver.startup != nil && driver.startup.nodeChain.selectedLast != "" {
            if driver.prepareLast == nil { return nil, errors.New("selected startup has no original Last adapter") }
            s, err = driver.prepareLast(ctx, a, selection, requested, driver.startup.nodeChain.selectedLast)
        } else { s, err = driver.prepare(ctx, a, selection, requested) }''',
        '''if err == nil && (s == nil || s.app != a || s.launch == nil || s.execution == nil || s.launch.command != nil || s.graph != nil || s.native != nil) {
            err = errors.New("ordered preparation did not return its unused original session")
        }''',
        "if err == nil { err = driver.checkPreparedStartup(ctx, a, s, requested) }",
        "if err == nil { err = a.guardDesktopOwnedNodeTransitionContext(ctx, s.launch) }",
        "if err == nil { err = a.stopModeWithIntent(true) }",
        "if err == nil { err = a.checkCapturedConnectionOperation(ctx) }",
        "if err == nil { err = driver.startupSelectedCurrent(ctx, a, selection, requested) }",
        '''if err != nil {
            if s != nil {
                cleanup, cancel := desktopNodeChainRetirementContext()
                err = errors.Join(err, a.retireDesktopOrderedExecutionPreparation(cleanup, s))
                cancel()
            }
            return s, err
        }''',
        'sessionTrackerFor(a).declareRequest("multihop", selection.Base)',
        "err = s.startContext(ctx)",
        "_, retainErr := a.retainDesktopOrderedExecution(s)",
        "err = errors.Join(err, retainErr)",
        "if s != nil && s.launch.command != nil && a.ownsConnectionRuntime(s.launch.command) { err = errors.Join(err, a.speedLabOwnRuntime(s.launch.command)) }",
        "if err == nil { err = s.Verify(ctx) }",
        "if err == nil { err = driver.checkStartupReady(ctx, a, s, requested) }",
        "if err == nil { err = a.publishDesktopOrderedExecutionWithStartup(ctx, s, usage, driver.startup) }",
        '''if err != nil {
            if s != nil {
                cleanup, cancel := desktopNodeChainRetirementContext()
                closeErr := s.Close(cleanup)
                cancel()
                err = errors.Join(err, closeErr)
            }
            return s, err
        }''',
        "return s, nil"):
        return False
    if any(_positions(body, fragment) for body in (connect, run) for fragment in
           ("routechoice.Compare(", "a.runMultihopExecution(", "runLocalServerComparison(")):
        return False
    retain = _function(product, "func (a *app) retainDesktopOrderedExecution(s *desktopNodeChainExecutionSession) (*desktopOrderedExecutionOwner, error)")
    if not _ordered_once(retain,
        "if s == nil || s.app != a || s.launch == nil || s.execution == nil { return nil, errors.New(\"ordered execution lost its actual startup owner\") }",
        "owner := &desktopOrderedExecutionOwner{session: s}",
        '''if s.launch.ownedNode != nil { s.launch.workspaceMu.Lock()
owner.slot = s.launch.ownedNode.slot
s.launch.workspaceMu.Unlock() }''',
        '''if old, exists := desktopOrderedExecutionOwners.LoadOrStore(a, owner); exists {
            if prior, ok := old.(*desktopOrderedExecutionOwner); ok && prior.session == s { return prior, nil }
            return nil, errors.New("ordered execution cannot replace an unretired session")
        }''',
        "return owner, nil"):
        return False
    publish = _function(product, "func (a *app) publishDesktopOrderedExecutionWithStartup(ctx context.Context, s *desktopNodeChainExecutionSession, usage bool, startup *startupPolicyCapture) error")
    if not _ordered_once(publish,
        "if s == nil || s.app != a { return errors.New(\"ordered publication lost its actual session\") }",
        "if err := s.Current(ctx); err != nil { return err } result, err := s.Result(ctx)",
        '''if err != nil || result.Winner == nil || s.graph == nil || string(result.Winner.Execution) != s.graph.Execution {
            return errors.Join(err, errors.New("ordered publication lost its child's selected proof"))
        }''',
        '''if usage && a.startupStatePath() != "" {
            proved, err := a.selectedStartupSelectionAtReady(ctx, s, startup)
            if err != nil { return err }
            last = &proved
            if err := s.Current(ctx); err != nil { return err }
        }''',
        "if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil { return err }",
        "defer a.mu.Unlock()",
        "current := func() error { owner, ownerErr := a.desktopOrderedExecutionOwner()",
        '''if ownerErr != nil || owner == nil || owner.session != s || a.cmd != s.launch.command ||
            a.checkCapturedConnectionOperationLocked(ctx) != nil || s.execution.publicationCurrentLocked(ctx, a, s.launch, s.selection) != nil {
            return errors.Join(ownerErr, errors.New("ordered publication changed its operation, source or native owner"))
        }''',
        '''if last != nil && (a.state.Mode != "multihop" || a.state.RouterID != last.RouterID || a.state.RuntimeMode != last.RuntimeMode ||
            a.state.LogicalMode != last.LogicalMode || a.state.Base != last.Base) {
            return errors.New("selected Last lost its original route before publication")
        }
        return ctx.Err() }
        if err := current(); err != nil { return err }''',
        "previous := cloneRouterProfileStore(a.profiles)",
        "used := make(map[string]bool, len(s.selection.Nodes))",
        "for _, node := range s.selection.Nodes { used[node.Profile.ID] = true }",
        '''for i := range a.profiles.Profiles { if used[a.profiles.Profiles[i].ID] { a.profiles.Profiles[i].UseCount++
a.profiles.Profiles[i].LastUsedAt = now } }''',
        '''if err := a.persistProfilesLocked(); err != nil { a.rollbackProfilesLocked(previous)
return err }''',
        '''if last != nil { if err := a.saveStartupSelectionCurrent(*last, current); err != nil {
            a.rollbackProfilesLocked(previous)
            return errors.Join(fmt.Errorf("could not commit selected startup Last: %w", err), a.persistProfilesLocked())
        } } }''',
        '''progress := &comparisonOwner{value: routeComparisonProgress{
            ID: s.launch.chain.policy.Metadata().SessionID, Stage: "selected", Complete: true,
            Execution: s.graph.Execution, Measurements: result.Measurements,
        }}''',
        "desktopComparisons.Store(a, progress)",
        'a.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""'):
        return False
    stop = _function(_tokens(read("cmd/client/main.go")),
        "func (a *app) stopModeWithDNSReceiptContext(caller context.Context, holdKillSwitch bool, expected *sessionDNSStopReceipt) (failure error)")
    if not _ordered_once(stop,
        "if caller == nil { return errors.New(\"Stop requires its original cleanup caller\") }",
        "ctx, cancel := context.WithTimeout(caller, 15*time.Second)",
        "dnsStop, err := a.drainCapturedSessionDNSForStop(ctx, expected)",
        "if err := retireLegacyStandardPreparations(a, ctx); err != nil { return err }",
        "nativeStop, err := a.captureDesktopRetainedStopContext(ctx)",
        "if err != nil { return err } releaseMTU, relayOwner, err := a.holdMTUForStop()",
        "if nativeStop != nil { return nativeStop.Retire(ctx, relayOwner, !holdKillSwitch) }"):
        return False
    capture = _function(product, "func (a *app) captureDesktopOrderedExecutionStopContext(ctx context.Context) (desktopRetainedStopCapture, error)")
    if not _ordered_once(capture,
        "if ctx == nil { return nil, errors.New(\"ordered Stop capture requires its original caller\") }",
        "owner, err := a.desktopOrderedExecutionOwner()",
        "if err != nil || owner == nil { return nil, err }",
        "if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil { return nil, err }",
        "stop := &desktopOrderedExecutionStop{owner: owner, operation: a.connectionContext, command: a.cmd}",
        "a.mu.Unlock()",
        "if stop.command != nil && stop.command != owner.session.launch.command { return nil, errors.New(\"ordered Stop cannot adopt a replacement command\") }",
        "if !owner.nativeRetired && owner.session.launch.chain.platform != nil {",
        "if !supported { return nil, errors.New(\"ordered platform has no captured execution Stop capability\") }",
        "captureCtx, cancel := context.WithTimeout(ctx, 2*time.Second)",
        "owner.stop, err = platform.captureExecutionProductStop(captureCtx, owner.session)",
        "cancel()",
        "if err != nil { return nil, err }",
        "if owner.stop == nil {",
        "if !desktopOrderedExecutionOwners.CompareAndDelete(a, owner) { return nil, errors.New(\"unentered execution cleanup owner changed\") }",
        "return a.captureDesktopRetainedStopWithoutExecution()",
        "return stop, nil"):
        return False
    retire = _function(product, "func (stop *desktopOrderedExecutionStop) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) error")
    if not _ordered_once(retire,
        "if ctx == nil || stop == nil || stop.owner == nil || stop.owner.session == nil { return errors.New(\"ordered Stop lost its captured session\") }",
        "owner, s := stop.owner, stop.owner.session",
        "a := s.app",
        "if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil { return err }",
        "current, ok := desktopOrderedExecutionOwners.Load(a)",
        "matched := ok && current == owner && a.connectionContext == stop.operation && a.cmd == stop.command && command == stop.command",
        "a.mu.Unlock()",
        "if !matched { return errors.New(\"ordered Stop belongs to a replaced operation or child\") }",
        "saved, err := a.speedLabOrderedExecutionRestore(ctx, owner)",
        "if err != nil { return err } if saved != nil {",
        "if disconnect { return errors.New(\"ordered temporary restore cannot release its retained native baseline\") }",
        "if err := saved.retire(ctx); err != nil { return err }",
        "if err := owner.stop.Retire(ctx, command, disconnect); err != nil { return err }",
        "owner.nativeRetired = true",
        "if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil { return err }",
        "s.captureDNSPublication()",
        "err := s.finishRetirementLocked(ctx)",
        "s.mu.Unlock()",
        "if err := s.Close(ctx); err != nil { return err }",
        "if disconnect && owner.slot != nil {",
        "if err := a.releaseCapturedDesktopNodeProtectionContext(ctx, owner.slot); err != nil { return err }",
        "desktopOrderedExecutionOwners.CompareAndDelete(a, owner)",
        "return ctx.Err()"):
        return False
    restore = _function(_tokens(read("cmd/client/desktop_node_chain_execution_product_restore.go")),
        "func (a *app) speedLabOrderedExecutionRestore(ctx context.Context, original *desktopOrderedExecutionOwner) (*desktopOrderedExecutionRestore, error)")
    if restore != _tokens('''
        if ctx == nil { return nil, errors.New("ordered restore lookup requires its original Stop caller") }
        if err := ctx.Err(); err != nil { return nil, err }
        raw, exists := speedLabTemporaryOwners.Load(a)
        if !exists { return nil, nil }
        owner, ok := raw.(*speedLabTemporaryOwner)
        if !ok || owner == nil { return nil, nil }
        if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil { return nil, err }
        defer a.mu.Unlock()
        saved := owner.orderedExecution
        if !a.speedLabOwnerCurrentLocked(owner) || owner.intent.Err() != nil || saved == nil || saved.owner != original { return nil, nil }
        return saved, nil
    '''):
        return False
    return True


def native_multihop_shipping_chain(source: str, read=None) -> bool:
    if not native_multihop_request_admission(read) or not native_multihop_execution_product(read):
        return False
    # Ordinary Darwin admission is bounded independently from CONNECT and
    # Server/Compare. Preserve the existing Linux/Windows target behavior.
    ordinary = _tokens(read("cmd/client/desktop_node_chain_public_admission.go"))
    if (_function(_tokens(source), "func nativeNodeChainPlatformSupported() bool") != _tokens("return nativeNodeChainHostSupported()") or
            _function(ordinary, "func nativeNodeChainHostSupported() bool") != _tokens("return desktopNodeChainPublicAdmissionSupported(runtime.GOOS, runtime.GOARCH, retainedNativeMultihopSelected())") or
            _function(ordinary, "func desktopNodeChainPublicAdmissionSupported(targetOS, targetArch string, retained bool) bool") != _tokens('return retained && (targetOS == "linux" || targetOS == "windows" || targetOS == "darwin" && (targetArch == "amd64" || targetArch == "arm64"))')):
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
            target != _tokens('return retained && (targetOS == "linux" || targetOS == "windows" || targetOS == "darwin") && (targetArch == "amd64" || targetArch == "arm64")')):
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
    connect_admission = _tokens(read("cmd/client/desktop_node_chain_connect_admission.go"))
    connect_bounds = _function(connect_admission,
        "func desktopNodeChainCONNECTAdmissionSupported(targetOS, targetArch string, retained, orderedHost bool) bool")
    connect_host = _function(connect_admission, "func nativeNodeChainCONNECTHostSupported() bool")
    if (connect_support != _tokens("return nativeNodeChainCONNECTHostSupported()") or
        connect_bounds != _tokens('''
            return retained && orderedHost && (targetOS == "linux" || targetOS == "windows" || targetOS == "darwin") &&
                (targetArch == "amd64" || targetArch == "arm64")
        ''') or connect_host != _tokens('''
            return desktopNodeChainCONNECTAdmissionSupported(runtime.GOOS, runtime.GOARCH,
                retainedNativeMultihopSelected(), nativeNodeChainPlatformSupported())
        ''') or connect_detector != _tokens('''
        for _, node := range nodes {
            if node.Mode == "http-connect" || node.Mode == "https-connect" { return true }
        }
        return false
    ''')):
        return False
    openvpn = _tokens(read("cmd/client/multihop_node_chain_openvpn.go"))
    if (_function(openvpn, "func nativeNodeChainOpenVPNPlatformSupported() bool") != _tokens('''
        return nativeNodeChainPlatformSupported() && (runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin") &&
            (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
    ''') or _function(openvpn, "func desktopNodeChainHasOpenVPN(nodes []common.MultihopNodeSelection) bool") != _tokens('''
        for _, node := range nodes {
            if node.Mode == "openvpn" { return true }
        }
        return false
    ''')):
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
            '''if q.ordered() && (!nativeNodeChainPlatformSupported() || desktopNodeChainHasSOCKS(q.Nodes) && !nativeNodeChainSOCKSPlatformSupported() || desktopNodeChainHasCONNECT(q.Nodes) && !nativeNodeChainCONNECTPlatformSupported() || desktopNodeChainHasOpenVPN(q.Nodes) && !nativeNodeChainOpenVPNPlatformSupported()) {
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
