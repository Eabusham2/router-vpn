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
        start == _tokens('''
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
    return (
        native_multihop_platform_chain(read)
        and admission == _tokens('''
            ctx, cancel := context.WithTimeout(a.connectionOperationContextOrBackground(), nativeMultihopProofTimeout(sel))
            defer cancel()
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
            if sel.Native.imported {
                for _, captured := range []common.RouterProfile{sel.Control, sel.Entry, sel.Exit} {
                    current, ok := a.profileByIDLocked(captured.ID)
                    owned = owned && ok && mtuProfileSnapshotToken(current) == mtuProfileSnapshotToken(captured)
                }
            }
            a.mu.Unlock()
            if !owned { return false }
            if !sel.Native.imported { return true }
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


def native_multihop_shipping_chain(source: str) -> bool:
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
    owned = _function(tokens, "func (a *app) nativeMultihopConnectOwned(w http.ResponseWriter, r *http.Request, driver nativeMultihopConnectRuntime)")
    if owned is None or owned.count("driver") != 4:
        return False
    calls = (
        "sel, err = driver.capture(a, sel, []string{sel.ExitMode})",
        "native, err := driver.preflight(a, sel, nil)",
        "a.stopModeWithIntent(native.ownedNode != nil || native.importedPlatform != nil)",
        "err = driver.stage(a, sel, native)",
        "cmd := native.command",
        '''protected := native.ownedNode != nil || native.importedPlatform != nil
        if native.importedPlatform != nil {
            err = startDesktopImportedPlatform(operation, a, sel, native)
            cmd = native.command
        } else if protected {
            a.mu.Lock()
            err = a.publishDesktopImportedMultihopStartLocked(operation, native, sel)
            a.mu.Unlock()
        } else {
            err = cmd.Start()
        }''',
        "err = bindNativeMultihopRuntime(a, native, sel, network)",
        '''if protected && native.importedPlatform == nil {
            if err := startDesktopOwnedImportedLaunch(operation, operation, a, native); err != nil {
                message, _ := a.multihopStopFailure(cmd, err.Error())
                sessionTrackerFor(a).markRequestFailure(message)
                http.Error(w, message, http.StatusInternalServerError)
                return
            }
        }''',
        "proofErr := driver.proof(a, sel, cmd)",
        '''if proofErr == nil && native.importedPlatform != nil {
            proofErr = native.importedPlatform.Activate(operation)
        }''',
    )
    previous = -1
    for call in calls:
        matches = _positions(owned, call)
        if len(matches) != 1 or matches[0] <= previous:
            return False
        previous = matches[0]
    return True
