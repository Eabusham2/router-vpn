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


def native_multihop_proof_lanes(source: str, imported_source: str) -> bool:
    """Source-only closure of both compiler captures and their exact proof routes."""
    tokens, imported = _tokens(source), _tokens(imported_source)
    capture = _function(tokens, "func captureNativeMultihopSelection(ctx context.Context, root string, sel multihopSelection, modes []string, lookup applexray.Lookup) (multihopSelection, error)")
    imported_capture = _function(imported, "func captureDesktopImportedMultihop(ctx context.Context, root string, sel multihopSelection, modes []string, lookup applexray.Lookup) (multihopSelection, error)")
    graph = _function(tokens, "func nativeMultihopProofConfig(config string, entry common.RouterProfile) (string, string, error)")
    return (
        _ordered_once(capture, '''
            if sel.Entry.NodeKind == "external" {
                return captureDesktopImportedMultihop(ctx, root, sel, modes, lookup)
            }
        ''', "config, _, e = nativeMultihopProofConfig(config, sel.Entry)")
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


def native_multihop_proof_admission(source: str, imported_source: str, dns_source: str) -> bool:
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
        admission == _tokens('''
            ctx, cancel := context.WithTimeout(a.connectionOperationContextOrBackground(), nativeMultihopProofTimeout(sel))
            defer cancel()
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
        "err = driver.stage(a, sel, native)",
        "cmd := native.command",
        "err = cmd.Start()",
        "err = bindNativeMultihopRuntime(a, native, sel, network)",
        "proofErr := driver.proof(a, sel, cmd)",
    )
    previous = -1
    for call in calls:
        matches = _positions(owned, call)
        if len(matches) != 1 or matches[0] <= previous:
            return False
        previous = matches[0]
    return True
