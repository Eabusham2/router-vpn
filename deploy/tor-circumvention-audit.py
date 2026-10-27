#!/usr/bin/env python3
"""Authoritative Tor censorship-circumvention and shipping contract."""
from __future__ import annotations

from pathlib import Path
import ast
import re

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing Tor source: {path}")
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing Tor marker {marker!r}")


def forbid(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker in body:
            errors.append(f"{path}: forbidden Tor marker {marker!r}")


def need_android_tor_editor_controls(path: str) -> None:
    try:
        tree = ast.parse(read(path))
        controls = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "controls" for target in node.targets))
        rows = ast.literal_eval(controls.value)
        expected = {"rewritten-policy", "ipv6-default", "lan-default", "dns-precedence", "hidden-mode-list"}
        if not expected.issubset({row[0] for row in rows}):
            raise ValueError("an actual Tor editor mutation control is missing")
        guard = "rejected.returncode == 0 or failure not in rejected.stderr"
        if not any(isinstance(node, ast.If) and ast.unparse(node.test) == guard
                   and any(isinstance(child, ast.Raise) for child in node.body) for node in ast.walk(tree)):
            raise ValueError("mutated shipping editor must fail its specific executable assertion")
    except (SyntaxError, ValueError, TypeError, IndexError, StopIteration) as error:
        errors.append(f"{path}: Tor editor negative controls are incomplete: {error}")


def go_contract_tokens(source: str) -> tuple[str, ...]:
    # Keep strings/runes as single tokens, so braces inside literals do not
    # affect block ownership and a comment/string cannot replace a real call.
    pattern = r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|`[^`]*`|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|\d+|:=|==|!=|<=|>=|<-|&&|\|\||\+\+|--|[^\s]'
    return tuple(token for token in re.findall(pattern, source)
                 if not token.startswith(("//", "/*")))


def go_contract_at(tokens: tuple[str, ...], marker: str) -> int:
    expected = go_contract_tokens(marker)
    matches = [i for i in range(len(tokens) - len(expected) + 1)
               if tokens[i:i + len(expected)] == expected]
    if len(matches) != 1:
        raise ValueError(f"expected one executable occurrence of {marker!r}")
    return matches[0]


def go_contract_block(tokens: tuple[str, ...], marker: str) -> tuple[str, ...]:
    start = tokens.index("{", go_contract_at(tokens, marker) + len(go_contract_tokens(marker)))
    depth = 1
    for end in range(start + 1, len(tokens)):
        depth += (tokens[end] == "{") - (tokens[end] == "}")
        if depth == 0:
            return tokens[start + 1:end]
    raise ValueError(f"unterminated executable block after {marker!r}")


def need_desktop_tor_choice() -> None:
    """Follow the admitted durable save instead of a retired inline call."""
    try:
        route = go_contract_block(go_contract_tokens(read("cmd/client/tor_bridge_routes.go")),
                                  "func (a *app) torBridgeConnectSelectionOwned(")
        save = go_contract_at(route, "saved, saveErr := a.commitDesktopTorChoice(selection, prelaunch.workspace, q, startup, operation, selected, actualIP)")
        rejected = go_contract_block(route, "if saveErr != nil")
        for marker in ("a.torBridgeStopFailure(cmd, saveErr.Error())", "http.Error(w, message, status)", "return"):
            go_contract_at(rejected, marker)
        adopted = go_contract_at(route, "retainedProof, err = saved.adopt(a)")
        monitored = go_contract_at(route, "a.monitorDesktopTorRuntime(prelaunch.workspace)")
        if not (save < go_contract_at(route, "if saveErr != nil") < adopted < monitored):
            raise ValueError("Tor route did not save and admit its captured choice before monitoring")
        failed_adoption = go_contract_block(route[adopted:monitored], "if err != nil")
        for marker in ("a.torBridgeStopFailure(cmd,", "http.Error(w, message, status)", "return"):
            go_contract_at(failed_adoption, marker)

        source = go_contract_tokens(read("cmd/client/desktop_tor_persistence.go"))
        commit = go_contract_block(source, "func (a *app) commitDesktopTorChoice(")
        write = go_contract_at(commit, "if err := a.persistProfilesLocked(); err != nil")
        before_write = commit[:write]
        for marker in ("proof, err := a.readDesktopTorProof(launch)", "if proof.Proof.IP != actualIP",
                       "if err := selection.current(a); err != nil"):
            go_contract_at(before_write, marker)
        go_contract_at(go_contract_block(before_write, "if err := selection.current(a); err != nil"), "return nil, err")
        admission = "if desktopTorOperationCurrentLocked(a, operation, selected) != nil || !present || registered != launch || !desktopTorChoiceRuntimeCurrentLocked(a, launch) || !found || launch.tor.committedChoice.Load() != nil || selection.currentLocked(a) != nil || a.validateExternalProfileExpectedProfilesLocked(q, selection.profile) != nil || startup != nil && startup.currentLocked(a) != nil"
        go_contract_at(go_contract_block(before_write, admission), "return nil, errors.New(")
        source_capture = go_contract_at(before_write, "source, err := startupExternalSourceToken(a, entry, mode)")
        source_guard = "if err != nil || selection.predecessor != nil && source != selection.predecessor.assetsSHA256"
        go_contract_at(go_contract_block(before_write, source_guard), "return nil, errors.New(")
        final_marker = "if err := desktopTorOperationCurrentLocked(a, operation, selected); err != nil"
        final_check = go_contract_at(before_write, final_marker)
        go_contract_at(go_contract_block(before_write, final_marker), "return nil, err")
        rollback = go_contract_block(commit, "if err := a.persistProfilesLocked(); err != nil")
        restore = go_contract_at(rollback, "a.rollbackProfilesLocked(previous)")
        failed_save = go_contract_at(rollback, 'return nil, fmt.Errorf("%w: %v", errDesktopTorChoiceSave, err)')
        choice = go_contract_at(commit, "choice := &desktopTorCommittedChoice{profileToken: desktopTorSourceIdentityToken(updated), nodeID: updated.ID, sessionID: launch.tor.expected.SessionID, sourceSHA256: launch.tor.expected.SourceSHA256}")
        bound = go_contract_at(commit, "launch.tor.committedChoice.Store(choice)")
        if not source_capture < go_contract_at(before_write, source_guard) < final_check < write < choice < bound or restore >= failed_save:
            raise ValueError("Tor committed-source binding preceded checked durable persistence")

        token = go_contract_block(source, "func (owner *desktopTorRuntime) sourceIdentityToken(")
        committed = go_contract_block(token, "if choice := owner.committedChoice.Load(); choice != nil")
        mismatch = go_contract_block(committed, "if choice.nodeID != owner.expected.NodeID || choice.sessionID != owner.expected.SessionID || choice.sourceSHA256 != owner.expected.SourceSHA256")
        go_contract_at(mismatch, 'return ""')
        if go_contract_at(committed, "if choice.nodeID") >= go_contract_at(committed, "return choice.profileToken"):
            raise ValueError("Tor committed-source token was not bound to its captured native session")

        adopt = go_contract_block(source, "func (saved *desktopTorChoiceAdoption) adopt(")
        startup = go_contract_at(adopt, "if err := a.saveStartupSelection(saved.startup); err != nil")
        before_startup = adopt[:startup]
        go_contract_at(before_startup, "a.readDesktopTorProof(saved.launch)")
        go_contract_at(go_contract_block(before_startup, "if err != nil"), "return desktopTorProof{}, err")
        go_contract_at(go_contract_block(before_startup, "if err := saved.currentLocked(a); err != nil"), "return desktopTorProof{}, err")
        failed_startup = go_contract_block(adopt, "if err := a.saveStartupSelection(saved.startup); err != nil")
        go_contract_at(failed_startup, "return desktopTorProof{}, fmt.Errorf(")
        final_proof = go_contract_at(adopt, "proof, err := a.readDesktopTorProof(saved.launch)")
        final = adopt[final_proof:]
        go_contract_at(go_contract_block(final, "if err != nil"), "return desktopTorProof{}, err")
        guard = go_contract_block(final, "if err := saved.currentLocked(a); err != nil")
        go_contract_at(guard, "return desktopTorProof{}, err")
        connected = go_contract_at(final, 'a.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""')
        if not startup < final_proof or go_contract_at(final, "if err := saved.currentLocked(a); err != nil") >= connected:
            raise ValueError("Tor Connected preceded fresh proof and final source/operation admission")
        for post_save in (failed_adoption, adopt):
            if any(post_save[i:i + 4] == ("a", ".", "rollbackProfilesLocked", "(") for i in range(len(post_save) - 3)):
                raise ValueError("Tor post-save failure tried to roll back the committed choice")
    except (ValueError, IndexError) as error:
        errors.append(f"desktop Tor durable choice/adoption ownership: {error}")


def need_desktop_tor_maintenance() -> None:
    try:
        command = go_contract_block(go_contract_tokens(read("mobile/desktop/external_tor.go.tmpl")), "func routerVPNRunTor(")
        worker_source = go_contract_tokens(read("mobile/desktop/external_tor_transition.go.tmpl"))
        worker = go_contract_block(worker_source, "func routerVPNTorMaintain(")
        heartbeat = go_contract_block(worker, "if result.heartbeat")
        for marker in ("verify, cancel := context.WithTimeout(ctx, mobiletor.DesktopBridgeHeartbeatMaxAge)",
                       "err := owner.VerifyCurrentPath(verify)", "cancel()"):
            go_contract_at(heartbeat, marker)
        invalid = go_contract_block(heartbeat, "if err != nil || ctx.Err() != nil || !owner.Healthy() || files.current() != nil || routerVPNTorRefreshReadback(owner, &result.proof) != nil")
        go_contract_at(invalid, "result.err = routerVPNTorFailure")
        if not (go_contract_at(heartbeat, "owner.VerifyCurrentPath(verify)") < go_contract_at(heartbeat, "cancel()") < go_contract_at(heartbeat, "result.err = routerVPNTorFailure")):
            raise ValueError("retained heartbeat must verify before adopting readback")

        admission = go_contract_block(command, "if maintenance == nil")
        for marker in ("ctx, cancel := context.WithCancel(parent)", "cancelMaintenance = cancel", "maintenance = completed", "version: proofVersion", "heartbeat: transitionDone == nil",
                       "go func() { completed <- routerVPNTorMaintain(ctx, owner, files, dnsFiles, mtuFiles, pathFiles, captured) }()"):
            go_contract_at(admission, marker)
        start = go_contract_at(command, "case result := <-maintenance:")
        end = go_contract_at(command, "case result := <-done:")
        adopted = command[start:end]
        stale = go_contract_block(adopted, "if result.version != proofVersion")
        go_contract_at(stale, "break")
        rejected = go_contract_block(adopted, "if result.err != nil")
        go_contract_at(rejected, "failure, stopping = routerVPNTorFailure, true")
        go_contract_at(rejected, "break")
        fresh = go_contract_block(adopted, "if result.heartbeat")
        for marker in ("receipt = result.proof", "receipt.HeartbeatAt = heartbeat.UnixMilli()", 'files.publish("proof.json", receipt)', "proofVersion++"):
            go_contract_at(fresh, marker)
        if not (go_contract_at(adopted, "if result.version != proofVersion") < go_contract_at(adopted, "if result.err != nil") < go_contract_at(adopted, "if result.heartbeat")):
            raise ValueError("late or failed worker result reached proof adoption")
        go_contract_at(go_contract_block(command, "if cancelMaintenance != nil"), "cancelMaintenance()")
        go_contract_at(go_contract_block(command, "if maintenance != nil"), "<-maintenance")
        if not (go_contract_at(command, "if cancelMaintenance != nil") < go_contract_at(command, "owner.Cancel()") <
                go_contract_at(command, "if maintenance != nil") < go_contract_at(command, "owner.Close(cleanup)")):
            raise ValueError("native close preceded retained maintenance cancellation/join")

        transition = go_contract_block(worker_source, "func routerVPNTorTransitionKeepsAlive(")
        for marker in ("value.ExpiresAt > now.UnixMilli()", "value.ExpiresAt-value.StartedAt > 0", "value.ExpiresAt-value.StartedAt <= mobiletor.DesktopBridgeMTUTransitionLimit.Milliseconds()",
                       "proof.HeartbeatAt == value.FromHeartbeatAt", "*proof.MTUReadback == value.From"):
            go_contract_at(transition, marker)
        native = go_contract_block(go_contract_tokens(read("mobile/desktop/external_tor_native.go.tmpl")), "func (n *routerVPNTorNative) VerifyCurrentPath(")
        go_contract_at(native, "if err := tor.VerifyCurrentPath(ctx); err != nil || !n.Healthy()")
        path = go_contract_block(go_contract_tokens(read("mobile/desktop/mtu_tor.go.tmpl")), "func (p *routerVPNTorFreshPath) VerifyCurrentPathContext(")
        go_contract_at(path, "state, err := mtu.owner.Capture()")
        go_contract_at(path, "mtu.owner.VerifyExternal(ctx, state) != nil")
        fixtures = go_contract_tokens(read("mobile/desktop/external_tor_transition_test.go.tmpl"))
        for marker in ("func TestRouterVPNDesktopTorMTUTransitionRejectsForeignExpiredAndReplacedAdmission(",
                       "func TestRouterVPNDesktopTorMTUTransitionKeepsControlResponsiveAndJoinsSlowReader(",
                       "func TestRouterVPNDesktopTorMTUTransitionWaitsForActualCompletionBeforeHeartbeat(",
                       "func TestRouterVPNDesktopTorHeartbeatAllowsOwnedSlowControlWithoutInventingFreshness("):
            go_contract_block(fixtures, marker)
    except (ValueError, IndexError) as error:
        errors.append(f"desktop Tor retained maintenance/proof ownership: {error}")


def need_desktop_tor_import() -> None:
    """Follow the captured bridge edit through policy merge and commit."""
    try:
        source = go_contract_tokens(read("cmd/client/tor_bridge_import.go"))
        route = go_contract_block(source, "func (a *app) torBridgeImport(")
        go_contract_at(route, "q, err := decodeTorBridgeImportRequest(http.MaxBytesReader(w, r.Body, 256<<10))")
        expected = go_contract_block(route, 'if q.expectedProfiles().hasExpectedProfiles() && strings.TrimSpace(q.ID) == ""')
        go_contract_at(expected, "return")
        update_call = go_contract_at(route, "handled, err := a.updateExistingTorBridgeProfile(r, &profile, updateIntent, q.expectedProfiles())")
        add_policy = go_contract_at(route, "profile, err = normalizeTorBridgeImportPolicy(profile)")
        if update_call >= add_policy:
            raise ValueError("saved path must merge before Direct Add policy validation")
        direct = go_contract_block(source, "func normalizeTorBridgeImportPolicy(")
        normalize = go_contract_at(direct, "if err := common.NormalizeRouterProfile(&profile); err != nil")
        go_contract_at(direct, 'strictLiteralObfs4 := cfg != nil && cfg.Transport == "obfs4" && len(cfg.Bridges) == 1')
        rejected_direct = go_contract_block(direct, 'if requestedKill != "off" && !strictLiteralObfs4 && !profile.MultihopEnabled')
        go_contract_at(rejected_direct, "return common.RouterProfile{}, errors.New(")
        policy = go_contract_at(direct, "policy, err := externalRuntimePolicy(profile)")
        translated = go_contract_at(direct, "if _, err := standardExitFromExternalProfile(policy); err != nil")
        if not normalize < policy < translated:
            raise ValueError("Tor import skipped the exact normalized policy translation")
        preserve = go_contract_block(source, "func preserveTorBridgeEditSettings(")
        for field in ("MultihopEnabled", "MultihopEntryID", "MultihopExitID", "MultihopEntryMode", "MultihopExecution"):
            go_contract_at(preserve, f"next.{field} = existing.{field}")
        saved_kill = go_contract_block(preserve, "if existing.MultihopEnabled && !intent.Kill")
        go_contract_at(saved_kill, "next.KillSwitchPolicy = existing.KillSwitchPolicy")

        update = go_contract_block(source, "func (a *app) updateExistingTorBridgeProfile(")
        owned = go_contract_at(update, "release, guardErr := a.beginMutationOperation(r)")
        locked = go_contract_at(update, "a.mu.Lock()")
        go_contract_at(update, "defer release()")
        go_contract_at(update, "defer a.mu.Unlock()")
        capture_marker = "if err := a.validateExternalProfileExpectedProfilesLocked(expected, existing); err != nil"
        capture = go_contract_at(update, capture_marker)
        go_contract_at(go_contract_block(update, capture_marker), "return false, err")
        missing = go_contract_block(update, "if index < 0")
        go_contract_at(go_contract_block(missing, "if expected.hasExpectedProfiles()"), "return false, errExternalProfileSelectionChanged")
        duplicate = go_contract_block(update, "if index >= 0")
        go_contract_at(duplicate, "return false, errors.New(")
        merged = go_contract_at(update, "merged := preserveTorBridgeEditSettings(existing, *profile, intent)")
        normalized = go_contract_at(update, "policy, err := normalizeTorBridgeImportPolicy(merged)")
        entry = go_contract_block(update, "if merged.MultihopEnabled")
        go_contract_at(go_contract_block(entry, "if matches != 1"), "return false, errors.New(")
        linked_marker = "if supported, reason := externalDevicePolicySupportForPath(merged, entry); !supported"
        linked = go_contract_at(update, linked_marker)
        go_contract_at(go_contract_block(update, linked_marker), "return false, errors.New(reason)")
        native_marker = "if err := validateExternalDeviceSettingsForPath(merged, entry); err != nil"
        native = go_contract_at(update, native_marker)
        go_contract_at(go_contract_block(update, native_marker), "return false, errors.New(")
        previous = go_contract_at(update, "previousStore := cloneRouterProfileStore(a.profiles)")
        adopted = go_contract_at(update, "a.profiles.Profiles[index] = merged")
        saved = go_contract_at(update, "if err := a.persistProfilesLocked(); err != nil")
        if not owned < locked < capture < merged < normalized < linked < native < previous < adopted < saved:
            raise ValueError("Tor edit persisted before its owned source/path admission")
        for bounds in (update[locked:capture], update[native:previous]):
            cancelled = go_contract_block(bounds, "if r.Context().Err() != nil")
            go_contract_at(cancelled, "return false, errors.New(")
        failed = go_contract_block(update, "if err := a.persistProfilesLocked(); err != nil")
        if go_contract_at(failed, "a.rollbackProfilesLocked(previousStore)") >= go_contract_at(failed, "return false, err"):
            raise ValueError("Tor update did not restore its private store before failure")

        decoder = go_contract_block(go_contract_tokens(read("cmd/client/tor_bridge_import_source.go")),
                                    "func (q *torBridgeImportRequest) UnmarshalJSON(")
        for marker in ("fields, err := externalConnectJSONObject(data)", "json.Unmarshal(expectationJSON, &capture)",
                       "decoder.DisallowUnknownFields()", "decoded.ExpectedSelectedNodeID = capture.ExpectedSelectedNodeID",
                       "decoded.ExpectedProfileTokens = capture.ExpectedProfileTokens"):
            go_contract_at(decoder, marker)
        aliases = go_contract_block(decoder, "if name != canonical && strings.EqualFold(name, canonical)")
        go_contract_at(aliases, "return errors.New(")
        append = go_contract_block(go_contract_tokens(read("cmd/client/external_profile_import.go")),
                                   "func (a *app) externalProfileImport(")
        after_lock = append[go_contract_at(append, "a.mu.Lock()"):]
        cancelled = go_contract_block(after_lock, "if r.Context().Err() != nil")
        go_contract_at(cancelled, "return")
        if go_contract_at(after_lock, "if r.Context().Err() != nil") >= go_contract_at(after_lock, "a.profiles.Profiles = append(a.profiles.Profiles, p)"):
            raise ValueError("cancelled Tor Add reached private-store adoption")
    except (ValueError, IndexError) as error:
        errors.append(f"desktop Tor captured bridge update ownership: {error}")


# Canonical external profile model: PT family is explicit, dynamic Tor exit is
# never replaced with a user-supplied fixed public IP, and imported data cannot
# supply executable paths or torrc directives. Native transport listeners are
# configured by the authenticated control owner, never by imported commands.
need(
    "internal/common/types.go",
    "ExternalTorBridgeConfig",
    'Transport string `json:"transport,omitempty"`',
    'TorBridge *ExternalTorBridgeConfig `json:"tor_bridge,omitempty"`',
)
need(
    "internal/common/tor_bridge.go",
    'return "obfs4", nil',
    'return "meek_lite", nil',
    'return "snowflake", nil',
    'return "webtunnel", nil',
    'return "custom", nil',
    "TorBridgeTransport",
    "mixed Tor pluggable transports require transport=custom",
)
need(
    "internal/common/profile_schema.go",
    'case "tor":',
    'case "tor_bridge", "tor-bridge":',
    'ext.Protocol = "tor-bridge"',
    "Tor bridge has a dynamic circuit exit",
    "normalizeExternalTorBridge",
)
need(
    "internal/common/tor_plain_test.go",
    "TestPlainTor",
)
need(
    "internal/common/tor_bridge_test.go",
    "TestTorBridgeSupportsCircumventionTransportFamilies",
    "TestTorBridgeCustomAndAutoAllowRecognizedMixedPTSets",
    "modern meek no fingerprint",
    "TestTorBridgeRejectsCustomTransportInjection",
)

# Desktop runtime: standalone disabled Tor, owned native Go PTs, authenticated
# control/bootstrap, one captured TUN, selected DNS and dynamic Tor exit proof.
# Windows ARM64 retains its native VPN engine/driver and checks the pinned
# standalone x64 Tor executable through the recorded OS compatibility boundary.
need(
    "cmd/client/tor_bridge_runtime.go",
    "torBridgeRuntimeCapabilityForRoot",
    'case "windows":',
    'windowsTorHostCompatibility()',
    'windowsTorRuntimeExecutable(root, "tor.exe")',
    "verifyBundledNative",
    "filepath.EvalSymlinks",
)
need(
    "cmd/client/desktop_tor_prepare.go",
    "native-tor-bridge-windows.ps1",
    'safeExecutable("powershell.exe")',
    '"-Action", "up"',
    '"-TunnelAlias", "router-vpn-tor"',
    "verifyBundledNative", "captureDesktopTorExecutable", "NewDesktopBridgeCapture",
    "HOMEVPN_TOR_BINARY_SHA256=", "desktopTorEnvironment", "preflightDesktopTorLaunch",
    '[]string{"routervpn-tor", "--help"}', "30*time.Second",
)
forbid("cmd/client/tor_bridge_runtime.go", "torBridgeTransportBinary", 'safeExecutable("lyrebird")')
need(
    "internal/mobiletor/desktop_capture.go",
    '"DisableNetwork 1"', '"SocksPort 0"', '"CookieAuthentication 1"',
    '"RunAsDaemon 0"', '"Log notice stdout"', "IsolationSecret", "ConfigSHA256",
)
need(
    "internal/mobiletor/desktop_control.go",
    "AUTHCHALLENGE SAFECOOKIE ", "TAKEOWNERSHIP", "GETINFO process/pid net/listeners/control",
    "pid != c.pid", '"DisableNetwork": {"1"}',
)
need(
    "internal/mobiletor/desktop_session.go",
    "Configure", "EnableNetwork", "WaitBootstrap", "Verify", "Quiesce",
)
need(
    "internal/mobiletor/desktop_bridge.go",
    "strict desktop Tor protection requires one fixed obfs4 bridge",
    "routervpn-desktop-tor-network", "BootstrapDNSTag", "ConfiguredMTU",
)
need(
    "mobile/desktop/tor_box.go.tmpl",
    "RouterVPNDesktopTorCreate", "RouterVPNDesktopMTU", "session.Configure",
    "session.EnableNetwork", "session.WaitBootstrap", "r.engine.DNSProof",
    "mobiletor.Prove", "proof.DNSProven = true", "VerifyCurrentPath", "DNSMeasurement",
    "r.workers.Wait()", "r.pt.Close(ctx)",
)
need(
    "mobile/desktop/external_tor.go.tmpl",
    'Use: "routervpn-tor"', "routerVPNOpenTorFiles", 'files.publish("progress.json", progress)',
    "routerVPNCaptureTorBinary", "routerVPNOpenDesktopDNSService",
    "owner.Cancel()", "<-done", "owner.Close(cleanup)", 'files.publish("stopped.json", closed)',
)
need_desktop_tor_maintenance()
need(
    "mobile/desktop/external_tor_test.go.tmpl",
    "TestRouterVPNDesktopTorCommandPublishesExactProofHeartbeatDNSAndStop",
    "TestRouterVPNDesktopTorCommandCancelJoinsStartProofAndNativeDrain",
    "TestRouterVPNDesktopTorCommandNoWorkIsBoundToExclusiveAdmission",
    "TestRouterVPNDesktopTorCommandDNSCancelRetainsActualWorkerAndHealthyConnection",
)
need(
    "cmd/client/desktop_tor_native.go",
    "validateDesktopTorProof", "proof.Policy != expected", "!proof.Proof.DNSProven",
    "desktopTorCurrent", "waitDesktopTorProof", "desktopNodeProcessExited",
    "requestDesktopTorStop", "cleanupDesktopTorLaunch", "monitorDesktopTorRuntime",
    "desktopTorNoNativeWork", "prelaunchAcknowledged", "admissionObserved", "invalidateDesktopDNSResults(a)",
)
need(
    "cmd/client/desktop_dns_owner.go",
    "capturedDesktopDNSRuntime", "a.readDesktopTorProof", "desktopDNSNativeClosed",
    "Selected DNS via captured Tor exit", "Current Tor connection",
)
need(
    "cmd/client/desktop_tor_prepare_test.go",
    "TestDesktopTorStagingCapturesAllTransportFamiliesAndDisabledInputs",
    "TestDesktopTorPreflightChecksNativeCommandAndRetainsInputIdentity",
    "TestDesktopTorPreparedStartRejectsStaleOwnersAndSameInodeChanges",
    "TestDesktopTorPreparedRealChildTransfersToCheckedDrain",
)
need(
    "cmd/client/desktop_tor_dns_test.go",
    "TestDesktopTorDNSUsesCapturedMailboxAndExplicitMeasuredDraft",
    "TestDesktopTorDNSCancellationRetainsNativeOwnerAndHoldUntilDrain",
    "TestDesktopTorDNSRejectsResolverTransportRouteAndReplacementOwners",
    "TestDesktopTorDNSCleanupRequiresBothReceiptAndRealProcessJoin",
)
need(
    "cmd/client/desktop_tor_prelaunch_failure_test.go",
    "TestDesktopTorPrelaunchFailureRetiresOnlyAfterWrapperExit",
    "TestDesktopTorPrelaunchFailureCannotExcuseNativeAdmissionOrChangedInputs",
    "TestDesktopTorPrelaunchCleanupRechecksAdmission",
)
need(
    "cmd/client/desktop_dns_retirement_test.go",
    "TestDesktopDNSNativeFailureRetiresCompletedDraftOnUnchangedNetwork",
    "monitorDesktopTorRuntime", "monitorDesktopExternalRuntime",
)
need(
    "cmd/client/speed_lab_tor_identity_test.go",
    "TestSpeedLabTorCapturesActualRegisteredNativeOwner",
    "TestSpeedLabTorRestoreRejectsChangedCapturedSource",
    "TestSpeedLabTorCancelledTestRestoresFreshOwnedSession",
)
need(
    "cmd/client/tor_bridge_windows_runtime.go",
    "torWindowsRuntimeWalkLimit",
    "safePinnedRuntimeExecutable",
    "findUniquePinnedRuntimeExecutable",
    "windowsTorRuntimeExecutable",
    'filepath.Join(windowsRoot, "tor-expert")',
    "must contain exactly one",
    "windowsTorHostCompatibility",
)
need(
    "cmd/client/tor_windows_compatibility_windows.go",
    "GetMachineTypeAttributes", "query.Call(0x8664", "attributes&1 != 0",
)
need(
    "client/test-windows-tor-compatibility.ps1",
    "ExpectedArchitecture", "Invoke-RouterVPNTorHelperVersion",
    "0x8664", "Install-PinnedTorExpertBundle", "No Tor network",
)
need(
    "client/Setup-Windows-Runtime.ps1",
    "TorExpertVersion = '15.0.24'",
    "TorExpertWindowsX64Sha256",
    "Install-PinnedTorExpertBundle",
    "tor.exe",
    "lyrebird.exe",
    "TorHelpersAvailable = $true",
    "GetMachineTypeAttributes",
    "Invoke-RouterVPNTorHelperVersion",
)
# Release pins remain reproducible after dist.torproject.org removes an older
# release. Installer and actual Windows execution tests use the same official
# archived bytes; neither a moving version nor an unchecked mirror is allowed.
for path in ("client/Setup-Windows-Runtime.ps1", "client/test-windows-tor-compatibility.ps1"):
    need(path, "https://archive.torproject.org/tor-package-archive/torbrowser/$TorExpertVersion/tor-expert-bundle-windows-x86_64-$TorExpertVersion.tar.gz")
    forbid(path, "https://dist.torproject.org/torbrowser/", "/latest/")
need("client/Setup-Windows-Runtime.ps1",
     "e9dc6ccc93cd6afa507193f4de284d6424233ff5102155cd2c94b259e8a22b65",
     "Get-FileHash -Algorithm SHA256", "if ($actual -ne $Sha256.ToLowerInvariant())")

need(
    "client/install-macos.sh",
    "refs/tags/lyrebird-0.8.1",
    "LYREBIRD_COMMIT_PREFIX=0b10edbb61e0",
    'rev-parse HEAD | cut -c1-12',
    "go mod verify",
    'LYREBIRD_TARGET="$ROOT/bin/lyrebird"',
    'LYREBIRD_SOURCE="$ROOT/bin/lyrebird.source"',
    "Router VPN-owned Lyrebird 0.8.1",
    "source-identity check failed",
)
need(
    "client/install-macos-current.sh",
    "/opt/router-vpn-client/bin:/usr/local/bin:/opt/homebrew/bin",
)
need(
    "client/install-linux.sh",
    "refs/tags/lyrebird-0.8.1",
    "LYREBIRD_COMMIT_PREFIX=0b10edbb61e0",
    'rev-parse HEAD | cut -c1-12',
    "go mod verify",
    'LYREBIRD_TARGET="$ROOT/bin/lyrebird"',
    'LYREBIRD_SOURCE="$ROOT/bin/lyrebird.source"',
    "Router VPN-owned Lyrebird 0.8.1",
    'Environment=PATH=$ROOT/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    "source-identity check failed",
)
need(
    "client/native-tor-bridge-windows.ps1",
    "windows-kill-switch.ps1",
    "HOMEVPN_TOR_BINARY_SHA256", "Get-RouterVPNTorNativeEnvironment",
    "Invoke-RouterVPNTorOwnedNative", "RecoveryOwner", "Start-RouterVPNPrivateJob",
    "Wait-RouterVPNPrivateJob", "Stop-RouterVPNPrivateJob", "Close-RouterVPNPrivateJob",
    "Invoke-RouterVPNTorKillSwitch 'check'", "Invoke-RouterVPNTorKillSwitch 'prepare'",
    "Write-RouterVPNTorPrelaunchFailure", "NoNativeChild", "NoChildFailure",
)
need(
    "client/Private-RouterVPN-Job.ps1",
    "CREATE_SUSPENDED", "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", "AssignProcessToJobObject",
    "ResumeThread", "RecoveryOwner", "WaitForSingleObject",
)
need(
    "client/test-windows-tor-wrapper-lifecycle.ps1",
    "RecoveryOwner", "Environment", "Detect-Defect",
)
need(
    "cmd/client/tor_bridge_windows_runtime_test.go",
    "TestPinnedWindowsTorRuntimeResolverRequiresOneRegularExecutable",
    "TestPinnedWindowsTorRuntimeResolverRejectsSymlink",
    "TestWindowsTorControllerUsesPinnedNativeLifecycle",
)
need(
    "modes/native-tor-bridge.sh",
    "HOMEVPN_TOR_SESSION", 'tor-prelaunch-witness.py" --validate', "router_vpn_standard_engine",
    'cleanup-private-runtime.py" verify-dir', 'python3 "$SCRIPT_DIR/kill-switch-platform.py" apply',
    'exec "$NATIVE_BIN" routervpn-tor', '--session "$HOMEVPN_TOR_SESSION"', '--tor-binary "$TOR_BIN"',
    "tor_prelaunch_failed", "tor-prelaunch-witness.py", "shopt -s execfail",
)
need(
    "modes/tor-prelaunch-witness.py",
    '"prelaunch-failed.json"', '"no_native_process": True', "os.O_EXCL",
    "regular_at", "verify_directory", "os.path.samestat", "os.fsync",
    "HOMEVPN_TOR_BINARY_SHA256", 'capture["tor_binary"] != tor_binary',
    'capture["schema"] not in {1, 2}', 'profile.get("multihop_execution") != "server"',
)
for path in ("modes/native-tor-bridge.sh", "client/native-tor-bridge-windows.ps1"):
    forbid(path, "Bootstrapped 100%", "HOMEVPN_TOR_PT_BINARY", "HOMEVPN_TOR_PLUGIN_TRANSPORTS")
forbid("modes/native-tor-bridge.sh", "rm -rf", "trap cleanup")
need(
    "cmd/client/tor_bridge_proof.go",
    "IsTor",
    "publicTorExit",
    "check.torproject.org",
)
need(
    "cmd/client/tor_bridge_routes.go",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "/api/tor-bridge/connect",
    "tor_transport",
    "tor-project-is-tor-passed",
    "a.stopOwnedConnectionRuntime(cmd)",
)
need_desktop_tor_choice()
need(
    "cmd/client/tor_bridge_dns.go",
    'case "tcp", "tls", "https"',
    "cannot use UDP/Fastest-UDP",
    "cannot use DoH3/QUIC",
)
need(
    "cmd/client/tor_bridge_dns_test.go",
    "TestTorBridgeDNSAllowsTCPCompatibleTransports",
    "TestTorBridgeDNSRejectsDatagramTransports",
)

# Capability and native profile-builder APIs are the one UI-facing source of
# truth. The shipping /api/tor-bridge/import boundary owns all Tor profile
# construction and delegates only final transactional persistence to the shared
# private external-profile store. A second unregistered Tor builder is forbidden.
need(
    "cmd/client/tor_bridge_capabilities.go",
    "obfs4",
    "meek_lite",
    "snowflake",
    "webtunnel",
    "custom",
    "active probing",
    "WebRTC",
    "HTTPS/domain-fronting",
    "strict_kill_switch",
    "upstream_hop",
    "torBridgeRuntimeCapabilityForRoot",
    'runtime.GOOS == "windows"',
    "Router VPN native transport owner",
)
need(
    "cmd/client/tor_bridge_import.go",
    "torBridgeImportRequest",
    "/api/external-profile/import",
    "common.NormalizeRouterProfile",
    'profile.DNSMode, profile.DNSProtocol, profile.DNSPort = "home", "udp", 53',
    "strictLiteralObfs4",
    "externalRuntimePolicy(profile)",
    "updateExistingTorBridgeProfile",
    "preserveTorBridgeEditSettings",
    "profile id belongs to a non-Tor node; refusing replacement",
    "Public exit, durable latency/DNS benchmarks, and effective-MTU measurement",
)
need_desktop_tor_import()
need(
    "cmd/client/tor_bridge_import_test.go",
    "TestTorBridgeImportExistingIDUpdatesInPlace",
    "TestTorBridgeImportUpdatePreservesUnrelatedSettingsAndClearsPathMeasurements",
    "TestTorBridgeImportExistingNonTorIDRefusesReplacement",
    "TestTorBridgeImportUpdatePersistenceFailureRollsBackExistingNode",
)
if (ROOT / "cmd/client/tor_bridge_profile.go").exists():
    errors.append("cmd/client/tor_bridge_profile.go: duplicate/unregistered Tor profile builder must remain removed")

# Product semantics: PT is circumvention; the proved Tor circuit is the
# encrypted final path. Tor-as-upstream-hop remains unavailable.
need(
    "client/unified-control-center-v2.json",
    '"id": "tor-bridge"',
    '"final_transport": true',
    '"upstream_hop": false',
    '"meek_lite"',
    '"snowflake"',
    '"webtunnel"',
    '"custom"',
    '"tor-ntor-v3-circuit"',
    '"tor_dynamic_pt_strict_kill_switch_requires_process_scoped_egress": true',
)
need("client/routervpn_unified_control_center.py", '"tor-bridge"', "proven ntor-v3 circuit")
need("client/RouterVPN-Windows-UnifiedControlCenter.ps1", "Tor pluggable transport + proven ntor-v3 circuit")
need("client/macos/UnifiedControlCenterPolicy.swift", "Tor pluggable transport + proven ntor-v3 circuit")

# Native desktop forms must actually ship, not merely exist as orphan sources.
need(
    "client/macos/RouterVPNMenuBar.m",
    "Tor Bridges…",
    'NSSelectorFromString(@"openTorBridgeBuilder")',
    "window.windowController",
    "[NSApp sendAction:action to:controller from:sender]",
)
need(
    "client/macos/macos-tor-bridge-ui-transform.py",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "obfs4",
    "meek",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
    "short-lived volunteer WebRTC proxies",
    "torBridgeImportBody",
    "externalValidateCapturedBody(body, current: current)",
    "profile_update_source_preconditions",
)
need(
    "client/RouterVPN-Windows-TorBridge.ps1",
    "UnifiedTorButton",
    "Tor bridges…",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
)
need(
    "client/RouterVPN-Windows-App.ps1",
    "RouterVPN-Windows-TorBridge.ps1",
    "Add-RouterVPNTorBridgeWindowsShell -ProductSource",
)
need(
    "client/linux/routervpn-tor-bridge-v13.inc",
    "LinuxTorBridgeV13",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "obfs4",
    "meek / meek_lite",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
    "It never accepts executable paths or raw torrc directives.",
    "Update the Tor node selected when this dialog opened",
    "copy_public_source_value_v24(displayed)",
    "external_captured_body_v24(payload, state->opened, current, validation_error)",
    'json_object_set_string_member(captured_object, "id", update_id)',
    "existing private lines are never read back",
)
need(
    "client/linux/routervpn-unified-shell-v8.inc",
    '#include "routervpn-tor-bridge-v13.inc"',
    "linux_unified_tor_v13",
    "Tor bridges…",
)
need(
    "client/linux/build-native-app.sh",
    "routervpn-unified-shell-v8.inc",
    "gcc -O2 -Wall -Wextra -Werror",
)

# Setup Center must explain the same real censorship-evasion family without
# publishing private bridge lines or pretending dynamic PT bootstrap is covered
# by the endpoint-only strict kill switch.
need(
    "server/scripts/setup_center_guide.py",
    "Tor censorship bridges in the Router VPN app",
    "obfs4",
    "meek / meek_lite",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
    "short-lived volunteer WebRTC proxies",
    "dynamic CDN/WebRTC/bootstrap egress",
    "Tor's proved circuit remains the encrypted final path",
    "does not substitute homemade XOR/custom cryptography",
)

# Mobile clients own the full PT family, native lifecycle and dynamic exit
# proof. The original entry profile and selected DNS remain captured throughout
# preparation, VPN permission handoff, startup and cancellation.
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java",
    "AndroidTorProfile.isTor(e.protocol)", "AndroidTorProfile.validate(e)",
    'o.put("tor_policy",e.torPolicy)', 'o.put("tor_bridge",new JSONObject()',
)
need("android/app/src/main/java/com/eabusham/routervpn/AndroidTorProfile.java",
     "Libbox.routerValidateTorProfile(captured)", "Libbox.routerCompileTorProfileWithPredecessor(",
     "Libbox.routerCompileProxyEntry",
     "capturedExit.equals(AndroidStandardExitStore.snapshot(selected))",
     '"Tor requires one owned runtime and one VPN interface."')
need("android/app/src/main/java/com/eabusham/routervpn/AndroidTorSession.java",
     "Libbox.routerTorCreateProofWithPredecessor", "captured.run()",
     "Libbox.routerStrategyDNSProof(server)", "captured.healthy()",
     "captured.cancel()", "network.equals(owner.network())")
need("android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java",
     "Libbox.routerTorSetStateDirectory", "getNoBackupFilesDir()",
     "torPhysicalNetwork = torPhysical", "capturedTor.prove()",
     "Libbox.routerStrategyCloseService(commandServer)",
     "if (torOwner || externalOwner || capturedMAX != null)",
     "Native captured-path teardown remains unconfirmed; runtime ownership is retained.")
need("android/app/src/main/java/com/eabusham/routervpn/StandardExitActivity.java",
     "showTorForm", "chooseNativeEntryMode(nodes.get(w),exit)",
     "NativeSingBoxController.nativeMultihopEntry(id)", "pendingEntryDigest", "pendingExitDigest",
     "A captured node changed while Android permission was open. Select the path again.")
# Tor and ordinary external exits share the captured owner/entry selector. Keep
# their executable cancellation, native-drain and permission negative coverage
# required instead of requiring the former Tor-only method names.
need("android/test_android_tor_session.py", "DNS completion owner check", "checked native close",
     "captured physical network binding", "Tor MTU Home generation ownership",
     "result.returncode!=0 and 'AssertionError' in result.stderr")
need("android/test_android_external_session.py", "checked native drain",
     "Home invalidation before native drain")
need("android/test_android_tor_form.py", "changed or denied permission started a stale capture",
     '"hidden-mode-list"', "entry.torPolicy=AndroidTorProfile.editedPolicy(saved,initialEditor,edited);")
need_android_tor_editor_controls("android/test_android_tor_form.py")
need("android/test_android_runtime_contract.py", '"test_android_tor_profile.py"',
     '"test_android_tor_form.py"', '"test_android_tor_session.py"',
     '"test_android_external_session.py"',
     '"test_android_start_layer_relay_lifecycle.py"')
need("deploy/test_android_tor_pinned.py", "with_naive_outbound", "TestRouterTorAndroidGeneratedGraphs",
     "all 690 captured Local/Server graphs and 690 missing-engine controls")
forbid(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java",
    "Tor obfs4 bridge is unavailable on Android",
)
need(
    "ios/RouterVPN/App/RouterVPNModelExternal.swift",
    '"tor", "tor-bridge"',
    "capturedEntry = try externalTorEntryData(source: bundle)",
    'let entryBundleKey = tor ? "tor_entry_bundle" : "external_entry_bundle"',
    'proto.providerConfiguration?[entryBundleKey] = capturedEntry',
    'saved.providerConfiguration?[entryBundleKey] as? Data == capturedEntry',
    'saved.providerConfiguration?[tor ? "external_entry_bundle" : "tor_entry_bundle"] == nil',
    "current circuit exit verified",
)
need("ios/RouterVPN/PacketTunnel/RouterVPNExternalExit.swift",
     'LibboxRouterCompileTorProfileWithPredecessor(String(decoding: source, as: UTF8.self), sessionID, predecessor, proofProfile ?? "", &failure)',
     "torPredecessorProfile: proofProfile",
     "torProfileJSON: String(decoding: source, as: UTF8.self)",
     'tor["session_id"] as? String == sessionID', 'tor["detour"] as? String == predecessorTag')
need("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift",
     'provider["tor_entry_bundle"]', "RouterVPNExternalExitBuilder.build(profile: selectedProfile, predecessorFiles: entryFiles, predecessorProfile: entryProfile,",
     "restoredExecution: restoredMultihopExecution)", "(runtime.policy?.executionRequested != nil) == (multihopExecutionSource != nil)",
     "engine.proveTor(sessionID: sessionID, profile: profile, predecessorProfile: runtime.torPredecessorProfile",
     "guard let profile = runtime.torProfileJSON", "engine.activateTorMTU()", "self.currentPathProofGuard() === externalPathGuard")
need("ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift",
     "LibboxRouterTorSetStateDirectory", "LibboxRouterTorCreateProofWithPredecessor", "TorProofDelivery",
     "LibboxRouterStrategyDNSProof(server", "request.healthy()", "request.cancel()",
     "Self.torRetirement.retain(server: owned", "torDelivery?.cancel()")
need("deploy/test_ios_tor_profile.py", "mobiletor.CompileProfile", "LibboxRouterCompileProxyEntry", "graphs==348", "profile_policy_combinations")
need("deploy/test_ios_libbox_delivery.py", "Tor requires its selected native DNS before Connected", "Tor stop cancels captured request immediately")
forbid(
    "ios/RouterVPN/App/RouterVPNModelExternal.swift",
    "Tor obfs4 bridge — unavailable",
    "Tor obfs4 bridges are unavailable",
)

# Homemade cipher ideas are explicitly superseded. The outer PT can disguise
# traffic, but confidentiality is provided by vetted Tor/tunnel cryptography.
for rel in (
    "client/unified-control-center-v2.json",
    "client/routervpn_unified_control_center.py",
    "client/RouterVPN-Windows-UnifiedControlCenter.ps1",
    "client/macos/UnifiedControlCenterPolicy.swift",
):
    forbid(rel, "xor cipher", "homemade cipher", "custom packet cipher")

if errors:
    print("TOR CIRCUMVENTION SHIPPING AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("TOR CIRCUMVENTION SHIPPING AUDIT: PASS")
