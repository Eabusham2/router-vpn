#!/usr/bin/env python3
"""Authoritative Router VPN Speed Lab source/shipping contract."""
from __future__ import annotations

from pathlib import Path
import importlib.util
import re

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []

_native_spec = importlib.util.spec_from_file_location(
    "routervpn_native_multihop_audit", Path(__file__).with_name("native_multihop_audit.py"))
_native_module = importlib.util.module_from_spec(_native_spec)
_native_spec.loader.exec_module(_native_module)
native_multihop_proof_lanes = _native_module.native_multihop_proof_lanes


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing Speed Lab shipping source: {path}")
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing Speed Lab marker {marker!r}")


def need_go_map_entry(path: str, key: str, value: str) -> None:
    # gofmt aligns map values with whitespace. Match the actual entry rather
    # than one formatting choice; comments/raw strings are not live code.
    body = re.sub(
        r'("(?:\\.|[^"\\])*")|`[^`]*`|//[^\n]*|/\*.*?\*/',
        lambda match: match.group(1) or "",
        read(path),
        flags=re.S,
    )
    pattern = rf'(?m)^\s*"{re.escape(key)}"\s*:\s*{re.escape(value)}\s*,\s*$'
    if not re.search(pattern, body):
        errors.append(f"{path}: missing Speed Lab response entry {key!r}: {value}")


def forbid(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker in body:
            errors.append(f"{path}: forbidden Speed Lab marker {marker!r}")


def need_ios_topology_routes(path: str) -> None:
    body = re.sub(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/',
                  lambda match: match.group(1) or "", read(path), flags=re.S)
    multihop = body.partition('case .multihop:')[2].partition('case .router:')[0]
    direct = body.partition('case .external:')[2].partition('\n            }')[0]
    for marker in ('selected.multihopEnabled == true',
                   'model.iosMultihopEntryBundle(for: saved)',
                   'if external { await model.connectSelectedExternal() }',
                   'else { await model.connect() }',
                   'model.activeEngine == (external ? "external-libbox" : "multihop-libbox")'):
        if marker not in multihop:
            errors.append(f"{path}: saved native multihop route lost {marker!r}")
    if 'selected.multihopEnabled != true' not in direct:
        errors.append(f"{path}: direct external testing no longer rejects a saved multihop graph")


def need_android_captured_transaction(path: str) -> None:
    # This is source closure, not a native traffic verdict. The ordered native
    # reads run on workers; their exact original receipts cross back to the UI
    # only while the captured operation, Home and saved choice still match.
    tokens, function, positions = _native_module._tokens, _native_module._function, _native_module._positions
    ordered = _native_module._ordered_once
    source = tokens(read(path))

    def method(declaration: str):
        return function(source, declaration)

    run = method("private void run(Request request,Callback callback,Object borrowedLease,ExternalWork work)")
    capture = positions(run, 'captured=connection.captureRestorePoint()') if run is not None else []
    home = positions(run, 'connection.pathCurrent(expected)') if run is not None else []
    if not (ordered(run,
            'AndroidHomeStateStore.Snapshot expected=AndroidHomeStateStore.snapshot(activity)',
            'expected.connected&&"node-chain".equals(expected.logicalMode)',
            'orderedCapturePending=true;orderedCaptureCancelled=false;ticket=++orderedCaptureGeneration',
            'new Thread(()->{',
            'captured=connection.captureRestorePoint()',
            'final AndroidUnifiedConnectionController.RestorePoint originalCapture=captured',
            'activity.runOnUiThread(()->{synchronized(AndroidSpeedLabController.this){',
            'if(!orderedCapturePending||ticket!=orderedCaptureGeneration)return',
            'if(orderedCaptureCancelled){callback.finished(null,cancelled());return;}',
            'if(error!=null){callback.finished(null,error);return;}',
            'if(!connection.pathCurrent(expected)||!connection.restoreChoiceCurrent(originalCapture))',
            'runCaptured(frozen,callback,borrowedLease,work,originalCapture)',
            '},"routervpn-speedlab-ordered-capture").start()')
            and len(capture) == 1 and len(home) == 3 and home[0] < capture[0] < home[1] < home[2]):
        errors.append(f"{path}: ordered Android capture lost its original worker receipt or current UI handoff")

    checks = (
        ("private void runCaptured(Request request,Callback callback,Object borrowedLease,ExternalWork work,AndroidUnifiedConnectionController.RestorePoint preparedOriginal)", (
            'owner=++generation',
            'original=preparedOriginal!=null?preparedOriginal:connection.captureRestorePoint()',
            'LayeredVpnService.quiesceMTUForSpeedLab(error->activity.runOnUiThread(()->{',
            'if(!current(owner)||mtuLease!=lease||!quiesced.compareAndSet(false,true))return',
            'runOwned(captured,ownedCallback,owner)')),
        ("private void runOwned(Request request,Callback callback,long owner)", (
            'if(original!=null&&"node-chain".equals(original.topology))',
            'new Thread(()->{boolean valid=connection.restorePointCurrent(original);activity.runOnUiThread(()->runWithOriginal(request,callback,owner,valid));},"routervpn-speedlab-ordered-admission").start();return',
            'runWithOriginal(request,callback,owner,connection.restorePointCurrent(original))')),
        ("private void runWithOriginal(Request request,Callback callback,long owner,boolean valid)", (
            'if(!current(owner))return;try{',
            'if(!valid||!connection.pathCurrent(original.home)||!connection.restoreChoiceCurrent(original))',
            'stopAndDrain(original.home.sessionId,original.topology,owner,new AndroidUnifiedConnectionController.Callback(){',
            'public void finished(boolean ok,String message){if(!current(owner))return',
            'if(!ok||pathDecisionChanged)',
            'originalSuspended=true',
            'try{idle=connection.captureIdle();}',
            'if(cancelled){complete(callback,null,cancelled());return;}startTemporary(request,callback,owner)')),
        ("private void stopAndDrain(String home,String topology,long owner,AndroidUnifiedConnectionController.Callback callback)", (
            'connection.stopCaptured(home,topology,new AndroidUnifiedConnectionController.Callback(){',
            'public void superseded(){pathDecisionChanged=true;}',
            'public void finished(boolean ok,String message){',
            'if(!current(owner))return',
            'if(!ok&&home.equals(AndroidHomeStateStore.snapshot(activity).sessionId)&&connection.capturedCleanupPending(home,topology))',
            'callback.finished(ok,message)')),
        ("private void restoreOriginal(Callback callback,long owner,AndroidSpeedLab.Result result,Throwable error)", (
            'if(pathDecisionChanged||!connection.idleCurrent(idle))',
            'if(!originalSuspended||original==null||!original.connected())',
            'final String[] restoredOwner={""}',
            'connection.restoreCaptured(original,idle,new AndroidUnifiedConnectionController.Callback(){',
            'public void owned(String session){if(current(owner)&&restoredOwner[0].isEmpty())restoredOwner[0]=session;}',
            'public void finished(boolean ok,String message){',
            'if(!current(owner))return',
            'AndroidHomeStateStore.Snapshot observed=AndroidHomeStateStore.snapshot(activity)',
            'new Thread(()->{boolean proved=ok&&connection.restoredCurrent(original,restoredOwner[0]);activity.runOnUiThread(()->finishRestored(proved,message,observed,callback,owner,result,error,restoredOwner[0]));},"routervpn-speedlab-ordered-restored").start();return',
            'finishRestored(ok&&connection.restoredCurrent(original,restoredOwner[0]),message,observed,callback,owner,result,error,restoredOwner[0])')),
        ("private void finishRestored(boolean proved,String message,AndroidHomeStateStore.Snapshot observed,Callback callback,long owner,AndroidSpeedLab.Result result,Throwable error,String restoredOwner)", (
            'if(!current(owner))return',
            'if(!proved||!connection.pathCurrent(observed)||!connection.restoreChoiceCurrent(original))',
            'if(!restoredOwner.equals(restored.sessionId))',
            'externalWork.returnedHome=restored',
            'finish(callback,cancelled?null:result,cancelled?cancelled():error)')),
        ("void cancel()", ('orderedCaptureCancelled=true', 'meter.cancel()', 'nativeHopMeter.cancel()')),
        ("private void finishOwned(Callback callback,AndroidSpeedLab.Result result,Throwable error)", (
            'if(callback!=activeCallback||!running.get())return',
            'if(!borrowed){AndroidMTUMeasurementGate.release(lease)',
            'callback.finished(cancelled?null:result,cancelled&&error==null?cancelled():error)')),
    )
    for declaration, fragments in checks:
        if not ordered(method(declaration), *fragments):
            errors.append(f"{path}: captured Android transaction lost its owned {declaration.split('(')[0]} flow")


def need_native_multihop_lanes(path: str) -> None:
    # Source-only evidence of both captured branches, including exact imported
    # entry-wg versus paired entry-private routing; not a live traffic verdict.
    if not native_multihop_proof_lanes(read(path), read("cmd/client/multihop_native_imported.go")):
        errors.append(f"{path}: captured paired/imported native proof lanes lost their original compiler or routes")


def need_imported_speed_lab_current() -> None:
    """Source-only binding; native traffic and physical transitions stay separate."""
    tokens, function, positions = _native_module._tokens, _native_module._function, _native_module._positions
    paths = tokens(read("cmd/client/speed_lab_paths.go"))
    capture = function(paths, "func captureSpeedLabIdentityContext(ctx context.Context, a *app) (speedLabPathIdentity, speedLabPath, error)")
    validate = function(paths, "func validateSpeedLabIdentityContext(ctx context.Context, a *app, identity speedLabPathIdentity) error")
    verify = function(tokens(read("cmd/client/desktop_external_path.go")),
                      "func verifySpeedLabPath(ctx context.Context, a *app, identity speedLabPathIdentity) error")
    temporary = function(tokens(read("cmd/client/speed_lab.go")),
                         "func (a *app) speedLabTemporary(r *http.Request, q speedLabRequest, duration speedLabDuration, minDuration, maxDuration time.Duration) (speedLabPath, speedLabMeasurement, []speedLabHopMeasurement, error)")
    runtime = tokens(read("cmd/client/multihop_native_launch.go"))
    legacy_bind = function(runtime, "func bindNativeMultihopRuntime(a *app, launch *desktopNodeLaunch, sel multihopSelection, network string) error")
    bind = function(runtime, "func bindNativeMultihopRuntimeContext(ctx context.Context, a *app, launch *desktopNodeLaunch, sel multihopSelection, network string) error")
    observe = function(runtime, "func capturedNativeMultihopRuntimeContext(ctx context.Context, a *app, command *exec.Cmd, graph activeMultihopGraph) (*nativeMultihopRuntime, error)")
    network = function(runtime, "func (owner *nativeMultihopRuntime) physicalNetworkContext(ctx context.Context) (string, error)")
    def has(body, *fragments):
        return body is not None and all(len(positions(body, fragment)) == 1 for fragment in fragments)
    checks = positions(verify, "validateSpeedLabIdentityContext(ctx, a, identity)") if verify is not None else []
    dns = positions(verify, "a.proveImportedNativeDNS(ctx, identity.Imported.selection, identity.Command)") if verify is not None else []
    valid = (
        _native_module.native_multihop_platform_chain(read)
        and has(capture,
            'if st.Mode == "multihop" && graphOK && (graph.ImportedEntry || graph.ChainNodes > 0) {',
            'imported, err = capturedNativeMultihopRuntimeContext(ctx, a, command, graph)',
            'Imported: imported')
        and has(validate,
            'if identity.GraphOK && identity.Graph.ImportedEntry {',
            'owner, exists := nativeMultihopOwners.Load(a)',
            'if !exists || identity.Imported == nil || owner != identity.Imported {',
            'network, err = identity.Imported.physicalNetworkContext(ctx)',
            'owner, err := capturedNativeMultihopRuntimeContext(ctx, a, identity.Command, current)',
            'if err != nil || identity.Imported == nil || owner != identity.Imported || !a.nativeMultihopProofOwnerCurrentContext(ctx, owner.selection, identity.Command) {',
            '''if identity.Imported != nil && identity.Imported.launch != nil && identity.Imported.launch.importedPlatform != nil {
                if identity.Linux != nil { return errors.New("Speed Lab imported graph cannot replace its original identity with a single-node path") }
                return identity.Imported.launch.importedPlatform.Current(ctx)
            }''')
        and len(checks) == 2 and len(dns) == 1 and checks[0] < dns[0] < checks[1]
        and has(verify, '''
            if identity.Imported != nil {
                if _, err := a.proveImportedNativeDNS(ctx, identity.Imported.selection, identity.Command); err != nil {
                    return errors.Join(err, ctx.Err())
                }
            }
        ''')
        and has(temporary,
            'if identity.External != nil || identity.Standard != nil || identity.Imported != nil || identity.Ordered != nil {',
            'if err := verifySpeedLabPath(pathCtx, a, identity); err != nil { return err }')
        and legacy_bind == tokens('return bindNativeMultihopRuntimeContext(context.Background(), a, launch, sel, network)')
        and _native_module._ordered_once(bind,
            'observe := physicalNetworkIdentityContext',
            '''if launch != nil && launch.ownedNode != nil && launch.ownedNode.imported != nil {
                observe = launch.ownedNode.imported.readNetwork
            }''',
            'if ctx == nil || observe == nil {',
            'actual, err := observe(ctx)',
            'if err != nil || ctx.Err() != nil { return errors.Join(err, ctx.Err()) }',
            '!a.ownsConnectionRuntime(launch.command) || network == "" || actual != network',
            'if err := nativeMultihopLaunchCurrent(ctx, a, launch); err != nil { return err }',
            'nativeMultihopOwners.Store(a, &nativeMultihopRuntime{launch: launch, selection: sel, graph: graph, network: network, networkIdentityContext: observe})')
        and _native_module._ordered_once(observe,
            'if err := nativeMultihopLaunchCurrent(ctx, a, owner.launch); err != nil { return nil, err }',
            '''if owner.launch.ownedNode != nil && owner.launch.ownedNode.imported != nil {
                if err := a.desktopOwnedNodeCurrentContext(ctx, owner.launch, true); err != nil {
                    return nil, err
                }
            }''',
            'network, err := owner.physicalNetworkContext(ctx)')
        and has(network,
            'if ctx == nil || owner == nil || owner.networkIdentityContext == nil {',
            'network, err := owner.networkIdentityContext(ctx)',
            'return network, errors.Join(err, ctx.Err())')
    )
    if not valid:
        errors.append("imported Speed Lab lost its captured native owner, caller, selected DNS or original physical observation")


# Shared desktop controller: current path is identity-bound, temporary paths are
# transactional/non-persistent, and real Mbps + idle/loaded latency are distinct.
need(
    "cmd/client/speed_lab_measure.go",
    "speedLabAutoMin     = 4 * time.Second",
    "speedLabAutoMax     = 12 * time.Second",
    "1s <= min <= max <= 60s",
    "idle_latency",
    "loaded_latency",
    "bufferbloat_ms",
    "speedLabStable",
    "speedLabDownloadRound",
    "speedLabUploadRound",
    "speedLabStreamCount",
    "speedLabParallelRound",
    "MaxConnsPerHost = 8",
    "adaptive 1-%d concurrent streams",
    "no latency probes succeeded",
)
need(
    "cmd/client/speed_lab_paths.go",
    "captureSpeedLabIdentity",
    "validateSpeedLabIdentity",
    "speedLabSnapshotTemporary",
    "speedLabRestoreTemporary",
    "system-direct",
    "multihop",
    "external",
    "temporary proven multihop graph",
    "temporary external direct/hopped exit",
)
need(
    "cmd/client/speed_lab.go",
    "/api/speed-lab/options",
    "/api/speed-lab/run",
    "download_loaded_ms",
    "upload_loaded_ms",
    "download_bufferbloat_ms",
    "upload_bufferbloat_ms",
    "beginSpeedLabTemporaryPersistenceGuard",
    "speedLabWriteStore(snapshot.Profiles)",
    "measureSpeedLabMultihopHops",
    "multihop entry/exit RTT and Mbps are independently measured on the same proved graph",
    "temporary path choices are restored after the test",
)

need_go_map_entry("cmd/client/speed_lab.go", "hops", "hops")
need_imported_speed_lab_current()

# Router VPN nodes commonly share the same private 10.77.0.1 API address. Per-hop
# telemetry must therefore use local routing lanes that bind the request to the
# entry or exit graph, then cryptographically prove which node answered. A plain
# request to entry.RouterAPI/exit.RouterAPI is not sufficient hop ownership proof.
need(
    "cmd/client/multihop_lane_telemetry.go",
    'const multihopEntryProofProxy = "http://127.0.0.1:1098"',
    'proxyURL.Port() != "1098" && proxyURL.Port() != "1099"',
    "proveMultihopLaneNode",
    "validateSelectedNodeProof(p, body)",
    "measureRoutedProfileLatencyViaProxy",
    "measureRoutedProfileSpeedViaProxy",
    "node identity proved before and after load",
    "reserved local multihop hop lane",
)
need(
    "cmd/client/speed_lab_hops.go",
    "speedLabHopMeasurement",
    "measureSpeedLabMultihopHops",
    "multihopEntryProofProxy",
    "multihopProofProxy",
    "measureRoutedProfileLatencyViaProxy",
    "measureRoutedProfileSpeedViaProxy",
    "validateSpeedLabIdentity",
    "validateActiveMultihopSpeedGraph",
    "could not prove and measure latency or throughput",
)
need(
    "cmd/client/telemetry_hops.go",
    "/api/profile/speed-test",
    "/api/multihop/speed-test",
    "measureRoutedProfileSpeedViaProxy",
    "multihopEntryProofProxy",
    "multihopProofProxy",
    "requested Router VPN node is not part of the active multihop graph",
    "reserved local proof lane bound to that hop's cryptographic Router VPN node identity",
    "http.StatusConflict",
)
need(
    "modes/multihop.py",
    "ENTRY_PROOF_PORT = 1098",
    "PROOF_PORT = 1099",
    '"tag": "entry-hop"',
    '"tag": "multihop-entry-proof"',
    '"tag": "multihop-proof"',
    '"inbound": ["multihop-entry-proof"]',
    '"outbound": "entry-hop"',
    '"inbound": ["multihop-proof"]',
    '"outbound": "proxy"',
)
need(
    "cmd/client/multihop_native.go",
    "nativeMultihopEntryProofPort = 1098",
    "nativeMultihopExitProofPort  = 1099",
    '"tag": "entry-private"',
    '"detour": "entry-wg"',
)
need_native_multihop_lanes("cmd/client/multihop_native_capture.go")
need(
    "cmd/client/speed_lab_persistence_guard.go",
    "speedLabTemporaryPersistenceSuppressed",
    "temporary Speed Lab persistence guard",
)
need("cmd/client/usage_metadata.go", "speedLabTemporaryPersistenceSuppressed(a)")

# Windows native WPF surface.
need(
    "client/RouterVPN-Windows-SpeedLab.ps1",
    "Router VPN Speed Lab",
    "Current path",
    "Temporary config",
    "System direct",
    "Router VPN node",
    "Multihop",
    "External exit / hop",
    "IDLE LATENCY",
    "DOWNLOAD",
    "UPLOAD",
    "loaded",
    "bufferbloat",
    "Auto timing",
    "Custom timing",
    'Minimum="1" Maximum="60"',
    "min_seconds",
    "max_seconds",
    "DAITA",
    "Jumbo",
    "Require encrypted AUTO",
    "Require obfuscation AUTO",
    "PER-HOP — SAME PROVED GRAPH",
    "$R.hops",
    "download_mbps",
    "upload_mbps",
    "$D.Add_Loaded",
    "StartUnifiedApiAsync 'Loading Speed Lab options…'",
    "StartUnifiedApiAsync 'Running Speed Lab…'",
    "CancelUnifiedApiAsync",
    "Temporary paths are transactional and will be torn down/restored when the test completes or is cancelled.",
)
forbid(
    "client/RouterVPN-Windows-SpeedLab.ps1",
    "$Opt=Api '/api/speed-lab/options'",
    "$R=Api '/api/speed-lab/run'",
)
need("client/RouterVPN-Windows-App.ps1", "RouterVPN-Windows-SpeedLab.ps1", "Add-RouterVPNSpeedLabWindowsShell")

# macOS native AppKit surface and build composition.
need(
    "client/macos/RouterVPNMacSpeedLab.swift",
    "Router VPN Speed Lab",
    "current",
    "temporary",
    "system-direct",
    "multihop",
    "external",
    "min_seconds",
    "max_seconds",
    "loaded_latency",
    "bufferbloat",
    "daita",
    "jumbo",
    "require_encrypted",
    "require_obfuscation",
    "hopSummary",
    "PER-HOP — SAME PROVED GRAPH",
    "download_mbps",
    "upload_mbps",
)
need("client/macos/build-native-app.sh", "RouterVPNMacSpeedLab.swift")

# Linux native GTK surface and compiled include.
need(
    "client/linux/routervpn-speed-lab-v12.inc",
    "Speed Lab",
    "current",
    "temporary",
    "system-direct",
    "multihop",
    "external",
    "min_seconds",
    "max_seconds",
    "loaded_latency",
    "bufferbloat",
    "require_encrypted",
    "require_obfuscation",
    "linux_speed_lab_hops_v12",
    "PER-HOP — SAME PROVED GRAPH",
    "download_mbps",
    "upload_mbps",
)
need("client/linux/build-native-app.sh", "routervpn-speed-lab-v12.inc")

# Android owns its own VpnService dataplane, so Speed Lab must use process-owned
# session/path identity and native temporary connect/disconnect transactions.
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeStateStore.java",
    "pathProof",
    'putString("path_proof", "passed")',
    "path_generation",
    "generation=p.getLong(\"path_generation\",0L)+1L",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLab.java",
    "DurationPolicy.normalize",
    "1s <= min <= max <= 60s",
    "loadedLatency",
    "bufferbloatMs",
    "StalePathException",
    "pathGeneration",
    "activeExternalId",
    "runtimeMode",
    '\"passed\".equals(now.pathProof)',
    "ParallelRound",
    "parallelRound",
    "streamCount",
    "Math.min(32<<20,v)",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLabController.java",
    'scope="current"',
    '"system-direct"',
    '"multihop"',
    '"external"',
    "connectNode",
    "connectMultihop",
    "connectExternal",
    "AndroidSpeedLabHopMeter",
    "lastHops",
)
need_android_captured_transaction("android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLabController.java")
need("android/test_android_speed_lab_restore.py", "fresh restoration owner", "captured original winner",
     "HTTP cancellation", "native cancellation", "negative control escaped")
need("android/test_android_runtime_contract.py", '"test_android_speed_lab_restore.py"',
     '"test_android_multihop_restore.py"')
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java",
    "ENTRY_PROOF_PORT = 1098",
    "EXIT_PROOF_PORT = 1099",
    'put("tag", "entry-private")',
    'put("detour", "entry-wg")',
    'put("tag", "multihop-entry-proof")',
    'put("tag", "multihop-proof")',
    'put("outbound", "entry-private")',
    'put("outbound", "proxy")',
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLabHopMeter.java",
    "sessionId",
    "pathGeneration",
    "activeEntryId",
    "activeExitId",
    '\"passed\".equals(s.pathProof)',
    "ENTRY_PROOF_PORT=1098",
    "EXIT_PROOF_PORT=1099",
    "AndroidPrivateBenchmarkHttp.open",
    "AndroidPrivateBenchmarkHttp.requireBase(api)",
    "AndroidProfileSelection.selectedRouterProfile(bundle)",
    "AndroidPrivateFileStore.read",
    "AndroidNodeStore.stableNodeIdentity(bundle)",
    'body.optString("node_id"',
    'body.optString("proof"',
    "Hop proof lane reached the wrong Router VPN node identity",
    "/api/benchmark/download",
    "/api/benchmark/upload",
    "/health",
    "stale results were discarded",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidPrivateBenchmarkHttp.java",
    "AndroidNumericAddress.parse(uri.getHost())",
    "Proxy.Type.HTTP",
    'new InetSocketAddress("127.0.0.1", proofPort)',
    "proofPort != 1098 && proofPort != 1099",
    "connection.setInstanceFollowRedirects(false)",
    "connection.setUseCaches(false)",
    'connection.setRequestProperty("Accept-Encoding", "identity")',
    "requireRoute(route, method)",
    "uri.getRawUserInfo() != null",
    "uri.getRawQuery() != null",
    "uri.getRawFragment() != null",
    "address.isAnyLocalAddress()",
    "address.isMulticastAddress()",
    "16 << 20",
)
forbid(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLabHopMeter.java",
    "openConnection(",
    "FileInputStream",
    "private static JSONObject selectedProfile(",
)
need("android/test_android_runtime_contract.py", "test_android_private_benchmark_http.py")
need(
    "android/test_android_private_benchmark_http.py",
    "Android private hop HTTP boundary: PASS",
    "HttpServer.create",
    "Credentials escaped on redirect",
    "Request used the wrong hop lane",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLabDialog.java",
    "Router VPN path performance",
    "Current path",
    "Temporary config",
    "Min 4 s",
    "Max 12 s",
    "loaded",
    "bufferbloat",
    "PER-HOP — SAME PROVED GRAPH",
    "controller.hops()",
    "controller.hopError()",
)
need("android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java", "AndroidSpeedLabDialog")

# iPhone/iPad use their native PacketTunnel model rather than the desktop HTTP
# controller. Current/temporary path identity is watched continuously. The bounded
# captured entry and the exact Router VPN/external/Tor exit remain mandatory.
need(
    "ios/RouterVPN/App/IOSSpeedLab.swift",
    "Router VPN Speed Lab",
    "4, maxSeconds: 12",
    "1s ≤ min ≤ max ≤ 60s",
    "loadedLatency",
    "bufferbloatMs",
    "speed.cloudflare.com",
    "stable(rates)",
    "parallelRound",
    "streamCount",
    "32 << 20",
    "withThrowingTaskGroup",
)
need(
    "ios/RouterVPN/App/IOSSpeedLabPersistenceJournal.swift",
    "router-vpn.speed-lab-journal-v1",
    "originalBundle",
    "originalLastRuntime",
    "reassertOriginalPersistentState",
    "recoverIfNeeded",
    "Speed Lab recovery is waiting for the temporary VPN tunnel to stop",
    "Recovered your original Router VPN state after an interrupted Speed Lab test",
)
need(
    "ios/RouterVPN/App/IOSSpeedLabRunner.swift",
    "case current",
    "case temporary",
    'case systemDirect = "system-direct"',
    "case router",
    "case external",
    "case multihop",
    "model.iosMultihopEntryBundle(for: saved)",
    'model.activeEngine == (external ? "external-libbox" : "multihop-libbox")',
    "Temporary multihop failed both-node path proof",
    "guardedMeasurement",
    "IOSSpeedLabTunnel.capture(model: model, owner: owner)",
    "original.stopOriginal(model: model, owner: owner)",
    "IOSSpeedLabTunnel.stopTemporary(model: model, owner: owner)",
    "original.restore(model: model, owner: owner, reconnect: reconnect, captureRestoredOwner: captureNative)",
    "try requireNative()",
    "IOSSpeedLabTunnel.retirementPending(error)",
    "model.activeSessionIdentity",
    "transitioning: model.tunnelTransitioning",
    "withTaskCancellationHandler",
    "IOSSpeedLabPersistenceJournal.begin",
    "IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState",
    "IOSSpeedLabPersistenceJournal.finish",
    "Recovery journal retained for next launch",
    "requireEncrypted",
    "requireObfuscation",
    "autoRequireEncrypted",
    "autoRequireObfuscation",
)
need(
    "ios/RouterVPN/App/IOSSpeedLabTunnel.swift",
    "Temporary Speed Lab tunnel did not fully stop",
    "manager.connection.connectedDate == identity.connectedAt",
    "Self.sameProtocol(manager.protocolConfiguration, expected)",
    "IOSStrategyPlan(kind: .manual, candidates: candidates)",
    "restored.rawProfile == identity.rawProfile",
    "restored.entryBundleData == identity.entryBundleData",
    '"routervpn_mtu_hold": hold as NSString',
)
need(
    "ios/RouterVPN/App/IOSSpeedLabView.swift",
    "Router VPN Speed Lab",
    "Current config",
    "Temporary config",
    "Auto / default",
    "Custom",
    "Minimum",
    "Maximum",
    "Idle",
    "Download",
    "Upload",
    "Loaded Δ",
    "bufferbloat",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "Saved multihop graph",
    "Tests the complete saved entry → exit graph, including external and Tor exits.",
    "Each path must pass its native node or circuit proof.",
)
need_ios_topology_routes("ios/RouterVPN/App/IOSSpeedLabRunner.swift")
need("ios/RouterVPN/App/ProductRootView.swift", "Open Router VPN Speed Lab", "IOSSpeedLabView()", "IOSSpeedLabPersistenceJournal.recoverIfNeeded")
forbid("ios/RouterVPN/App/IOSSpeedLabRunner.swift", "fake multihop", "pretend multihop")

if errors:
    print("SPEED LAB SHIPPING AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("SPEED LAB SHIPPING AUDIT: PASS")
