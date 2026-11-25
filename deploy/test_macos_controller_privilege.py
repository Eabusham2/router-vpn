#!/usr/bin/env python3
"""Execute the exact installed macOS controller/supervisor and native AppKit owner.

The build user compiles both shipping source closures. Only an explicit tagged
test runs under sudo -n on a disposable native macOS build host. It refuses an
existing fixed install, socket or lock, creates no accounts/services, and runs
the real kill-switch reassert with no saved policy (no PF or route mutation).
The AppKit client executes as the original nonroot build user. No skipped gate
or cross-compilation substitutes for Darwin peer credentials and process joins.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import pwd
import re
import subprocess
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / 'client/macos'
SPEC = importlib.util.spec_from_file_location('macos_controller_compiler', ROOT / 'deploy/test_desktop_socket_uid.py')
UID = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UID)
PROBE_SPEC = importlib.util.spec_from_file_location('macos_controller_image_probe', ROOT/'deploy/macos_process_inventory_probe.py')
PROBE = importlib.util.module_from_spec(PROBE_SPEC)
PROBE_SPEC.loader.exec_module(PROBE)
CASES = ('InterpreterSelection', 'InstallerCapabilities', 'InstallerExclusionAndRetry', 'LifetimeAndInheritedLocks', 'ParentImageReplacement', 'CapturedRuntimeChild', 'RejectsForeignUIDAndInvalidFrames',
         'RejectsUnsafeInstalledAuthority', 'SupervisorRestartDoesNotAdoptLiveChild', 'AppKitClient', 'PFBaselineUtility', 'FixtureEventsPreserveCapturedDirectoryMetadata')
PARENT_CASES = ('ParentOriginalSessionAndJoin', 'ParentFailedDependentRetainsOriginalLocks',
                'ParentRejectsReplacedControllerAndSession', 'ParentLifetimeCancellationAndBoundedJoin',
                'ParentConcurrentCloseJoinsEnteredDependent', 'SessionCloseDoesNotCloseBorrowedController',
                'SessionCapturesOriginalApplication', 'ParentCancelledReadDoesNotRetireSharedSession',
                'SessionReleaseJoinsOnlyOriginalDependent', 'SessionCleanupRetainsOnlyOriginalAuthorityAfterCancellation',
                'ExternalBaselineExactReceiptAndRetirement', 'ExternalRetirementRetryEscalatesHeldBaseline',
                'ExternalRetirementRetryDoesNotRemoveWorkspaceTwice', 'ExternalRetirementPreservesReplacementDNSIdentity')
EXECUTION_PARENT_CASES = ('ExecutionReaderKeepsPreparationAndAdoptionDistinct',
                          'ExecutionReaderCancellationDoesNotWaitForOwnerMutex',
                          'ExecutionReaderRequiresPhysicalRetirement',
                          'ExecutionReplacementJoinsBeforeHoldingOriginalProtection',
                          'ExecutionReplacementRefusesForeignPreparation')
EXECUTION_PRODUCT_CASES = ('ExecutionProductStopKeepsOriginalOwnerAndIntent',
                           'ExecutionProductStopRejectsForeignOwners',
                           'ExecutionProductStopCancellationKeepsCallerBudget',
                           'ExecutionProductStopRetainsFailedJoinAndReplacement',
                           'ExecutionProductStopProvesJoinedCleanupBeforeAbsence',
                           'ExecutionProductStopRetainsTerminalProtectionUntilDisconnect',
                           'ExecutionProductStopRejectsFalseTerminalAbsence')


# These five roots were matched by the original External prefix. Retain them
# explicitly so partitioning cannot silently remove an existing native check.
ADDITIONAL_PARENT_CASES = ('ExternalBaselineBindsEachOriginalProtectionMember',
                           'ExternalOffRequiresOriginalController',
                           'ExternalOffPreservesLegacyRouterExecution',
                           'ExternalOffRetirementKeepsOriginalRetry',
                           'ExternalOffRetirementPreservesReplacementOwner')


def native_groups():
    return {
        'original': tuple('TestMacOSOwnedControllerNative'+name for name in CASES) +
                    tuple('TestDesktopMacOS'+name for name in PARENT_CASES+ADDITIONAL_PARENT_CASES),
        'execution': tuple('TestDesktopMacOS'+name for name in EXECUTION_PARENT_CASES+EXECUTION_PRODUCT_CASES),
    }


def native_test_arguments(group=None):
    original = '^Test(MacOSOwnedControllerNative|DesktopMacOS(Parent|Session|External))'
    execution = '|'.join('TestDesktopMacOS'+name for name in EXECUTION_PARENT_CASES+EXECUTION_PRODUCT_CASES)
    pattern = original+'|^('+execution+')$'
    if group is not None:
        if group not in native_groups():
            raise ValueError('Unknown original native controller group')
        pattern = '^('+'|'.join(native_groups()[group])+')$'
    return ['-test.run='+pattern, '-test.v', '-test.timeout=180s']


def require_native_verdicts(output, group=None):
    """Only complete, unique top-level Go verdicts prove the required cases."""
    if not isinstance(output, str) or re.search(
            r'(?im)^\s*(?:--- (?:FAIL|SKIP):|FAIL(?:\s|$)|SKIP(?:\s|$)|'
            r'WARNING: DATA RACE|panic:|fatal error:)|\[build failed\]', output):
        raise RuntimeError('Native macOS output contains failure, skip, race or incomplete build evidence')
    groups = native_groups()
    if group is not None and group not in groups:
        raise ValueError('Unknown original native controller verdict group')
    names = groups[group] if group is not None else sum(groups.values(), ())
    top = re.findall(r'^--- PASS: (Test\S+) \([0-9]+(?:\.[0-9]+)?s\)$', output, re.MULTILINE)
    if len(top) != len(names) or set(top) != set(names):
        raise RuntimeError('Native macOS verdict inventory was omitted, duplicated or borrowed')
    for name in names:
        pattern = r'^--- PASS: '+re.escape(name)+r' \([0-9]+(?:\.[0-9]+)?s\)$'
        if len(re.findall(pattern, output, flags=re.MULTILINE)) != 1:
            raise RuntimeError('Mandatory exact-once native macOS verdict was missing or repeated: '+name)
    if output.splitlines().count('PASS') != 1 or not output.rstrip().endswith('\nPASS'):
        raise RuntimeError('Native macOS execution did not finish with one complete PASS verdict')


def native_image_identity(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not before.st_mode & 0o111:
        raise RuntimeError('Native controller lost its original regular executable')
    data = path.read_bytes()
    after = path.lstat()
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after):
        raise RuntimeError('Native controller image changed during capture')
    return (*identity(after), hashlib.sha256(data).hexdigest())


def require_native_inventory(output):
    expected = sum(native_groups().values(), ())
    names = output.splitlines()
    if len(set(expected)) != len(expected) or len(names) != len(expected) or set(names) != set(expected):
        raise RuntimeError('Compiled native controller inventory changed before partitioning')


def execute_native_groups(command, images, before, environment, sudo):
    def current():
        if source_identity() != before or any(native_image_identity(path) != identity for path, identity in images.items()):
            raise RuntimeError('Native controller original source or image changed between groups')
    current()
    selector = native_test_arguments()[0].removeprefix('-test.run=')
    inventory = reported_run([*command, '-test.list='+selector], cwd=ROOT, env=environment, timeout=15, sudo=sudo)
    require_native_inventory(inventory)
    current()
    completed = []
    for group in native_groups():
        current()
        print('Original native controller group: '+group, flush=True)
        output = reported_run([*command, *native_test_arguments(group)], cwd=ROOT, env=environment, timeout=200, sudo=sudo)
        print(output, end='', flush=True)
        require_native_verdicts(output, group)
        current()
        completed.append(group)
    if completed != list(native_groups()):
        raise RuntimeError('Native controller omitted an original required group')
    return completed


def native_failure_excerpt(output):
    """Retain original failed Go leaves before a large successful verdict tail."""
    raw = output.decode('utf-8', errors='replace') if isinstance(output, bytes) else str(output)
    limit = 24*1024
    failures = list(re.finditer(r'^\s*--- FAIL: (\S+) \([^\n]*\)$', raw, re.MULTILINE))
    names = {match.group(1) for match in failures}
    leaves = [match for match in failures if not any(
        name.startswith(match.group(1)+'/') for name in names)]
    if not leaves or len(raw) <= limit:
        return raw[-limit:]
    excerpts = []
    for match in leaves[:4]:
        name = match.group(1)
        starts = list(re.finditer(r'^=== RUN\s+'+re.escape(name)+r'\s*$', raw[:match.start()], re.MULTILINE))
        start = starts[-1].start() if starts else max(0, match.start()-3500)
        excerpts.append(name+':\n'+raw[max(start, match.end()-3500):match.end()])
    context = ('Original failed native cases (bounded):\n'+'\n'.join(excerpts))[:16000]
    separator = '\nNative process tail:\n'
    return context+separator+raw[-(limit-len(context)-len(separator)):]


def reported_run(command, **kwargs):
    """Expose the actual failed native child without changing its verdict."""
    try:
        return UID.run(command, **kwargs)
    except subprocess.CalledProcessError as error:
        output = native_failure_excerpt(error.output or b'')
        print('Darwin native command failure output (bounded evidence):\n'+output, file=sys.stderr, flush=True)
        raise


def source_identity():
    files = [ROOT / 'go.mod', ROOT / 'go.sum', Path(__file__).resolve(), ROOT/'deploy/macos_process_inventory_probe.py',
             ROOT/'deploy/installcap_fixture.go', ROOT/'deploy/test_darwin_install_capability.py',
             ROOT / 'client/install-macos-native.sh', *(ROOT / 'cmd/client').glob('*'),
             *(ROOT / 'internal').rglob('*.go'), *MAC.glob('*.swift'),
             *(ROOT / 'modes' / name for name in ['kill-switch-platform.py', 'kill-switch.py', 'darwin_kill_switch.py', 'darwin_pf_baseline.py', 'darwin_install_capability.py', 'profile_id.py'])]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(set(files)) if path.is_file() and not path.is_symlink()}


def discover_python(uid):
    """Use the ordinary installer's discovery without elevating a candidate."""
    if type(uid) is not int or uid <= 0 or os.geteuid() not in (0, uid):
        raise ValueError('Native interpreter discovery requires its captured ordinary user')
    account = pwd.getpwuid(uid)
    identity = dict(user=uid, group=account.pw_gid, extra_groups=[]) if os.geteuid() == 0 else {}
    result = subprocess.run(['/bin/bash', str(ROOT / 'client/install-macos-native.sh'), '--discover-python'],
                            cwd=ROOT, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                                           'HOME': account.pw_dir, 'LC_ALL': 'C'},
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            timeout=20, check=False, **identity)
    candidate = result.stdout.rstrip('\n')
    if result.returncode or not candidate or len(candidate) > 4096 or '\n' in candidate or '\r' in candidate or '\0' in candidate or not Path(candidate).is_absolute():
        raise RuntimeError('The shipping installer could not select its native Python runtime: ' + result.stderr[-4096:])
    return candidate


def block(source, marker):
    start = source.index(marker)
    position = source.index('{', start)
    depth, quoted, escaped = 0, False, False
    for index in range(position, len(source)):
        character = source[index]
        if quoted:
            if escaped: escaped = False
            elif character == '\\': escaped = True
            elif character == '"': quoted = False
        elif character == '"': quoted = True
        elif character == '{': depth += 1
        elif character == '}':
            depth -= 1
            if depth == 0: return source[start:index + 1]
    raise ValueError('Actual AppKit source block is incomplete: ' + marker)


def appkit_source():
    source = (MAC / 'RouterVPNMacProduct.swift').read_text()
    api = '\n'.join(block(source, marker) for marker in (
        'enum RouterVPNNodeEntryModes {', 'enum RouterVPNNodeExitModes {',
        'enum RouterVPNMultihopStartup {', 'final class ProductAPI {'))
    profiles = (MAC / 'RouterVPNConnectionProfiles.swift').read_text()
    profile_models = '\n'.join(block(profiles, marker) for marker in (
        'func macCustomPresetName(', 'struct MacConnectionCustomPreset:',
        'struct RouterVPNConnectionProfileSelection:', 'enum RouterVPNOrderedNodes {'))
    delegate = block(source, '@MainActor final class ProductDelegate:')
    comparison = block(source, 'private final class ProductComparisonTransportDelegate:')
    progress_transport = block(source, 'private final class MultihopProgressTransportDelegate:')
    methods = '\n'.join(block(source, name) for name in [
        '    func stopMultihopProgress(', '    func startMultihopProgress(',
        '    func startCapturedComparisonProgress(', '    func stopCapturedComparisonProgress(',
        '    private func beginMultihopProgress(', '    func pollMultihopProgress(',
        '    func multihopComparisonSummary('])
    # The UI scaffolding supplies only visible fields. Every HTTP constructor,
    # authorization call, process capture and checked Quit callback is copied
    # unchanged from the actual shipping sources; no lifecycle implementation
    # is duplicated by the fixture.
    return r'''
import AppKit
import Foundation
import CoreFoundation
import Darwin
let routerVPNProductBaseURL=URL(string:"http://127.0.0.1:8788")!
COMPARISON
PROFILE_MODELS
API
PROGRESS_TRANSPORT
@MainActor final class ProductWindowController: NSWindowController {
    init(api: ProductAPI) { super.init(window: nil) }
    required init?(coder: NSCoder) { nil }
}
DELEGATE
final class FixtureWindow { var isVisible=true }
final class FixtureLabel { var stringValue="" }
final class FixtureProgress {
 var window:FixtureWindow?=FixtureWindow();let multihopComparisonLabel=FixtureLabel()
 var multihopProgressTimer:Timer?;var multihopProgressTask:URLSessionDataTask?;var multihopProgressSession:URLSession?
 var multihopProgressGeneration=UUID();var multihopProgressDeadline=Date.distantPast
 var multihopProgressLastID="",multihopProgressOldID=""
 var multihopProgressExpectedID:String?;var multihopProgressUpdate:(([String:Any],String)->Void)?
 METHODS
}
@MainActor final class FixtureApplication: NSApplication {
    var replies:[Bool]=[]
    override func reply(toApplicationShouldTerminate value:Bool) { replies.append(value) }
}
func require(_ condition:Bool,_ message:String) {
    if !condition { try! FileHandle.standardError.write(contentsOf:Data((message+"\n").utf8));exit(1) }
}
@MainActor func wait(_ condition:()->Bool,_ message:String) {
    let deadline=Date().addingTimeInterval(12)
    while !condition() && Date()<deadline { _=RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.005)) }
    require(condition(),message)
}
@MainActor func runNativeOwner() throws {
    // Private test progress only. Mark the inherited descriptor close-on-exec
    // before touching AppKit so a framework-launched process cannot retain it.
    let stages=FileHandle(fileDescriptor:3,closeOnDealloc:true)
    let flags=fcntl(stages.fileDescriptor,F_GETFD)
    require(flags >= 0 && fcntl(stages.fileDescriptor,F_SETFD,flags | FD_CLOEXEC) == 0,"Cannot retain the original AppKit progress pipe")
    try stages.write(contentsOf:Data("L".utf8))
    require(RouterVPNMacLocalAuthorization.installedBundle(),"Native fixture did not execute the installed app branch")
    // AppKit requires the subclass's shared accessor to register NSApp. A
    // directly initialized object makes the real shutdown panel create a
    // second application when it obtains NSApplication.shared.
    guard let app=FixtureApplication.shared as? FixtureApplication else {
        require(false,"Native fixture did not create its captured application subclass");return
    }
    require(app === NSApplication.shared && app === NSApp,"Native fixture lost AppKit's actual shared application")
    let delegate=ProductDelegate()
    try delegate.ensureController()
    guard let process=delegate.installedController else { require(false,"AppKit adopted a localhost listener instead of its root-owned child");return }
    require(delegate.controller === process && delegate.ownsController && process.acceptsRequests,"Installed AppKit lost its exact process capability")
    try stages.write(contentsOf:Data("R".utf8))
    require(String(data:try delegate.api.request("/api/status"),encoding:.utf8)=="captured installed controller","ProductAPI bearer request did not reach the installed child")
    require(String(data:try delegate.api.requestRaw("/api/status",body:Data("{}".utf8)),encoding:.utf8)=="captured installed controller","Raw ProductAPI lost captured authorization")
    try stages.write(contentsOf:Data("H".utf8))
    var mtuOK=false,dnsOK=false,speedOK=false,progressOK=false
    let mtu=try RouterVPNMacMTUTransport(url:routerVPNProductBaseURL.appendingPathComponent("api/mtu/status"),body:nil,timeout:2){ value in
        DispatchQueue.main.async { if case .success(let reply)=value { mtuOK=reply.code==200 } }
    }
    let dns=try RouterVPNMacDNSTransport(url:routerVPNProductBaseURL.appendingPathComponent("api/dns/measurement"),body:nil,timeout:2){ value in
        DispatchQueue.main.async { if case .success(let reply)=value { dnsOK=reply.code==200 } }
    }
    let speed=try RouterVPNMacSpeedLabTransport(url:routerVPNProductBaseURL.appendingPathComponent("api/speed-lab/options"),body:nil,timeout:2){ value in
        DispatchQueue.main.async { if case .success(let data)=value { speedOK=String(data:data,encoding:.utf8)=="captured installed controller" } }
    }
    mtu.start();dns.start();speed.start()
    let progress=FixtureProgress()
    let progressOwner=progress.startCapturedComparisonProgress(requestID:String(repeating:"a",count:32),timeout:8){_,_ in progressOK=true}
    wait({mtuOK&&dnsOK&&speedOK&&progressOK},"An actual native transport bypassed or lost installed-controller authorization")
    progress.stopCapturedComparisonProgress(progressOwner)
    try stages.write(contentsOf:Data("T".utf8))
    let unknown=RouterVPNMacControllerCredentials(accessToken:String(repeating:"f",count:64),ownerToken:String(repeating:"e",count:32))
    require(!unknown.acceptsIdentity(Data("{}".utf8),pid:process.processIdentifier,challenge:String(repeating:"a",count:32)),"Malformed identity became ready")
    for raw in ["http://example.invalid:8788/api/status","https://127.0.0.1:8788/api/status","http://127.0.0.1:8789/api/status","http://u:p@127.0.0.1:8788/api/status"] {
        var request=URLRequest(url:URL(string:raw)!)
        do { try RouterVPNMacLocalAuthorization.shared.authorize(&request);require(false,"Bearer authority escaped its exact loopback endpoint") } catch {}
    }
    require(delegate.applicationShouldTerminate(app) == .terminateLater,"Installed Quit did not retain captured cleanup ownership")
    try stages.write(contentsOf:Data("Q".utf8))
    try stages.close()
    wait({!app.replies.isEmpty},"AppKit never observed both the cleanup receipt and authenticated actual join")
    require(app.replies==[true] && process.joinedSuccessfully && !process.isRunning,"AppKit accepted missing or failed process join")
    var late=URLRequest(url:routerVPNProductBaseURL.appendingPathComponent("api/status"))
    do { try RouterVPNMacLocalAuthorization.shared.authorize(&late);require(false,"Retired authority was reused by a replacement listener") } catch {}
    delegate.shutdownPanel?.close()
    print("Actual native AppKit root peer, HTTP identity, bearer admission and joined exit: PASS")
}
// A Swift 5 executable's synchronous entry point is the actual main thread,
// but does not implicitly acquire MainActor isolation on every supported SDK.
MainActor.assumeIsolated {
    if CommandLine.arguments.contains("--reject-unsafe-supervisor-acl") {
        do { _ = try RouterVPNMacOwnedProcess.launch(); require(false,"Native AppKit trusted a mutable supervisor directory ACL") }
        catch {
            require(error.localizedDescription.contains("ACL permissions"),"Native AppKit failed before exercising its actual ACL authority check: "+error.localizedDescription)
            print("Actual native AppKit unsafe supervisor ACL rejected: PASS")
        }
    } else {
        do { try runNativeOwner() } catch { require(false,error.localizedDescription) }
    }
}
'''.replace('COMPARISON', comparison).replace('PROGRESS_TRANSPORT', progress_transport).replace('PROFILE_MODELS', profile_models).replace('API\n', api + '\n').replace('DELEGATE', delegate).replace('METHODS', methods)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default=os.environ.get('GO', 'go'))
    parser.add_argument('--swift', default=os.environ.get('SWIFTC', 'swiftc'))
    parser.add_argument('--python', help='Explicit candidate; otherwise use the ordinary native installer discovery')
    arguments = parser.parse_args()
    if platform.system() != 'Darwin':
        raise RuntimeError('The native macOS ownership gate must execute on a matching real macOS host')
    uid = int(os.environ.get('SUDO_UID', '0')) if os.getuid() == 0 else os.getuid()
    if uid <= 0: raise RuntimeError('The native gate needs its captured ordinary build-user UID')
    before = source_identity()
    python = arguments.python or discover_python(uid)
    compiler, environment = UID.RACE.capture(ROOT, arguments.go, dict(os.environ))
    sudo = UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-macos-controller-') as temporary:
        work = Path(temporary)
        # The actual nonroot AppKit child must traverse this exact build-user
        # workspace; it never receives write access to the fixed root install.
        work.chmod(0o755)
        binary = work / 'controller-native-test'
        subprocess.run([str(compiler), 'test', '-race', '-c', '-tags', 'routervpn_controller_privileged',
                        './cmd/client', '-o', str(binary)], cwd=ROOT, env=environment, check=True, timeout=240)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none',
                        '--identifier', 'routervpn.fixture.captured.controller', str(binary)],
                       check=True, timeout=30)
        capability = work/'installcap-native-test'
        subprocess.run([str(compiler), 'build', '-race', '-o', str(capability), 'deploy/installcap_fixture.go'],
                       cwd=ROOT, env=environment, check=True, timeout=120)
        main = work / 'main.swift'; main.write_text(appkit_source())
        appkit = work / 'native-appkit-owner'
        sources = [MAC / name for name in ['RouterVPNMacControllerAuth.swift', 'RouterVPNMacControllerLaunch.swift',
                   'RouterVPNMacShutdown.swift', 'RouterVPNMacMTUTransport.swift', 'RouterVPNMacDNSTransport.swift',
                   'RouterVPNMacDNSController.swift', 'RouterVPNMacSpeedLabTransport.swift', 'RouterVPNProfileLoadTransaction.swift']]
        subprocess.run([arguments.swift, '-swift-version', '5', '-module-cache-path', str(work / 'module-cache'),
                        *map(str, sources), str(main), '-framework', 'AppKit', '-o', str(appkit)], check=True, timeout=180)
        binary.chmod(0o755); appkit.chmod(0o755); capability.chmod(0o755)
        if source_identity() != before: raise RuntimeError('Native ownership source changed during compilation')
        print('Known macOS fixture image objects (diagnostic only): '+json.dumps({
            'admission_authority': False, 'observed_unix_ns': time.time_ns(),
            'fixtures': [PROBE.fixture_image(binary, 'controller-native-test'),
                         PROBE.fixture_image(appkit, 'native-appkit-owner')]}, sort_keys=True), flush=True)
        command = ['/usr/bin/env', 'ROUTERVPN_MACOS_CONTROLLER_PRIVILEGE_FIXTURE=1',
                   'ROUTERVPN_MACOS_FIXTURE_UID=' + str(uid), 'ROUTERVPN_MACOS_FIXTURE_SOURCE=' + str(ROOT),
                   'ROUTERVPN_MACOS_FIXTURE_PYTHON=' + str(Path(python).absolute()),
                   'ROUTERVPN_MACOS_FIXTURE_INSTALLCAP=' + str(capability),
                   'ROUTERVPN_MACOS_FIXTURE_APPKIT=' + str(appkit), 'GORACE=atexit_sleep_ms=0',
                   str(binary)]
        if sudo: command = [sudo, '-n', '--', *command]
        images = {path: native_image_identity(path) for path in (binary, capability, appkit)}
        execute_native_groups(command, images, before, environment, sudo)
    print('Exact native macOS supervisor, actual peer credentials, inherited locks, owned cleanup, crash boundaries and AppKit authenticated transports passed.')


if __name__ == '__main__':
    main()
