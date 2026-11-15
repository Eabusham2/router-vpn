"""Actual Windows worker permission controls and causal guard-removal checks.

The small module copies the projected original capture/reader and verbatim
shipping DACL/identity bodies. It performs real Windows security-descriptor and
file-handle operations; cross-compilation alone is not acceptance.
"""
from pathlib import Path
import hashlib
import importlib.util
import re

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('windows_worker_projection', ROOT/'deploy/windows_connect_execution_overlay.py')
SCOPE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SCOPE)
TEST = 'TestRouterVPNWindowsExecutionPrivateWorker'
CASES = ('private','original-posix-modes','public-input','null-input','unknown-input','public-code-writer','public-code-reader','hardlink-input','replaced-input','worker-environment')


def sources():
    peer = SCOPE.peer_sources()
    process = peer['routervpn_windows_imported_execution_process_test.go'].decode()
    start, end = 'func captureImportedExecutionImage(', 'type importedExecutionProcess struct {'
    if process.count(start) != 1 or process.count(end) != 1 or process.index(start) >= process.index(end):
        raise ValueError('Original image capture control boundary changed')
    head = SCOPE.HEADER+'package routervpnamnezia\nimport ("crypto/sha256";"encoding/hex";"errors";"io";"os")\n'
    result = {'capture_test.go': (head+process[process.index(start):process.index(end)]).encode()}
    for key in ('routervpn_windows_execution_private_identity_test.go','routervpn_windows_execution_private_dacl_test.go','routervpn_windows_connect_execution_security_test.go','routervpn_windows_connect_execution_security_controls_test.go','routervpn_windows_execution_reader_test.go'):
        result[key] = peer[key]
    for path in sorted([*(ROOT/'internal/windowscontroller').glob('*.go'),*(ROOT/'internal/windowsbootstrap').glob('*.go')]):
        if path.name.endswith('_test.go'):
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError('Original machine environment source changed')
        result['routervpn/'+path.parent.name+'/'+path.name] = path.read_bytes().replace(b'"router-vpn/internal/windowsbootstrap"', b'"github.com/sagernet/sing-box/routervpn/windowsbootstrap"')
    result['go.mod'] = b'module github.com/sagernet/sing-box\n\ngo 1.25.0\n'
    return result


def verdict(output, cases=CASES, failed=None):
    required = [TEST, *(TEST+'/'+case for case in cases)]
    runs = re.findall(r'^\s*=== RUN\s+(\S+)\s*$', output, re.M)
    kind = 'FAIL' if failed else 'PASS'
    records = re.findall(r'^\s*--- '+kind+r':\s+(\S+)\s+\([0-9.]+s\)$', output, re.M)
    if sorted(runs) != sorted(required) or sorted(records) != sorted(required) or any(token in output for token in ('--- SKIP:', 'WARNING: DATA RACE', 'panic:', 'fatal error:')):
        raise ValueError('Windows worker control lost exact original verdicts')
    if failed:
        if failed not in output or '--- PASS:' in output or re.search(r'^PASS\s*$',output,re.M):
            raise ValueError('Windows worker mutant failed for another cause')
    elif '--- FAIL:' in output or len(re.findall(r'^PASS\s*$',output,re.M)) != 1:
        raise ValueError('Original Windows worker controls did not pass')
    return required


MUTANTS = (
    ('code-private-writer','capture_test.go',' || windowsCONNECTExecutionCodePermissions(file, actual) != nil','', 'public-code-writer','original Windows code DACL boundary changed'),
    ('input-private-reader','routervpn_windows_execution_reader_test.go',' || validatePrivateRuntimePathPermissions(filepath.Join(root.Name(), name), before) != nil','', 'public-input','original Windows worker DACL boundary changed'),
    ('captured-machine-root','routervpn_windows_connect_execution_security_test.go','"SystemRoot=" + paths.Windows','"SystemRoot="', 'worker-environment','worker lost actual Windows machine environment'),
)


def execute(compiler, captured, target, owner):
    original = sources()
    hashes = {name:hashlib.sha256(raw).hexdigest() for name,raw in original.items()}
    receipts = []
    race = ['-race'] if target == 'windows/amd64' else []
    with owner.workspace(prefix='routervpn-windows-worker-controls-') as temporary:
        directory = Path(temporary)
        for name, raw in original.items():
            path = directory/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        command = [compiler,'test','-p=1','-count=1','-v',*race,'-tags='+SCOPE.TAG,'-timeout=60s']
        status, output = owner.run([*command,'-run=^'+TEST+'$','.'],cwd=directory,env=captured,timeout=180)
        print(output,flush=True)
        if status:
            raise ValueError('Actual Windows worker security controls failed:\n'+output[-16384:])
        verdict(output)
        receipts.append(dict(case='original',output_sha256=hashlib.sha256(output.encode()).hexdigest()))
        for name, file, before, after, case, witness in MUTANTS:
            raw = original[file].decode()
            if raw.count(before) != 1:
                raise ValueError('Worker causal control lost its exact original guard')
            path = directory/file
            path.write_text(raw.replace(before,after,1))
            try:
                status, output = owner.run([*command,'-run=^'+TEST+'$/^'+case+'$','.'],cwd=directory,env=captured,timeout=120)
                print(output,flush=True)
                if not status:
                    raise ValueError('Windows worker guard removal was accepted: '+name)
                verdict(output,(case,),failed=witness)
                receipts.append(dict(case=name,output_sha256=hashlib.sha256(output.encode()).hexdigest()))
            finally:
                path.write_bytes(original[file])
        if any((directory/name).read_bytes()!=raw for name,raw in original.items()) or sources()!=original:
            raise ValueError('Windows worker causal controls changed captured source')
    return dict(native=True,scope='windows-connect-worker-private-path-controls',target=target,sources=hashes,cases=list(CASES),controls=receipts)
