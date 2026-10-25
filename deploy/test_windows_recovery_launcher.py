#!/usr/bin/env python3
"""Execute the packaged recovery writer and its real PowerShell launcher dispatch."""
from pathlib import Path
import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = r'''package main
import (
    "encoding/json"
    "os"
    "strconv"
    "time"
)
func main() {
    cwd, err := os.Getwd(); if err != nil { os.Exit(91) }
    file, err := os.OpenFile(os.Getenv("ROUTERVPN_RECOVERY_RECORD"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); if err != nil { os.Exit(92) }
    err = json.NewEncoder(file).Encode(map[string]any{"args":append([]string{},os.Args[1:]...),"cwd":cwd,"pid":os.Getpid()})
    closeErr := file.Close(); if err != nil || closeErr != nil { os.Exit(93) }
    time.Sleep(200*time.Millisecond)
    code, err := strconv.Atoi(os.Getenv("ROUTERVPN_RECOVERY_EXIT")); if err != nil { os.Exit(94) }
    os.Exit(code)
}
'''


def require(value, text):
    if not value:
        raise AssertionError(text)


def run(command, **options):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, **options)
    require(result.returncode == 0, 'Fixture preparation failed:\n' + result.stdout + result.stderr)
    return result


def package_bash(*, windows=None, which=shutil.which):
    if windows is None:
        windows = os.name == 'nt'
    if not windows:
        bash = which('bash')
        require(bash is not None, 'Bash is required for the actual package writer')
        return bash
    # A bare bash.exe can be the Windows WSL launcher, even when Git for
    # Windows is installed. Resolve only a shell in the selected Git install.
    git = which('git')
    require(git is not None, 'Git for Windows is required for the actual package writer')
    root = Path(git).resolve().parent.parent
    if root.name.lower() in ('mingw32', 'mingw64', 'clangarm64'):
        root = root.parent
    for bash in (root/'bin/bash.exe', root/'usr/bin/bash.exe'):
        if bash.is_file():
            return str(bash)
    raise AssertionError('Git for Windows Bash is missing beside the selected Git executable: ' + git)


def bash_resolution_contracts():
    with tempfile.TemporaryDirectory(prefix='routervpn-recovery-bash-') as temporary:
        root = Path(temporary)/'Git with spaces'
        git = root/'cmd/git.exe'; git.parent.mkdir(parents=True); git.write_bytes(b'fixture')
        shadow = Path(temporary)/'Windows/bash.exe'; shadow.parent.mkdir(); shadow.write_bytes(b'fixture')
        looked_up = []
        def lookup(name):
            looked_up.append(name)
            return str(git if name == 'git' else shadow)
        for directory in ('bin', 'usr/bin'):
            parent = root/directory; parent.mkdir(parents=True)
            # Preserve an alias so the fixture exercises file identity on every
            # host, including Windows temporary paths with short-name aliases.
            bash = parent/'..'/parent.name/'bash.exe'; bash.write_bytes(b'fixture')
            selected = Path(package_bash(windows=True, which=lookup))
            require(selected.samefile(bash), f'Did not select the explicit Git Bash: {selected!s} != {bash!s}')
            require(not selected.samefile(shadow), 'Selected another Bash file with identical fixture contents')
            bash.unlink()
        # Existing WSL-style PATH entry cannot replace missing Git Bash.
        for missing_git in (False, True):
            try:
                package_bash(windows=True, which=(lambda name: None if name == 'git' else str(shadow)) if missing_git else lookup)
            except AssertionError:
                pass
            else:
                raise AssertionError('Missing Git Bash incorrectly fell back to a Windows PATH shell')
        require(looked_up == ['git'] * 3, 'Windows resolver consulted the ambiguous bare Bash')
        print('Git Bash resolution: explicit install paths + missing Git/shell rejection PASS')


def generate(package, bash):
    source = (ROOT/'deploy/package-builds.sh').read_text(encoding='utf-8')
    found = re.search(r"^write_windows_app_launcher\(\)\{.*?\nPS1\n\}", source, re.M | re.S)
    require(found is not None, 'Actual package recovery writer is missing')
    script = package/'Start-RouterVPN.ps1'
    # Execute only the real writer function. The package-building shell is not
    # sourced: it also removes/rebuilds dist, which is unrelated to this fixture.
    run([bash, '-c', found.group(0)+'\nwrite_windows_app_launcher "$1"\n', '--', script.as_posix()])
    require(script.is_file(), 'Actual package writer did not emit its recovery entry point')
    emitted = script.read_text(encoding='utf-8')
    for forbidden in ('/api/emergency-stop', 'Stop-Process', 'router-vpn-client.exe', 'HOMEVPN_CONTROLLER_OWNER'):
        require(forbidden not in emitted, 'Recovery script still owns a separate controller lifecycle: '+forbidden)
    return script



def audit_contracts():
    audit = ROOT/'deploy/full-audit-v4.py'
    tree = ast.parse(audit.read_text(encoding='utf-8'), filename=str(audit))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'windows_controller_lifecycle']
    require(len(nodes) == 1, 'Actual checked-launcher audit function is missing')
    code = compile(ast.Module(body=nodes, type_ignores=[]), str(audit), 'exec')
    paths = ('cmd/portable-launcher/main.go', 'cmd/portable-launcher/controller_shutdown.go',
             'cmd/windows-app-launcher/main.go', 'internal/controllerprocess/client.go', 'deploy/package-builds.sh')
    sources = {name: (ROOT/name).read_text(encoding='utf-8') for name in paths}
    def verify(changes=None):
        content = {**sources, **(changes or {})}; errors = []
        def need(path, *parts):
            errors.extend(path+': missing '+part for part in parts if part not in content[path])
        def no(path, *parts):
            errors.extend(path+': forbidden '+part for part in parts if part in content[path])
        scope = {'need':need, 'no':no}; exec(code, scope); scope['windows_controller_lifecycle']()
        return errors
    require(not verify(), 'Current checked-launcher audit failed')
    package = 'deploy/package-builds.sh'; owner = 'internal/controllerprocess/client.go'
    mutations = (
        (package, '$process=Start-Process @start', '$process=$null'),
        (package, '$process.Refresh()', 'Stop-Process -InputObject $controller -Force'),
        (owner, 'receipt.Token != token', 'false'),
        (owner, '<-owner.done', '<-unrelatedDone'),
        (owner, 'owners.Load(cmd)', 'owners.Load(otherCommand)'),
    )
    for path, before, after in mutations:
        require(before in sources[path], 'Lifecycle audit mutation drifted')
        require(verify({path:sources[path].replace(before,after)}), 'Broken checked-launcher invariant passed its actual audit: '+before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shell', default='pwsh')
    args = parser.parse_args()
    bash_resolution_contracts()
    audit_contracts()
    shell = shutil.which(args.shell)
    require(shell is not None, 'Required PowerShell executable is unavailable: '+args.shell)
    bash = package_bash()
    require(shutil.which('go') is not None, 'Go fixture compiler is required')
    with tempfile.TemporaryDirectory(prefix='routervpn-recovery-dispatch-') as temporary:
        root = Path(temporary)
        package = root/'Package with spaces'/'RouterVPN-Windows-fixture'
        package.mkdir(parents=True)
        script = generate(package, bash)
        source = root/'fixture.go'; source.write_text(FIXTURE, encoding='utf-8')
        executable = package/'RouterVPN.exe'
        command = ['go', 'build', '-trimpath']
        if sys.platform == 'win32':
            command += ['-ldflags=-H=windowsgui']
        command += ['-o', str(executable), str(source)]
        environment = dict(os.environ)
        environment['GOWORK'] = 'off'; environment['GOTOOLCHAIN'] = 'local'
        run(command, cwd=ROOT, env=environment)
        for number, (self_test, code) in enumerate(((False, 0), (False, 37), (True, 0), (True, 23))):
            record = root/f'invocation-{number}.json'
            child_env = dict(environment, ROUTERVPN_RECOVERY_RECORD=str(record), ROUTERVPN_RECOVERY_EXIT=str(code))
            invocation = [shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script)]
            if self_test:
                invocation.append('-SelfTest')
            started = time.monotonic()
            result = subprocess.run(invocation, cwd=root, env=child_env, capture_output=True, text=True, timeout=30)
            require(result.returncode == code, f'Recovery exit status {result.returncode} differs from owned launcher {code}:\n'+result.stdout+result.stderr)
            require(record.is_file(), 'Recovery entry point did not invoke the adjacent native launcher')
            value = json.loads(record.read_text(encoding='utf-8'))
            require(value['args'] == (['--self-test'] if self_test else []), 'Recovery arguments were changed or lost')
            require(os.path.normcase(str(Path(value['cwd']).resolve())) == os.path.normcase(str(package.resolve())), 'Recovery dispatched from another package directory')
            require(type(value['pid']) is int and value['pid'] > 0, 'No actual native process was executed')
            require(time.monotonic()-started >= 0.2, 'Recovery script returned before the owned launcher exited')
        executable.unlink()
        missing_record = root/'missing.json'
        result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script)],
                                cwd=root, env=dict(environment, ROUTERVPN_RECOVERY_RECORD=str(missing_record), ROUTERVPN_RECOVERY_EXIT='0'),
                                capture_output=True, text=True, timeout=30)
        require(result.returncode != 0 and not missing_record.exists() and 'RouterVPN.exe is missing' in result.stderr,
                'Missing adjacent launcher was silently replaced or accepted')
    print('Packaged Windows recovery dispatch: 4 actual native exits + missing-launcher rejection + 5 lifecycle-audit negatives PASS ('+args.shell+')')


if __name__ == '__main__':
    main()
