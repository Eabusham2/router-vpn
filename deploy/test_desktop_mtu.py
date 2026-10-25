#!/usr/bin/env python3
"""Execute shipping Windows/GTK MTU owners, real loopback requests, and controls."""
from pathlib import Path
import argparse
import contextlib
import http.server
import json
import os
import select
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]


def run(command, *, expect_failure=False, timeout=60):
    result = subprocess.run([str(x) for x in command], text=True, capture_output=True, timeout=timeout)
    if expect_failure:
        if result.returncode == 0:
            raise AssertionError('Broken ownership control unexpectedly passed: '+str(command))
    else:
        if result.returncode:
            raise RuntimeError(result.stdout+'\n'+result.stderr)
        print(result.stdout.strip(), flush=True)
    return result


class State:
    def __init__(self, scenario):
        self.scenario = scenario
        self.lock = threading.Lock()
        self.request = None
        self.registered = False
        self.cancelled = False
        self.completed = False
        self.replaced = False
        self.closed = False
        self.polls = 0
        self.cancel_polls = 0
        self.cancel_ids = []
        self.paths = []
        self.failures = []
        self.stop = threading.Event()

    def status(self, request=''):
        return {'session_id': 'captured-session', 'profile_id': 'router-a', 'requested': False,
                'waiting_commit': False, 'status': {
                    'request_id': request, 'phase': 'measuring', 'running': bool(request),
                    'complete': False, 'measured': False, 'restored': False, 'original_mtu': 1420,
                    'effective_mtu': 1420, 'source': 'saved-auto-throughput', 'candidates': []}}


@contextlib.contextmanager
def controller(scenario):
    state = State(scenario)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def reply(self, code, value):
            raw = json.dumps(value).encode()
            try:
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            with state.lock:
                state.paths.append(self.path)
                if parsed.path != '/api/mtu/status':
                    state.failures.append('foreign GET path')
                    return self.reply(400, {})
                if not query:
                    return self.reply(200, state.status())
                if query.get('session_id') != ['captured-session']:
                    state.failures.append('unowned GET session')
                    return self.reply(409, {})
                requested = query.get('request_id', [''])[0]
                if not requested:
                    return self.reply(200, state.status())
                if not state.registered:
                    return self.reply(404, {'error': 'not registered'})
                if requested != state.request:
                    state.failures.append('GET followed replacement request')
                    return self.reply(409, {})
                state.polls += 1
                if scenario == 'replaced' and state.polls >= 2:
                    state.replaced = True
                    return self.reply(409, {'error': 'session retired'})
                value = state.status(state.request)
                if state.cancelled:
                    state.cancel_polls += 1
                    value['status']['phase'] = 'restoring'
                    value['waiting_commit'] = state.cancel_polls < 2
                    if state.cancel_polls >= 2:
                        state.completed = True
                        value['status'].update(running=False, complete=True, restored=True,
                                               source='restored-captured-interface')
                return self.reply(200, value)

        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
                request = body['request_id']
                assert isinstance(request, str) and len(request) == 32 and all(x in '0123456789abcdef' for x in request)
                assert body['session_id'] == 'captured-session'
            except Exception as error:
                state.failures.append('invalid captured POST: '+str(error))
                return self.reply(400, {})
            with state.lock:
                state.paths.append(self.path)
                if self.path == '/api/mtu/cancel':
                    state.cancel_ids.append(request)
                    if state.request is not None and state.request != request:
                        state.failures.append('cancelled another request')
                        return self.reply(409, {})
                    state.cancelled = True
                    if not state.registered:
                        return self.reply(404, {'error': 'not registered'})
                    return self.reply(200, {'request_id': request, 'phase': 'canceling'})
                if self.path != '/api/mtu/retest' or body.get('profile_id') != 'router-a':
                    state.failures.append('wrong Retest operation/profile')
                    return self.reply(400, {})
                if state.request is not None:
                    state.failures.append('duplicate Retest')
                state.request = request
                state.registered = scenario != 'early' and not state.cancelled
            until = time.monotonic()+7
            while time.monotonic() < until and not state.stop.is_set():
                with state.lock:
                    completed = state.completed
                if completed:
                    return self.reply(409, {'error': 'cancelled after captured rollback'})
                try:
                    readable, _, _ = select.select([self.connection], [], [], .02)
                    if readable and self.connection.recv(1, socket.MSG_PEEK) == b'':
                        state.closed = True
                        return
                except (ConnectionResetError, OSError):
                    state.closed = True
                    return
            self.reply(500, {'error': 'test POST did not finish'})

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        block_on_close = False

    # A collision is an explicit failure; never stop somebody else's controller.
    server = Server(('127.0.0.1', 8788), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
        assert not state.failures, state.failures
        if scenario == 'accepted':
            assert state.completed and state.cancel_ids == [state.request] and state.cancel_polls >= 2
        elif scenario == 'replaced':
            assert state.replaced and not state.cancel_ids and state.closed
        else:
            assert state.cancelled and not state.registered
    finally:
        state.stop.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


def windows(directory, shell):
    helper = ROOT/'client/RouterVPN-Windows-MTU.ps1'
    test = ROOT/'client/test-windows-mtu.ps1'
    prefix = [shell, '-NoLogo', '-NoProfile']
    if os.name == 'nt':
        prefix += ['-STA']
    prefix += ['-ExecutionPolicy', 'Bypass', '-File', test]
    run(prefix)
    source = helper.read_text(encoding='utf-8')
    mutations = {
        'session': ("if($State.Session-and($State.Session-cne$Session-or$State.Profile-cne$Profile))", 'if($false)'),
        'commit': ('$ID-and$Complete-and-not$Running-and-not$Waiting', '$ID-and$Complete-and-not$Running'),
        'early-cancel': ('if($State.Own-and-not$State.Seen-and$null-ne$State.Run)', 'if($false)'),
        'generation': ('$Job.Generation-ne$State.Generation-or$State.Closed-or$State.Detaching', '$State.Closed-or$State.Detaching'),
        'drain': ('if($Pending){return $false}', 'if($false){return $false}'),
        'final-get': ('$Candidate-and$null-eq$State.Cancel-and(-not$State.Own-or($State.RunDone-and$AfterRun))', '$Candidate'),
        'cancel-epoch': ('$Job.Completion-ne$State.Completion-or($State.Own-and$State.RunDone-and-not$Job.AfterRun)', '$State.Own-and$State.RunDone-and-not$Job.AfterRun'),
    }
    for name, (before, after) in mutations.items():
        assert source.count(before) == 1, name
        path = directory/('windows-'+name+'.ps1')
        path.write_text(source.replace(before, after), encoding='utf-8')
        run([*prefix, '-Source', path], expect_failure=True)
    for scenario in ('accepted', 'early', 'replaced'):
        with controller(scenario):
            run([*prefix, '-Live', '-Scenario', scenario], timeout=25)
    print('PASS: Windows seven defect mutations and three real loopback lifecycle cases', flush=True)


def linux(directory):
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'gtk+-3.0', 'libcurl', 'json-glib-1.0'], text=True).split()
    source = (ROOT/'client/linux/routervpn-mtu-v20.inc').read_text(encoding='utf-8')
    def build(name, extra=()):
        binary = directory/name
        run(['cc', '-std=c11', '-D_GNU_SOURCE', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
             '-I'+str(ROOT/'client/linux'), *extra, ROOT/'client/linux/test-mtu-v20.c', '-o', binary, *flags, '-pthread'])
        return ['xvfb-run', '-a', binary]
    run(build('gtk-state'))
    mutations = {
        'session': ('if(s->session!=NULL&&(strcmp(s->session,session)!=0||strcmp(s->profile,profile)!=0))', 'if(FALSE)'),
        'commit': ('gboolean candidate=id[0]&&complete&&!running&&!waiting;', 'gboolean candidate=id[0]&&complete&&!running;'),
        'early-cancel': ('if(s->own&&!s->seen)rv_http_cancel_v16(s->jobs[LINUX_MTU_RUN_V20]);', 'if(FALSE)rv_http_cancel_v16(s->jobs[LINUX_MTU_RUN_V20]);'),
        'generation': ('s->job_generation[kind]==s->generation&&!s->detaching', '!s->detaching'),
        'final-get': ('s->terminal=candidate&&s->jobs[LINUX_MTU_CANCEL_V20]==NULL&&(!s->own||(s->run_done&&after_run));', 's->terminal=candidate;(void)after_run;'),
        'cancel-epoch': ('s->job_completion[kind]!=s->completion||(s->own&&s->run_done&&!s->job_after_run[kind])', 's->own&&s->run_done&&!s->job_after_run[kind]'),
    }
    for name,(before,after) in mutations.items():
        assert source.count(before)==1,name
        path=directory/('linux-'+name+'.inc');path.write_text(source.replace(before,after),encoding='utf-8')
        run(build('gtk-'+name, ['-DROUTERVPN_MTU_SOURCE="'+str(path)+'"']),expect_failure=True)
    live=build('gtk-live',['-DROUTERVPN_MTU_LIVE'])
    for scenario in ('accepted','early','replaced'):
        with controller(scenario):
            run([*live,scenario],timeout=25)
    print('PASS: GTK six defect mutations and three real loopback lifecycle cases',flush=True)


def integration(platform):
    if platform == 'windows':
        launcher=(ROOT/'client/RouterVPN-Windows-App.ps1').read_text(encoding='utf-8')
        assert "'RouterVPN-Windows-MTU.ps1'" in launcher and '$MTUSource=Get-Content -LiteralPath $MTUHelpers -Raw -Encoding UTF8' in launcher
        for file, count in [('RouterVPN-Windows-ProfileSettings.ps1',1),('RouterVPN-Windows-UnifiedShell.ps1',2),('RouterVPN-Windows-Telemetry.ps1',1)]:
            source=(ROOT/'client'/file).read_text(encoding='utf-8')
            assert source.count('Show-RouterVPNMTUDialog -BaseUrl $BaseUrl')==count,file
        settings=(ROOT/'client/RouterVPN-Windows-ProfileSettings.ps1').read_text(encoding='utf-8')
        assert settings.index('Name="MtuRetest"')>settings.index('</StackPanel>\n<Button Name="MtuRetest"')
        assert "'/api/mtu/retest') -Method Post" not in settings
    else:
        for file, call in [('routervpn-gtk-product-v5.c','linux_mtu_dialog_v20((App *)data)'),('routervpn-unified-shell-v8.inc','linux_mtu_dialog_v20(((LinuxUnifiedV8 *)data)->app)'),('routervpn-performance-v17.inc','linux_mtu_dialog_v20(p->app)')]:
            assert call in (ROOT/'client/linux'/file).read_text(encoding='utf-8'),file
        build=(ROOT/'client/linux/build-native-app.sh').read_text(encoding='utf-8')
        assert '#include "routervpn-mtu-v20.inc"' in build and '"$MTU_INC"' in build


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform',choices=('windows','linux'),required=True)
    parser.add_argument('--shell',default=shutil.which('pwsh') or 'powershell.exe')
    args=parser.parse_args()
    integration(args.platform)
    with tempfile.TemporaryDirectory(prefix='routervpn-desktop-mtu-') as temporary:
        directory=Path(temporary)
        if args.platform=='windows':windows(directory,args.shell)
        else:linux(directory)


if __name__=='__main__':
    main()
