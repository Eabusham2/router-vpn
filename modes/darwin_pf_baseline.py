"""Exact fixed-controller handoff for the owned macOS PF baseline.

The caller holds the protected installation/state locks and persists each
returned transition through the existing private state writer before apply.
This module accepts no command, namespace, rules text or caller-selected path.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable

ROOT = Path('/opt/router-vpn-client')
CONTROLLER = ROOT / 'router-vpn-client'
INSTALL_LOCK = Path('/opt/router-vpn-client.install.lock')
LIMIT = 4096
STATE_KEY = 'darwin_native_baseline'
_PROCESS_AUTHORITY_FDS: tuple[int, ...] = ()


@contextlib.contextmanager
def process_authority(descriptors: tuple[int, ...]):
    """Carry exact lock lifetimes across PF and native-helper exec boundaries."""
    global _PROCESS_AUTHORITY_FDS
    previous = _PROCESS_AUTHORITY_FDS
    _PROCESS_AUTHORITY_FDS = tuple(dict.fromkeys((*previous, *descriptors)))
    try:
        yield
    finally:
        _PROCESS_AUTHORITY_FDS = previous


def process_authority_fds() -> tuple[int, ...]:
    return _PROCESS_AUTHORITY_FDS


class PersistenceError(RuntimeError):
    def __init__(self, message: str, *, retained):
        super().__init__(message)
        # True means the exact new record is present; False means an
        # independent private read proved it was not adopted. None is unknown.
        self.retained = retained


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def _fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise RuntimeError('macOS baseline record has missing or unknown fields')


def _proof(value):
    _fields(value, ('present', 'rules_sha256'))
    present, digest = value['present'], value['rules_sha256']
    if type(present) is not bool or type(digest) is not str or (not re.fullmatch('[0-9a-f]{64}', digest) if present else digest != ''):
        raise RuntimeError('macOS baseline record has no exact namespace/rule proof')
    return {'present': present, 'rules_sha256': digest}


def _request(action: str, lan: bool, capture, expected):
    if action not in ('replace', 'clear') or type(lan) is not bool or type(expected) is not list or len(expected) not in (1, 2):
        raise RuntimeError('macOS baseline request has no bounded transition')
    session, source = '', ''
    if capture is not None:
        if type(capture) is not tuple or len(capture) != 2 or any(type(v) is not str for v in capture) or not re.fullmatch('[0-9a-f]{32}', capture[0]) or not re.fullmatch('[0-9a-f]{64}', capture[1]):
            raise RuntimeError('macOS baseline request lost its complete session/source')
        session, source = capture
    if action == 'clear' and (lan or capture is not None):
        raise RuntimeError('macOS baseline removal cannot borrow a connection')
    proofs = [_proof(value) for value in expected]
    if len(proofs) == 2 and proofs[0] == proofs[1]:
        raise RuntimeError('macOS baseline transition contains duplicate proofs')
    # Field order is the native canonical record contract, not arbitrary JSON.
    return {'schema': 1, 'action': action, 'home_lan_access': lan,
            'session_id': session, 'source_sha256': source, 'expected': proofs}


def _parse_request(value):
    _fields(value, ('schema', 'action', 'home_lan_access', 'session_id', 'source_sha256', 'expected'))
    if type(value['schema']) is not int or value['schema'] != 1:
        raise RuntimeError('macOS baseline request has another schema')
    session, source = value['session_id'], value['source_sha256']
    capture = None if session == '' and source == '' else (session, source)
    return _request(value['action'], value['home_lan_access'], capture, value['expected'])


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError('macOS baseline response has duplicate fields')
        result[key] = value
    return result


def _result(raw: bytes, request: dict, apply: bool):
    if type(raw) is not bytes or not raw or len(raw) > LIMIT:
        raise RuntimeError('macOS baseline response exceeds its private bound')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=_strict_object)
    except (ValueError, UnicodeError) as error:
        raise RuntimeError('macOS baseline response is not an exact record') from error
    _fields(value, ('schema', 'request_sha256', 'previous', 'target', 'applied'))
    previous, target = _proof(value['previous']), _proof(value['target'])
    if type(value['schema']) is not int or value['schema'] != 1 or type(value['applied']) is not bool or value['applied'] != apply or value['request_sha256'] != hashlib.sha256(_canonical(request)).hexdigest() or previous not in request['expected'] or target['present'] != (request['action'] == 'replace'):
        raise RuntimeError('macOS baseline response changed its captured request or target')
    return {'schema': 1, 'request_sha256': value['request_sha256'],
            'previous': previous, 'target': target, 'applied': apply}


def _native(phase: str, raw: bytes):
    if phase not in ('plan', 'apply', 'reference') or os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError('macOS baseline requires its existing privileged helper')
    if Path(os.environ.get('HOMEVPN_ROOT', str(ROOT))) != ROOT:
        raise RuntimeError('macOS native baseline requires the fixed protected installation')
    if type(raw) is not bytes or not raw or len(raw) > LIMIT:
        raise RuntimeError('macOS baseline request exceeds its private bound')
    # No additional elevation, shell, PATH lookup, inherited loader settings,
    # executable override, private credential or node bundle reaches this call.
    result = subprocess.run([str(CONTROLLER), '--darwin-owned-pf', phase], input=raw,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/',
                            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/var/root', 'LC_ALL': 'C'},
                            timeout=15, check=False, pass_fds=process_authority_fds())
    if result.returncode:
        raise RuntimeError('the exact native macOS baseline transaction did not finish: '+result.stderr[-1024:].decode('utf-8', errors='replace'))
    return result.stdout


def _invoke(phase: str, request: dict):
    if phase not in ('plan', 'apply'):
        raise RuntimeError('macOS baseline has another mutation phase')
    raw = _canonical(_parse_request(request))
    return _result(_native(phase, raw), request, phase == 'apply')


def token(value: str) -> str:
    if type(value) is not str or not re.fullmatch('[1-9][0-9]{0,19}', value) or int(value) > 18446744073709551615:
        raise RuntimeError('macOS PF reference has no canonical nonzero uint64 identity')
    return value


def reference(value: str) -> bool:
    value = token(value)
    raw = _native('reference', _canonical({'schema': 1, 'token': value}))
    if type(raw) is not bytes or not raw or len(raw) > 128:
        raise RuntimeError('macOS PF reference response exceeds its bound')
    try:
        result = json.loads(raw.decode('ascii'), object_pairs_hook=_strict_object)
    except (ValueError, UnicodeError) as error:
        raise RuntimeError('macOS PF reference response is not an exact record') from error
    _fields(result, ('schema', 'token', 'present'))
    if type(result['schema']) is not int or result['schema'] != 1 or result['token'] != value or type(result['present']) is not bool:
        raise RuntimeError('macOS PF reference response changed its exact identity')
    return result['present']


def retained(state: dict):
    value = state.get(STATE_KEY)
    if value is None:
        if state.get('native_socket_broker') is True or state.get('darwin_pf_anchor') == 'com.apple/000.router-vpn':
            raise RuntimeError('retained macOS native protection has no exact baseline receipt; prior-owner recovery is required')
        return [{'present': False, 'rules_sha256': ''}]
    _fields(value, ('schema', 'request', 'previous', 'target', 'complete'))
    if type(value['schema']) is not int or value['schema'] != 1 or type(value['complete']) is not bool:
        raise RuntimeError('macOS baseline receipt has another schema or phase')
    request = _parse_request(value['request'])
    previous, target = _proof(value['previous']), _proof(value['target'])
    if previous not in request['expected'] or target['present'] != (request['action'] == 'replace'):
        raise RuntimeError('macOS baseline receipt lost its exact planned transition')
    if value['complete'] or previous == target:
        return [target]
    return [previous, target]


def transition(state: dict, *, action: str, lan: bool = False, capture=None,
               retain: Callable[[dict], None]):
    if not callable(retain):
        raise RuntimeError('macOS native baseline requires durable cleanup ownership')
    request = _request(action, lan, capture, retained(state))
    try:
        plan = _invoke('plan', request)
    except RuntimeError:
        if STATE_KEY not in state or not state.get('pf_token') or reference(state['pf_token']):
            raise
        # A reboot may remove both the owned reference and the whole namespace.
        # The exact old token has now been independently proved absent. This
        # second read-only plan accepts only actual namespace absence; it never
        # treats a different present baseline as an old owner or a fresh start.
        request = _request(action, lan, capture, [{'present': False, 'rules_sha256': ''}])
        plan = _invoke('plan', request)
    # Validate even an internal adapter result; tests exercise this same seam.
    plan = _result(_canonical(plan), request, False)
    receipt = {'schema': 1, 'request': request, 'previous': plan['previous'],
               'target': plan['target'], 'complete': False}
    retain({STATE_KEY: receipt})
    # From the completed private write onward, any failure keeps both exact
    # possible kernel outcomes. Neither an exception nor a stale reply clears it.
    applied = _invoke('apply', request)
    applied = _result(_canonical(applied), request, True)
    if applied['previous'] != plan['previous'] or applied['target'] != plan['target']:
        raise RuntimeError('macOS baseline apply differs from its durably retained plan')
    return {STATE_KEY: {**receipt, 'complete': True}}


def status(state: dict) -> bool:
    try:
        expected = retained(state)
        value = state.get(STATE_KEY)
        if value is None or value['complete'] is not True or len(expected) != 1 or not expected[0]['present']:
            return False
        original = _parse_request(value['request'])
        capture = (original['session_id'], original['source_sha256']) if original['session_id'] else None
        request = _request('replace', original['home_lan_access'], capture, expected)
        result = _invoke('plan', request)
        result = _result(_canonical(result), request, False)
        return result['previous'] == result['target'] == expected[0] and reference(state.get('pf_token'))
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return False


def _owned_info(info, *, directory=False):
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    return kind and info.st_uid == 0 and info.st_gid == 0 and not info.st_mode & 0o022 and (directory or not info.st_mode & 0o077)


def sync_state(root: Path, value: dict):
    """Require private exact contents and both syncs before native mutation.

    The older general state writer tolerates a directory-sync failure for
    compatibility. A native pre-commit journal must propagate that failure.
    """
    directory = root/'run'
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    try:
        parent_info = os.fstat(parent)
        if not _owned_info(parent_info, directory=True) or parent_info.st_mode & 0o077 or not os.path.samestat(parent_info, directory.lstat()):
            raise RuntimeError('macOS baseline journal directory changed its private owner')
        descriptor = os.open('kill-switch.json', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        opened = os.fstat(descriptor)
        if not _owned_info(opened) or opened.st_size <= 0 or opened.st_size > 4 << 20:
            raise RuntimeError('macOS baseline journal is not a bounded private file')
        expected = (json.dumps(value, indent=2)+'\n').encode('utf-8')
        body = bytearray()
        while len(body) <= len(expected):
            part = os.read(descriptor, min(65536, len(expected)+1-len(body)))
            if not part:
                break
            body.extend(part)
        if bytes(body) != expected or not os.path.samestat(opened, os.stat('kill-switch.json', dir_fd=parent, follow_symlinks=False)):
            raise RuntimeError('macOS baseline journal changed before its durable proof')
        os.fsync(descriptor)
        os.fsync(parent)
        if not os.path.samestat(parent_info, directory.lstat()) or not os.path.samestat(opened, os.stat('kill-switch.json', dir_fd=parent, follow_symlinks=False)):
            raise RuntimeError('macOS baseline journal changed during its durable proof')
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _lock(path: Path, operation: int):
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        opened, current = os.fstat(descriptor), path.lstat()
        if not _owned_info(opened) or not _owned_info(current) or not os.path.samestat(opened, current):
            raise RuntimeError('macOS PF state lock changed its private identity')
        fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextlib.contextmanager
def state_guard(root: Path):
    """Cover the complete installed plan/journal/apply and final state write.

    Existing standalone legacy roots retain their original path behavior; the
    native adapter independently refuses those roots. No native test override
    or installation selector is accepted from the process environment.
    """
    if root != ROOT:
        yield ()
        return
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError('the installed macOS PF transaction requires its protected root helper')
    for parent in (ROOT.parent, *ROOT.parent.parents):
        if not _owned_info(parent.lstat(), directory=True):
            raise RuntimeError('the installed macOS PF state ancestor is not protected')
    install = _lock(INSTALL_LOCK, fcntl.LOCK_SH)
    state_lock = None
    try:
        before = ROOT.lstat()
        if not _owned_info(before, directory=True):
            raise RuntimeError('the installed macOS PF state root is not protected')
        state_lock = _lock(ROOT/'pf-state.lock', fcntl.LOCK_EX)
        if not os.path.samestat(before, ROOT.lstat()):
            raise RuntimeError('the installed macOS PF state root changed before capture')
        # The fixed native utility independently checks extended ACLs of this
        # root, both locks and all installed inputs before planning or applying.
        with process_authority((install, state_lock)):
            yield (install, state_lock)
    finally:
        if state_lock is not None:
            os.close(state_lock)
        os.close(install)
