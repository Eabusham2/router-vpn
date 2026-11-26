#!/usr/bin/env python3
"""Platform dispatcher for Router VPN Unix kill-switch policy.

Linux remains owned by the established kill-switch.py nftables implementation.
Darwin uses darwin_kill_switch.py and a fail-closed watcher: pre-connect rules
allow only the selected literal node endpoint (plus optional LAN/link traffic),
then only a newly-created utun that owns a public route is promoted.
"""
from __future__ import annotations

import importlib.util
import hashlib
import json
import contextlib
import fcntl
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Any

HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_linux = _load("routervpn_linux_killswitch", HERE / "kill-switch.py")
_darwin = _load("routervpn_darwin_killswitch", HERE / "darwin_kill_switch.py")

_WATCHER_KEY = 'darwin_watcher'
_WATCHER_GUARD_FD: int | None = None
_WATCHER_RETIRE_SECONDS = 3.0
_WATCHER_ADMISSION_SECONDS = 3.0


def _private_owner(info, *, directory=False):
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    return kind and info.st_uid == os.geteuid() and not info.st_mode & 0o077


@contextlib.contextmanager
def _private_run(root: Path):
    _linux._require_private_dir(root)
    directory = root / 'run'
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.geteuid() or not os.path.samestat(opened, directory.lstat()):
            raise RuntimeError('macOS watcher directory changed its private owner')
        # Legacy wrappers may create run with their ordinary umask. Preserve
        # the existing state writer's hardening, through this retained owner
        # descriptor rather than chmod of a path that could be replaced.
        if opened.st_mode & 0o077:
            os.fchmod(descriptor, 0o700)
            opened = os.fstat(descriptor)
        if not _private_owner(opened, directory=True) or not os.path.samestat(opened, directory.lstat()):
            raise RuntimeError('macOS watcher directory changed its private owner')
        yield descriptor
        if not os.path.samestat(opened, directory.lstat()):
            raise RuntimeError('macOS watcher directory changed during its owned operation')
    finally:
        os.close(descriptor)


def _private_descriptor(parent: int, leaf: str, *, create=False, exclusive=False):
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    if create:
        flags |= os.O_CREAT
    if exclusive:
        flags |= os.O_EXCL
    descriptor = os.open(leaf, flags, 0o600, dir_fd=parent)
    try:
        opened = os.fstat(descriptor)
        if not _private_owner(opened) or not os.path.samestat(opened, os.stat(leaf, dir_fd=parent, follow_symlinks=False)):
            raise RuntimeError('macOS watcher lease changed its private identity')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextlib.contextmanager
def _watcher_state_guard(root: Path):
    """Serialize every root, including the standalone legacy dispatcher.

    The fixed installation's independent native guard remains the outer lock.
    Never unlink this lock: a replacement inode could admit a second writer.
    PF children inherit the retained description until their own completion.
    """
    global _WATCHER_GUARD_FD
    if _WATCHER_GUARD_FD is not None:
        raise RuntimeError('macOS watcher transaction cannot borrow another root owner')
    with _private_run(root) as parent:
        descriptor = _private_descriptor(parent, 'darwin-watcher-state.lock', create=True)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _WATCHER_GUARD_FD = descriptor
            with _darwin.pf_process_authority((descriptor,)):
                yield
        finally:
            _WATCHER_GUARD_FD = None
            # Closing, rather than LOCK_UN, preserves any in-flight child's
            # shared authority if this Python owner fails or exits early.
            os.close(descriptor)


@contextlib.contextmanager
def _darwin_action_guard(root: Path):
    """Admit one foreground action after a bounded existing-watcher turn.

    Retry only lock acquisition, releasing every acquired outer guard before
    waiting. Once admitted, a failed action is never replayed.
    """
    deadline = time.monotonic() + _WATCHER_ADMISSION_SECONDS
    busy = None
    while True:
        if time.monotonic() >= deadline:
            raise RuntimeError('macOS policy transaction is still owned by another operation') from busy
        guards = contextlib.ExitStack()
        try:
            guards.enter_context(_darwin._baseline.state_guard(root))
            guards.enter_context(_watcher_state_guard(root))
        except BlockingIOError as error:
            guards.close()
            busy = error
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.02, remaining))
            continue
        except BaseException:
            guards.close()
            raise
        with guards:
            yield
        return


def _watcher_record(state: dict[str, Any]):
    value = state.get(_WATCHER_KEY)
    if (type(value) is not dict or set(value) != {'schema', 'generation', 'device', 'inode', 'phase'}
            or type(value['schema']) is not int or value['schema'] != 1
            or type(value['generation']) is not str or not re.fullmatch('[0-9a-f]{32}', value['generation'])
            or type(value['device']) is not int or value['device'] < 0
            or type(value['inode']) is not int or value['inode'] <= 0
            or value['phase'] not in ('starting', 'active', 'cancel', 'finished', 'retired')
            or type(state.get('darwin_watcher_pid')) is not int or state['darwin_watcher_pid'] < 0):
        raise RuntimeError('macOS protection has an unresolved private watcher lease')
    return value


def _watcher_leaf(record):
    return 'darwin-watcher-' + record['generation'] + '.lease'


def _check_watcher_descriptor(descriptor: int, record) -> None:
    info = os.fstat(descriptor)
    if not _private_owner(info) or (info.st_dev, info.st_ino) != (record['device'], record['inode']):
        raise RuntimeError('macOS watcher lease no longer matches its captured owner')


def _write_watcher_state(root: Path, state: dict[str, Any]) -> None:
    _write_state(root, state)
    # Cancellation/adoption is also a durable ownership transition. The older
    # generic writer tolerates directory-sync failure; a lease owner cannot.
    with _private_run(root) as parent:
        descriptor = _private_descriptor(parent, 'kill-switch.json')
        try:
            if _linux.read_state(root) != state:
                raise RuntimeError('macOS watcher journal changed before its durable proof')
            os.fsync(descriptor)
            os.fsync(parent)
            if not os.path.samestat(os.fstat(descriptor), os.stat('kill-switch.json', dir_fd=parent, follow_symlinks=False)):
                raise RuntimeError('macOS watcher journal changed during its durable proof')
        finally:
            os.close(descriptor)


def _dry_run() -> bool:
    return os.environ.get("HOMEVPN_KILLSWITCH_DRY_RUN") == "1"


def _write_state(root: Path, value: dict[str, Any]) -> None:
    native = not _dry_run() and _darwin._baseline.STATE_KEY in value
    try:
        _linux.write_state(root, value)
        if native:
            _darwin._baseline.sync_state(root, value)
    except Exception as error:
        if not native:
            raise
        # A writer can adopt the file and then fail its final sync. Retain the
        # reference when that exact record exists or its current state cannot
        # be independently read; only proved non-adoption permits balancing a
        # newly acquired reference before any baseline mutation.
        retained = None
        try:
            retained = _linux.read_state(root) == value
        except Exception:
            pass
        raise _darwin._baseline.PersistenceError('macOS baseline private persistence did not finish: '+str(error), retained=retained) from error


def _retained_removal(root: Path, state: dict[str, Any]):
    def persist(extra):
        _write_state(root, {**state, **extra, 'darwin_transition_pending': True})
    return persist


def _darwin_state_base(runtime_id: str, control_id: str, endpoint: str, endpoint_ips, lan: bool, policy: str) -> dict[str, Any]:
    return {
        "policy": policy,
        "profile_id": runtime_id,
        "policy_profile_id": control_id,
        "endpoint": endpoint,
        "endpoint_ips": [str(ip) for ip in endpoint_ips],
        "home_lan_access": lan,
        "platform": "darwin",
        "enforced": not _dry_run(),
    }


def _require_watcher_retired(state: dict[str, Any]) -> None:
    if not state:
        return
    if _WATCHER_KEY in state:
        root = _linux.root_dir()
        if _WATCHER_GUARD_FD is None:
            raise RuntimeError('macOS watcher retirement requires its captured state transaction')
        record = _watcher_record(state)
        with _private_run(root) as parent:
            descriptor = None
            try:
                try:
                    descriptor = _private_descriptor(parent, _watcher_leaf(record))
                except FileNotFoundError:
                    # Only a durable exact retirement receipt permits the
                    # missing-file retry after unlink or parent-sync failure.
                    if record['phase'] != 'retired':
                        raise RuntimeError('macOS watcher lease is missing before proved retirement')
                if descriptor is not None:
                    _check_watcher_descriptor(descriptor, record)
                    if record['phase'] != 'retired':
                        # Check cancellation outside the transaction lock too,
                        # so the watcher can retire while this caller waits.
                        cancelled = {**state, _WATCHER_KEY: {**record, 'phase': 'cancel'}}
                        _write_watcher_state(root, cancelled)
                        deadline = time.monotonic() + _WATCHER_RETIRE_SECONDS
                        while True:
                            try:
                                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                break
                            except BlockingIOError:
                                if time.monotonic() >= deadline:
                                    raise RuntimeError('macOS watcher cancellation has not yet retired its captured lease')
                                time.sleep(0.02)
                        _check_watcher_descriptor(descriptor, record)
                        if _linux.read_state(root) != cancelled:
                            raise RuntimeError('macOS watcher cancellation lost its captured journal')
                        state.clear()
                        state.update({**cancelled, 'darwin_watcher_pid': 0,
                                      _WATCHER_KEY: {**record, 'phase': 'retired'}})
                        _write_watcher_state(root, state)
                    else:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    if not os.path.samestat(os.fstat(descriptor), os.stat(_watcher_leaf(record), dir_fd=parent, follow_symlinks=False)):
                        raise RuntimeError('macOS watcher lease changed before owned cleanup')
                    os.unlink(_watcher_leaf(record), dir_fd=parent)
                # Keep the retired receipt until the exact leaf's absence is
                # durable. A failed unlink/sync remains retryable and cannot
                # rearm a watcher or authorize deleting a foreign replacement.
                os.fsync(parent)
                retired = {**state, 'darwin_watcher_pid': 0}
                retired.pop(_WATCHER_KEY)
                _write_watcher_state(root, retired)
                state.clear()
                state.update(retired)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        return
    # Old journals retain only a numeric PID, without a creation identity,
    # captured child handle or authenticated retirement receipt. It cannot
    # authorize signaling, including after PID reuse. Preserve an unresolved
    # owner before changing its rules or private journal; do not coerce a
    # missing/malformed identity into a successful no-watcher observation.
    pid = state.get('darwin_watcher_pid')
    if type(pid) is not int or pid != 0:
        raise RuntimeError('macOS protection requires exact prior watcher retirement; saved process identities cannot authorize signaling')


def _spawn_watcher() -> int:
    if _dry_run():
        return 0
    if _WATCHER_GUARD_FD is None:
        raise RuntimeError('macOS watcher launch requires its captured state transaction')
    root = _linux.root_dir()
    state = _linux.read_state(root)
    _require_watcher_retired(state)
    generation = secrets.token_hex(16)
    with _private_run(root) as parent:
        leaf = _watcher_leaf({'generation': generation})
        descriptor = _private_descriptor(parent, leaf, create=True, exclusive=True)
        launched = False
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(descriptor)
            os.fsync(descriptor)
            record = {'schema': 1, 'generation': generation, 'device': info.st_dev, 'inode': info.st_ino, 'phase': 'starting'}
            # Publish before launch. An interrupted launch keeps an exact
            # recoverable lease; a child cannot mutate PF before activation.
            state[_WATCHER_KEY] = record
            _write_watcher_state(root, state)
            proc = subprocess.Popen(
                [sys.executable, '-EsS', str(Path(__file__).resolve()), 'watch', generation, str(descriptor)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True, close_fds=True, pass_fds=(descriptor,),
            )
            launched = True
            state['darwin_watcher_pid'] = int(proc.pid)
            state[_WATCHER_KEY] = {**record, 'phase': 'active'}
            _write_watcher_state(root, state)
            return int(proc.pid)
        except BaseException:
            # A failed first journal write can leave an unreferenced lease.
            # Delete it only before a child was launched and after an exact
            # independent read proves this generation was never adopted.
            adopted = None
            if not launched:
                try:
                    saved = _linux.read_state(root).get(_WATCHER_KEY)
                    adopted = type(saved) is dict and saved.get('generation') == generation
                except Exception:
                    pass
            if adopted is False:
                if not os.path.samestat(os.fstat(descriptor), os.stat(leaf, dir_fd=parent, follow_symlinks=False)):
                    raise RuntimeError('macOS unpublished watcher lease changed before cleanup')
                os.unlink(leaf, dir_fd=parent)
                os.fsync(parent)
            raise
        finally:
            os.close(descriptor)


def darwin_apply(*, spawn_watch: bool = True, retained_state=None, external_capture=None, node_chain_capture=None, candidate_prefix_capture=None, node_capture=None) -> int:
    root = _linux.root_dir()
    store = _linux.read_store(root)
    runtime_id = _linux.safe_profile_id()
    control_id = _linux.policy_profile_id(runtime_id)
    runtime_profile = _linux.required_profile(store, runtime_id, "runtime/entry")
    control_profile = _linux.required_profile(store, control_id, "policy/control")
    policy = _linux.policy_value(control_profile)
    previous = _linux.read_state(root)
    if sum(value is not None for value in (external_capture, node_chain_capture, candidate_prefix_capture, node_capture)) > 1:
        raise RuntimeError('macOS baseline cannot combine independent native policy families')
    if external_capture is not None:
        external_capture = _darwin_external_capture(external_capture)
        if external_capture['schema'] == 1:
            if retained_state is None or external_capture['policy'] != 'always':
                raise RuntimeError('legacy macOS external capture cannot acquire a new baseline')
            _darwin_external_state(retained_state, external_capture)
        _darwin_external_profile(control_profile, runtime_id, control_id, external_capture, store)
        policy = external_capture['policy']
    if node_chain_capture is not None:
        node_chain_capture = _darwin_node_chain_capture(node_chain_capture)
        if node_chain_capture['schema'] == 2 and retained_state is None:
            raise RuntimeError('legacy macOS ordered capture cannot acquire a new baseline')
        if retained_state is not None:
            _darwin_node_chain_state(retained_state, node_chain_capture)
        _darwin_node_chain_profile(control_profile, runtime_id, control_id, node_chain_capture, store)
        policy = node_chain_capture['policy']
        if retained_state is None and store.get('selected_id') != _darwin_node_chain_control(node_chain_capture):
            raise RuntimeError('macOS ordered baseline changed its original selected Router control')
    if node_capture is not None:
        node_capture = _darwin_node_capture(node_capture)
        if retained_state is not None:
            _darwin_node_state(retained_state, node_capture)
        _darwin_node_profile(control_profile, runtime_id, control_id, node_capture, store)
        policy = node_capture['policy']
        if retained_state is None and store.get('selected_id') != node_capture['profile_id']:
            raise RuntimeError('macOS paired-node baseline changed its original selected profile')
    if candidate_prefix_capture is not None:
        candidate_prefix_capture = _darwin_candidate_prefix_capture(candidate_prefix_capture)
        if candidate_prefix_capture['schema'] == 2 and retained_state is None:
            raise RuntimeError('legacy macOS prefix capture cannot authorize a new baseline')
        if retained_state is not None:
            _darwin_candidate_prefix_state(retained_state, candidate_prefix_capture)
        _darwin_candidate_prefix_profile(control_profile, runtime_id, control_id, candidate_prefix_capture, store)
        policy = candidate_prefix_capture['policy']
        if retained_state is None and store.get('selected_id') != candidate_prefix_capture['profile_id']:
            raise RuntimeError('macOS candidate prefix baseline changed its full saved Router control')

    if policy == "off" and external_capture is None and node_chain_capture is None and candidate_prefix_capture is None and node_capture is None:
        if previous and previous.get("platform") == "darwin":
            _require_watcher_retired(previous)
            _darwin.remove_darwin(previous, dry_run=_dry_run(), retain_state=_retained_removal(root, previous))
            _linux.remove_state(root)
        print("kill switch off", file=sys.stderr)
        return 0

    endpoint = os.environ.get("HOMEVPN_ENDPOINT") or str(runtime_profile.get("endpoint") or "")
    if external_capture is not None or node_chain_capture is not None or candidate_prefix_capture is not None or node_capture is not None:
        socket_broker = True
    else:
        socket_broker = _linux.native_socket_broker_policy(control_profile, runtime_id, control_id, retained_state)
    retained = _linux.retained_native_policy(retained_state, endpoint) if retained_state is not None and not socket_broker else None
    if socket_broker:
        endpoint, endpoint_ips, native_egress = '', [], None
    elif retained is None:
        endpoint_ips = _linux.captured_endpoint_ips(endpoint)
        native_egress = _linux.captured_native_egress(endpoint_ips)
    else:
        endpoint_ips, native_egress = retained
    lan = bool(control_profile.get("home_lan_access", False))
    if node_capture is not None:
        lan = node_capture["home_lan_access"]
    if candidate_prefix_capture is not None:
        lan = candidate_prefix_capture["home_lan_access"]
    _require_watcher_retired(previous)
    socket_capture = ((os.environ['HOMEVPN_TOR_SESSION'], os.environ['HOMEVPN_TOR_SOURCE_SHA256'])
                      if socket_broker and retained_state is None and external_capture is None and node_chain_capture is None and candidate_prefix_capture is None and node_capture is None else None)
    if external_capture is not None:
        socket_capture = ((external_capture['session_id'], external_capture['source_sha256'])
                          if retained_state is None else None)
    if node_chain_capture is not None:
        socket_capture = ((node_chain_capture['session_id'], node_chain_capture['source_sha256'])
                          if retained_state is None else None)
    if candidate_prefix_capture is not None:
        socket_capture = ((candidate_prefix_capture['session_id'], candidate_prefix_capture['source_sha256'])
                          if retained_state is None else None)
    if node_capture is not None:
        socket_capture = ((node_capture['session_id'], node_capture['source_sha256'])
                          if retained_state is None else None)
    state = _darwin_state_base(runtime_id, control_id, endpoint, endpoint_ips, lan, policy)
    if node_capture is not None:
        state['native_socket_family'] = 'paired-node-v1'
        state['native_node_capture'] = node_capture
    if external_capture is not None:
        state['native_socket_family'] = 'external-v1'
        state['native_external_capture'] = external_capture
    if node_chain_capture is not None:
        state['native_socket_family'] = node_chain_capture['family']
        state['native_node_chain_capture'] = node_chain_capture
    if candidate_prefix_capture is not None:
        state['native_socket_family'] = 'node-candidate-prefix-v1'
        state['native_candidate_prefix_capture'] = candidate_prefix_capture
    if native_egress is not None:
        state["native_egress"] = native_egress
    if socket_broker:
        state['native_socket_broker'] = True
    state["darwin_watcher_pid"] = 0
    def retain_state(extra):
        _write_state(root, {**state, **extra, "darwin_transition_pending": True})
    extra = _darwin.apply_darwin(endpoint_ips, lan, previous, refresh=False, dry_run=_dry_run(), native_egress=native_egress,
                               socket_broker=socket_broker, socket_capture=socket_capture, isolated_only=policy == "off", retain_state=retain_state)
    state.update(extra)
    _write_state(root, state)
    if spawn_watch and not socket_broker:
        _spawn_watcher()
    print(f"strict macOS kill switch {policy} applied pre-connect for {endpoint}", file=sys.stderr)
    return 0


def _watcher_matches(state: dict[str, Any], capture: dict[str, Any], *, active=False) -> bool:
    if not state or state.get('platform') != 'darwin' or state.get('native_socket_broker') is True:
        return False
    try:
        record = _watcher_record(state)
    except RuntimeError:
        return False
    if any(record[key] != capture[key] for key in ('schema', 'generation', 'device', 'inode')):
        return False
    if active:
        return record['phase'] == 'active' and state['darwin_watcher_pid'] == os.getpid()
    return record['phase'] in ('starting', 'active')


def darwin_watch(generation: str = '', descriptor: int = -1) -> int:
    # A manual or old PID-only `watch` invocation has no inherited ownership.
    if not re.fullmatch('[0-9a-f]{32}', generation) or type(descriptor) is not int or descriptor < 3:
        raise RuntimeError('macOS watcher requires its captured generation and inherited lease')
    root = _linux.root_dir()
    try:
        initial = _linux.read_state(root)
        capture = _watcher_record(initial)
        if capture['generation'] != generation:
            raise RuntimeError('macOS watcher launch changed its captured generation')
        _check_watcher_descriptor(descriptor, capture)
        with _private_run(root) as parent:
            current = os.stat(_watcher_leaf(capture), dir_fd=parent, follow_symlinks=False)
            if not os.path.samestat(os.fstat(descriptor), current):
                raise RuntimeError('macOS watcher inherited another private lease')
        # This succeeds on the inherited open description. Opening the same
        # leaf independently cannot borrow the launcher's already-held lock.
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            state = _linux.read_state(root)
            if not _watcher_matches(state, capture):
                return 0
            if state[_WATCHER_KEY]['phase'] == 'starting':
                time.sleep(0.02)
                continue
            try:
                with _darwin._baseline.state_guard(root):
                    with _watcher_state_guard(root):
                        state = _linux.read_state(root)
                        if not _watcher_matches(state, capture, active=True):
                            return 0
                        endpoint_ips = [_linux.ipaddress.ip_address(x) for x in state.get('endpoint_ips', [])]
                        retained = _linux.retained_native_policy(state, str(state.get('endpoint') or ''))
                        native_egress = None
                        if retained is not None:
                            endpoint_ips, native_egress = retained
                        with _darwin.pf_process_authority((descriptor,)):
                            extra = _darwin.apply_darwin(
                                endpoint_ips, bool(state.get('home_lan_access', False)), state,
                                refresh=True, dry_run=_dry_run(), native_egress=native_egress,
                            )
                        state.update(extra)
                        state[_WATCHER_KEY] = {**capture, 'phase': 'finished'}
                        _write_watcher_state(root, state)
            except Exception:
                time.sleep(0.02)
                continue
            print('strict macOS kill switch promoted proven Router VPN utun', file=sys.stderr)
            return 0
        # Timeout only closes this captured lease. It never zeros a saved PID
        # or rewrites whichever replacement/native journal is now selected.
        return 1
    finally:
        os.close(descriptor)


def darwin_release(force: bool = False, *, retain_protection: bool = False) -> int:
    root = _linux.root_dir()
    try:
        state = _linux.read_state(root)
    except RuntimeError:
        if not force:
            raise
        # Explicit local recovery for poisoned state: without a valid persisted
        # pf_token we cannot safely call pfctl -X, because that could interfere
        # with another PF owner. Clear only Router VPN's fixed dispatches and
        # independently prove both absent before discarding the poisoned leaf.
        # An unknown/failed removal retains that recovery record and reports
        # failure; global enablement and every foreign reference stay untouched.
        if not _dry_run():
            if _darwin.owned_namespace_present(_darwin.OWNED_PF_ANCHOR):
                raise RuntimeError('unreadable state cannot authorize another retained native PF owner; exact prior-owner recovery is required')
            if _darwin.owned_namespace_present(_darwin.PF_ANCHOR):
                _darwin._clear_anchor(check=True)
            for anchor in (_darwin.PF_ANCHOR, _darwin.OWNED_PF_ANCHOR):
                if _darwin.run_pf(['-a', anchor, '-s', 'rules']).stdout.strip() or _darwin.owned_namespace_present(anchor):
                    raise RuntimeError('explicit macOS force-off could not prove the owned dispatch absent')
        _linux.remove_state(root, force_recovery=True)
        print(
            "strict macOS kill switch force-off cleared the Router VPN PF anchor; "
            "persisted PF reference token was unreadable, so global PF enablement was left untouched",
            file=sys.stderr,
        )
        return 0
    if not state:
        return 0
    _require_watcher_retired(state)
    if not force and (state.get("policy") == "always" or retain_protection and state.get("policy") != "off"):
        # Remove the old tunnel-interface permission but retain the fail-closed
        # pre-connect endpoint exception while disconnected.
        socket_broker = state.get('native_socket_broker') is True
        endpoint_ips = [] if socket_broker else [_linux.ipaddress.ip_address(x) for x in state.get("endpoint_ips", [])]
        retained = None if socket_broker else _linux.retained_native_policy(state, str(state.get("endpoint") or ""))
        native_egress = None
        if retained is not None:
            endpoint_ips, native_egress = retained
        extra = _darwin.apply_darwin(
            endpoint_ips,
            bool(state.get("home_lan_access", False)),
            state,
            refresh=False,
            dry_run=_dry_run(),
            native_egress=native_egress,
            socket_broker=socket_broker,
            socket_capture=None,
            retain_state=lambda extra: _write_state(root, {**state, **extra, 'darwin_watcher_pid': 0, 'darwin_transition_pending': True}),
        )
        state.pop('darwin_previous_pf_anchor', None)
        state.pop('darwin_transition_pending', None)
        state.update(extra)
        state["darwin_watcher_pid"] = 0
        _write_state(root, state)
        print("strict macOS kill switch remains active (always policy)", file=sys.stderr)
        return 0
    _darwin.remove_darwin(state, dry_run=_dry_run(), retain_state=_retained_removal(root, state))
    _linux.remove_state(root, force_recovery=force)
    print("strict macOS kill switch released", file=sys.stderr)
    return 0

def darwin_reassert() -> int:
    root = _linux.root_dir()
    state = _linux.read_state(root)
    if not state or state.get("policy") != "always":
        return 0
    runtime_id = _linux.validate_profile_id(str(state.get("profile_id") or ""), "persistent kill-switch runtime profile id")
    control_id = _linux.validate_profile_id(str(state.get("policy_profile_id") or runtime_id), "persistent kill-switch policy profile id")
    os.environ["HOMEVPN_PROFILE_ID"] = runtime_id
    os.environ["HOMEVPN_POLICY_PROFILE_ID"] = control_id
    os.environ["HOMEVPN_ENDPOINT"] = str(state.get("endpoint") or "")
    os.environ.pop("HOMEVPN_NATIVE_ENDPOINTS_JSON", None)
    os.environ.pop("HOMEVPN_NATIVE_EGRESS_JSON", None)
    os.environ.pop("HOMEVPN_TOR_PHYSICAL_BROKER", None)
    os.environ.pop("HOMEVPN_EXTERNAL_SESSION", None)
    # Record possible protection mutation after read-only profile validation,
    # before apply can acquire a reference or change its durable journal.
    _darwin._baseline.CAPABILITY.possible_mutation()
    if state.get('native_socket_family') == 'paired-node-v1':
        capture = _darwin_node_capture(state.get('native_node_capture'))
        _darwin_node_state(state, capture)
        return darwin_apply(spawn_watch=False, retained_state=state, node_capture=capture)
    if state.get('native_socket_family') == 'node-candidate-prefix-v1':
        capture = _darwin_candidate_prefix_capture(state.get('native_candidate_prefix_capture'))
        return darwin_apply(spawn_watch=False, retained_state=state, candidate_prefix_capture=capture)
    if state.get('native_socket_family') in _NODE_CHAIN_FAMILIES:
        capture = _darwin_node_chain_capture(state.get('native_node_chain_capture'))
        _darwin_node_chain_state(state, capture)
        return darwin_apply(spawn_watch=False, retained_state=state, node_chain_capture=capture)
    capture = (state.get('native_external_capture')
               if state.get('native_socket_family') == 'external-v1' else None)
    return darwin_apply(spawn_watch=False, retained_state=state, external_capture=capture)



_EXTERNAL_LEGACY_CAPTURE_FIELDS = ('schema', 'profile_id', 'protocol', 'session_id', 'source_sha256',
                                   'config_sha256', 'home_lan_access', 'policy')
_EXTERNAL_CAPTURE_FIELDS = _EXTERNAL_LEGACY_CAPTURE_FIELDS + ('entry_profile_id', 'final_policy', 'entry_policy')
_EXTERNAL_PROTOCOLS = {'socks5', 'shadowsocks', 'http-connect', 'https-connect',
                       'hysteria2', 'wireguard', 'amneziawg', 'openvpn'}


def _darwin_external_capture(value):
    fields = _EXTERNAL_LEGACY_CAPTURE_FIELDS if type(value) is dict and value.get('schema') == 1 else _EXTERNAL_CAPTURE_FIELDS
    _darwin._baseline._fields(value, fields)
    if (type(value['schema']) is not int or value['schema'] not in (1, 2)
            or type(value['protocol']) is not str or value['protocol'] not in _EXTERNAL_PROTOCOLS
            or type(value['home_lan_access']) is not bool
            or value['policy'] not in ('off', 'on-connect', 'always')
            or type(value['session_id']) is not str or not re.fullmatch('[0-9a-f]{32}', value['session_id'])
            or any(type(value[key]) is not str or not re.fullmatch('[0-9a-f]{64}', value[key])
                   for key in ('source_sha256', 'config_sha256'))):
        raise RuntimeError('macOS external baseline lost its exact ordinary policy capture')
    _linux.validate_profile_id(value['profile_id'], 'native external profile id')
    if value['schema'] == 2:
        if (type(value['entry_profile_id']) is not str
                or value['final_policy'] not in ('off', 'on-connect', 'always')
                or type(value['entry_policy']) is not str):
            raise RuntimeError('macOS external capture lost its exact original member protection')
        policies = [value['final_policy']]
        if value['entry_profile_id']:
            _linux.validate_profile_id(value['entry_profile_id'], 'native external entry profile id')
            if value['entry_profile_id'] == value['profile_id'] or value['entry_policy'] not in ('off', 'on-connect', 'always'):
                raise RuntimeError('macOS external capture substituted its original entry protection')
            policies.append(value['entry_policy'])
        elif value['entry_policy'] != '':
            raise RuntimeError('direct macOS external capture invented another member protection')
        strength = {'off': 0, 'on-connect': 1, 'always': 2}
        if max(policies, key=strength.__getitem__) != value['policy']:
            raise RuntimeError('macOS external capture downgraded its original member protection')
    return {key: value[key] for key in fields}


def _darwin_external_profile(profile, runtime_id, control_id, capture, store):
    external = profile.get('external')
    final_policy = capture['final_policy'] if capture['schema'] == 2 else capture['policy']
    saved_policy = (_darwin_saved_member_policy(profile) if capture['schema'] == 2
                    else _linux.policy_value(profile))
    if (runtime_id != control_id or runtime_id != capture['profile_id']
            or profile.get('node_kind') != 'external' or type(external) is not dict
            or external.get('protocol') != capture['protocol']
            or saved_policy != final_policy
            or bool(profile.get('home_lan_access', False)) != capture['home_lan_access']):
        raise RuntimeError('macOS external baseline differs from the captured saved protection policy')
    if capture['schema'] == 2:
        profiles = store.get('profiles')
        if type(profiles) is not list or sum(type(row) is dict and row.get('id') == capture['profile_id'] for row in profiles) != 1:
            raise RuntimeError('macOS external baseline lost the captured saved protection policy identity')
        if capture['entry_profile_id']:
            entries = [row for row in profiles if type(row) is dict and row.get('id') == capture['entry_profile_id']]
            if (len(entries) != 1 or entries[0].get('node_kind') != 'external'
                    or type(entries[0].get('external')) is not dict
                    or entries[0]['external'].get('protocol') not in ('wireguard', 'amneziawg', 'shadowsocks', 'openvpn')
                    or _darwin_saved_member_policy(entries[0]) != capture['entry_policy']):
                raise RuntimeError('macOS external entry differs from the captured saved protection policy')
    # Only this independent ordinary family chooses the deny baseline. It
    # never imports endpoint exceptions or borrows Tor's session marker.
    if any(os.environ.get(key) for key in ('HOMEVPN_ENDPOINT', 'HOMEVPN_NATIVE_ENDPOINTS_JSON',
            'HOMEVPN_NATIVE_EGRESS_JSON', 'HOMEVPN_TOR_PHYSICAL_BROKER', 'HOMEVPN_TOR_SESSION',
            'HOMEVPN_TOR_SOURCE_SHA256', 'HOMEVPN_EXTERNAL_SESSION')):
        raise RuntimeError('macOS external baseline mixed another native protection family')


def _darwin_external_state(state, capture):
    if (not state or state.get('platform') != 'darwin'
            or state.get('native_socket_family') != 'external-v1'
            or state.get('native_socket_broker') is not True
            or state.get('native_external_capture') != capture
            or state.get('profile_id') != capture['profile_id']
            or state.get('policy_profile_id') != capture['profile_id']
            or state.get('policy') != capture['policy']
            or state.get('home_lan_access') is not capture['home_lan_access']
            or state.get('endpoint') != '' or state.get('endpoint_ips') != []
            or 'native_egress' in state):
        raise RuntimeError('macOS external cleanup belongs to another retained owner')
    _darwin._baseline.retained(state)
    return state


def _darwin_external_receipt(value, capture):
    _darwin._baseline._fields(value, ('schema', 'capture', 'phase', 'pf_token', 'baseline'))
    if (type(value['schema']) is not int or value['schema'] != 1
            or value['capture'] != capture or value['phase'] not in ('active', 'held', 'retired')):
        raise RuntimeError('macOS external baseline receipt belongs to another original capture')
    _darwin._baseline.token(value['pf_token'])
    proof = _darwin._baseline._proof(value['baseline'])
    if proof['present'] is not (value['phase'] == 'active' or value['phase'] == 'held' and capture['policy'] != 'off' or capture['policy'] == 'always'):
        raise RuntimeError('macOS external receipt changed its selected retirement policy')
    return value


def _darwin_external_result(capture, phase, token, baseline):
    return _darwin_external_receipt(dict(schema=1, capture=capture, phase=phase,
                                        pf_token=token, baseline=baseline), capture)


def _darwin_external_live_receipt(state, capture):
    _darwin_external_state(state, capture)
    value = state[_darwin._baseline.STATE_KEY]
    request = value['request']
    if (value['complete'] is not True or state.get('darwin_transition_pending') is True
            or request['session_id'] != capture['session_id']
            or request['source_sha256'] != capture['source_sha256']
            or request['home_lan_access'] is not capture['home_lan_access']
            or request.get('isolated_only', False) is not (capture['policy'] == 'off')
            or not _darwin._baseline.status(state)):
        raise RuntimeError('macOS external baseline lacks its current native session proof')
    return _darwin_external_result(capture, 'active', state['pf_token'], value['target'])


def darwin_external(action, value):
    """Same existing journal/namespace, with an exact ordinary owner boundary.

    The original app holds installation/process authority and serializes this
    action with the existing state guards. A request cannot introduce rules,
    executable paths, endpoints, UID exemptions or another PF namespace.
    """
    if action not in ('apply', 'current', 'retire', 'release') or _dry_run():
        raise RuntimeError('macOS external baseline requires its actual native transaction')
    _darwin._baseline._fields(value, ('capture', 'expected'))
    capture = _darwin_external_capture(value['capture'])
    expected = value['expected']
    if expected is not None:
        expected = _darwin_external_receipt(expected, capture)
    root = _linux.root_dir()
    state = _linux.read_state(root)
    if action == 'apply':
        if expected is not None:
            raise RuntimeError('macOS external application cannot reuse a prior receipt')
        os.environ['HOMEVPN_PROFILE_ID'] = capture['profile_id']
        os.environ['HOMEVPN_POLICY_PROFILE_ID'] = capture['profile_id']
        # Retry the same captured application only by readback. A prior
        # unfinished transition remains in the existing durable journal.
        if state.get('native_external_capture') == capture:
            result = _darwin_external_live_receipt(state, capture)
        else:
            darwin_apply(spawn_watch=False, external_capture=capture)
            result = _darwin_external_live_receipt(_linux.read_state(root), capture)
    elif action == 'current':
        result = _darwin_external_live_receipt(state, capture)
        if expected is None or result != expected:
            raise RuntimeError('macOS external readback changed its original baseline receipt')
    elif not state:
        # Only an originally observed reference can authorize an idempotent
        # post-removal readback. Unknown partial application stays owned.
        if (expected is None or capture['policy'] not in ('off', 'on-connect')
                or action != 'release' and not (action == 'retire' and capture['policy'] == 'off')
                or _darwin.owned_namespace_present(_darwin.OWNED_PF_ANCHOR)
                or _darwin._baseline.reference(expected['pf_token'])):
            raise RuntimeError('macOS external removal has no exact retired reference proof')
        result = _darwin_external_result(capture, 'held' if action == 'retire' else 'retired', expected['pf_token'],
                                          {'present': False, 'rules_sha256': ''})
    else:
        _darwin_external_state(state, capture)
        token = _darwin._baseline.token(state.get('pf_token'))
        if expected is not None and token != expected['pf_token']:
            raise RuntimeError('macOS external cleanup changed its original PF reference')
        # Native baseline transition refuses every live guardian generation,
        # grant, table and unreferenced child before replacing its deny rules.
        darwin_release(False, retain_protection=action == 'retire')
        after = _linux.read_state(root)
        if action == 'retire' and capture['policy'] != 'off' or capture['policy'] == 'always':
            _darwin_external_state(after, capture)
            journal = after[_darwin._baseline.STATE_KEY]
            request = journal['request']
            if (request['session_id'] != '' or request['source_sha256'] != ''
                    or journal['complete'] is not True or after.get('darwin_transition_pending') is True
                    or after.get('pf_token') != token or not _darwin._baseline.status(after)):
                raise RuntimeError('macOS Always retirement lost its exact empty native baseline')
            proof = journal['target']
        else:
            if (after or _darwin.owned_namespace_present(_darwin.OWNED_PF_ANCHOR)
                    or _darwin._baseline.reference(token)):
                raise RuntimeError('macOS On-connect retirement retained its original native reference')
            proof = {'present': False, 'rules_sha256': ''}
        result = _darwin_external_result(capture, 'held' if action == 'retire' else 'retired', token, proof)
    return result


_NODE_CHAIN_FAMILIES = ('ordered-node-chain-v1', 'ordered-node-chain-socks-v1',
                        'ordered-node-chain-connect-v1', 'ordered-node-chain-execution-v1')

_NODE_CHAIN_CAPTURE_FIELDS = ('schema', 'family', 'profile_id', 'session_id', 'source_sha256',
                             'config_sha256', 'home_lan_access', 'policy')


def _darwin_node_chain_capture(value):
    schema = value.get('schema') if type(value) is dict else None
    fields = _NODE_CHAIN_CAPTURE_FIELDS + (('members_json', 'members_sha256') if schema in (3, 4, 5) else ())
    if schema in (4, 5):
        fields += ('control_profile_id',)
        if 'entry_start_layer' in value or schema == 5:
            if not _linux._darwin_external_entry_layer(value):
                raise RuntimeError('macOS ordered baseline lost its captured entry Start Layer')
            fields += ('entry_start_layer',)
    _darwin._baseline._fields(value, fields)
    if (type(schema) is not int or schema not in (2, 3, 4, 5)
            or type(value['family']) is not str or value['family'] not in _NODE_CHAIN_FAMILIES
            or type(value['home_lan_access']) is not bool
            or value['policy'] not in ('off', 'on-connect', 'always')
            or type(value['session_id']) is not str or not re.fullmatch('[0-9a-f]{32}', value['session_id'])
            or any(type(value[key]) is not str or not re.fullmatch('[0-9a-f]{64}', value[key])
                   for key in ('source_sha256', 'config_sha256'))):
        raise RuntimeError('macOS ordered baseline lost its exact complete policy capture')
    _linux.validate_profile_id(value['profile_id'], 'native ordered control profile id')
    if schema in (4, 5):
        _linux.validate_profile_id(value['control_profile_id'], 'native ordered entry control profile id')
    if schema in (3, 4, 5):
        _darwin_node_chain_rows(value)
    return {key: value[key] for key in fields}


def _darwin_node_chain_rows(capture):
    fail = 'macOS ordered baseline lost its original member policy rows'
    raw, digest = capture['members_json'], capture['members_sha256']
    if (type(raw) is not str or not 0 < len(raw) <= 512+192*96 or type(digest) is not str
            or not re.fullmatch('[0-9a-f]{64}', digest)):
        raise RuntimeError(fail)
    try:
        rows = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise RuntimeError(fail) from error
    if (type(rows) is not list or not 2 <= len(rows) <= 96
            or len(raw) > (4096 if len(rows) <= 8 else max(4096, 512+192*len(rows)))
            or json.dumps(rows, separators=(',', ':'), ensure_ascii=True) != raw
            or hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode('utf-8')).hexdigest() != digest):
        raise RuntimeError(fail)
    extended = len(rows) > 8
    external_final = capture['schema'] in (4, 5)
    if external_final and (not _linux._darwin_external_final_roles(capture['schema'], capture['family'], rows)
            or capture['control_profile_id'] != rows[0][0]
            or capture['control_profile_id'] == capture['profile_id']):
        raise RuntimeError(fail)
    private_streams = _linux._darwin_private_stream_roles(capture['family'], rows)
    if extended and capture['family'] not in ('ordered-node-chain-v1', 'ordered-node-chain-execution-v1'):
        raise RuntimeError(fail)
    seen, policy, lan = set(), 'off', True
    for position, row in enumerate(rows):
        if (type(row) is not list or len(row) != 6 or type(row[0]) is not str
                or not re.fullmatch('[A-Za-z0-9_-]{1,64}', row[0]) or row[0] in seen
                or type(row[1]) is not str or not re.fullmatch('[a-z0-9-]{1,64}', row[1])
                or row[2] not in ('router-vpn', 'external') or row[3] not in ('off', 'on-connect', 'always')
                or row[4] not in ('auto', 'on', 'off') or type(row[5]) is not bool):
            raise RuntimeError(fail)
        seen.add(row[0])
        if extended and not external_final:
            expected = _linux._darwin_extended_member_role(capture['family'], rows, position)
            if tuple(row[1:3]) != expected:
                raise RuntimeError(fail)
        if row[2] == 'external':
            middle = {'ordered-node-chain-v1': ('shadowsocks', 'openvpn'),
                      'ordered-node-chain-socks-v1': ('socks5',),
                      'ordered-node-chain-connect-v1': ('http-connect', 'https-connect'),
                      'ordered-node-chain-execution-v1': ('shadowsocks', 'socks5', 'http-connect', 'https-connect')}
            connect = capture['family'] == 'ordered-node-chain-connect-v1'
            variable = (connect
                        or capture['family'] == 'ordered-node-chain-socks-v1' and row[1] == 'socks5'
                        or capture['family'] == 'ordered-node-chain-execution-v1' and row[1] in ('shadowsocks', 'socks5', 'http-connect', 'https-connect')
                        or capture['family'] == 'ordered-node-chain-v1' and row[1] in ('shadowsocks', 'openvpn'))
            independent = row[1] == 'shadowsocks' and capture['family'] in ('ordered-node-chain-v1', 'ordered-node-chain-execution-v1')
            count_valid = 3 <= len(rows) <= (96 if extended else 8) if variable else len(rows) == 3
            positioned = 0 < position < len(rows)-1 if independent else position == (len(rows)-2 if variable else 1)
            if external_final:
                positioned = position > 0
            if not count_valid or not positioned or row[1] not in middle.get(capture['family'], ()) or rows[-1][1] != 'shadowsocks':
                raise RuntimeError(fail)
        elif position < len(rows)-1 and row[1] not in ('wg', 'awg2-fast', 'awg2-strong') and not (private_streams and row[1] == 'shadowsocks') or position == len(rows)-1 and row[1] not in ('shadowsocks', 'hysteria2'):
            raise RuntimeError(fail)
        if row[3] == 'always' or policy == 'off' and row[3] == 'on-connect':
            policy = row[3]
        lan = lan and row[5]
    if rows[-1][0] != capture['profile_id'] or policy != capture['policy'] or lan is not capture['home_lan_access']:
        raise RuntimeError(fail)
    return rows


def _darwin_node_chain_control(capture):
    return capture['control_profile_id'] if capture['schema'] in (4, 5) else capture['profile_id']


def _darwin_node_chain_profile(profile, runtime_id, control_id, capture, store=None):
    fail = 'macOS ordered baseline differs from the captured saved Router protection policy'
    if (runtime_id != capture['profile_id'] or control_id != _darwin_node_chain_control(capture)
            or profile.get('id') != control_id
            or profile.get('node_kind', '') not in ('', 'router-vpn') or profile.get('external') is not None):
        raise RuntimeError(fail)
    if capture['schema'] == 2:
        if (_linux.policy_value(profile) != capture['policy']
                or profile.get('home_lan_access', False) is not capture['home_lan_access']):
            raise RuntimeError(fail)
    else:
        if type(store) is not dict or type(store.get('profiles')) is not list:
            raise RuntimeError(fail)
        rows = _darwin_node_chain_rows(capture)
        for position, row in enumerate(rows):
            matches = [member for member in store['profiles'] if type(member) is dict and member.get('id') == row[0]]
            if len(matches) != 1:
                raise RuntimeError(fail)
            member = matches[0]
            expected_layer = capture.get('entry_start_layer', 'off') if position == 0 else 'off'
            if (len(rows) > 8 or capture['schema'] in (4, 5)) and (member.get('start_layer', '') or 'off') != expected_layer:
                raise RuntimeError(fail)
            kind = member.get('node_kind', '') or 'router-vpn'
            if kind != row[2]:
                raise RuntimeError(fail)
            if kind == 'external':
                if type(member.get('external')) is not dict or member['external'].get('protocol') != row[1]:
                    raise RuntimeError(fail)
            elif member.get('external') is not None:
                raise RuntimeError(fail)
            ipv6 = member.get('ipv6_mode', '') or 'on'
            lan = member.get('home_lan_access', True)
            if (_darwin_saved_member_policy(member) != row[3] or ipv6 != row[4]
                    or type(lan) is not bool or lan is not row[5]):
                raise RuntimeError(fail)
    # Original guardians alone grant physical tuples after this empty baseline.
    if any(os.environ.get(key) for key in ('HOMEVPN_ENDPOINT', 'HOMEVPN_NATIVE_ENDPOINTS_JSON',
            'HOMEVPN_NATIVE_EGRESS_JSON', 'HOMEVPN_TOR_PHYSICAL_BROKER', 'HOMEVPN_TOR_SESSION',
            'HOMEVPN_TOR_SOURCE_SHA256', 'HOMEVPN_EXTERNAL_SESSION')):
        raise RuntimeError('macOS ordered baseline mixed another native protection family')


def _darwin_node_chain_selected(root, capture):
    store = _linux.read_store(root)
    control = _darwin_node_chain_control(capture)
    if store.get('selected_id') != control:
        raise RuntimeError('macOS ordered baseline changed its original selected Router control')
    profile = _linux.required_profile(store, control, 'ordered policy/control')
    _darwin_node_chain_profile(profile, capture['profile_id'], control, capture, store)


def _darwin_node_chain_state(state, capture):
    if (not state or state.get('platform') != 'darwin'
            or capture.get('family') not in _NODE_CHAIN_FAMILIES
            or state.get('native_socket_family') != capture['family']
            or state.get('native_socket_broker') is not True
            or state.get('native_node_chain_capture') != capture
            or 'native_external_capture' in state or 'native_candidate_prefix_capture' in state or 'native_node_capture' in state
            or state.get('profile_id') != capture['profile_id']
            or state.get('policy_profile_id') != _darwin_node_chain_control(capture)
            or state.get('policy') != capture['policy']
            or state.get('home_lan_access') is not capture['home_lan_access']
            or state.get('endpoint') != '' or state.get('endpoint_ips') != []
            or 'native_egress' in state):
        raise RuntimeError('macOS ordered cleanup belongs to another retained owner')
    _darwin._baseline.retained(state)
    return state


def _darwin_node_chain_receipt(value, capture):
    _darwin._baseline._fields(value, ('schema', 'capture', 'phase', 'pf_token', 'baseline'))
    if (type(value['schema']) is not int or value['schema'] != capture['schema']
            or _darwin_node_chain_capture(value['capture']) != capture
            or value['phase'] not in ('active', 'held', 'retired')):
        raise RuntimeError('macOS ordered baseline receipt belongs to another original capture')
    _darwin._baseline.token(value['pf_token'])
    proof = _darwin._baseline._proof(value['baseline'])
    if proof['present'] is not (value['phase'] == 'active' or value['phase'] == 'held' and capture['policy'] != 'off' or capture['policy'] == 'always'):
        raise RuntimeError('macOS ordered receipt changed its selected retirement policy')
    return value


def _darwin_node_chain_result(capture, phase, token, baseline):
    return _darwin_node_chain_receipt(dict(schema=capture['schema'], capture=capture, phase=phase,
                                          pf_token=token, baseline=baseline), capture)


def _darwin_node_chain_live_receipt(state, capture):
    _darwin_node_chain_state(state, capture)
    value = state[_darwin._baseline.STATE_KEY]
    request = value['request']
    if (value['complete'] is not True or state.get('darwin_transition_pending') is True
            or request['session_id'] != capture['session_id']
            or request['source_sha256'] != capture['source_sha256']
            or request['home_lan_access'] is not capture['home_lan_access']
            or request.get('isolated_only', False) is not (capture['policy'] == 'off')
            or not _darwin._baseline.status(state)):
        raise RuntimeError('macOS ordered baseline lacks its current native session proof')
    return _darwin_node_chain_result(capture, 'active', state['pf_token'], value['target'])


def darwin_node_chain(action, value):
    """A distinct ordered capture on the original guarded PF journal.

    No source can request a command, rule, namespace, endpoint or UID exception.
    Native graph/source proof and joined process retirement remain separate.
    """
    if action not in ('apply', 'current', 'retire', 'release') or _dry_run():
        raise RuntimeError('macOS ordered baseline requires its actual native transaction')
    _darwin._baseline._fields(value, ('capture', 'expected'))
    capture = _darwin_node_chain_capture(value['capture'])
    expected = value['expected']
    if expected is not None:
        expected = _darwin_node_chain_receipt(expected, capture)
    root = _linux.root_dir()
    state = _linux.read_state(root)
    if action == 'apply':
        if expected is not None or capture['schema'] not in (3, 4, 5):
            raise RuntimeError('macOS ordered application requires original member policy capture')
        _darwin_node_chain_selected(root, capture)
        os.environ['HOMEVPN_PROFILE_ID'] = capture['profile_id']
        os.environ['HOMEVPN_POLICY_PROFILE_ID'] = _darwin_node_chain_control(capture)
        if state.get('native_node_chain_capture') == capture:
            result = _darwin_node_chain_live_receipt(state, capture)
        else:
            darwin_apply(spawn_watch=False, node_chain_capture=capture)
            result = _darwin_node_chain_live_receipt(_linux.read_state(root), capture)
    elif action == 'current':
        result = _darwin_node_chain_live_receipt(state, capture)
        if expected is None or result != expected:
            raise RuntimeError('macOS ordered readback changed its original baseline receipt')
    elif not state:
        if (expected is None or capture['policy'] not in ('off', 'on-connect')
                or action != 'release' and not (action == 'retire' and capture['policy'] == 'off')
                or _darwin.owned_namespace_present(_darwin.OWNED_PF_ANCHOR)
                or _darwin._baseline.reference(expected['pf_token'])):
            raise RuntimeError('macOS ordered removal has no exact retired reference proof')
        result = _darwin_node_chain_result(capture, 'held' if action == 'retire' else 'retired', expected['pf_token'],
                                            {'present': False, 'rules_sha256': ''})
    else:
        _darwin_node_chain_state(state, capture)
        token = _darwin._baseline.token(state.get('pf_token'))
        if expected is not None and token != expected['pf_token']:
            raise RuntimeError('macOS ordered cleanup changed its original PF reference')
        # Existing retirement checks every live guardian generation, grant,
        # table and unreferenced child before settling the original baseline.
        darwin_release(False, retain_protection=action == 'retire')
        after = _linux.read_state(root)
        if action == 'retire' and capture['policy'] != 'off' or capture['policy'] == 'always':
            _darwin_node_chain_state(after, capture)
            journal = after[_darwin._baseline.STATE_KEY]
            request = journal['request']
            if (request['session_id'] != '' or request['source_sha256'] != ''
                    or journal['complete'] is not True or after.get('darwin_transition_pending') is True
                    or after.get('pf_token') != token or not _darwin._baseline.status(after)):
                raise RuntimeError('macOS ordered retirement lost its exact empty native baseline')
            proof = journal['target']
        else:
            if (after or _darwin.owned_namespace_present(_darwin.OWNED_PF_ANCHOR)
                    or _darwin._baseline.reference(token)):
                raise RuntimeError('macOS ordered retirement retained its original native reference')
            proof = {'present': False, 'rules_sha256': ''}
        result = _darwin_node_chain_result(capture, 'held' if action == 'retire' else 'retired', token, proof)
    return result


_NODE_CAPTURE_FIELDS = ('schema', 'family', 'profile_id', 'node_id', 'mode', 'start_layer',
                        'session_id', 'source_sha256', 'config_sha256', 'home_lan_access', 'policy')
_NODE_MODES = ('wg', 'awg2-fast', 'awg2-strong', 'shadowsocks', 'hysteria2', 'ss-v2ray', 'naive-h2', 'reality-vision', 'reality-pq-vision', 'reality-xhttp')
_NODE_LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')


def _darwin_node_capture(value):
    _darwin._baseline._fields(value, _NODE_CAPTURE_FIELDS)
    if (type(value['schema']) is not int or value['schema'] != 1 or value['family'] != 'paired-node-v1'
            or value['mode'] not in _NODE_MODES or value['start_layer'] not in _NODE_LAYERS
            or type(value['home_lan_access']) is not bool or value['policy'] not in ('off', 'on-connect', 'always')
            or type(value['session_id']) is not str or not re.fullmatch('[0-9a-f]{32}', value['session_id'])
            or any(type(value[key]) is not str or not re.fullmatch('[0-9a-f]{64}', value[key])
                   for key in ('source_sha256', 'config_sha256', 'node_id'))):
        raise RuntimeError('macOS paired-node baseline lost its exact original policy capture')
    _linux.validate_profile_id(value['profile_id'], 'native paired-node profile id')
    return {key: value[key] for key in _NODE_CAPTURE_FIELDS}


def _darwin_node_profile(profile, runtime_id, control_id, capture, store=None):
    if (runtime_id != control_id or runtime_id != capture['profile_id']
            or profile.get('node_kind', '') not in ('', 'router-vpn') or profile.get('external') is not None
            or profile.get('node_proof_id') != capture['node_id']
            or (profile.get('start_layer') or 'off') != capture['start_layer']
            or _darwin_saved_member_policy(profile) != capture['policy']
            or profile.get('home_lan_access', True) is not capture['home_lan_access']):
        raise RuntimeError('macOS paired-node baseline differs from its original saved paired policy')
    if any(os.environ.get(key) for key in ('HOMEVPN_ENDPOINT', 'HOMEVPN_NATIVE_ENDPOINTS_JSON',
            'HOMEVPN_NATIVE_EGRESS_JSON', 'HOMEVPN_TOR_PHYSICAL_BROKER', 'HOMEVPN_TOR_SESSION',
            'HOMEVPN_TOR_SOURCE_SHA256', 'HOMEVPN_EXTERNAL_SESSION')):
        raise RuntimeError('macOS paired-node baseline mixed another native protection family')


def _darwin_node_selected(root, capture):
    store = _linux.read_store(root)
    if store.get('selected_id') != capture['profile_id']:
        raise RuntimeError('macOS paired-node baseline changed its original selected profile')
    profile = _linux.required_profile(store, capture['profile_id'], 'paired-node control')
    _darwin_node_profile(profile, capture['profile_id'], capture['profile_id'], capture, store)


def _darwin_node_state(state, capture):
    if (not state or state.get('platform') != 'darwin'
            or capture.get('family') != 'paired-node-v1'
            or state.get('native_socket_family') != capture['family']
            or state.get('native_socket_broker') is not True
            or state.get('native_node_capture') != capture
            or any(key in state for key in ('native_external_capture', 'native_candidate_prefix_capture', 'native_node_chain_capture'))
            or state.get('profile_id') != capture['profile_id']
            or state.get('policy_profile_id') != capture['profile_id']
            or state.get('policy') != capture['policy']
            or state.get('home_lan_access') is not capture['home_lan_access']
            or state.get('endpoint') != '' or state.get('endpoint_ips') != []
            or 'native_egress' in state):
        raise RuntimeError('macOS paired-node cleanup belongs to another retained owner')
    _darwin._baseline.retained(state)
    return state


def _darwin_node_receipt(value, capture):
    _darwin._baseline._fields(value, ('schema', 'capture', 'phase', 'pf_token', 'baseline'))
    if (type(value['schema']) is not int or value['schema'] != capture['schema']
            or _darwin_node_capture(value['capture']) != capture
            or value['phase'] not in ('active', 'held', 'retired')):
        raise RuntimeError('macOS paired-node baseline receipt belongs to another original capture')
    _darwin._baseline.token(value['pf_token'])
    proof = _darwin._baseline._proof(value['baseline'])
    if proof['present'] is not (value['phase'] == 'active' or value['phase'] == 'held' and capture['policy'] != 'off' or capture['policy'] == 'always'):
        raise RuntimeError('macOS paired-node receipt changed its selected retirement policy')
    return value


def _darwin_node_result(capture, phase, token, baseline):
    return _darwin_node_receipt(dict(schema=capture['schema'], capture=capture, phase=phase,
                                          pf_token=token, baseline=baseline), capture)


def _darwin_node_live_receipt(state, capture):
    _darwin_node_state(state, capture)
    value = state[_darwin._baseline.STATE_KEY]
    request = value['request']
    if (value['complete'] is not True or state.get('darwin_transition_pending') is True
            or request['session_id'] != capture['session_id']
            or request['source_sha256'] != capture['source_sha256']
            or request['home_lan_access'] is not capture['home_lan_access']
            or request.get('isolated_only', False) is not (capture['policy'] == 'off')
            or not _darwin._baseline.status(state)):
        raise RuntimeError('macOS paired-node baseline lacks its current native session proof')
    return _darwin_node_result(capture, 'active', state['pf_token'], value['target'])


def darwin_node(action, value):
    """A distinct ordered capture on the original guarded PF journal.

    No source can request a command, rule, namespace, endpoint or UID exception.
    Native graph/source proof and joined process retirement remain separate.
    """
    if action not in ('apply', 'current', 'retire', 'release') or _dry_run():
        raise RuntimeError('macOS paired-node baseline requires its actual native transaction')
    _darwin._baseline._fields(value, ('capture', 'expected'))
    capture = _darwin_node_capture(value['capture'])
    expected = value['expected']
    if expected is not None:
        expected = _darwin_node_receipt(expected, capture)
    root = _linux.root_dir()
    state = _linux.read_state(root)
    if action == 'apply':
        if expected is not None or capture['schema'] != 1:
            raise RuntimeError('macOS paired-node application requires original member policy capture')
        _darwin_node_selected(root, capture)
        os.environ['HOMEVPN_PROFILE_ID'] = capture['profile_id']
        os.environ['HOMEVPN_POLICY_PROFILE_ID'] = capture['profile_id']
        if state.get('native_node_capture') == capture:
            result = _darwin_node_live_receipt(state, capture)
        else:
            darwin_apply(spawn_watch=False, node_capture=capture)
            result = _darwin_node_live_receipt(_linux.read_state(root), capture)
    elif action == 'current':
        result = _darwin_node_live_receipt(state, capture)
        if expected is None or result != expected:
            raise RuntimeError('macOS paired-node readback changed its original baseline receipt')
    elif not state:
        if (expected is None or capture['policy'] not in ('off', 'on-connect')
                or action != 'release' and not (action == 'retire' and capture['policy'] == 'off')
                or _darwin.owned_namespace_present(_darwin.OWNED_PF_ANCHOR)
                or _darwin._baseline.reference(expected['pf_token'])):
            raise RuntimeError('macOS paired-node removal has no exact retired reference proof')
        result = _darwin_node_result(capture, 'held' if action == 'retire' else 'retired', expected['pf_token'],
                                            {'present': False, 'rules_sha256': ''})
    else:
        _darwin_node_state(state, capture)
        token = _darwin._baseline.token(state.get('pf_token'))
        if expected is not None and token != expected['pf_token']:
            raise RuntimeError('macOS paired-node cleanup changed its original PF reference')
        # Existing retirement checks every live guardian generation, grant,
        # table and unreferenced child before settling the original baseline.
        darwin_release(False, retain_protection=action == 'retire')
        after = _linux.read_state(root)
        if action == 'retire' and capture['policy'] != 'off' or capture['policy'] == 'always':
            _darwin_node_state(after, capture)
            journal = after[_darwin._baseline.STATE_KEY]
            request = journal['request']
            if (request['session_id'] != '' or request['source_sha256'] != ''
                    or journal['complete'] is not True or after.get('darwin_transition_pending') is True
                    or after.get('pf_token') != token or not _darwin._baseline.status(after)):
                raise RuntimeError('macOS paired-node retirement lost its exact empty native baseline')
            proof = journal['target']
        else:
            if (after or _darwin.owned_namespace_present(_darwin.OWNED_PF_ANCHOR)
                    or _darwin._baseline.reference(token)):
                raise RuntimeError('macOS paired-node retirement retained its original native reference')
            proof = {'present': False, 'rules_sha256': ''}
        result = _darwin_node_result(capture, 'held' if action == 'retire' else 'retired', token, proof)
    return result


_CANDIDATE_PREFIX_CAPTURE_LEGACY_FIELDS = ('schema', 'family', 'profile_id', 'session_id', 'source_sha256',
                             'config_sha256', 'home_lan_access', 'policy')
_CANDIDATE_PREFIX_CAPTURE_FIELDS = (*_CANDIDATE_PREFIX_CAPTURE_LEGACY_FIELDS, 'members_sha256')


def _darwin_candidate_prefix_capture(value):
    fields = (_CANDIDATE_PREFIX_CAPTURE_LEGACY_FIELDS if type(value) is dict and value.get('schema') == 2
              else _CANDIDATE_PREFIX_CAPTURE_FIELDS)
    _darwin._baseline._fields(value, fields)
    if (type(value['schema']) is not int or value['schema'] not in (2, 3)
            or value['family'] != 'node-candidate-prefix-v1'
            or type(value['home_lan_access']) is not bool
            or value['policy'] not in ('off', 'on-connect', 'always')
            or type(value['session_id']) is not str or not re.fullmatch('[0-9a-f]{32}', value['session_id'])
            or any(type(value[key]) is not str or not re.fullmatch('[0-9a-f]{64}', value[key])
                   for key in ('source_sha256', 'config_sha256'))
            or value['schema'] == 3 and (type(value['members_sha256']) is not str
                                        or not re.fullmatch('[0-9a-f]{64}', value['members_sha256']))):
        raise RuntimeError('macOS candidate prefix baseline lost its exact closed prefix policy capture')
    _linux.validate_profile_id(value['profile_id'], 'native candidate prefix control profile id')
    return {key: value[key] for key in fields}


def _darwin_saved_member_policy(profile):
    """Match the sealed Go accessor, without changing legacy global parsing."""
    if type(profile) is not dict or type(profile.get('kill_switch', False)) is not bool:
        raise RuntimeError('macOS native baseline requires canonical saved member protection')
    policy = profile.get('kill_switch_policy', '')
    if type(policy) is not str:
        raise RuntimeError('macOS native baseline requires canonical saved member protection')
    if policy == '':
        return 'on-connect' if profile.get('kill_switch', False) else 'off'
    if policy not in ('off', 'on-connect', 'always'):
        raise RuntimeError('macOS native baseline requires canonical saved member protection')
    return policy


def _darwin_candidate_prefix_members(store, profile):
    # The original saved control supplies the complete ordered references.
    # Unrelated profiles are neither participants nor policy inputs.
    fail = 'macOS candidate prefix baseline differs from the captured saved Router protection policy'
    nodes = profile.get('multihop_nodes')
    if (type(store) is not dict or type(store.get('profiles')) is not list
            or profile.get('multihop_enabled') is not True or profile.get('multihop_execution') != 'local'
            or type(nodes) is not list or not 2 <= len(nodes) <= 96 or type(nodes[0]) is not dict):
        raise RuntimeError(fail)
    entry_control = nodes[0].get('id') == profile.get('id')
    if (entry_control and len(nodes) < 3) or (not entry_control and len(nodes) > 8):
        raise RuntimeError(fail)
    rows, seen = [], set()
    policy, lan = 'off', True
    for position, reference in enumerate(nodes):
        if (type(reference) is not dict or set(reference) != {'id', 'mode'}
                or type(reference['id']) is not str or not re.fullmatch('[A-Za-z0-9_-]{1,64}', reference['id'])
                or reference['id'] in seen or type(reference['mode']) is not str
                or not re.fullmatch('[a-z0-9-]{1,64}', reference['mode'])):
            raise RuntimeError(fail)
        seen.add(reference['id'])
        matches = [member for member in store['profiles'] if type(member) is dict and member.get('id') == reference['id']]
        if len(matches) != 1:
            raise RuntimeError(fail)
        member = matches[0]
        kind = member.get('node_kind', '')
        if type(kind) is not str:
            raise RuntimeError(fail)
        if kind == '':
            kind = 'router-vpn'
        if kind not in ('router-vpn', 'external'):
            raise RuntimeError(fail)
        if kind == 'external':
            if (reference['mode'] != 'shadowsocks' or type(member.get('external')) is not dict
                    or member['external'].get('protocol') != 'shadowsocks'
                    or not entry_control and (len(nodes) != 3 or position != 1)):
                raise RuntimeError(fail)
            if entry_control:
                shadowsocks = member['external'].get('shadowsocks')
                if (type(shadowsocks) is not dict or type(shadowsocks.get('server')) is not str
                        or type(shadowsocks.get('port')) is not int or not 1 <= shadowsocks['port'] <= 65535
                        or shadowsocks.get('method') not in ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
                                                            '2022-blake3-chacha20-poly1305')):
                    raise RuntimeError(fail)
                try:
                    address = _linux.ipaddress.ip_address(shadowsocks['server'])
                except ValueError as error:
                    raise RuntimeError(fail) from error
                if (str(address) != shadowsocks['server'] or member.get('endpoint') != shadowsocks['server']
                        or address.is_multicast or address.is_unspecified or getattr(address, 'scope_id', None)
                        or getattr(address, 'ipv4_mapped', None) is not None):
                    raise RuntimeError(fail)
        elif member.get('external') is not None:
            raise RuntimeError(fail)
        if entry_control and (member.get('start_layer', '') not in ('', 'off')
                or (reference['mode'], kind) != (('wg', 'router-vpn') if position == 0 else ('shadowsocks', 'external'))):
            raise RuntimeError(fail)
        # Match normalized RouterProfile device fields, including legacy bool
        # defaults, before comparing the Go accessor's original canonical rows.
        kill = _darwin_saved_member_policy(member)
        ipv6 = member.get('ipv6_mode', '')
        if type(ipv6) is not str:
            raise RuntimeError(fail)
        if ipv6 == '':
            ipv6 = 'on'
        member_lan = member.get('home_lan_access', True)
        if kill not in ('off', 'on-connect', 'always') or ipv6 not in ('auto', 'on', 'off') or type(member_lan) is not bool:
            raise RuntimeError(fail)
        rows.append([reference['id'], reference['mode'], kind, kill, ipv6, member_lan])
        if kill == 'always' or policy == 'off' and kill == 'on-connect':
            policy = kill
        lan = lan and member_lan
    if not entry_control and nodes[-1]['id'] != profile['id']:
        raise RuntimeError(fail)
    encoded = json.dumps(['routervpn-prefix-protection-members-v1', rows], separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest(), policy, lan


def _darwin_candidate_prefix_profile(profile, runtime_id, control_id, capture, store=None):
    fail = 'macOS candidate prefix baseline differs from the captured saved Router protection policy'
    if (runtime_id != control_id or runtime_id != capture['profile_id'] or profile.get('id') != control_id
            or profile.get('node_kind', '') not in ('', 'router-vpn') or profile.get('external') is not None):
        raise RuntimeError(fail)
    if capture['schema'] == 2:
        # Only exact retained legacy readback/cleanup/reassert can reach this
        # branch; a new owner must supply the sealed full-member binding.
        if (_linux.policy_value(profile) != capture['policy']
                or profile.get('home_lan_access', False) is not capture['home_lan_access']):
            raise RuntimeError(fail)
    else:
        digest, policy, lan = _darwin_candidate_prefix_members(store, profile)
        if digest != capture['members_sha256'] or policy != capture['policy'] or lan is not capture['home_lan_access']:
            raise RuntimeError(fail)
    if any(os.environ.get(key) for key in ('HOMEVPN_ENDPOINT', 'HOMEVPN_NATIVE_ENDPOINTS_JSON',
            'HOMEVPN_NATIVE_EGRESS_JSON', 'HOMEVPN_TOR_PHYSICAL_BROKER', 'HOMEVPN_TOR_SESSION',
            'HOMEVPN_TOR_SOURCE_SHA256', 'HOMEVPN_EXTERNAL_SESSION')):
        raise RuntimeError('macOS candidate prefix baseline mixed another native protection family')


def _darwin_candidate_prefix_selected(root, capture):
    store = _linux.read_store(root)
    if store.get('selected_id') != capture['profile_id']:
        raise RuntimeError('macOS candidate prefix baseline changed its original selected Router control')
    profile = _linux.required_profile(store, capture['profile_id'], 'candidate prefix policy/control')
    _darwin_candidate_prefix_profile(profile, capture['profile_id'], capture['profile_id'], capture, store)


def _darwin_candidate_prefix_state(state, capture):
    if (not state or state.get('platform') != 'darwin'
            or state.get('native_socket_family') != 'node-candidate-prefix-v1'
            or state.get('native_socket_broker') is not True
            or state.get('native_candidate_prefix_capture') != capture
            or 'native_external_capture' in state or 'native_node_chain_capture' in state or 'native_node_capture' in state
            or state.get('profile_id') != capture['profile_id']
            or state.get('policy_profile_id') != capture['profile_id']
            or state.get('policy') != capture['policy']
            or state.get('home_lan_access') is not capture['home_lan_access']
            or state.get('endpoint') != '' or state.get('endpoint_ips') != []
            or 'native_egress' in state):
        raise RuntimeError('macOS candidate prefix cleanup belongs to another retained owner')
    _darwin._baseline.retained(state)
    return state


def _darwin_candidate_prefix_receipt(value, capture):
    _darwin._baseline._fields(value, ('schema', 'capture', 'phase', 'pf_token', 'baseline'))
    if (type(value['schema']) is not int or value['schema'] != capture['schema']
            or _darwin_candidate_prefix_capture(value['capture']) != capture
            or value['phase'] not in ('active', 'held', 'retired')):
        raise RuntimeError('macOS candidate prefix baseline receipt belongs to another original capture')
    _darwin._baseline.token(value['pf_token'])
    proof = _darwin._baseline._proof(value['baseline'])
    if proof['present'] is not (value['phase'] == 'active' or value['phase'] == 'held' and capture['policy'] != 'off' or capture['policy'] == 'always'):
        raise RuntimeError('macOS candidate prefix receipt changed its selected retirement policy')
    return value


def _darwin_candidate_prefix_result(capture, phase, token, baseline):
    return _darwin_candidate_prefix_receipt(dict(schema=capture['schema'], capture=capture, phase=phase,
                                          pf_token=token, baseline=baseline), capture)


def _darwin_candidate_prefix_live_receipt(state, capture):
    _darwin_candidate_prefix_state(state, capture)
    value = state[_darwin._baseline.STATE_KEY]
    request = value['request']
    if (value['complete'] is not True or state.get('darwin_transition_pending') is True
            or request['session_id'] != capture['session_id']
            or request['source_sha256'] != capture['source_sha256']
            or request['home_lan_access'] is not capture['home_lan_access']
            or request.get('isolated_only', False) is not (capture['policy'] == 'off')
            or not _darwin._baseline.status(state)):
        raise RuntimeError('macOS candidate prefix baseline lacks its current native session proof')
    return _darwin_candidate_prefix_result(capture, 'active', state['pf_token'], value['target'])


def darwin_candidate_prefix(action, value):
    """A distinct selected-prefix capture on the original guarded PF journal.

    No source can request a command, rule, namespace, endpoint or UID exception.
    Private prefix/source proof and joined process retirement remain separate.
    """
    if action not in ('apply', 'current', 'retire', 'release') or _dry_run():
        raise RuntimeError('macOS candidate prefix baseline requires its actual native transaction')
    _darwin._baseline._fields(value, ('capture', 'expected'))
    capture = _darwin_candidate_prefix_capture(value['capture'])
    expected = value['expected']
    if expected is not None:
        expected = _darwin_candidate_prefix_receipt(expected, capture)
    root = _linux.root_dir()
    state = _linux.read_state(root)
    if action == 'apply':
        if expected is not None:
            raise RuntimeError('macOS candidate prefix application cannot reuse a prior receipt')
        if capture['schema'] == 2 and state.get('native_candidate_prefix_capture') != capture:
            raise RuntimeError('legacy macOS prefix capture cannot authorize a new baseline')
        _darwin_candidate_prefix_selected(root, capture)
        os.environ['HOMEVPN_PROFILE_ID'] = capture['profile_id']
        os.environ['HOMEVPN_POLICY_PROFILE_ID'] = capture['profile_id']
        if state.get('native_candidate_prefix_capture') == capture:
            result = _darwin_candidate_prefix_live_receipt(state, capture)
        else:
            darwin_apply(spawn_watch=False, candidate_prefix_capture=capture)
            result = _darwin_candidate_prefix_live_receipt(_linux.read_state(root), capture)
    elif action == 'current':
        result = _darwin_candidate_prefix_live_receipt(state, capture)
        if expected is None or result != expected:
            raise RuntimeError('macOS candidate prefix readback changed its original baseline receipt')
    elif not state:
        if (expected is None or capture['policy'] not in ('off', 'on-connect')
                or action != 'release' and not (action == 'retire' and capture['policy'] == 'off')
                or _darwin.owned_namespace_present(_darwin.OWNED_PF_ANCHOR)
                or _darwin._baseline.reference(expected['pf_token'])):
            raise RuntimeError('macOS candidate prefix removal has no exact retired reference proof')
        result = _darwin_candidate_prefix_result(capture, 'held' if action == 'retire' else 'retired', expected['pf_token'],
                                            {'present': False, 'rules_sha256': ''})
    else:
        _darwin_candidate_prefix_state(state, capture)
        token = _darwin._baseline.token(state.get('pf_token'))
        if expected is not None and token != expected['pf_token']:
            raise RuntimeError('macOS candidate prefix cleanup changed its original PF reference')
        # Existing retirement checks every live guardian generation, grant,
        # table and unreferenced child before settling the original baseline.
        darwin_release(False, retain_protection=action == 'retire')
        after = _linux.read_state(root)
        if action == 'retire' and capture['policy'] != 'off' or capture['policy'] == 'always':
            _darwin_candidate_prefix_state(after, capture)
            journal = after[_darwin._baseline.STATE_KEY]
            request = journal['request']
            if (request['session_id'] != '' or request['source_sha256'] != ''
                    or journal['complete'] is not True or after.get('darwin_transition_pending') is True
                    or after.get('pf_token') != token or not _darwin._baseline.status(after)):
                raise RuntimeError('macOS candidate prefix retirement lost its exact empty native baseline')
            proof = journal['target']
        else:
            if (after or _darwin.owned_namespace_present(_darwin.OWNED_PF_ANCHOR)
                    or _darwin._baseline.reference(token)):
                raise RuntimeError('macOS candidate prefix retirement retained its original native reference')
            proof = {'present': False, 'rules_sha256': ''}
        result = _darwin_candidate_prefix_result(capture, 'held' if action == 'retire' else 'retired', token, proof)
    return result


@contextlib.contextmanager
def _darwin_external_authority():
    # Fixed inherited descriptors, never caller-selected paths or PID labels.
    # Reasserting flock on their open descriptions proves the exclusive
    # controller lock was inherited instead of independently reopened.
    for descriptor, path, operation in ((3, '/opt/router-vpn-client.install.lock', fcntl.LOCK_SH),
                                         (4, '/opt/router-vpn-client.controller.lock', fcntl.LOCK_EX)):
        os.set_inheritable(descriptor, False)
        opened, named = os.fstat(descriptor), os.lstat(path)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0
                or opened.st_gid != 0 or stat.S_IMODE(opened.st_mode) != 0o600
                or not os.path.samestat(opened, named)):
            raise RuntimeError('macOS external helper lost its inherited controller lock')
        fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
    with _darwin.pf_process_authority((3, 4)):
        yield


def darwin_external_input():
    maximum = 2*(512+192*96)+8192
    raw = sys.stdin.buffer.read(maximum+1)
    if not raw or len(raw) > maximum:
        raise RuntimeError('macOS external baseline request exceeds its private bound')
    value = json.loads(raw.decode('ascii'), object_pairs_hook=_darwin._baseline._strict_object)
    if len(raw) > 8192:
        capture = value.get('capture') if type(value) is dict else None
        capture = _darwin_node_chain_capture(capture)
        rows = _darwin_node_chain_rows(capture)
        if len(rows) <= 8 or len(raw) > 2*max(4096, 512+192*len(rows))+8192:
            raise RuntimeError('macOS ordered baseline request exceeds its original inventory bound')
    return value


def darwin_status() -> int:
    root = _linux.root_dir()
    state = _linux.read_state(root)
    active = bool(state and state.get("platform") == "darwin" and _darwin.status_darwin(state, dry_run=_dry_run()))
    import json
    print(json.dumps({"active": active, **state}, sort_keys=True))
    return 0 if active else 1


def main() -> int:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if sys.platform != "darwin" and os.environ.get("HOMEVPN_KILLSWITCH_DARWIN_TEST") != "1":
        return _linux.main()
    try:
        if len(sys.argv) == 3 and sys.argv[1] in ('external-native', 'ordered-native', 'candidate-prefix-native', 'paired-node-native'):
            if os.getuid() != 0 or os.geteuid() != 0 or _linux.root_dir() != _darwin._baseline.ROOT:
                raise RuntimeError('macOS external baseline requires its fixed privileged controller')
            with _darwin_external_authority():
                with _darwin_action_guard(_linux.root_dir()):
                    dispatch = {'external-native': darwin_external, 'ordered-native': darwin_node_chain,
                                'candidate-prefix-native': darwin_candidate_prefix, 'paired-node-native': darwin_node}[sys.argv[1]]
                    result = dispatch(sys.argv[2], darwin_external_input())
            print(json.dumps(result, separators=(',', ':')))
            return 0
        if len(sys.argv) == 5 and sys.argv[1] == 'reassert-install':
            with _darwin._baseline.CAPABILITY.borrow(int(sys.argv[2]), sys.argv[3], int(sys.argv[4])):
                with _darwin_action_guard(_linux.root_dir()):
                    return darwin_reassert()
        if len(sys.argv) == 4 and sys.argv[1] == 'watch':
            return darwin_watch(sys.argv[2], int(sys.argv[3]))
        if action == "watch": return darwin_watch()
        if action == "status": return darwin_status()
        if action in ('apply', 'release', 'force-off', 'reassert'):
            with _darwin_action_guard(_linux.root_dir()):
                if action == "apply": return darwin_apply()
                if action == "release": return darwin_release(False)
                if action == "force-off": return darwin_release(True)
                if action == "reassert": return darwin_reassert()
        print("usage: kill-switch-platform.py apply|watch|release|force-off|reassert|status", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"kill switch error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
