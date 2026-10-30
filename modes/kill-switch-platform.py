#!/usr/bin/env python3
"""Platform dispatcher for Router VPN Unix kill-switch policy.

Linux remains owned by the established kill-switch.py nftables implementation.
Darwin uses darwin_kill_switch.py and a fail-closed watcher: pre-connect rules
allow only the selected literal node endpoint (plus optional LAN/link traffic),
then only a newly-created utun that owns a public route is promoted.
"""
from __future__ import annotations

import importlib.util
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


def darwin_apply(*, spawn_watch: bool = True, retained_state=None) -> int:
    root = _linux.root_dir()
    store = _linux.read_store(root)
    runtime_id = _linux.safe_profile_id()
    control_id = _linux.policy_profile_id(runtime_id)
    runtime_profile = _linux.required_profile(store, runtime_id, "runtime/entry")
    control_profile = _linux.required_profile(store, control_id, "policy/control")
    policy = _linux.policy_value(control_profile)
    previous = _linux.read_state(root)

    if policy == "off":
        if previous and previous.get("platform") == "darwin":
            _require_watcher_retired(previous)
            _darwin.remove_darwin(previous, dry_run=_dry_run(), retain_state=_retained_removal(root, previous))
            _linux.remove_state(root)
        print("kill switch off", file=sys.stderr)
        return 0

    endpoint = os.environ.get("HOMEVPN_ENDPOINT") or str(runtime_profile.get("endpoint") or "")
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
    _require_watcher_retired(previous)
    socket_capture = ((os.environ['HOMEVPN_TOR_SESSION'], os.environ['HOMEVPN_TOR_SOURCE_SHA256'])
                      if socket_broker and retained_state is None else None)
    state = _darwin_state_base(runtime_id, control_id, endpoint, endpoint_ips, lan, policy)
    if native_egress is not None:
        state["native_egress"] = native_egress
    if socket_broker:
        state['native_socket_broker'] = True
    state["darwin_watcher_pid"] = 0
    def retain_state(extra):
        _write_state(root, {**state, **extra, "darwin_transition_pending": True})
    extra = _darwin.apply_darwin(endpoint_ips, lan, previous, refresh=False, dry_run=_dry_run(), native_egress=native_egress,
                               socket_broker=socket_broker, socket_capture=socket_capture, retain_state=retain_state)
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


def darwin_release(force: bool = False) -> int:
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
    if not force and state.get("policy") == "always":
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
    return darwin_apply(spawn_watch=False, retained_state=state)


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
        if len(sys.argv) == 4 and sys.argv[1] == 'watch':
            return darwin_watch(sys.argv[2], int(sys.argv[3]))
        if action == "watch": return darwin_watch()
        if action == "status": return darwin_status()
        if action in ('apply', 'release', 'force-off', 'reassert'):
            with _darwin._baseline.state_guard(_linux.root_dir()):
                with _watcher_state_guard(_linux.root_dir()):
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
