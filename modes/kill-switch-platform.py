#!/usr/bin/env python3
"""Platform dispatcher for Router VPN Unix kill-switch policy.

Linux remains owned by the established kill-switch.py nftables implementation.
Darwin uses darwin_kill_switch.py and a fail-closed watcher: pre-connect rules
allow only the selected literal node endpoint (plus optional LAN/link traffic),
then only a newly-created utun that owns a public route is promoted.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import signal
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


def _dry_run() -> bool:
    return os.environ.get("HOMEVPN_KILLSWITCH_DRY_RUN") == "1"


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


def _stop_watcher(state: dict[str, Any]) -> None:
    try:
        pid = int(state.get("darwin_watcher_pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    if pid > 1 and pid != os.getpid():
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass


def _spawn_watcher() -> int:
    if _dry_run():
        return 0
    proc = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "watch"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    return int(proc.pid)


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
            _stop_watcher(previous)
            _darwin.remove_darwin(previous, dry_run=_dry_run())
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
    _stop_watcher(previous)
    socket_capture = ((os.environ['HOMEVPN_TOR_SESSION'], os.environ['HOMEVPN_TOR_SOURCE_SHA256'])
                      if socket_broker and retained_state is None else None)
    state = _darwin_state_base(runtime_id, control_id, endpoint, endpoint_ips, lan, policy)
    if native_egress is not None:
        state["native_egress"] = native_egress
    if socket_broker:
        state['native_socket_broker'] = True
    state["darwin_watcher_pid"] = 0
    def retain_state(extra):
        _linux.write_state(root, {**state, **extra, "darwin_transition_pending": True})
    extra = _darwin.apply_darwin(endpoint_ips, lan, previous, refresh=False, dry_run=_dry_run(), native_egress=native_egress,
                               socket_broker=socket_broker, socket_capture=socket_capture, retain_state=retain_state)
    state.update(extra)
    _linux.write_state(root, state)
    if spawn_watch and not socket_broker:
        state["darwin_watcher_pid"] = _spawn_watcher()
        _linux.write_state(root, state)
    print(f"strict macOS kill switch {policy} applied pre-connect for {endpoint}", file=sys.stderr)
    return 0


def darwin_watch() -> int:
    root = _linux.root_dir()
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        state = _linux.read_state(root)
        if not state or state.get("platform") != "darwin":
            return 0
        if state.get('native_socket_broker') is True:
            # Only the native guardian can admit the actual retained utun FD.
            return 0
        try:
            endpoint_ips = [_linux.ipaddress.ip_address(x) for x in state.get("endpoint_ips", [])]
            retained = _linux.retained_native_policy(state, str(state.get("endpoint") or ""))
            native_egress = None
            if retained is not None:
                endpoint_ips, native_egress = retained
            extra = _darwin.apply_darwin(
                endpoint_ips,
                bool(state.get("home_lan_access", False)),
                state,
                refresh=True,
                dry_run=_dry_run(),
                native_egress=native_egress,
            )
        except Exception:
            time.sleep(0.2)
            continue
        state.update(extra)
        state["darwin_watcher_pid"] = 0
        _linux.write_state(root, state)
        print("strict macOS kill switch promoted proven Router VPN utun", file=sys.stderr)
        return 0
    # The pre-connect anchor remains installed, so timeout is fail-closed.
    state = _linux.read_state(root)
    if state:
        state["darwin_watcher_pid"] = 0
        _linux.write_state(root, state)
    return 1


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
            _darwin._clear_anchor(check=True)
            _darwin._clear_anchor(check=True, anchor=_darwin.OWNED_PF_ANCHOR)
            for anchor in (_darwin.PF_ANCHOR, _darwin.OWNED_PF_ANCHOR):
                if _darwin.run_pf(['-a', anchor, '-s', 'rules']).stdout.strip():
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
    _stop_watcher(state)
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
            retain_state=lambda extra: _linux.write_state(root, {**state, **extra, 'darwin_watcher_pid': 0, 'darwin_transition_pending': True}),
        )
        state.pop('darwin_previous_pf_anchor', None)
        state.pop('darwin_transition_pending', None)
        state.update(extra)
        state["darwin_watcher_pid"] = 0
        _linux.write_state(root, state)
        print("strict macOS kill switch remains active (always policy)", file=sys.stderr)
        return 0
    _darwin.remove_darwin(state, dry_run=_dry_run())
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
        if action == "apply": return darwin_apply()
        if action == "watch": return darwin_watch()
        if action == "release": return darwin_release(False)
        if action == "force-off": return darwin_release(True)
        if action == "reassert": return darwin_reassert()
        if action == "status": return darwin_status()
        print("usage: kill-switch-platform.py apply|watch|release|force-off|reassert|status", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"kill switch error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
