#!/usr/bin/env python3
"""Post-connect, fail-closed Router VPN MTU optimizer.

The pre-connect mtu-policy.py finds a safe PMTU ceiling. This helper is an
explicit post-connect optimization pass: it tests several safe live tunnel MTUs
against the private Router VPN node, measures bidirectional packet success, RTT
and aggregate transfer rate through the existing bounded DAITA test sink, then
remembers the best candidate for the same network/path context.

It never opens a benchmark listener, never uses a public speed-test service,
and refuses non-private proof/benchmark destinations. On failure it restores
the interface MTU that was active when optimization began.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from typing import Any

from network_context import generated_profile_fingerprint, network_fingerprint
from private_profile_store import private_root, read_profile_store
from profile_id import validate_profile_id

MIN_OPT_MTU = 1200
MAX_OPT_MTU = 1500
STEP = 20
MAX_CANDIDATES = 16
RTT_SAMPLES = 6
BURST_PACKETS = 32
BURST_ROUNDS = 3
SOCKET_TIMEOUT = 0.75
PROOF_KIND = "router-vpn-private-agent-v1"


def root_dir() -> Path:
    return private_root(os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client"))


def load_profile(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    store = read_profile_store(root)
    selected = os.environ.get("HOMEVPN_PROFILE_ID", "").strip() or str(store.get("selected_id") or "").strip()
    try:
        selected = validate_profile_id(selected, default="")
    except ValueError as exc:
        raise RuntimeError("MTU optimizer selected profile id is invalid") from exc
    if not selected:
        raise RuntimeError("MTU optimizer requires one selected Router VPN node")
    profiles = [p for p in store.get("profiles", []) if isinstance(p, dict)]
    profile = next((p for p in profiles if str(p.get("id") or "") == selected), None)
    if profile is None:
        raise RuntimeError(f"MTU optimizer selected node {selected!r} is missing")
    return store, profile


def private_ip(value: str) -> ipaddress._BaseAddress:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError as exc:
        raise RuntimeError("MTU optimizer requires a literal private tunnel address") from exc
    if not (ip.is_private or ip.is_link_local or ip.is_loopback):
        raise RuntimeError("MTU optimizer refuses a public benchmark destination")
    return ip


def validate_proof_url(raw: str) -> str:
    from urllib.parse import urlsplit
    parsed = urlsplit(raw)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError("MTU optimizer proof URL must be private literal HTTP")
    private_ip(parsed.hostname)
    if parsed.path not in {"", "/health"}:
        raise RuntimeError("MTU optimizer proof URL must use the Router VPN /health endpoint")
    return raw


def prove_node(profile: dict[str, Any]) -> None:
    expected = str(profile.get("node_proof_id") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError("selected node has no valid exact proof id")
    url = validate_proof_url(str(profile.get("path_probe_url") or "http://10.77.0.1:8787/health"))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"Accept": "application/json", "Cache-Control": "no-store"})
    with opener.open(req, timeout=3.0) as response:
        raw = response.read(16 * 1024 + 1)
        if response.status != 200 or len(raw) > 16 * 1024:
            raise RuntimeError("selected-node path proof failed during MTU optimization")
    body = json.loads(raw.decode("utf-8"))
    if not isinstance(body, dict) or body.get("ok") is not True or body.get("node_id") != expected or body.get("proof") != PROOF_KIND:
        raise RuntimeError("selected-node identity changed during MTU optimization")


def enforce_kill_switch() -> None:
    helper = Path(__file__).with_name("kill-switch.py")
    proc = subprocess.run([sys.executable, str(helper), "apply"], env=mtu_kill_switch_environment(), text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError("strict kill switch could not be enforced before MTU optimization" + (": " + detail if detail else ""))


def route_interface(host: str) -> str:
    override = os.environ.get("HOMEVPN_TUN_IFACE", "").strip() or os.environ.get("HOMEVPN_TUN_ALIAS", "").strip()
    if override:
        return override
    system = platform.system().lower()
    if system == "linux":
        out = subprocess.check_output(["ip", "route", "get", host], text=True, timeout=3)
        match = re.search(r"\bdev\s+(\S+)", out)
        if match:
            return match.group(1)
    elif system == "darwin":
        out = subprocess.check_output(["route", "-n", "get", host], text=True, timeout=3)
        match = re.search(r"^\s*interface:\s*(\S+)", out, re.M)
        if match:
            return match.group(1)
    elif system == "windows":
        escaped = host.replace("'", "''")
        cmd = f"$r=Find-NetRoute -RemoteIPAddress '{escaped}'; if($r){{$r.InterfaceAlias | Select-Object -First 1}}"
        out = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd], text=True, timeout=6).strip()
        if out:
            return out.splitlines()[0].strip()
    raise RuntimeError("could not identify the active Router VPN tunnel interface")


def interface_mtu(alias: str, family: int) -> int:
    return owner_state(alias, family)["mtu"]


MTU_GRAPH_FIELDS = ("HOMEVPN_MTU_GRAPH_TOKEN", "HOMEVPN_MTU_GRAPH_SCOPE", "HOMEVPN_MTU_CONTROL_PROFILE_ID",
                    "HOMEVPN_MTU_PHYSICAL_ENTRY_ID", "HOMEVPN_MTU_PHYSICAL_ENTRY_ENDPOINT")


def mtu_graph_context() -> dict[str, str] | None:
    present = [name in os.environ for name in MTU_GRAPH_FIELDS]
    if not any(present):
        return None
    if not all(present):
        raise RuntimeError("incomplete captured MTU graph identity")
    values = {name: os.environ[name] for name in MTU_GRAPH_FIELDS}
    token, scope, control, entry, endpoint = (values[name] for name in MTU_GRAPH_FIELDS)
    if not re.fullmatch(r"[0-9a-f]{64}", token) or scope != "multihop-exit-path":
        raise RuntimeError("invalid captured MTU graph identity")
    try:
        if validate_profile_id(control, default="") != control or validate_profile_id(entry, default="") != entry:
            raise ValueError("noncanonical identity")
        physical = ipaddress.ip_address(endpoint)
        if "%" in endpoint or str(physical) != endpoint or entry == os.environ.get("HOMEVPN_PROFILE_ID", ""):
            raise ValueError("invalid physical entry")
    except ValueError as exc:
        raise RuntimeError("invalid captured MTU graph entry or control identity") from exc
    return {"token": token, "scope": scope, "control_id": control, "entry_id": entry, "endpoint": endpoint}


def mtu_kill_switch_environment() -> dict[str, str]:
    graph = mtu_graph_context()
    store, profile = load_profile(root_dir())
    runtime_id = str(profile.get("id") or "")
    control_id = runtime_id
    endpoint = str(profile.get("endpoint") or "")
    if graph is not None:
        runtime_id, control_id, endpoint = graph["entry_id"], graph["control_id"], graph["endpoint"]
        profiles = [item for item in store.get("profiles", []) if isinstance(item, dict)]
        entry = next((item for item in profiles if item.get("id") == runtime_id), None)
        control = next((item for item in profiles if item.get("id") == control_id), None)
        try:
            same_entry = entry is not None and str(ipaddress.ip_address(str(entry.get("endpoint") or "").strip("[]"))) == endpoint
        except ValueError:
            same_entry = False
        if control is None or not same_entry:
            raise RuntimeError("captured MTU graph guard profiles or physical entry changed")
    # Firewall reassertion uses the physical entry and selected control policy.
    # Exit proof/benchmark keeps its own HOMEVPN_PROFILE_ID in this process.
    # Neither a stale external egress exception nor a mutation capability is
    # inherited by the firewall helper.
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(("HOMEVPN_MTU_", "HOMEVPN_NATIVE_", "HOMEVPN_NODE_"))
                   and name not in {"HOMEVPN_EXTERNAL_SESSION", "HOMEVPN_PROFILE_ID", "HOMEVPN_POLICY_PROFILE_ID", "HOMEVPN_ENDPOINT"}}
    environment.update({"HOMEVPN_PROFILE_ID": runtime_id, "HOMEVPN_POLICY_PROFILE_ID": control_id, "HOMEVPN_ENDPOINT": endpoint})
    return environment


def minimum_mtu(*, captured: bool = False) -> int:
    raw = os.environ.get("HOMEVPN_MTU_MINIMUM", "")
    if not raw and not captured:
        return 576  # Algorithm-only self-tests have no runtime capability.
    if not re.fullmatch(r"[0-9]{3,4}", raw) or not 576 <= int(raw) <= 1280:
        raise RuntimeError("invalid captured MTU minimum")
    return int(raw)


def owner_capability() -> tuple[str, str]:
    # The controller keeps the actual native TUN/sysfs descriptor/Windows LUID.
    # This subprocess receives only the capability for that captured operation;
    # an interface alias is never sufficient authority for a write or rollback.
    from urllib.parse import urlsplit
    token = os.environ.get("HOMEVPN_MTU_OWNER_TOKEN", "")
    endpoint = os.environ.get("HOMEVPN_MTU_OWNER_URL", "")
    helper = os.environ.get("HOMEVPN_MTU_OWNER_HELPER", "")
    mtu_graph_context()
    minimum_mtu(captured=True)
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise RuntimeError("missing captured MTU operation capability")
    try:
        parsed = urlsplit(endpoint)
        valid_url = (parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
                     and parsed.port is not None and 1 <= parsed.port <= 65535
                     and parsed.netloc == f"127.0.0.1:{parsed.port}"
                     and parsed.path == "/mtu" and not parsed.query and not parsed.fragment)
    except ValueError:
        valid_url = False
    path = Path(helper)
    if (not valid_url or not path.is_absolute() or path.is_symlink()
            or not path.is_file() or not os.access(path, os.X_OK)):
        raise RuntimeError("invalid captured MTU helper or operation endpoint")
    return helper, token


def owner_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate MTU owner reply field")
        result[key] = value
    return result


def owner_state(alias: str, family: int, mtu: int | None = None) -> dict[str, Any]:
    helper, token = owner_capability()
    if not alias or family not in {4, 6} or type(family) is not int:
        raise RuntimeError("invalid captured MTU interface request")
    arguments = [helper, "--mtu-owner-read"]
    if mtu is not None:
        if type(mtu) is not int or not minimum_mtu(captured=True) <= mtu <= 9000:
            raise RuntimeError("invalid captured live MTU")
        arguments = [helper, "--mtu-owner-set", str(mtu)]
    try:
        proc = subprocess.run(arguments, capture_output=True, timeout=18, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("captured MTU helper is unavailable") from exc
    if proc.returncode != 0 or proc.stderr or not 0 < len(proc.stdout) <= 4096:
        raise RuntimeError("captured MTU operation was rejected")
    try:
        reply = json.loads(proc.stdout.decode("utf-8"), object_pairs_hook=owner_json_object)
    except (UnicodeError, ValueError) as exc:
        raise RuntimeError("invalid captured MTU owner reply") from exc
    if (not isinstance(reply, dict)
            or set(reply) != {"owner_token", "interface", "family", "index", "mtu", "identity"}
            or reply["owner_token"] != token or reply["interface"] != alias
            or type(reply["family"]) is not int or reply["family"] != family
            or type(reply["index"]) is not int or not 0 < reply["index"] <= 0x7fffffff
            or type(reply["mtu"]) is not int or not minimum_mtu(captured=True) <= reply["mtu"] <= 9000
            or not isinstance(reply["identity"], str) or not 0 < len(reply["identity"]) <= 256
            or any(character in reply["identity"] for character in "\x00\r\n")
            or mtu is not None and reply["mtu"] != mtu):
        raise RuntimeError("captured MTU owner or exact kernel readback changed")
    # The native engine may replace its own TUN reader while changing MTU. Its
    # new index/identity is accepted only through the same captured capability.
    return reply


def set_interface_mtu(alias: str, family: int, mtu: int) -> None:
    # Validate the caller's alias/family before a set, since the helper itself
    # deliberately addresses only its captured owner, never a supplied alias.
    owner_state(alias, family)
    owner_state(alias, family, mtu)


def candidate_mtus(ceiling: int) -> list[int]:
    minimum = max(MIN_OPT_MTU, minimum_mtu())
    ceiling = max(minimum, min(MAX_OPT_MTU, int(ceiling)))
    floor = max(minimum, ceiling - STEP * (MAX_CANDIDATES - 1))
    values = list(range(floor, ceiling + 1, STEP))
    for preferred in (1280, 1320, 1360, 1380, 1400, 1420, 1440, 1460, 1480, 1500):
        if floor <= preferred <= ceiling:
            values.append(preferred)
    values = sorted(set(values), reverse=True)
    return values[:MAX_CANDIDATES]


def packet_payload_size(mtu: int, family: int) -> int:
    overhead = 48 if family == 6 else 28
    return max(64, mtu - overhead)


def bench_candidate(host: str, port: int, family: int, mtu: int) -> dict[str, Any]:
    fake = os.environ.get("HOMEVPN_MTU_BENCH_FAKE", "").strip()
    if fake:
        table = json.loads(fake)
        row = table.get(str(mtu))
        if not isinstance(row, dict):
            return {"mtu": mtu, "working": False, "success_ratio": 0.0, "mbps": 0.0, "median_rtt_ms": 9999.0}
        return {
            "mtu": mtu,
            "working": bool(row.get("working", True)),
            "success_ratio": float(row.get("success_ratio", 1.0)),
            "mbps": float(row.get("mbps", 0.0)),
            "median_rtt_ms": float(row.get("median_rtt_ms", 0.0)),
        }

    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    destination: tuple[Any, ...] = (host, port, 0, 0) if family == 6 else (host, port)
    payload = os.urandom(packet_payload_size(mtu, family))
    rtts: list[float] = []
    throughputs: list[float] = []
    replies = 0
    sent = 0

    with socket.socket(af, socket.SOCK_DGRAM) as sock:
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect(destination)
        for _ in range(RTT_SAMPLES):
            started = time.monotonic()
            try:
                sock.send(payload)
                sent += 1
                data = sock.recv(4096)
                if data:
                    replies += 1
                    rtts.append((time.monotonic() - started) * 1000.0)
            except (socket.timeout, OSError):
                continue

        for _ in range(BURST_ROUNDS):
            started = time.monotonic()
            round_sent = 0
            round_replies = 0
            recv_bytes = 0
            for _n in range(BURST_PACKETS):
                try:
                    sock.send(payload)
                    round_sent += 1
                    sent += 1
                except OSError:
                    break
            deadline = time.monotonic() + SOCKET_TIMEOUT
            while round_replies < round_sent and time.monotonic() < deadline:
                sock.settimeout(max(0.02, deadline - time.monotonic()))
                try:
                    data = sock.recv(4096)
                except (socket.timeout, OSError):
                    break
                if data:
                    round_replies += 1
                    replies += 1
                    recv_bytes += len(data)
            elapsed = max(0.001, time.monotonic() - started)
            if round_sent:
                bits = (round_sent * len(payload) + recv_bytes) * 8
                throughputs.append(bits / elapsed / 1_000_000.0)

    ratio = replies / sent if sent else 0.0
    median_rtt = statistics.median(rtts) if rtts else 9999.0
    mbps = statistics.median(throughputs) if throughputs else 0.0
    return {
        "mtu": mtu,
        "working": ratio >= 0.90 and len(rtts) >= max(3, RTT_SAMPLES // 2) and mbps > 0,
        "success_ratio": round(ratio, 4),
        "mbps": round(mbps, 3),
        "median_rtt_ms": round(median_rtt, 3),
    }


def pick_winner(results: list[dict[str, Any]]) -> dict[str, Any]:
    good = [r for r in results if r.get("working") and float(r.get("success_ratio", 0)) >= 0.90]
    if not good:
        raise RuntimeError("no MTU candidate passed the private tunnel benchmark")
    fastest = max(float(r.get("mbps", 0)) for r in good)
    near = [r for r in good if float(r.get("mbps", 0)) >= fastest * 0.97]
    # Within 3% throughput, prefer the lower RTT; within 0.25 ms, prefer the
    # larger MTU to avoid choosing a smaller packet size for noise alone.
    best_rtt = min(float(r.get("median_rtt_ms", 9999)) for r in near)
    near_rtt = [r for r in near if float(r.get("median_rtt_ms", 9999)) <= best_rtt + 0.25]
    return max(near_rtt, key=lambda r: int(r["mtu"]))


def path_context(profile: dict[str, Any], root: Path | None = None) -> tuple[str, str, str]:
    root = root or root_dir()
    graph = mtu_graph_context()
    endpoint = graph["endpoint"] if graph is not None else str(profile.get("endpoint") or os.environ.get("HOMEVPN_ENDPOINT", "")).strip()
    mode = os.environ.get("HOMEVPN_MODE", "").strip()
    profile_id = str(profile.get("id") or os.environ.get("HOMEVPN_PROFILE_ID", "")).strip()
    family = os.environ.get("HOMEVPN_IP_FAMILY", "").strip().lower()
    if not family:
        try:
            family = str(ipaddress.ip_address(endpoint.strip("[]")).version)
        except ValueError:
            family = "unknown"
    network = network_fingerprint(endpoint)
    try:
        generated = generated_profile_fingerprint(root, profile_id, mode)
    except RuntimeError:
        generated = hashlib.sha256(f"unavailable|{profile_id}|{mode}".encode("utf-8")).hexdigest()[:24]
    graph_identity = "" if graph is None else "|".join(graph[name] for name in ("scope", "token", "control_id", "entry_id", "endpoint"))
    if graph is not None:
        generated = hashlib.sha256(("mtu-owned-graph-v1\0" + generated + "\0" + graph_identity).encode("utf-8")).hexdigest()[:24]
    parts = [
        endpoint.lower(),
        mode.lower(),
        os.environ.get("HOMEVPN_LOGICAL_MODE", "").strip().lower(),
        os.environ.get("HOMEVPN_BASE", "").strip().lower(),
        family,
        profile_id.lower(),
        network,
        generated,
    ]
    if graph is not None:
        parts.append(graph_identity)
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24], network, generated


def path_context_key(profile: dict[str, Any]) -> str:
    return path_context(profile)[0]


def persist(root: Path, store: dict[str, Any], profile: dict[str, Any], winner: dict[str, Any], results: list[dict[str, Any]]) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    key, network, generated = path_context(profile, root)
    profile["effective_mtu"] = int(winner["mtu"])
    profile["effective_mtu_source"] = "auto-throughput"
    profile["effective_mtu_path_key"] = key
    profile["effective_mtu_network_fingerprint"] = network
    profile["effective_mtu_profile_fingerprint"] = generated
    profile["effective_mtu_tested_at"] = now
    profile["effective_mtu_mbps"] = float(winner["mbps"])
    profile["effective_mtu_median_rtt_ms"] = float(winner["median_rtt_ms"])
    profile["effective_mtu_success_ratio"] = float(winner["success_ratio"])
    profile["effective_mtu_candidates"] = results
    path = root / "routers.json"
    fd, tmp = tempfile.mkstemp(prefix="routers.json.mtu.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(store, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def measurement_context(profile: dict[str, Any], root: Path) -> dict[str, str]:
    key, network, generated = path_context(profile, root)
    return {"path_key": key, "network_fingerprint": network, "profile_fingerprint": generated}


def optimize(*, defer_adopt: bool = False) -> dict[str, Any]:
    root = root_dir()
    store, profile = load_profile(root)
    policy = str(profile.get("mtu_policy") or "default").strip().lower()
    if policy != "auto" and os.environ.get("HOMEVPN_MTU_OPTIMIZE_FORCE", "").lower() not in {"1", "true", "yes"}:
        raise RuntimeError("set this node MTU policy to Auto before running Optimize MTU")
    if os.environ.get("HOMEVPN_JUMBO", "").lower() == "true":
        raise RuntimeError("Jumbo is explicit; disable Jumbo before automatic MTU optimization")

    prove_node(profile)
    enforce_kill_switch()
    host = str(profile.get("daita_host") or "10.77.0.1").strip().strip("[]")
    ip = private_ip(host)
    family = ip.version
    port = int(profile.get("daita_port") or 45999)
    if not 1 <= port <= 65535:
        raise RuntimeError("invalid private MTU benchmark port")
    alias = route_interface(host)
    original = interface_mtu(alias, family)
    ceiling = int(profile.get("effective_mtu") or 0)
    if not max(MIN_OPT_MTU, minimum_mtu(captured=True)) <= ceiling <= MAX_OPT_MTU:
        ceiling = min(MAX_OPT_MTU, original)
    candidates = candidate_mtus(ceiling)
    results: list[dict[str, Any]] = []
    winner: dict[str, Any] | None = None
    try:
        for mtu in candidates:
            set_interface_mtu(alias, family, mtu)
            time.sleep(0.12)
            prove_node(profile)
            results.append(bench_candidate(host, port, family, mtu))
        winner = pick_winner(results)
        set_interface_mtu(alias, family, int(winner["mtu"]))
        prove_node(profile)
        context = measurement_context(profile, root)
        if defer_adopt:
            # The controller owns the transaction. Never leave a measured winner
            # live or durable until it has re-proved the same session/profile/path.
            set_interface_mtu(alias, family, original)
        else:
            persist(root, store, profile, winner, results)
        return {
            "ok": True,
            "owner_token": owner_capability()[1],
            "interface": alias,
            "family": family,
            "original_mtu": original,
            "winner": winner,
            "results": results,
            **context,
            "adopted": not defer_adopt,
        }
    except Exception:
        try:
            set_interface_mtu(alias, family, original)
        except Exception as restore_error:
            raise RuntimeError("MTU optimization failed and captured interface rollback was not confirmed") from restore_error
        raise


def apply_measured_result(*, rollback: bool = False) -> dict[str, Any]:
    root = root_dir()
    _store, profile = load_profile(root)
    raw_alias = os.environ.get("HOMEVPN_MTU_APPLY_INTERFACE", "").strip()
    raw_family = os.environ.get("HOMEVPN_MTU_APPLY_FAMILY", "").strip()
    raw_mtu = os.environ.get("HOMEVPN_MTU_APPLY_VALUE", "").strip()
    if not raw_alias or raw_family not in {"4", "6"} or not raw_mtu.isdigit():
        raise RuntimeError("MTU apply requires an explicit measured interface, IP family, and MTU")
    value = int(raw_mtu)
    family = int(raw_family)
    previous = interface_mtu(raw_alias, family)
    if rollback:
        set_interface_mtu(raw_alias, family, value)
        return {"ok": True, "owner_token": owner_capability()[1], "interface": raw_alias, "family": family, "previous_mtu": previous, "applied_mtu": value, "rollback": True}

    policy = str(profile.get("mtu_policy") or "default").strip().lower()
    if policy != "auto":
        raise RuntimeError("MTU policy changed before measured result adoption")
    prove_node(profile)
    enforce_kill_switch()
    host = str(profile.get("daita_host") or "10.77.0.1").strip().strip("[]")
    ip = private_ip(host)
    if ip.version != family:
        raise RuntimeError("active MTU path IP family changed before adoption")
    if route_interface(host) != raw_alias:
        raise RuntimeError("active MTU path interface changed before adoption")
    expected = os.environ.get("HOMEVPN_MTU_EXPECTED_PATH_KEY", "").strip()
    current = measurement_context(profile, root)
    if not expected or current["path_key"] != expected:
        raise RuntimeError("active MTU path fingerprint changed before adoption")
    try:
        set_interface_mtu(raw_alias, family, value)
        prove_node(profile)
    except Exception:
        try:
            set_interface_mtu(raw_alias, family, previous)
        except Exception as restore_error:
            raise RuntimeError("MTU adoption failed and captured interface rollback was not confirmed") from restore_error
        raise
    return {"ok": True, "owner_token": owner_capability()[1], "interface": raw_alias, "family": family, "previous_mtu": previous, "applied_mtu": value, **current, "rollback": False}


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        sample = [
            {"mtu": 1380, "working": True, "success_ratio": 1.0, "mbps": 100.0, "median_rtt_ms": 10.0},
            {"mtu": 1360, "working": True, "success_ratio": 1.0, "mbps": 102.0, "median_rtt_ms": 9.9},
            {"mtu": 1340, "working": False, "success_ratio": 0.5, "mbps": 130.0, "median_rtt_ms": 8.0},
        ]
        assert pick_winner(sample)["mtu"] == 1380
        assert candidate_mtus(1380)[0] == 1380
        fixture_environment = {
            "HOMEVPN_ROOT": "", "HOMEVPN_MODE": "wg",
            "HOMEVPN_LOGICAL_MODE": "wg", "HOMEVPN_BASE": "wg",
            "HOMEVPN_IP_FAMILY": "4", "HOMEVPN_NETWORK_CONTEXT": "wifi-a",
        }
        old = {key: os.environ.get(key) for key in fixture_environment}
        try:
            # Exercise the real private-root and generated-source path without
            # depending on an installed node, caller environment, or network.
            with tempfile.TemporaryDirectory(prefix="router-vpn-mtu-self-test-") as directory:
                root = Path(directory).resolve()
                fixture_environment["HOMEVPN_ROOT"] = str(root)
                os.environ.update(fixture_environment)
                source = root / "generated" / "node" / "wg" / "wg.conf"
                source.parent.mkdir(parents=True)
                source.write_text("[Peer]\nEndpoint = 203.0.113.10:51820\n", encoding="utf-8")
                p = {"id": "node", "endpoint": "203.0.113.10"}
                first = path_context_key(p)
                assert first == path_context_key(p)
                os.environ["HOMEVPN_NETWORK_CONTEXT"] = "cellular-b"
                second = path_context_key(p)
                assert first != second
                source.write_text("[Peer]\nEndpoint = 203.0.113.10:51822\n", encoding="utf-8")
                assert second != path_context_key(p)
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        print("MTU throughput optimizer self-test OK")
        return 0
    if len(sys.argv) != 2 or sys.argv[1] not in {"optimize", "measure", "apply", "restore"}:
        print("usage: mtu-throughput-tuner.py optimize | measure | apply | restore | --self-test", file=sys.stderr)
        return 2
    try:
        if sys.argv[1] == "measure":
            result = optimize(defer_adopt=True)
        elif sys.argv[1] == "apply":
            result = apply_measured_result(rollback=False)
        elif sys.argv[1] == "restore":
            result = apply_measured_result(rollback=True)
        else:
            result = optimize(defer_adopt=False)
    except Exception as exc:
        print(f"MTU optimization failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
