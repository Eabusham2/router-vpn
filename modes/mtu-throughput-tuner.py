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
    proc = subprocess.run([sys.executable, str(helper), "apply"], text=True, capture_output=True, check=False)
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
    system = platform.system().lower()
    if system == "linux":
        return int((Path("/sys/class/net") / alias / "mtu").read_text().strip())
    if system == "darwin":
        out = subprocess.check_output(["ifconfig", alias], text=True, timeout=3)
        match = re.search(r"\bmtu\s+(\d+)", out)
        if match:
            return int(match.group(1))
    if system == "windows":
        fam = "IPv6" if family == 6 else "IPv4"
        escaped = alias.replace("'", "''")
        cmd = f"(Get-NetIPInterface -InterfaceAlias '{escaped}' -AddressFamily {fam} | Sort-Object InterfaceMetric | Select-Object -First 1).NlMtuBytes"
        out = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd], text=True, timeout=6).strip()
        if out.isdigit():
            return int(out)
    raise RuntimeError("could not read current tunnel MTU")


def set_interface_mtu(alias: str, family: int, mtu: int) -> None:
    if not MIN_OPT_MTU <= mtu <= 9000:
        raise RuntimeError(f"refusing invalid live MTU {mtu}")
    system = platform.system().lower()
    if system == "linux":
        cmd = ["ip", "link", "set", "dev", alias, "mtu", str(mtu)]
    elif system == "darwin":
        cmd = ["ifconfig", alias, "mtu", str(mtu)]
    elif system == "windows":
        fam = "IPv6" if family == 6 else "IPv4"
        escaped = alias.replace("'", "''")
        ps = f"Set-NetIPInterface -InterfaceAlias '{escaped}' -AddressFamily {fam} -NlMtuBytes {mtu} -ErrorAction Stop"
        cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps]
    else:
        raise RuntimeError("live MTU optimization is not implemented for this platform")
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=8, check=False)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "could not set live tunnel MTU").strip())


def candidate_mtus(ceiling: int) -> list[int]:
    ceiling = max(MIN_OPT_MTU, min(MAX_OPT_MTU, int(ceiling)))
    floor = max(MIN_OPT_MTU, ceiling - STEP * (MAX_CANDIDATES - 1))
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
    endpoint = str(profile.get("endpoint") or os.environ.get("HOMEVPN_ENDPOINT", "")).strip()
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
    raw = "|".join([
        endpoint.lower(),
        mode.lower(),
        os.environ.get("HOMEVPN_LOGICAL_MODE", "").strip().lower(),
        os.environ.get("HOMEVPN_BASE", "").strip().lower(),
        family,
        profile_id.lower(),
        network,
        generated,
    ])
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
    if not MIN_OPT_MTU <= ceiling <= MAX_OPT_MTU:
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
        except Exception:
            pass
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
        return {"ok": True, "interface": raw_alias, "family": family, "previous_mtu": previous, "applied_mtu": value, "rollback": True}

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
        except Exception:
            pass
        raise
    return {"ok": True, "interface": raw_alias, "family": family, "previous_mtu": previous, "applied_mtu": value, **current, "rollback": False}


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        sample = [
            {"mtu": 1380, "working": True, "success_ratio": 1.0, "mbps": 100.0, "median_rtt_ms": 10.0},
            {"mtu": 1360, "working": True, "success_ratio": 1.0, "mbps": 102.0, "median_rtt_ms": 9.9},
            {"mtu": 1340, "working": False, "success_ratio": 0.5, "mbps": 130.0, "median_rtt_ms": 8.0},
        ]
        assert pick_winner(sample)["mtu"] == 1380
        assert candidate_mtus(1380)[0] == 1380
        old = os.environ.get("HOMEVPN_NETWORK_CONTEXT")
        try:
            os.environ["HOMEVPN_NETWORK_CONTEXT"] = "wifi-a"
            p = {"id": "node", "endpoint": "203.0.113.10"}
            first = path_context_key(p)
            os.environ["HOMEVPN_NETWORK_CONTEXT"] = "cellular-b"
            second = path_context_key(p)
            assert first != second
        finally:
            if old is None:
                os.environ.pop("HOMEVPN_NETWORK_CONTEXT", None)
            else:
                os.environ["HOMEVPN_NETWORK_CONTEXT"] = old
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
