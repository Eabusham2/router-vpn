#!/usr/bin/env python3
"""Qualify installed SMART's protected Linux owner against private reference peers."""
import concurrent.futures
import errno
import fcntl
import functools
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import pwd
import re
import secrets
import shutil
import select
import signal
import struct
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from linux_smart_peers import OUTER, open_peers, prepare_reference_tools

HERE = Path(__file__).resolve()
REPO = HERE.parents[1]
INSTALL = Path("/opt/router-vpn-client")
CLIENT = INSTALL / "router-vpn-client"
ENGINE = INSTALL / "runtime/native/sing-box-routervpn"
POLICY = "com.eabusham.routervpn.controller.policy"
CLIENT_PHYSICAL = "172.30.241.1"
DECOY = ("198.18.0.3", 39471)
PAIRS = (("wg-pq", "wg"), ("naive-h3", "hysteria2"), ("naive-h3", "naive-h2"))


def run(*args, **kw):
    return subprocess.run(list(args), check=True, **kw)


def read_json(path):
    return json.loads(path.read_bytes())


def private_write(path, value):
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), "wb"
    ) as stream:
        stream.write(value if isinstance(value, bytes) else json.dumps(value).encode())
        os.fchmod(stream.fileno(), 0o600)


def wait_for(check, description, timeout=30):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise RuntimeError("Timed out waiting for " + description)


@functools.lru_cache(maxsize=1)
def diagnostic_markers():
    # Only checked-in fixed error text may reach the public qualification log.
    # Runtime strings (paths, credentials, captures and prompts) are never echoed.
    paths = set()
    for directory, pattern in (
        ("cmd/client", "*.go"), ("internal/linuxprocess", "*.go"),
        ("internal/linuxprotection", "*.go"), ("internal/mobiletor", "*linux*.go"),
        ("internal/mobilemultihop", "desktop*.go"), ("mobile/desktop", "*.tmpl"),
    ):
        paths.update((REPO / directory).glob(pattern))
    markers = {}
    expression = re.compile(r'(?:errors\.New|fmt\.Errorf|E\.New)\(\s*("(?:[^"\\]|\\.)*")')
    for path in sorted(paths):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text()
        for match in expression.finditer(text):
            try:
                fixed = json.loads(match[1]).split("%", 1)[0].strip()
            except ValueError:
                continue
            if not 12 <= len(fixed) <= 240 or "\n" in fixed or not fixed.isascii():
                continue
            source = str(path.relative_to(REPO)) + ":" + str(text.count("\n", 0, match.start()) + 1)
            markers.setdefault(fixed, []).append(source)
    for fixed in ("context deadline exceeded", "context canceled", "permission denied",
                  "operation not permitted", "no such file or directory", "connection refused",
                  "i/o timeout", "unexpected EOF", "EOF", "set routes:", "add route"):
        markers.setdefault(fixed, []).append("fixed system/runtime error")
    return markers


def diagnostic_error(value):
    if not isinstance(value, str):
        return {"markers": ["non-text error"], "type": type(value).__name__}
    encoded = value.encode("utf-8", errors="replace")
    sample = value[:65536]
    result = {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}
    try:
        found = [(sample.find(marker), -len(marker), marker, sources)
                 for marker, sources in diagnostic_markers().items() if marker in sample]
        accepted = []
        for start, _, marker, sources in sorted(found):
            if any(start >= prior[0] and start + len(marker) <= prior[0] + len(prior[1])
                   for prior in accepted):
                continue
            accepted.append((start, marker, sources))
            if len(accepted) == 8:
                break
        result["markers"] = [{"text": marker, "source": sources[:3]} for _, marker, sources in accepted]
        if not accepted:
            result["markers"] = ["unclassified"]
    except Exception as error:
        result["markers"] = ["classification unavailable"]
        result["classification_error_type"] = type(error).__name__
    if len(value) > len(sample):
        result["sample_truncated"] = True
    return result


def private_stderr_diagnostic(path, owner):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                return {"error": "diagnostic ownership, mode or file type changed"}
            first = stream.read(128 << 10)
            samples = [{"offset": 0, "summary": diagnostic_error(first.decode("utf-8", errors="replace"))}]
            if info.st_size > len(first):
                offset = max(len(first), info.st_size - (64 << 10))
                stream.seek(offset)
                samples.append({"offset": offset, "summary": diagnostic_error(
                    stream.read(64 << 10).decode("utf-8", errors="replace"))})
            return {"file_bytes": info.st_size, "samples": samples}
    except FileNotFoundError:
        return {"present": False}
    except OSError as error:
        return {"error": "diagnostic read failed", "errno": error.errno}


def native_stage(data, directory):
    # This is only a diagnostic view of an already-observed exact engine child.
    # Never serialize the captured source, selected DNS, token or original error.
    result = {"pid": data["pid"], "ready": "ready" in data}
    mode = data.get("mode")
    if isinstance(mode, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,31}", mode):
        result["mode"] = mode
    result["runtime_files"] = {name: (directory / name).is_file()
        for name in ("capture.json", "node-source.json", "sing-box.json",
                     "node-ready.json", "node-mtu-status.json")}
    ready = data.get("ready")
    if isinstance(ready, dict):
        result["ready_numbers"] = {key: ready[key] for key in
            ("schema", "interface_index", "mtu", "proved_at", "cover_services")
            if type(ready.get(key)) is int}
    return result


def attempt_summary(result):
    # The controller's errors may embed private capture material. Report only
    # known diagnostic text and never echo the original error or response body.
    rows = result.get("attempts", []) if isinstance(result, dict) else []
    summary = []
    for row in rows[:32] if isinstance(rows, list) else ():
        if not isinstance(row, dict):
            continue
        mode, action = row.get("mode"), row.get("action")
        if not all(isinstance(x, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,31}", x) for x in (mode, action)):
            continue
        error = row.get("error", "")
        item = {"mode": mode, "action": action, "success": row.get("success") is True}
        if not item["success"]:
            item["error"] = diagnostic_error(error)
        summary.append(item)
    return summary


def api(path, *, method="GET", headers, timeout=20):
    connection = http.client.HTTPConnection("127.0.0.1", 8788, timeout=timeout)
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read(1 << 20)
        if not 200 <= response.status < 300:
            attempts = []
            try:
                attempts = attempt_summary(json.loads(body))
            except ValueError:
                pass
            raise RuntimeError(f"{path} returned HTTP {response.status}, attempts={attempts}")
        return json.loads(body)
    finally:
        connection.close()


def qualification_vt():
    auto = subprocess.check_output(["busctl", "get-property", "org.freedesktop.login1",
                                    "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                                    "NAutoVTs"], text=True).split()
    if len(auto) != 2 or auto[0] != "u" or not auto[1].isdigit():
        raise RuntimeError("Could not read the running logind automatic VT range")
    # ReserveVT is marked busy by logind. Check only the VTs represented in the
    # kernel mask; openvt repeats its busy check and is never allowed to force one.
    with open("/dev/tty1", "rb", opener=lambda path, flags: os.open(path, flags | os.O_NOCTTY)) as tty:
        active, _, used = struct.unpack("=HHH", fcntl.ioctl(tty, 0x5603, bytes(6)))  # VT_GETSTATE
    for number in range(15, int(auto[1]), -1):
        if number != active and not used & (1 << number) and Path(f"/dev/tty{number}").is_char_device():
            return number
    raise RuntimeError("No unused kernel-verified VT outside logind's automatic range is available")


def qualification_uid():
    # A removed account may still belong to logind. Keep one exclusive identity
    # for the entire matrix instead of reusing its lowest recently freed UID.
    existing = {entry.pw_uid for entry in pwd.getpwall()}
    logged_in = subprocess.check_output(["loginctl", "list-users", "--no-legend", "--no-pager"], text=True)
    existing.update(int(row.split()[0]) for row in logged_in.splitlines() if row.split())
    available = [number for number in range(20000, 60000) if number not in existing]
    if not available:
        raise RuntimeError("No unused disposable login UID is available")
    return secrets.choice(available)


@contextmanager
def controller(work, user, password):
    session = work / "session"
    session.mkdir(mode=0o700)
    uid = pwd.getpwnam(user).pw_uid
    token = secrets.token_hex(32)
    for name, contents in (("password", password.read_bytes()),
                           ("frame", {"schema": 1, "access_token": token, "owner_token": secrets.token_hex(16)})):
        private_write(session / name, contents)
        os.chown(session / name, uid, -1)
    os.chown(session, uid, -1)
    login_log = work / "login-diagnostics"
    private_write(login_log, b"")
    completed = work / "login-complete"
    vt = qualification_vt()
    print(f"Opening unused foreground tty{vt} for the disposable PAM login", flush=True)
    launch = subprocess.Popen(["openvt", "-c", str(vt), "-s", "-w", "--", work.parent / "login", user, password,
                               work.parent / "session.py", session, login_log, completed])

    def retired_login():
        # The root-owned parent directory and nofollow read keep this separate
        # from the user's progress files and openvt's child-status forwarding.
        try:
            descriptor = os.open(completed, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                        stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                        stream.read(64) == b"routervpn-smart-login-retired-v1\n")
        except OSError:
            return False

    def diagnostics():
        try:
            records = {"openvt_exit": launch.poll(),
                       "controller_stderr": private_stderr_diagnostic(session / "controller-stderr", uid)}
            for label, path, owner in (("login", login_log, 0), ("session_failure", session / "failure", uid),
                                       ("session_stage", session / "stage", uid)):
                try:
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(descriptor, "rb") as stream:
                        info = os.fstat(stream.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner:
                            records[label] = "diagnostic ownership or file type changed"
                            continue
                        data = stream.read(4097)
                    records[label] = data[:4096].decode("utf-8", errors="replace")
                    if len(data) > 4096:
                        records[label] += " [truncated]"
                except FileNotFoundError:
                    continue
                except OSError as error:
                    records[label] = "diagnostic read failed: errno=" + str(error.errno)
            return json.dumps(records, ensure_ascii=True)
        except Exception as error:
            return "Login diagnostics unavailable: " + type(error).__name__

    def prove():
        if launch.poll() is not None or (session / "failure").exists():
            raise RuntimeError("The real foreground VT login or stock PolicyKit auth_admin challenge failed: " + diagnostics())
        if not (session / "pid").is_file():
            return False
        pid = int((session / "pid").read_text())
        challenge = secrets.token_hex(16)
        sign = lambda message: hmac.new(token.encode(), message.encode(), hashlib.sha256).hexdigest()
        try:
            identity = api("/api/controller/identity", headers={
                "Authorization": "RouterVPN-Identity " + sign("routervpn-controller-identity-request\n" + challenge),
                "X-RouterVPN-Challenge": challenge})
            owned = os.path.samefile(f"/proc/{pid}/exe", CLIENT)
        except (ConnectionError, FileNotFoundError):
            return False
        if (not owned or identity.get("process_id") != pid or identity.get("schema") != 1 or
                identity.get("challenge") != challenge or not hmac.compare_digest(
                    identity.get("proof", ""), sign(f"routervpn-controller-identity-response\n{pid}\n{challenge}"))):
            raise RuntimeError("The listener did not prove this exact installed, authenticated controller")
        return pid

    failure = None
    try:
        pid = wait_for(prove, "active VT authorization and the original controller identity", 90)
        yield pid, {"Authorization": "Bearer " + token}
    except BaseException as error:
        failure = error
        error.add_note("Bounded login diagnostics: " + diagnostics())
        raise
    finally:
        try:
            (session / "close").touch()
            if launch.wait(timeout=150) != 0 or not retired_login():
                raise RuntimeError("The authenticated controller, PAM session or VT did not complete retirement: " + diagnostics())
        except BaseException as error:
            if failure is None:
                raise
            failure.add_note("Session retirement also failed: " + type(error).__name__ + "; " + diagnostics())


@contextmanager
def canary(peer):
    # Each socket stays in its original namespace after the calling thread returns.
    with open("/proc/self/ns/net") as client_ns, open("/run/netns/" + peer) as peer_ns:
        os.setns(peer_ns.fileno(), os.CLONE_NEWNET)
        try:
            receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receiver.bind(DECOY)
        finally:
            os.setns(client_ns.fileno(), os.CLONE_NEWNET)
    stop = threading.Event()
    armed = threading.Event()
    with receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"smartphy\0")
        sender.bind((CLIENT_PHYSICAL, 0))
        nonce = secrets.token_bytes(16)
        def send():
            while not stop.is_set():
                try:
                    sender.sendto(nonce + (b"protected" if armed.is_set() else b"control"), DECOY)
                except OSError as exc:
                    if exc.errno not in (errno.EPERM, errno.EACCES, errno.ENETUNREACH, errno.EHOSTUNREACH):
                        raise
                stop.wait(.002)
        control, leaked = threading.Event(), threading.Event()
        def receive():
            receiver.settimeout(.1)
            while True:
                try:
                    payload = receiver.recv(100)
                except TimeoutError:
                    if stop.is_set():
                        return
                    continue
                if payload == nonce + b"protected":
                    leaked.set()
                if payload == nonce + b"control":
                    control.set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            workers = [pool.submit(receive), pool.submit(send)]
            try:
                if not control.wait(5):
                    raise RuntimeError("The physical leak canary failed its positive control")
                yield armed, control
            finally:
                stop.set()
                for future in workers:
                    future.result(timeout=5)
                if leaked.is_set():
                    raise RuntimeError("Protected SMART leaked a canary to the physical peer")


def captured_processes(parent):
    result = set()
    for task in Path(f"/proc/{parent}/task").iterdir():
        try:
            result.update((task / "children").read_text().split())
        except FileNotFoundError:
            pass
    for pid in result:
        try:
            args = Path(f"/proc/{pid}/cmdline").read_bytes().decode().split("\0")
            if os.path.samefile(f"/proc/{pid}/exe", ENGINE) and "routervpn-node" in args:
                yield int(pid), Path(args[args.index("--runtime-dir") + 1])
        except (FileNotFoundError, ProcessLookupError):
            continue


def snapshot(pid, directory):
    meta = read_json(directory / "capture.json")
    state = {"pid": pid, "mode": meta["mode"], "session": meta["session_id"]}
    try:
        ready = read_json(directory / "node-ready.json")
        mtu = read_json(directory / "node-mtu-status.json")
        if not (ready["session_id"] == mtu["session_id"] == state["session"] and
                ready["config_sha256"] == mtu["config_sha256"] == meta["config_sha256"] and
                ready["interface_index"] == mtu["index"] and ready["mtu"] == mtu["mtu"]):
            raise RuntimeError("The engine's readiness and MTU records identify different owners")
        interface = json.loads(subprocess.check_output(["ip", "-j", "link", "show", "dev", ready["interface_name"]]))[0]
        if (interface["ifindex"], interface["mtu"]) != (mtu["index"], mtu["mtu"]):
            raise RuntimeError("The engine's observed TUN and live MTU differ from its receipts")
        state.update(ready=ready, mtu=mtu["mtu"], original={
            key: meta[key] for key in ("original_capture_sha256", "original_config_sha256", "original_source_sha256")},
            source_digest=hashlib.sha256((directory / "node-source.json").read_bytes()).digest(),
            dns=read_json(directory / "sing-box.json")["dns"], restored=meta.get("restored_mtu", 0))
    except FileNotFoundError:
        pass
    return state


def check_guard_history(path, original, final):
    # Kernel netfilter multicast events are ordered. A successor's actual
    # default-drop OUTPUT chain must exist before the predecessor disappears.
    guarded = set()
    first = "router_vpn_node_" + original
    last = "router_vpn_node_" + final
    started = False
    for line in path.read_text().splitlines():
        match = re.match(r"(add|delete) (chain|table) inet (router_vpn_(?:node|standard)_[0-9a-f]{32})(?:\s+(.*))?$", line)
        if not match:
            continue
        action, obj, table, detail = match.groups()
        if action == "add" and obj == "chain" and detail.startswith("output ") and "hook output" in detail and "policy drop" in detail:
            guarded.add(table)
            started |= table == first
        if action == "delete" and (obj == "table" or detail == "output"):
            guarded.discard(table)
        if started and not guarded:
            raise RuntimeError("There was no native default-drop OUTPUT chain between SMART owners")
    if not started or last not in guarded:
        raise RuntimeError("Kernel events did not prove the first and final SMART protection owners")


def physical_rejections(peer):
    inventory = json.loads(subprocess.check_output(
        ["ip", "netns", "exec", peer, "nft", "-j", "list", "table", "inet", "smart_peer"]))
    return sum(expr["counter"]["packets"] for row in inventory["nftables"] if "rule" in row
               for expr in row["rule"]["expr"] if "counter" in expr)


def qualify(work, user, password, peer_ns, source, candidate, policy, layer, succeed):
    with open_peers(peer_ns, work, source, candidate, layer) as peers:
        profile = dict(peers.profile, kill_switch_policy=policy, home_lan_access=False, mtu_policy="manual", manual_mtu=1360)
        private_write(INSTALL / "routers.json", {"schema_version": 4, "selected_id": profile["id"], "profiles": [profile]})
        base = INSTALL / "generated" / profile["id"]
        base.mkdir(mode=0o700)
        for mode, files in peers.assets.items():
            directory = base / mode
            directory.mkdir(mode=0o700)
            for name, body in files.items():
                private_write(directory / name, body)
        with canary(peer_ns) as (armed, control), controller(work, user, password) as (owner, headers):
            with (work / "nft.events").open("wb") as log:
                monitor = subprocess.Popen(["stdbuf", "-oL", "nft", "-nn", "monitor"], stdout=log)
                result = None
                observed_stages = {}
                try:
                    # A harmless table marker establishes monitor subscription before SMART.
                    marker = "qualification_monitor"
                    run("nft", "add", "table", "inet", marker)
                    run("nft", "delete", "table", "inet", marker)
                    def listening():
                        if marker in (work / "nft.events").read_text():
                            return True
                        run("nft", "add", "table", "inet", marker)
                        run("nft", "delete", "table", "inet", marker)
                    wait_for(listening, "kernel nftables monitor", 5)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(api, "/api/strategy/smart-auto", method="POST", headers=headers, timeout=420)
                        sessions = {}
                        first, first_proof = None, None
                        rejected = 0
                        while True:
                            for pid, directory in captured_processes(owner):
                                try:
                                    data = snapshot(pid, directory)
                                except (FileNotFoundError, subprocess.CalledProcessError):
                                    # A child may retire between /proc enumeration and TUN readback.
                                    continue
                                key = data["session"]
                                try:
                                    observed_stages[data["pid"]] = native_stage(data, directory)
                                except Exception:
                                    pass  # Diagnostics cannot replace the original qualification failure.
                                if key not in sessions or "ready" not in sessions[key]:
                                    sessions[key] = data
                                if data["mode"] == source and first is None and "ready" in data:
                                    first = data
                                    armed.set()
                            if first is not None and first_proof is None:
                                observation = peers.observation()
                                if observation["http"] and observation["dns"] and (
                                        observation["pq_key_applied"] if source == "wg-pq" else observation["source_uot"]):
                                    first_proof = observation
                                    rejected = physical_rejections(peer_ns)
                                    if succeed:
                                        peers.enable_candidate()
                            if future.done():
                                break
                            time.sleep(.01)
                        result = future.result()
                    live = [snapshot(pid, directory) for pid, directory in captured_processes(owner)]
                    if len(live) != 1 or "ready" not in live[0]:
                        raise RuntimeError("Settled SMART has no unique live retained TUN owner")
                    final = live[0]
                    sessions[final["session"]] = final
                    wanted = candidate if succeed else source
                    if not first or not first_proof or final["mode"] != wanted or first["session"] == final["session"]:
                        raise RuntimeError("SMART failed to produce fresh, observed source and winner TUN owners")
                    status = api("/api/status", headers=headers)
                    if not (status["connected"] and status["phase"] == "connected" and status["runtime_mode"] == wanted and
                            status["logical_mode"] == "smart-auto" and status["router_id"] == profile["id"]):
                        raise RuntimeError("SMART's published winner differs from the live installed owner")
                    actions = [(a["mode"], a["action"], a["success"]) for a in result["attempts"]]
                    if not (result["ok"] and result["strategy"] == "smart-auto" and result["runtime_mode"] == wanted and
                            (source, "candidate", True) in actions and (candidate, "simplify", succeed) in actions):
                        raise RuntimeError(f"Unexpected SMART outcome {actions}")
                    after = list(sessions.values())[list(sessions).index(first["session"])+1:]
                    if not any(s["mode"] == candidate for s in after):
                        raise RuntimeError("SMART never launched the simplification's real engine")
                    if not succeed and ((source, "restore", True) not in actions or result.get("restored_mode") != source or
                            first["original"] != final["original"] or first["source_digest"] != final["source_digest"] or
                            first["dns"] != final["dns"] or not (first["mtu"] == final["restored"] == final["mtu"])):
                        raise RuntimeError("SMART did not restore its sealed source, selected DNS and previous live MTU")
                    # Re-prove private packets after settlement through the actual final TUN.
                    prior = peers.observation()
                    challenge_private_router(profile)
                    probe_private_dns(profile)
                    def observed():
                        now = peers.observation()
                        return (now["http"] > prior["http"] and now["dns"] > prior["dns"] and
                                (source != "wg-pq" or now["pq_key_applied"] and now["wg_handshake"] > 0) and
                                (source != "naive-h3" or now["source_uot"] > 0) and
                                (wanted != "wg" or now["candidate_handshake"] > 0) and
                                (wanted != "naive-h2" or now["candidate_uot"] > 0) and
                                (wanted != "hysteria2" or now["candidate_hy2"] > 0 and now["candidate_hy2_dns"] > 0) and
                                (succeed or source != "wg-pq" or now["pq_generation"] > first_proof["pq_generation"]) and
                                (layer == "off" or now["source_layer_packets"] > 0 and
                                 (source != "wg-pq" or now["pq_layer_packets"] > 0) and
                                 (not succeed or now["candidate_layer_packets"] > 0)))
                    wait_for(observed, "independent peer packet and protocol observations", 10)
                    if physical_rejections(peer_ns) != rejected:
                        raise RuntimeError("SMART attempted direct physical access to a private proof or layered transport")
                    if monitor.poll() is not None:
                        raise RuntimeError("Kernel nftables monitor stopped early")
                    check_guard_history(work / "nft.events", first["session"], final["session"])
                except Exception as error:
                    try:
                        error.add_note("Observed native startup stages: " + json.dumps(
                            list(observed_stages.values())[:32], ensure_ascii=True))
                        if result is not None:
                            error.add_note("Observed SMART attempts: " + json.dumps(attempt_summary(result)))
                    except Exception:
                        pass  # Preserve the first failure even if diagnostics cannot be recorded.
                    raise
                finally:
                    monitor.terminate()
                    monitor.wait(timeout=5)
            if policy == "on-connect":
                armed.clear()
                control.clear()
            api("/api/disconnect", method="POST", headers=headers)
            if policy == "on-connect" and not control.wait(5):
                raise RuntimeError("Normal On-connect disconnect did not release physical traffic")
            if policy == "always":
                records = json.loads(subprocess.check_output(["nft", "-j", "list", "ruleset"]))["nftables"]
                expected = "router_vpn_node_" + final["session"]
                if not any(row.get("chain", {}).get("policy") == "drop" and row["chain"].get("table") == expected and
                           row["chain"].get("name") == row["chain"].get("hook") == "output" and
                           row["chain"].get("comment") == "routervpn-owned-baseline:" + final["session"] + ":" +
                           final["ready"]["source_sha256"] for row in records):
                    raise RuntimeError("Always disconnect lost its live kernel drop policy")


def probe_private_dns(profile):
    nonce = secrets.token_hex(12).encode()
    tx = secrets.randbelow(65536)
    labels = (nonce, b"router", b"test")
    request = struct.pack("!6H", tx, 0x0100, 1, 0, 0, 0)
    request += b"".join(bytes([len(label)]) + label for label in labels) + b"\0" + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(6)
        udp.connect((profile["adguard_ipv4"], 53))
        udp.send(request)
        reply = udp.recv(4096)
        if len(reply) < 12 or struct.unpack_from("!H", reply)[0] != tx or not (reply[2] & 0x80) or not reply[7]:
            raise RuntimeError("Final SMART tunnel lost its selected private DNS response")


def challenge_private_router(profile):
    from urllib.parse import urlsplit
    parsed = urlsplit(profile["path_probe_url"])
    nonce = secrets.token_hex(16)
    node = profile["node_proof_id"]
    def sign(phase):
        message = f"routervpn-private-candidate-response-v1\n{phase}\n{node}\n{nonce}"
        return hmac.new(profile["api_token"].encode(), message.encode(), hashlib.sha256).hexdigest()
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=8)
    try:
        conn.request("GET", "/health")
        health = conn.getresponse()
        if health.status != 200 or json.loads(health.read(65536)) != {
                "node_id": node, "ok": True, "proof": "router-vpn-private-agent-v1"}:
            raise RuntimeError("Final TUN failed the selected Router's private health proof")
        conn.request("GET", "/api/benchmark/candidate-response?nonce=" + nonce,
                     headers={"Authorization": "Bearer " + sign("request")})
        response = conn.getresponse()
        if response.status != 200:
            raise RuntimeError("Final TUN failed the private authenticated Router challenge")
        answer = json.loads(response.read(65536))
        if answer.get("node_id") != node or answer.get("nonce") != nonce or not hmac.compare_digest(
                answer.get("response", ""), sign("response")):
            raise RuntimeError("Final TUN returned a foreign or replayed Router response")
    finally:
        conn.close()


def remove_namespace(name):
    # On a failed case, join only processes which still occupy this private
    # namespace. A reused PID can never redirect cleanup to a host process.
    with ExitStack() as stack:
        for pid in subprocess.check_output(["ip", "netns", "pids", name], text=True).split():
            try:
                handle = os.pidfd_open(int(pid))
                stack.callback(os.close, handle)
                if not os.path.samefile("/proc/" + pid + "/ns/net", "/run/netns/" + name):
                    continue
                signal.pidfd_send_signal(handle, signal.SIGKILL)
                if not select.select([handle], [], [], 5)[0]:
                    raise RuntimeError("An isolated qualification process failed to exit")
            except (ProcessLookupError, FileNotFoundError):
                continue
    run("ip", "netns", "delete", name)


@contextmanager
def paired_namespaces():
    suffix = secrets.token_hex(4)
    client, peer = "rvsmart-c-" + suffix, "rvsmart-p-" + suffix
    with ExitStack() as cleanup:
        for name in (client, peer):
            run("ip", "netns", "add", name)
            cleanup.callback(remove_namespace, name)
            run("ip", "-n", name, "link", "set", "lo", "up")
        run("ip", "-n", client, "link", "add", "smartphy", "type", "veth", "peer", "name", "smartpeer", "netns", peer)
        for ns, link, address in ((client, "smartphy", CLIENT_PHYSICAL + "/24"), (peer, "smartpeer", OUTER + "/24")):
            run("ip", "-n", ns, "addr", "add", address, "dev", link)
            run("ip", "-n", ns, "link", "set", link, "up")
        run("ip", "-n", peer, "addr", "add", DECOY[0] + "/32", "dev", "smartpeer")
        run("ip", "-n", client, "route", "add", "default", "via", OUTER)
        yield client, peer


def install_image(archive, temp):
    import tarfile
    archive = archive.resolve()
    name = archive.name.removesuffix(".tar.gz")
    if name not in ("RouterVPN-linux-amd64", "RouterVPN-linux-arm64"):
        raise ValueError("Expected a packaged native Linux archive")
    with tarfile.open(archive) as tar:
        tar.extractall(temp, filter="data")
    source = temp / name
    template = temp / "installed"
    template.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location("native_installer", source / "client/install-linux-native.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    installer.stage_application(source, INSTALL, template)
    installer.verify_runtimes(template)
    template.chmod(0o755)
    return template


@contextmanager
def installed_policy(template):
    policy = Path("/usr/share/polkit-1/actions") / POLICY
    stock = (template / "client/linux" / POLICY).read_bytes()
    if policy.exists():
        if policy.read_bytes() != stock:
            raise RuntimeError("An existing system PolicyKit policy differs from the installed package")
        yield
        return
    with policy.open("xb") as stream:
        stream.write(stock)
        os.fchmod(stream.fileno(), 0o644)
        stream.flush()
        try:
            wait_for(lambda: "com.eabusham.routervpn.controller" in subprocess.check_output(["pkaction"], text=True),
                     "stock installed PolicyKit action", 10)
            yield
        finally:
            if os.path.samestat(os.fstat(stream.fileno()), policy.stat()):
                policy.unlink()


def remove_login_user(name, uid):
    # logind may retain this test account's user manager briefly after PAM closes.
    def current():
        if pwd.getpwnam(name).pw_uid != uid:
            raise RuntimeError("The disposable login identity changed during cleanup")
    current()
    login = subprocess.run(["loginctl", "show-user", str(uid)], capture_output=True)
    if login.returncode == 0:
        run("loginctl", "terminate-user", str(uid))
    def remove():
        current()
        attempt = subprocess.run(["userdel", "--remove", name], capture_output=True)
        if attempt.returncode not in (0, 8):  # shadow-utils 8 denotes an active account
            raise RuntimeError(f"Removing the qualification user returned {attempt.returncode}")
        return attempt.returncode == 0
    wait_for(remove, "final retirement of the disposable login user", 30)


def root_fixture(archive, references):
    if os.getuid() or os.path.samefile("/proc/self/ns/mnt", "/proc/1/ns/mnt"):
        raise RuntimeError("Qualification requires its own private root mount namespace")
    for name in ("/dev/net/tun", "/dev/tty0", "/sys/class/tty/tty0/active", "/run/systemd/system"):
        if not Path(name).exists():
            raise RuntimeError(f"Hosted Linux qualification requires a real foreground VT, logind and TUN (missing {name})")
    run("loginctl", "show-seat", "seat0", "--property=CanTTY")
    run("mount", "-t", "tmpfs", "-o", "mode=0755,size=4m", "tmpfs", "/opt")
    INSTALL.mkdir(mode=0o755)
    with tempfile.TemporaryDirectory(prefix="routervpn-smart-", dir="/var/tmp") as temporary, ExitStack() as cleanup:
        temp = Path(temporary)
        temp.chmod(0o711)
        secure = temp / "private"
        secure.mkdir(mode=0o700)
        for key, exe in (("ROSENPASS", "rosenpass"), ("ROUTER_AGENT", "router-agent")):
            shutil.copyfile(references / exe, secure / exe)
            (secure / exe).chmod(0o700)
            os.environ["ROUTERVPN_QUALIFICATION_" + key] = str(secure / exe)
        template = install_image(archive, secure)
        cleanup.enter_context(installed_policy(template))
        run("cc", "-O2", "-Wall", "-Wextra", "-Werror", HERE.with_name("linux-smart-login.c"), "-lpam", "-o", temp / "login")
        shutil.copyfile(HERE.with_name("linux-smart-session.py"), temp / "session.py")
        (temp / "session.py").chmod(0o644)
        user = "rvsmart" + secrets.token_hex(4)
        password = secure / "password"
        private_write(password, secrets.token_hex(32).encode() + b"\n")
        uid = qualification_uid()
        run("useradd", "--uid", str(uid), "--create-home", "--groups", "sudo", "--shell", "/bin/bash", user)
        if pwd.getpwnam(user).pw_uid != uid:
            raise RuntimeError("The disposable login UID changed after exclusive allocation")
        cleanup.callback(remove_login_user, user, uid)
        run("chpasswd", input=user.encode() + b":" + password.read_bytes())
        for source, candidate, policy, layer, outcome in matrix(archive.name):
            label = "-".join((source, candidate, policy, layer, outcome))
            print("Qualifying installed SMART", label, flush=True)
            with tempfile.TemporaryDirectory(prefix=label+"-", dir=temp) as scratch, paired_namespaces() as (client, peer):
                work = Path(scratch)
                work.chmod(0o711)
                backing = work / "overlay-backing"
                backing.mkdir(mode=0o700)
                upper, overlay_work = backing / "upper", backing / "work"
                upper.mkdir(mode=0o700)
                overlay_work.mkdir(mode=0o700)
                # Overlayfs exposes the upper directory's mode at the mounted root.
                installed_mode = stat.S_IMODE(template.stat().st_mode)
                upper.chmod(installed_mode)
                run("mount", "-t", "overlay", "overlay", "-o",
                    f"lowerdir={template},upperdir={upper},workdir={overlay_work}", INSTALL)
                try:
                    if stat.S_IMODE(INSTALL.stat().st_mode) != installed_mode:
                        raise RuntimeError("Mounted application root differs from the installed directory mode")
                    run("ip", "netns", "exec", client, sys.executable, HERE, "--case",
                        work, user, password, peer, source, candidate, policy, layer, outcome, timeout=650)
                finally:
                    run("umount", INSTALL)


def matrix(package_name):
    # Each architecture runs every transport, layer and policy with one outcome.
    # Together the two release jobs exercise successful and restored trials for each.
    arch = 0 if "amd64" in package_name else 1
    for pair, (source, candidate) in enumerate(PAIRS):
        for number, layer in enumerate(("off", "aes-256-gcm", "aes-256-gcm+xor-whitening")):
            for position, policy in enumerate(("on-connect", "always")):
                outcome = ("success", "restore")[(arch + pair + number + position) % 2]
                yield source, candidate, policy, layer, outcome


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--archive":
        with tempfile.TemporaryDirectory(prefix="routervpn-peer-tools-") as temp:
            tools = prepare_reference_tools(temp)
            references = Path(tools["ROUTERVPN_QUALIFICATION_ROSENPASS"]).parent
            run("sudo", "--", "unshare", "--mount", "--propagation", "private", "/usr/bin/python3",
                HERE, "--installed", Path(sys.argv[2]).resolve(), references)
    elif len(sys.argv) == 4 and sys.argv[1] == "--installed":
        root_fixture(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 11 and sys.argv[1] == "--case":
        qualify(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), *sys.argv[5:10], sys.argv[10] == "success")
    else:
        raise SystemExit("usage: verify-linux-smart.py --archive PATH")


if __name__ == "__main__":
    main()
