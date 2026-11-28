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

from linux_smart_peers import OUTER, OrderedChild, open_ordered_peers, open_peers, prepare_reference_tools

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


def api(path, *, method="GET", headers, timeout=20, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", 8788, timeout=timeout)
    try:
        request_headers = dict(headers)
        payload = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode()
            if len(payload) > (1 << 20):
                raise ValueError("Qualification API body exceeded its bound")
            request_headers["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=request_headers)
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
def controller_resolver(work, pid, prove, retired):
    """Own a real system bus/resolved pair in the proved controller's namespaces."""
    record = {"schema": 1, "controller_pid": pid, "ready": False, "cleanup_complete": False,
              "daemons": [], "mounts": []}
    receipt = work / "resolver-receipt"
    failure, processes, attempted = None, [], []
    parent_mount = os.stat("/proc/self/ns/mnt")
    parent_net = os.stat("/proc/self/ns/net")
    identity = lambda info: [info.st_dev, info.st_ino]

    def save():
        private_write(receipt, record)

    with ExitStack() as handles:
        pidfd = os.pidfd_open(pid)
        handles.callback(os.close, pidfd)
        proc = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.callback(os.close, proc)
        mount = os.open("ns/mnt", os.O_RDONLY, dir_fd=proc)
        handles.callback(os.close, mount)
        network = os.open("ns/net", os.O_RDONLY, dir_fd=proc)
        handles.callback(os.close, network)
        mount_identity, network_identity = identity(os.fstat(mount)), identity(os.fstat(network))
        record.update(mount_namespace=mount_identity, network_namespace=network_identity)
        if (mount_identity == identity(parent_mount) or
                mount_identity == identity(os.stat("/proc/1/ns/mnt")) or
                network_identity != identity(parent_net)):
            raise RuntimeError("SMART resolver namespaces are not the original private controller view")

        def current():
            if (select.select([pidfd], [], [], 0)[0] or
                    not os.path.samestat(os.stat("exe", dir_fd=proc), CLIENT.stat()) or
                    identity(os.stat("ns/mnt", dir_fd=proc)) != mount_identity or
                    identity(os.stat("ns/net", dir_fd=proc)) != network_identity or prove() != pid):
                raise RuntimeError("SMART resolver lost its proved original controller")
            # The login child made every inherited mount private before dropping UID.
            with os.fdopen(os.open("mountinfo", os.O_RDONLY, dir_fd=proc)) as stream:
                for line in stream:
                    optional = line.split(" - ", 1)[0].split()[6:]
                    if any(item.startswith(("shared:", "master:")) for item in optional):
                        raise RuntimeError("SMART controller mount propagation is not private")

        prefix = ["nsenter", "--mount=/proc/self/fd/" + str(mount),
                  "--net=/proc/self/fd/" + str(network), "--"]
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
                       "SYSTEMD_LOG_TARGET": "console", "SYSTEMD_LOG_COLOR": "0"}

        def inside(*args, timeout=5):
            completed = subprocess.run(prefix + list(map(str, args)), pass_fds=(mount, network),
                                       env=environment, capture_output=True, timeout=timeout)
            if completed.returncode:
                raise RuntimeError("SMART isolated resolver setup command failed: exit=" +
                                   str(completed.returncode))
            return completed.stdout.decode("utf-8")

        layout_source = (
            "import json,os\n"
            "r={'mnt':[os.stat('/proc/self/ns/mnt').st_dev,os.stat('/proc/self/ns/mnt').st_ino],"
            "'net':[os.stat('/proc/self/ns/net').st_dev,os.stat('/proc/self/ns/net').st_ino],"
            "'mounts':{}}\n"
            "for line in open('/proc/self/mountinfo'):\n"
            " a,b=line.rstrip().split(' - ',1); a=a.split(); b=b.split()\n"
            " if a[4] in ('/run/dbus','/run/systemd'):"
            " r['mounts'][a[4]]={'id':int(a[0]),'type':b[0],'source':b[1]}\n"
            "print(json.dumps(r))\n")

        def layout():
            value = json.loads(inside("/usr/bin/python3", "-I", "-c", layout_source))
            if value["mnt"] != mount_identity or value["net"] != network_identity:
                raise RuntimeError("SMART resolver entered a different namespace")
            return value["mounts"]

        def daemon_current(item):
            process = item["process"]
            if process.poll() is not None:
                raise RuntimeError("SMART owned resolver daemon exited: " + item["name"])
            try:
                path = Path("/proc") / str(process.pid)
                return (os.path.samestat((path / "exe").stat(), item["executable_info"]) and
                        identity((path / "ns/mnt").stat()) == mount_identity and
                        identity((path / "ns/net").stat()) == network_identity)
            except FileNotFoundError:
                return False

        def start(name, executable, *arguments):
            executable = executable.resolve(strict=True)
            info = executable.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError("SMART resolver executable is not a trusted installed file")
            descriptor = os.open(work / (name + "-diagnostics"),
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as log:
                process = subprocess.Popen(prefix + [str(executable), *arguments],
                                           pass_fds=(mount, network), env=environment,
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            item = {"name": name, "process": process, "executable": executable,
                    "executable_info": info, "pidfd": None}
            processes.append(item)  # Even a failed pidfd acquisition retains the exact Popen child.
            item["pidfd"] = os.pidfd_open(process.pid)
            handles.callback(os.close, item["pidfd"])
            wait_for(lambda: daemon_current(item), "the original " + name + " daemon", 10)
            entry = {"name": name, "pid": process.pid, "executable": str(executable),
                     "executable_identity": identity(info),
                     "mount_namespace": mount_identity, "network_namespace": network_identity,
                     "joined": False}
            item["receipt"] = entry
            record["daemons"].append(entry)
            save()
            return item

        def bus_call(member, *arguments):
            return inside("busctl", "--system", "--timeout=2", "call", "org.freedesktop.DBus",
                          "/org/freedesktop/DBus", "org.freedesktop.DBus", member, *arguments).strip()

        try:
            current()
            for target in ("/run/dbus", "/run/systemd"):
                source = "routervpn-smart-resolver-" + secrets.token_hex(12)
                item = {"target": target, "source": source, "id": None, "unmounted": False}
                attempted.append(item)
                record["mounts"].append(item)
                # Existing parent directories are hidden only in the child's private mount
                # view. resolved itself creates/chowns its own runtime subdirectory.
                inside("mount", "-t", "tmpfs", "-o", "mode=0755,size=8m,nosuid,nodev,noexec",
                       source, target)
                observed = layout().get(target)
                if not observed or observed["type"] != "tmpfs" or observed["source"] != source:
                    raise RuntimeError("SMART resolver mount did not retain its original identity")
                item["id"] = observed["id"]
                save()
            bus = start("system-bus", Path("/usr/bin/dbus-daemon"), "--system", "--nofork", "--nopidfile")

            def bus_ready():
                if not daemon_current(bus):
                    return False
                try:
                    return bool(re.fullmatch(r's "[0-9a-f]{32}"', bus_call("GetId")))
                except RuntimeError:
                    return False

            wait_for(bus_ready, "the owned ordinary system bus", 10)
            resolved = start("resolved", Path("/usr/lib/systemd/systemd-resolved"))

            def resolved_ready():
                if not daemon_current(bus) or not daemon_current(resolved):
                    return False
                try:
                    owner = bus_call("GetNameOwner", "s", "org.freedesktop.resolve1")
                    match = re.fullmatch(r's "(:[0-9]+\.[0-9]+)"', owner)
                    if not match:
                        return False
                    actual = bus_call("GetConnectionUnixProcessID", "s", match[1])
                    if actual != "u " + str(resolved["process"].pid):
                        return False
                    if bus_call("GetNameOwner", "s", "org.freedesktop.resolve1") != owner:
                        return False
                    record["resolver_unique_name"] = match[1]
                    return True
                except RuntimeError:
                    return False

            wait_for(resolved_ready, "the original resolved owner on the owned system bus", 15)
            current()
            record["ready"] = True
            save()
            print("SMART isolated resolver ready: " + json.dumps(record, sort_keys=True), flush=True)
            yield record
            for item in processes:
                if not daemon_current(item):
                    raise RuntimeError("SMART resolver daemon changed before controller retirement")
        except BaseException as error:
            failure = error
            raise
        finally:
            errors = []
            for item in reversed(processes):
                process = item["process"]
                try:
                    if process.poll() is None:
                        try:
                            if item["pidfd"] is None:
                                process.terminate()  # Exact, unreaped Popen child; no numeric-PID lookup.
                            else:
                                signal.pidfd_send_signal(item["pidfd"], signal.SIGTERM)
                        except ProcessLookupError:
                            pass  # A just-exited original child must still be joined below.
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            try:
                                if item["pidfd"] is None:
                                    process.kill()
                                else:
                                    signal.pidfd_send_signal(item["pidfd"], signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            process.wait(timeout=5)
                            errors.append(item["name"] + " required forced termination")
                    if item.get("receipt"):
                        item["receipt"].update(joined=True, exit_code=process.returncode)
                except BaseException as error:
                    errors.append(item["name"] + " cleanup: " + type(error).__name__)
            # Revealing the host paths is allowed only after both the exact
            # controller and its real login/PAM parent have finished. On partial
            # setup or failed retirement, the existing owned-namespace teardown
            # destroys these mounts instead; a live owner never sees the host bus.
            can_unmount = retired() and bool(select.select([pidfd], [], [], 0)[0])
            retained_mounts = False
            for item in reversed(attempted):
                try:
                    observed = layout().get(item["target"])
                    if observed and observed["source"] == item["source"] and observed["type"] == "tmpfs":
                        if item["id"] is not None and observed["id"] != item["id"]:
                            raise RuntimeError("original resolver mount was replaced")
                        if not can_unmount:
                            item["retained_for_namespace_teardown"] = True
                            retained_mounts = True
                            continue
                        inside("umount", item["target"])
                        if layout().get(item["target"]) == observed:
                            raise RuntimeError("original resolver mount remained after unmount")
                        item["unmounted"] = True
                    elif item["id"] is not None:
                        raise RuntimeError("original resolver mount disappeared or was replaced")
                except BaseException as error:
                    errors.append(item["target"] + " cleanup: " + type(error).__name__)
            if (not os.path.samestat(os.stat("/proc/self/ns/mnt"), parent_mount) or
                    not os.path.samestat(os.stat("/proc/self/ns/net"), parent_net)):
                errors.append("the qualification parent's original namespace changed")
            if retained_mounts:
                errors.append("private resolver mounts retained for original namespace teardown")
            record["processes_joined"] = all(item["process"].poll() is not None for item in processes)
            record["mounts_retained_for_namespace_teardown"] = retained_mounts
            record["cleanup_complete"] = not errors and not retained_mounts
            record["cleanup_errors"] = errors
            try:
                save()
                print("SMART isolated resolver retirement: " + json.dumps(record, sort_keys=True), flush=True)
            except BaseException as error:
                errors.append("resolver receipt: " + type(error).__name__)
            if errors:
                cleanup_error = RuntimeError("SMART isolated resolver cleanup failed: " + "; ".join(errors))
                if failure is None:
                    raise cleanup_error
                failure.add_note(str(cleanup_error))


@contextmanager
def controller(work, user, password, helpers=None):
    helpers = work.parent if helpers is None else helpers
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
    launch = subprocess.Popen(["openvt", "-c", str(vt), "-s", "-w", "--", helpers / "login", user, password,
                               helpers / "session.py", session, login_log, completed])

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
    retirement_complete = False
    resolver = ExitStack()
    try:
        pid = wait_for(prove, "active VT authorization and the original controller identity", 90)
        resolver.enter_context(controller_resolver(work, pid, prove, lambda: retirement_complete))
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
            retirement_complete = True
        except BaseException as error:
            if failure is None:
                failure = error
                raise
            failure.add_note("Session retirement also failed: " + type(error).__name__ + "; " + diagnostics())
        finally:
            # Keep the owned resolver alive until the original controller/PAM
            # retirement attempt has joined. Failed cases still fail and the
            # outer namespace cleanup retains its existing owned-process checks.
            try:
                resolver.close()
            except BaseException as error:
                if failure is None:
                    raise
                failure.add_note("Owned resolver retirement also failed: " + type(error).__name__)


@contextmanager
def canary(peer, policy):
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
    started = time.monotonic()
    protected_count = 0
    first_protected_ms = last_protected_ms = retirement_ms = None
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
            nonlocal protected_count, first_protected_ms, last_protected_ms
            receiver.settimeout(.1)
            while True:
                try:
                    payload = receiver.recv(100)
                except TimeoutError:
                    if stop.is_set():
                        return
                    continue
                if payload == nonce + b"protected":
                    now = round((time.monotonic()-started)*1000)
                    protected_count += 1
                    if first_protected_ms is None:
                        first_protected_ms = now
                    last_protected_ms = now
                    leaked.set()
                if payload == nonce + b"control":
                    control.set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            workers = [pool.submit(receive), pool.submit(send)]
            def retire():
                nonlocal retirement_ms
                if retirement_ms is None:
                    retirement_ms = round((time.monotonic()-started)*1000)
                stop.set()
                failure = None
                for future in workers:
                    try:
                        future.result(timeout=5)
                    except BaseException as error:
                        if failure is None:
                            failure = error
                        else:
                            failure.add_note("Another physical canary worker failed: " + type(error).__name__)
                if failure is not None:
                    raise failure
            failure = None
            try:
                if not control.wait(5):
                    raise RuntimeError("The physical leak canary failed its positive control")
                yield armed, control, retire
            except BaseException as error:
                failure = error
                raise
            finally:
                try:
                    retire()
                except BaseException as error:
                    if failure is None:
                        raise
                    failure.add_note("Physical canary retirement also failed: " + type(error).__name__)
                if leaked.is_set():
                    if failure is None:
                        raise RuntimeError("Protected SMART leaked a canary to the physical peer")
                    # Preserve the failed request as the primary error. In a
                    # failed On-connect case, its accepted Off can precede the
                    # API error; these packet times alone cannot locate that Off.
                    failure.add_note("Protected-tagged canary packets during the failed case: " + json.dumps({
                        "policy": policy, "packets": protected_count,
                        "first_received_ms": first_protected_ms, "last_received_ms": last_protected_ms,
                        "retirement_started_ms": retirement_ms,
                        "receiver_joined": workers[0].done(), "sender_joined": workers[1].done(),
                        "on_connect_release_interval_unproved": policy == "on-connect"}))


@contextmanager
def retire_failed_canary(policy, retire):
    try:
        yield
    except BaseException as error:
        if policy == "on-connect":
            # The failed body, including its request and monitor, has joined.
            # Join/drain the original sender before controller/PAM cleanup can
            # release On-connect protection. Keep all recorded packets intact.
            try:
                retire()
            except BaseException as cleanup:
                error.add_note("Physical canary retirement before controller cleanup failed: " + type(cleanup).__name__)
        raise


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
        with canary(peer_ns, policy) as (armed, control, retire_canary), \
                controller(work, user, password) as (owner, headers), retire_failed_canary(policy, retire_canary):
            with (work / "nft.events").open("wb") as log:
                monitor = subprocess.Popen(["stdbuf", "-oL", "nft", "-nn", "monitor"], stdout=log)
                result = None
                observed_stages = {}
                trace_started = time.monotonic()
                first_ready_ms = first_proof_ms = None
                first_proof = None
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
                        first = None
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
                                    stage = native_stage(data, directory)
                                    previous = observed_stages.get(data["pid"], {})
                                    elapsed_ms = round((time.monotonic()-trace_started)*1000)
                                    stage["first_seen_ms"] = previous.get("first_seen_ms", elapsed_ms)
                                    stage["last_seen_ms"] = elapsed_ms
                                    if "first_ready_ms" in previous:
                                        stage["first_ready_ms"] = previous["first_ready_ms"]
                                        stage["first_ready_numbers"] = previous.get("first_ready_numbers", {})
                                    elif stage["ready"]:
                                        stage["first_ready_ms"] = elapsed_ms
                                        stage["first_ready_numbers"] = stage.get("ready_numbers", {})
                                    observed_stages[data["pid"]] = stage
                                except Exception:
                                    pass  # Diagnostics cannot replace the original qualification failure.
                                if key not in sessions or "ready" not in sessions[key]:
                                    sessions[key] = data
                                if data["mode"] == source and first is None and "ready" in data:
                                    first = data
                                    first_ready_ms = round((time.monotonic()-trace_started)*1000)
                                    armed.set()
                            if first is not None and first_proof is None:
                                observation = peers.observation()
                                if observation["http"] and observation["dns"] and (
                                        observation["pq_key_applied"] if source == "wg-pq" else observation["source_uot"]):
                                    first_proof = observation
                                    first_proof_ms = round((time.monotonic()-trace_started)*1000)
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
                        timing = {"elapsed_ms": round((time.monotonic()-trace_started)*1000),
                                  "source_first_ready_ms": first_ready_ms,
                                  "source_first_peer_proof_ms": first_proof_ms,
                                  "source_first_peer_counters": first_proof,
                                  "candidate_enabled": peers.enabled,
                                  "peer_processes": [{"name": name, "pid": process.pid, "exit_code": process.poll()}
                                      for name, process in list(peers.processes.items())[:16]]}
                        try:
                            timing["peer_observation"] = peers.observation(diagnostic=True)
                        except Exception as diagnostic_failure:
                            timing["peer_observation_error_type"] = type(diagnostic_failure).__name__
                        error.add_note("SMART failure timing and peer counters: " + json.dumps(timing, ensure_ascii=True))
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


@contextmanager
def fixture_directory(prefix, parent, retirement):
    directory = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    original = directory.stat()
    try:
        yield directory
    finally:
        if not retirement["complete"]:
            print("SMART retained original fixture directory after unproved retirement:", directory, flush=True)
        else:
            try:
                if not os.path.samestat(original, directory.stat()):
                    raise RuntimeError("The original fixture directory was replaced before cleanup")
                shutil.rmtree(directory)
            except BaseException:
                retirement["complete"] = False
                raise


@contextmanager
def installed_case(template, work, retirement, namespace_factory=paired_namespaces):
    # The production journal and stable locks are siblings of INSTALL under
    # /opt. Each independent network namespace needs its own complete ancestry;
    # a new application overlay alone must not inherit another case's journal.
    previous = os.stat("/opt")
    run("mount", "-t", "tmpfs", "-o", "mode=0755,size=4m",
        "routervpn-smart-case-" + secrets.token_hex(12), "/opt")
    anchor = os.stat("/opt")
    namespaces = ExitStack()
    overlay = None
    try:
        if os.path.samestat(previous, anchor):
            raise RuntimeError("The case did not acquire a fresh installation ancestry")
        INSTALL.mkdir(mode=0o755)
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
        overlay = INSTALL.stat()
        if stat.S_IMODE(overlay.st_mode) != installed_mode:
            raise RuntimeError("Mounted application root differs from the installed directory mode")
        yield namespaces.enter_context(namespace_factory())
    finally:
        # Join both original namespace process groups before releasing their
        # installation ancestry. A failed join leaves these mounts retained.
        namespaces.close()
        if overlay is not None:
            if not os.path.samestat(overlay, INSTALL.stat()):
                raise RuntimeError("The case's original installed overlay was replaced")
            run("umount", INSTALL)
        if not os.path.samestat(anchor, os.stat("/opt")):
            raise RuntimeError("The case's original installation ancestry was replaced")
        run("umount", "/opt")
        if not os.path.samestat(previous, os.stat("/opt")):
            raise RuntimeError("The previous private installation ancestry was not restored")
        retirement["complete"] = True


def root_fixture(archive, references, ordered_admission=None, ordered_evidence=None):
    if os.getuid() or os.path.samefile("/proc/self/ns/mnt", "/proc/1/ns/mnt"):
        raise RuntimeError("Qualification requires its own private root mount namespace")
    for name in ("/dev/net/tun", "/dev/tty0", "/sys/class/tty/tty0/active", "/run/systemd/system"):
        if not Path(name).exists():
            raise RuntimeError(f"Hosted Linux qualification requires a real foreground VT, logind and TUN (missing {name})")
    run("loginctl", "show-seat", "seat0", "--property=CanTTY")
    run("mount", "-t", "tmpfs", "-o", "mode=0755,size=4m", "tmpfs", "/opt")
    INSTALL.mkdir(mode=0o755)
    retirement = {"complete": True}
    with fixture_directory("routervpn-smart-", "/var/tmp", retirement) as temp, ExitStack() as cleanup:
        temp.chmod(0o711)
        secure = temp / "private"
        secure.mkdir(mode=0o700)
        for key, exe in (("ROSENPASS", "rosenpass"), ("ROUTER_AGENT", "router-agent")):
            shutil.copyfile(references / exe, secure / exe)
            (secure / exe).chmod(0o700)
            os.environ["ROUTERVPN_QUALIFICATION_" + key] = str(secure / exe)
        template = install_image(archive, secure)
        admitted = None
        if ordered_admission is not None:
            admitted = ordered_package_admission(archive, template, secure/archive.name.removesuffix(".tar.gz"), ordered_admission)
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
        if admitted is not None:
            ordered_installed_case(template, temp, user, password, retirement, admitted, ordered_evidence)
            return
        for source, candidate, policy, layer, outcome in matrix(archive.name):
            label = "-".join((source, candidate, policy, layer, outcome))
            print("Qualifying installed SMART", label, flush=True)
            retirement["complete"] = False
            with fixture_directory(label+"-", temp, retirement) as work:
                work.chmod(0o711)
                with installed_case(template, work, retirement) as (client, peer):
                    run("ip", "netns", "exec", client, sys.executable, HERE, "--case",
                        work, user, password, peer, source, candidate, policy, layer, outcome, timeout=650)


def matrix(package_name):
    # Each architecture runs every transport, layer and policy with one outcome.
    # Together the two release jobs exercise successful and restored trials for each.
    arch = 0 if "amd64" in package_name else 1
    for pair, (source, candidate) in enumerate(PAIRS):
        for number, layer in enumerate(("off", "aes-256-gcm", "aes-256-gcm+xor-whitening")):
            for position, policy in enumerate(("on-connect", "always")):
                outcome = ("success", "restore")[(arch + pair + number + position) % 2]
                yield source, candidate, policy, layer, outcome



class OrderedPublicRelay:
    """Pass unchanged TCP/TLS bytes to one numeric public endpoint only."""
    def __init__(self, address, client, deadline):
        self.address, self.client, self.deadline = address, client, deadline
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.sockets, self.workers, self.errors = set(), [], []
        self.counts = {'accepted':0,'public_connected':0,'to_public':0,'from_public':0}
        self.listener = None
        self.worker = None
        self.started = False

    def open(self):
        self.listener = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sockets.add(self.listener)
        self.listener.bind((self.address,0))
        self.listener.listen(16)
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.worker = threading.Thread(target=self.accept,name='ordered-public-listener')
        self.started = False

    def start(self):
        previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        try:
            self.worker.start()
            self.started = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK,previous)

    def record_error(self, error):
        with self.lock:
            self.errors.append(type(error).__name__)
        self.stop.set()

    def accept(self):
        try:
            while not self.stop.is_set() and time.monotonic()<self.deadline:
                try:
                    conn,peer = self.listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self.stop.is_set():
                        return
                    raise
                with self.lock:
                    self.sockets.add(conn)
                    if self.stop.is_set():
                        conn.close()
                        self.sockets.remove(conn)
                        return
                    if peer[0]!=self.client or sum(w.is_alive() for w in self.workers)>=16:
                        conn.close()
                        self.sockets.remove(conn)
                        raise RuntimeError('Unexpected original public relay peer or capacity')
                    self.counts['accepted']+=1
                    child=threading.Thread(target=self.forward,args=(conn,),name='ordered-public-stream')
                    self.workers.append(child)
                    child.start()
        except BaseException as error:
            self.record_error(error)

    def forward(self, incoming):
        outgoing = None
        try:
            if self.stop.is_set():
                return
            outgoing = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            with self.lock:
                self.sockets.add(outgoing)
            outgoing.settimeout(min(5,max(.01,self.deadline-time.monotonic())))
            outgoing.connect(('1.1.1.1',443))
            with self.lock:
                self.counts['public_connected']+=1
            incoming.setblocking(False)
            outgoing.setblocking(False)
            peers={incoming:outgoing,outgoing:incoming}
            pending={incoming:bytearray(),outgoing:bytearray()}
            readable={incoming,outgoing}
            shutdown=set()
            while not self.stop.is_set() and time.monotonic()<self.deadline:
                reads=[s for s in readable if len(pending[peers[s]])<(256<<10)]
                writes=[s for s in peers if pending[s]]
                if not reads and not writes:
                    break
                ready_read,ready_write,_=select.select(reads,writes,[],.2)
                for current in ready_read:
                    try:
                        data=current.recv(65536)
                    except BlockingIOError:
                        continue
                    if data:
                        pending[peers[current]].extend(data)
                    else:
                        readable.remove(current)
                for current in ready_write:
                    try:
                        written=current.send(pending[current])
                    except BlockingIOError:
                        continue
                    if not written:
                        raise RuntimeError('Original public relay made no write progress')
                    del pending[current][:written]
                    with self.lock:
                        self.counts['to_public' if current is outgoing else 'from_public']+=written
                for current,peer in peers.items():
                    if current not in readable and not pending[peer] and peer not in shutdown:
                        peer.shutdown(socket.SHUT_WR)
                        shutdown.add(peer)
        except (ConnectionResetError,BrokenPipeError):
            # A normal canceled production probe may terminate its exact stream.
            pass
        except OSError as error:
            if not self.stop.is_set():
                self.record_error(error)
        except BaseException as error:
            self.record_error(error)
        finally:
            for original in (incoming,outgoing):
                if original is None:
                    continue
                try:
                    original.close()
                except OSError as error:
                    self.record_error(error)
                with self.lock:
                    self.sockets.discard(original)

    def close(self):
        self.stop.set()
        errors=[]
        with self.lock:
            original_sockets=list(self.sockets)
        for original in original_sockets:
            try:
                original.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                original.close()
            except OSError as error:
                errors.append(type(error).__name__)
        if self.started:
            self.worker.join(5)
        with self.lock:
            workers=list(self.workers)
        until=time.monotonic()+5
        for worker in workers:
            if worker.ident is not None:
                worker.join(max(0,until-time.monotonic()))
        alive=self.started and self.worker.is_alive() or any(w.is_alive() for w in workers)
        with self.lock:
            errors+=self.errors
            result=dict(self.counts,listener_joined=not(self.started and self.worker.is_alive()),
                        stream_workers=len(workers),streams_joined=all(not w.is_alive() for w in workers),
                        original_sockets_closed=all(s.fileno()<0 for s in original_sockets) and
                            all(s.fileno()<0 for s in self.sockets),errors=errors)
        if alive or errors or not result['original_sockets_closed']:
            raise RuntimeError('Original fixed-target public relay did not retire cleanly')
        return result


def ordered_json(args):
    result=subprocess.run(list(args),check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    if len(result.stdout)>(2<<20):
        raise RuntimeError('Ordered kernel readback exceeded its bound')
    return json.loads(result.stdout)


def ordered_host_snapshot():
    result={}
    for family in ('-4','-6'):
        for kind in ('route','rule'):
            args=['ip',family,'-j',kind,'show']+(['table','all'] if kind=='route' else [])
            result[family+'/'+kind]=sorted(json.dumps(row,sort_keys=True) for row in ordered_json(args))
    result['links']=sorted(json.dumps({k:row.get(k) for k in ('ifindex','ifname','address','mtu','ifalias')},sort_keys=True)
                           for row in ordered_json(['ip','-j','link','show']))
    result['forwarding']={p:Path(p).read_text().strip() for p in
        ('/proc/sys/net/ipv4/ip_forward','/proc/sys/net/ipv6/conf/all/forwarding')}
    result['resolv_sha256']=hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest()
    return result


def ordered_private_subnets():
    import ipaddress
    occupied=[ipaddress.ip_network('172.30.241.0/24'),ipaddress.ip_network('10.77.0.0/16')]
    for row in ordered_json(['ip','-4','-j','route','show','table','all']):
        destination=row.get('dst','default')
        if destination!='default':
            occupied.append(ipaddress.ip_network(destination,strict=False))
    chosen=[]
    for _ in range(128):
        network=ipaddress.ip_network('172.%d.%d.%d/30' %
            (16+secrets.randbelow(16),secrets.randbelow(256),4*secrets.randbelow(64)))
        if any(network.overlaps(other) for other in occupied+chosen):
            continue
        chosen.append(network)
        if len(chosen)==2:
            return chosen
    raise RuntimeError('No independent private /30 is available for original ordered links')



def ordered_public_rule(namespace, table, owner, host, port):
    data=ordered_json(['ip','netns','exec',namespace,'nft','-j','-a','list','table','ip',table])
    rows=data['nftables']
    rules=[row['rule'] for row in rows if 'rule' in row]
    chains=[row['chain'] for row in rows if 'chain' in row]
    ordered_require(len(rules)==len(chains)==1 and chains[0].get('name')=='output' and
                    chains[0].get('type')=='nat' and chains[0].get('hook')=='output' and
                    chains[0].get('prio')==-100 and chains[0].get('policy')=='accept',
                    'Original final public redirection chain changed')
    rule=rules[0]
    ordered_require(rule.get('family')=='ip' and rule.get('table')==table and rule.get('chain')=='output' and
                    rule.get('comment')==owner and rule.get('handle'),
                    'Original final public redirection rule changed owner')
    expr=rule['expr']
    matches=[item['match'] for item in expr if 'match' in item]
    expected=[{'op':'==','left':{'payload':{'protocol':'ip','field':'daddr'}},'right':'1.1.1.1'},
              {'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':443}]
    dnat=[item['dnat'] for item in expr if 'dnat' in item]
    counters=[item['counter'] for item in expr if 'counter' in item]
    ordered_require(matches==expected and len(dnat)==len(counters)==1 and len(expr)==4 and
                    dnat[0].get('addr')==host and dnat[0].get('port')==port,
                    'Final public redirection expanded beyond its original exact TCP tuple')
    sealed=[]
    for row in rows:
        if 'metainfo' in row:
            continue
        copied=json.loads(json.dumps(row))
        if 'rule' in copied:
            copied['rule']['expr']=[{'counter':{}} if 'counter' in item else item for item in copied['rule']['expr']]
        sealed.append(copied)
    return sealed


def remove_ordered_namespace(name, original):
    ordered_require(os.path.samestat(original,os.stat('/run/netns/'+name)),
                    'The original ordered namespace was replaced before retirement')
    remove_namespace(name)


def ordered_uplink_pair(host_link, peer_link, namespace):
    ordered_require(os.path.samestat(namespace,os.stat('/proc/self/ns/net')),
                    'Original host namespace changed during uplink capture')
    links=[]
    for name in (host_link,peer_link):
        rows=ordered_json(['ip','-j','-d','link','show','dev',name])
        ordered_require(len(rows)==1, 'Original created uplink endpoint is not unique')
        row=rows[0]
        ordered_require(row.get('ifname')==name and type(row.get('ifindex')) is int and row['ifindex']>0 and
                        row.get('linkinfo',{}).get('info_kind')=='veth' and
                        re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',row.get('address','')) is not None,
                        'Original created uplink endpoint identity was not captured')
        links.append(row)
    first,second=links
    ordered_require(first['ifindex']!=second['ifindex'] and
                    int(Path('/sys/class/net',host_link,'iflink').read_text().strip())==second['ifindex'] and
                    int(Path('/sys/class/net',peer_link,'iflink').read_text().strip())==first['ifindex'] and
                    os.path.samestat(namespace,os.stat('/proc/self/ns/net')),
                    'Original created uplink pair or namespace changed')
    identity=tuple((row['ifname'],row['ifindex'],row['address']) for row in links)
    return first,identity


@contextmanager
def ordered_namespaces(work):
    before=ordered_host_snapshot()
    suffix=secrets.token_hex(5)
    final='rvordered-f-'+suffix
    host_link='rvo'+suffix
    moved_link='rvp'+suffix
    owner='routervpn-ordered:'+suffix
    peer_net,uplink_net=ordered_private_subnets()
    peer_ip,final_ip=map(str,list(peer_net.hosts()))
    host_ip,uplink_ip=map(str,list(uplink_net.hosts()))
    records={'schema':1,'kind':'installed-complete-node-chain-topology-v1','owner':owner,
             'host_link':host_link,'peer_private':peer_ip,'final_private':final_ip,
             'host_uplink':host_ip,'final_uplink':uplink_ip,'final':final}
    failure=None
    relay=None
    relay_receipt=None
    identities={}
    host_identity=None
    owner_capture={}
    table=None
    route=None
    rule_seal=None
    host_attempted=False
    cleanup_errors=[]
    try:
        with paired_namespaces() as (client,peer), ExitStack() as cleanup:
            records.update(client=client,peer=peer)
            try:
                run('ip','netns','add',final)
                final_original=os.stat('/run/netns/'+final)
                cleanup.callback(remove_ordered_namespace,final,final_original)
                run('ip','-n',final,'link','set','lo','up')
                for name in (client,peer,final):
                    identities[name]=(os.open('/run/netns/'+name,os.O_RDONLY),None)
                    descriptor=identities[name][0]
                    identities[name]=(descriptor,os.fstat(descriptor))
                run('ip','-n',peer,'link','add','ordered-final','type','veth','peer','name','ordered-peer','netns',final)
                for namespace,link,address in ((peer,'ordered-final',peer_ip),(final,'ordered-peer',final_ip)):
                    run('ip','-n',namespace,'addr','add',address+'/30','dev',link)
                    run('ip','-n',namespace,'link','set',link,'mtu','9000','up')
                if any(row['ifname'] in (host_link,moved_link) for row in ordered_json(['ip','-j','link','show'])):
                    raise RuntimeError('An original ordered uplink name is already present')
                host_namespace=os.stat('/proc/self/ns/net')
                host_attempted=True
                run('ip','link','add','name',host_link,'type','veth','peer','name',moved_link)
                host_identity,created_pair=ordered_uplink_pair(host_link,moved_link,host_namespace)
                owner_capture.update(expected_alias=owner,namespace_device=host_namespace.st_dev,
                                     namespace_inode=host_namespace.st_ino,created_host=host_identity,
                                     created_pair=created_pair)
                # Linux applies IFLA_IFALIAS when updating the retained link, not when creating it.
                run('ip','link','set','dev',host_link,'alias',owner)
                tagged,tagged_pair=ordered_uplink_pair(host_link,moved_link,host_namespace)
                owner_capture.update(tagged_host=tagged,tagged_pair=tagged_pair,
                                     pair_equal=tagged_pair==created_pair,alias_equal=tagged.get('ifalias')==owner)
                if tagged_pair!=created_pair or tagged.get('ifalias')!=owner:
                    raise RuntimeError('Original host uplink owner was not captured')
                host_identity=tagged
                run('ip','link','set',moved_link,'netns',final)
                run('ip','-n',final,'link','set',moved_link,'name','ordered-uplink')
                run('ip','addr','add',host_ip+'/30','dev',host_link)
                run('ip','link','set',host_link,'mtu','9000','up')
                run('ip','-n',final,'addr','add',uplink_ip+'/30','dev','ordered-uplink')
                run('ip','-n',final,'link','set','ordered-uplink','mtu','9000','up')
                for namespace,link in ((client,'smartphy'),(peer,'smartpeer')):
                    run('ip','-n',namespace,'link','set',link,'mtu','9000')
                records['physical_interfaces']={namespace:ordered_json(['ip','-n',namespace,'-j','link','show','dev',link])[0]
                    for namespace,link in ((client,'smartphy'),(peer,'smartpeer'))}
                ordered_require(all(row['mtu']==9000 for row in records['physical_interfaces'].values()),
                                'Original ordered physical interface MTU did not bind its carrier capacity')
                records['captured_carrier_mtu']=2000
                records['final_tun_mtu']=1280
                records['host_ifindex']=host_identity['ifindex']
                records['final_uplink_ifindex']=ordered_json(['ip','-n',final,'-j','link','show','dev','ordered-uplink'])[0]['ifindex']
                records['namespace_inodes']={name:original.st_ino for name,(_,original) in identities.items()}
                relay=OrderedPublicRelay(host_ip,uplink_ip,time.monotonic()+650)
                relay.open()
                records['relay_port']=relay.port
                table='ordered_public_'+suffix
                run('ip','netns','exec',final,'nft','create','table','ip',table)
                run('ip','netns','exec',final,'nft','-f','-',input=(
                    'table ip '+table+' { chain output { type nat hook output priority -100; policy accept; '+
                    'ip daddr 1.1.1.1 tcp dport 443 counter dnat to '+host_ip+':'+str(relay.port)+
                    ' comment "'+owner+'"; } }\n').encode())
                run('ip','-n',final,'route','add','1.1.1.1/32','via',host_ip,'dev','ordered-uplink')
                records['public_route']=ordered_json(['ip','-n',final,'-j','route','show','1.1.1.1/32'])
                route=records['public_route']
                rule_seal=ordered_public_rule(final,table,owner,host_ip,relay.port)
                records['public_rule']=rule_seal
                if len(route)!=1 or route[0].get('gateway')!=host_ip or route[0].get('dev')!='ordered-uplink' or route[0].get('dst') not in ('1.1.1.1','1.1.1.1/32'):
                    raise RuntimeError('Original final namespace public /32 route did not bind')
                if any(row.get('dst','default')=='default' for row in ordered_json(['ip','-n',final,'-j','route','show'])):
                    raise RuntimeError('Final peer unexpectedly has a public default route')
                private_write(work/'ordered-topology.json',records)
                relay.start()
                yield records
                ordered_require(ordered_public_rule(final,table,owner,host_ip,relay.port)==rule_seal and
                                ordered_json(['ip','-n',final,'-j','route','show','1.1.1.1/32'])==route,
                                'Original final public rule or route changed during the actual case')
                ordered_require(ordered_json(['ip','-n',final,'-j','link','show','dev','ordered-uplink'])[0]['ifindex']==
                                records['final_uplink_ifindex'], 'Original final uplink interface was replaced')
                for name,(descriptor,original) in identities.items():
                    if not os.path.samestat(original,os.stat('/run/netns/'+name)):
                        raise RuntimeError('Original ordered namespace was replaced')
                    if subprocess.check_output(['ip','netns','pids',name],text=True,timeout=10).split():
                        raise RuntimeError('Original ordered namespace still contains unjoined processes')
            except BaseException as error:
                failure=error
                raise
            finally:
                # A late first signal must not interrupt original joins/restoration.
                signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
                if relay is not None:
                    try:
                        relay_receipt=relay.close()
                    except BaseException as error:
                        cleanup_errors.append(type(error).__name__)
                if route is not None:
                    try:
                        ordered_require(ordered_json(['ip','-n',final,'-j','route','show','1.1.1.1/32'])==route,
                                        'Original final public route was replaced before retirement')
                        run('ip','-n',final,'route','delete','1.1.1.1/32','via',host_ip,'dev','ordered-uplink')
                    except BaseException as error:
                        cleanup_errors.append('route:'+type(error).__name__)
                if table is not None:
                    try:
                        if rule_seal is not None:
                            ordered_require(ordered_public_rule(final,table,owner,host_ip,relay.port)==rule_seal,
                                            'Original public redirection was replaced before retirement')
                        run('ip','netns','exec',final,'nft','delete','table','ip',table)
                    except BaseException as error:
                        cleanup_errors.append(type(error).__name__)
                if host_attempted:
                    try:
                        current=ordered_json(['ip','-j','link','show','dev',host_link])[0]
                        owner_capture['retirement_host']=current
                        if (host_identity is None or current.get('ifalias')!=owner or
                                current['ifindex']!=host_identity['ifindex'] or
                                current.get('address')!=host_identity.get('address') or
                                not os.path.samestat(host_namespace,os.stat('/proc/self/ns/net'))):
                            raise RuntimeError('Original host uplink was replaced')
                        run('ip','link','delete','dev',host_link)
                    except BaseException as error:
                        cleanup_errors.append(type(error).__name__)
                if cleanup_errors:
                    if failure is not None:
                        failure.add_note('Original ordered topology retirement failed: '+','.join(cleanup_errors))
                    else:
                        raise RuntimeError('Original ordered topology retirement failed')
    except BaseException as error:
        if failure is None:
            failure=error
        elif error is not failure:
            failure.add_note('Original namespace context retirement also failed: '+type(error).__name__)
        raise failure
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        # All original namespace process scans and context retirements precede
        # final descriptor closure and publication of an accepted receipt.
        for name,(descriptor,original) in identities.items():
            try:
                os.close(descriptor)
                ordered_require(not Path('/run/netns/'+name).exists(),
                                'An original ordered namespace name survived retirement')
            except BaseException as error:
                cleanup_errors.append('namespace:'+type(error).__name__)
        try:
            ordered_require(ordered_host_snapshot()==before,
                            'Host routes, interfaces, forwarding or DNS were not restored')
        except BaseException as error:
            cleanup_errors.append('host:'+type(error).__name__)
        receipt={'schema':1,'kind':'installed-complete-node-chain-topology-v1',
                 'status':'passed' if failure is None and not cleanup_errors else 'failed',
                 'relay':relay_receipt,'host_restored':not cleanup_errors,
                 'namespace_descriptors_closed':not any(e.startswith('namespace:') for e in cleanup_errors),
                 'physical_interfaces':records.get('physical_interfaces'),
                 'uplink_owner_capture':owner_capture,
                 'captured_carrier_mtu':records.get('captured_carrier_mtu'),
                 'final_tun_mtu':records.get('final_tun_mtu'),'cleanup_errors':cleanup_errors}
        try:
            private_write(work/'ordered-topology-result.json',receipt)
        except BaseException as evidence_error:
            if failure is None:
                raise
            failure.add_note('Original topology receipt also failed: '+type(evidence_error).__name__)
        if cleanup_errors and failure is None:
            raise RuntimeError('Original ordered topology terminal readback failed')



def ordered_require(value, message):
    if not value:
        raise RuntimeError(message)


def ordered_sha(value):
    return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None


def ordered_profile_tokens(catalog, ids):
    rows={row['id']:row for row in catalog['profiles']}
    ordered_require(len(rows)==len(catalog['profiles']) and all(i in rows for i in ids),
                    'Original ordered profile inventory is incomplete or ambiguous')
    result={i:rows[i]['profile_token'] for i in ids}
    ordered_require(all(ordered_sha(token) for token in result.values()),
                    'Original ordered profile revision is missing')
    return result


def ordered_load(headers, saved, device, tokens, nodes, request):
    base='/api/connection-profile/setup/load/'
    operation=secrets.token_hex(16)
    bound=None
    finished=False
    failure=None
    try:
        status=request(base+'status',{'operation_id':operation})
        ordered_require(status.get('ok') and status['transaction']['operation_id']==operation and
                        status['transaction']['state']=='absent' and str(status['revision']).isdigit(),
                        'Original profile Load operation was not absent')
        prepared=request(base+'prepare',{'operation_id':operation,'expected_revision':status['revision'],
            'id':saved['profile_id'],'expected_mode':'shadowsocks','expected_selected_node_id':device,
            'expected_profile_tokens':tokens})
        receipt=prepared['transaction']
        ordered_require(prepared.get('ok') and receipt['operation_id']==operation and
                        receipt['state']=='prepared' and not receipt['finished'] and
                        receipt['generation'] and ordered_sha(receipt['receipt_sha256']),
                        'Original profile Load preparation did not bind its receipt')
        bound={key:receipt[key] for key in ('operation_id','generation','receipt_sha256')}
        snapshot=prepared['snapshot']
        ordered_require(snapshot['selected_node_id']==nodes[-1]['id'] and
                        snapshot['profile']['id']==saved['profile_id'] and
                        snapshot['profile']['name']==saved['profile_name'] and
                        snapshot['profile']['mode']=='shadowsocks' and
                        snapshot['multihop_nodes']==nodes and snapshot['multihop_execution']=='local' and
                        snapshot.get('multihop_enabled') is True,
                        'Original profile Load changed the saved complete path')
        committed=request(base+'commit',bound)
        ordered_require(committed.get('ok') and committed['transaction']['state']=='committed' and
                        all(committed['transaction'][key]==value for key,value in bound.items()),
                        'Original profile Load commit lost its preparation')
        result=request(base+'finish',bound)
        ordered_require(result.get('ok') and result['transaction']['finished'] and
                        result['transaction']['state']=='committed' and
                        all(result['transaction'][key]==value for key,value in bound.items()),
                        'Original profile Load transaction did not finish')
        finished=True
        return {'operation_id':operation,'generation':bound['generation'],
                'receipt_sha256':bound['receipt_sha256'],'finished':True}
    except BaseException as error:
        failure=error
        raise
    finally:
        if not finished:
            try:
                # Recover only this original operation; never invent a replacement.
                status=api(base+'status',method='POST',headers=headers,timeout=10,
                           body={'operation_id':operation})
                receipt=status.get('transaction',{})
                if receipt.get('operation_id')!=operation:
                    raise RuntimeError('Failed Load status lost its original operation')
                if receipt.get('state')!='absent' and not receipt.get('finished'):
                    exact={key:receipt[key] for key in ('operation_id','generation','receipt_sha256')}
                    if not ordered_sha(exact['receipt_sha256']) or not exact['generation']:
                        raise RuntimeError('Failed Load operation has no exact retirement receipt')
                    api(base+'abort',method='POST',headers=headers,timeout=10,body=exact)
                    ended=api(base+'finish',method='POST',headers=headers,timeout=10,body=exact)
                    ordered_require(ended['transaction']['finished'], 'Original failed Load did not finish')
            except BaseException as cleanup:
                if failure is None:
                    raise
                failure.add_note('Original Load retirement also failed: '+type(cleanup).__name__)


class OrderedNativeObserver:
    def __init__(self, parent, started, nodes, proof_ids, companions):
        self.parent,self.started=parent,started
        self.nodes,self.proof_ids=nodes,proof_ids
        # compileMember retains encoded original WG assets, not a NodeProfile launch.
        self.companions=tuple({name:base64.b64encode(bytes(body)).decode('ascii')
                               for name,body in files.items()} for files in companions)
        ordered_require(len(self.companions)==len(nodes)==len(proof_ids)==3 and
                        all(files for files in self.companions),
                        'Original paired companion asset inventory is incomplete')
        self.pid=self.pidfd=self.directory=None
        self.pinned={}
        self.identity=None
        self.first=None

    @staticmethod
    def private(path):
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(descriptor,'rb') as stream:
            info=os.fstat(stream.fileno())
            ordered_require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==0,
                            'Original ordered native source file changed ownership')
            raw=stream.read((4<<20)+1)
            ordered_require(len(raw)<=(4<<20), 'Original ordered native source exceeded its bound')
        return json.loads(raw),(info.st_dev,info.st_ino,info.st_size,hashlib.sha256(raw).hexdigest())

    def capture(self):
        children=set()
        for task in Path('/proc/%d/task'%self.parent).iterdir():
            try:
                children.update((task/'children').read_text().split())
            except FileNotFoundError:
                continue
        matches=[]
        for value in children:
            try:
                pid=int(value)
                args=Path('/proc/%d/cmdline'%pid).read_bytes().decode().split('\0')
                if 'routervpn-node-chain' in args and os.path.samefile('/proc/%d/exe'%pid,ENGINE):
                    matches.append((pid,args))
            except FileNotFoundError:
                continue
        ordered_require(len(matches)==1,'The protected installed parent has no unique original ordered child')
        pid,args=matches[0]
        flags={name:args[args.index(name)+1] for name in
               ('--runtime-dir','--session','--config-sha256','--physical-source-sha256',
                '--linux-parent-channel','--linux-parent-directory','--linux-parent-capture')}
        ordered_require(flags['--linux-parent-channel']=='3' and flags['--linux-parent-directory']=='4' and
                        ordered_sha(flags['--linux-parent-capture']),
                        'The original ordered child lost its inherited Linux parent contract')
        if self.pid is None:
            self.pid=pid
            self.pidfd=os.pidfd_open(pid)
            self.proc_identity=os.stat('/proc/%d'%pid)
            self.flags=flags
            self.directory=Path(flags['--runtime-dir'])
        ordered_require(self.pid==pid and self.flags==flags and
                        os.path.samestat(self.proc_identity,os.stat('/proc/%d'%pid)) and
                        not select.select([self.pidfd],[],[],0)[0],
                        'The original ordered child changed or stopped')
        source,source_info=self.private(self.directory/'node-chain-source.json')
        config,config_info=self.private(self.directory/'sing-box.json')
        for name,info in (('source',source_info),('config',config_info)):
            ordered_require(self.pinned.setdefault(name,info)==info,
                            'Original ordered native input was replaced')
        physical,_=self.private(self.directory/'node-ready.json')
        ready,_=self.private(self.directory/'node-chain-ready.json')
        mtu,_=self.private(self.directory/'node-mtu-status.json')
        identity=ready['identity']
        ordered_require(source['schema']==1 and source['kind']=='routervpn-node-chain-launch-input' and
                        source['execution']=='local' and len(source['nodes'])==3 and len(source['identity_sources'])==3,
                        'Native launch input is not the actual complete three-node Local source')
        original_rows=[]
        for raw,companion,node,proof,expected in zip(source['nodes'],source['identity_sources'],self.nodes,self.proof_ids,self.companions):
            member=json.loads(raw)
            identity_files=json.loads(companion)
            profile=json.loads(member['profile_json'])
            encoded_identity=json.dumps(expected,sort_keys=True,separators=(',',':'))
            ordered_require(isinstance(identity_files,dict) and identity_files==expected and
                            companion==encoded_identity and member.get('schema')==1 and
                            member.get('kind')=='routervpn-node-launch-input' and
                            member.get('mode')==node['mode'] and profile.get('id')==node['id'] and
                            profile.get('node_kind')=='router-vpn' and profile.get('node_proof_id')==proof and
                            profile.get('start_layer')=='off' and not member.get('start') and
                            all(ordered_sha(member.get(field))
                                for field in ('source_sha256','config_sha256','metadata_sha256')),
                            'Actual native launch changed a complete paired node or its original WG assets')
            original_rows.append({'id':node['id'],'mode':node['mode'],'node_id':proof,
                                  'source_sha256':member['source_sha256'],
                                  'identity_assets_sha256':hashlib.sha256(companion.encode()).hexdigest()})
        ordered_require(ready['schema']==1 and ready['kind']=='routervpn-node-chain-ready-v1' and
                        ready['source_sha256']==physical['source_sha256']==flags['--physical-source-sha256'] and
                        ready['transfer_sha256']==physical['transfer_sha256'] and
                        ready['dns_config_sha256']==physical['dns_config_sha256'] and
                        identity['session_id']==flags['--session']==physical['session_id']==mtu['session_id'] and
                        identity['source_sha256']==source['source_sha256'] and
                        identity['config_sha256']==flags['--config-sha256']==config_info[3]==source['config_sha256']==
                            physical['config_sha256']==mtu['config_sha256'],
                        'Ordered, physical and source records identify different original owners')
        ordered_require(ready['proof_generation']==1 and ready['reader']==mtu['reader']==1 and
                        ready['interface_name']==mtu['interface']=='router-vpn' and
                        ready['interface_index']==mtu['index'] and ready['mtu']==mtu['mtu']==1280 and
                        not mtu['active'] and mtu['generation']==0 and not mtu.get('request_id') and
                        not mtu.get('lease_id') and not mtu.get('restored') and not mtu.get('expired') and
                        not mtu.get('failure'), 'Ordered initial reader or fixed TUN MTU changed')
        now=time.time_ns()//1000000
        ordered_require(self.started<=ready['observed_at']<=now and now-ready['observed_at']<=2000,
                        'Original ordered proof heartbeat is stale')
        invariant={key:ready[key] for key in ('source_sha256','transfer_sha256','dns_config_sha256','identity',
                    'proof_generation','reader','interface_name','interface_index','mtu')}
        if self.identity is None:
            self.identity=invariant
        ordered_require(self.identity==invariant, 'Original ordered native proof identity changed')
        link=ordered_json(['ip','-j','link','show','dev','router-vpn'])[0]
        ordered_require(link['ifindex']==ready['interface_index'] and link['mtu']==1280,
                        'Actual kernel TUN differs from the original native reader')
        ordered_require('10.77.3.1' in json.dumps(config['dns']),
                        'Complete route lost its actual final selected DNS')
        table='router_vpn_node_'+flags['--session']
        nft=ordered_json(['nft','-j','-a','list','table','inet',table])
        ordered_require(any(row.get('chain',{}).get('name')=='output' and
                            row['chain'].get('hook')=='output' and row['chain'].get('policy')=='drop'
                            for row in nft['nftables']), 'Original protected OUTPUT policy is absent')
        result=dict(invariant,pid=pid,original_rows=original_rows,source_file_sha256=source_info[3],config_file_sha256=config_info[3],
                    inherited_parent_capture=flags['--linux-parent-capture'],observed_at=ready['observed_at'])
        if self.first is None:
            self.first=result
        return result

    def retired(self):
        ordered_require(self.pidfd is not None and bool(select.select([self.pidfd],[],[],5)[0]),
                        'Original ordered native child is not terminal after normal Disconnect')
        ordered_require(not Path('/proc/%d'%self.pid).exists(),
                        'Original ordered child was not reaped by its installed parent')
        ordered_require(not any(link['ifindex']==self.identity['interface_index'] or link['ifname']=='router-vpn'
                                for link in ordered_json(['ip','-j','link','show'])),
                        'Original ordered TUN survived normal Disconnect')
        return {'original_pid':self.pid,'pidfd_terminal':True,'original_pid_absent':True,'tun_absent':True}

    def close(self):
        if self.pidfd is not None:
            ordered_require(bool(select.select([self.pidfd],[],[],0)[0]),
                            'The original native observer cannot retire a live child handle')
            os.close(self.pidfd)
            self.pidfd=None


def ordered_latency(value, expected, count):
    import math
    ordered_require(value.get('connected') is True and value.get('mode')=='multihop' and
                    value.get('router_id')==expected and value.get('samples')==count and value.get('failed')==0 and
                    isinstance(value.get('proof'),str) and bool(value['proof']) and value.get('measured_at'),
                    'Actual routed response did not prove its complete sample set')
    numbers=[value[key] for key in ('min_ms','median_ms','average_ms','p90_ms','max_ms')]
    ordered_require(all(isinstance(v,(int,float)) and math.isfinite(v) and v>0 for v in numbers) and
                    numbers[0]<=numbers[1]<=numbers[3]<=numbers[4] and numbers[0]<=numbers[2]<=numbers[4],
                    'Actual routed latency statistics are not finite ordered measurements')


def ordered_performance(value,capture,nodes):
    import math
    ordered_require(value.get('connected') is True and value.get('mode')=='multihop' and
                    value.get('execution')=='local' and value.get('ordered_capture')==capture and
                    value.get('ordered_nodes')==3 and value.get('entry_id')==nodes[0]['id'] and
                    value.get('exit_id')==nodes[-1]['id'] and value.get('bytes')==(8<<20) and len(value['hops'])==3,
                    'Performance result changed its original complete path')
    for row,node,role in zip(value['hops'],nodes,('entry','intermediate','exit')):
        ordered_require(row['router_id']==node['id'] and row['role']==role,
                        'Performance reordered the original node identities')
        ordered_latency(row['latency'],node['id'],6)
        speed=row['speed']
        ordered_require(speed.get('router_id')==node['id'] and speed.get('bytes')==(8<<20) and speed.get('proof'),
                        'Performance lost exact authenticated transfer bytes')
        for direction in ('download','upload'):
            elapsed,rate=speed[direction+'_ms'],speed[direction+'_mbps']
            ordered_require(all(isinstance(v,(int,float)) and math.isfinite(v) and v>0 for v in (elapsed,rate)) and
                            elapsed<=90000 and abs(rate-(8<<20)*8/elapsed/1000)<.0011,
                            'Performance rate does not match its actual bytes and elapsed time')


def ordered_physical_denials(topology):
    results=[]
    for host,port in (('10.77.1.1',8787),('10.77.2.1',8787),('10.77.3.1',8787),
                      (topology['final_private'],8388),(topology['host_uplink'],topology['relay_port'])):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'smartphy\0')
            probe.bind((CLIENT_PHYSICAL,0));probe.settimeout(.6)
            try:
                probe.connect((host,port))
            except OSError as error:
                results.append({'network':'tcp','host':host,'port':port,'denied':True,'errno':error.errno})
            else:
                raise RuntimeError('Protected client reached a forbidden physical TCP target')
    for host,port in ((OUTER,18445),(topology['final_private'],8388)):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'smartphy\0')
            probe.bind((CLIENT_PHYSICAL,0));probe.settimeout(.6)
            try:
                probe.sendto(secrets.token_bytes(32),(host,port))
            except OSError as error:
                ordered_require(error.errno in (errno.EPERM,errno.EACCES),
                                'Physical UDP denial was not an actual local permission refusal')
                results.append({'network':'udp','host':host,'port':port,'denied':True,'errno':error.errno})
            else:
                raise RuntimeError('Protected client allowed a forbidden physical UDP datagram')
    return results


def ordered_public_application_probe():
    import ipaddress
    import ssl
    nonce=secrets.token_hex(16)
    connection=http.client.HTTPSConnection('1.1.1.1',443,timeout=8,context=ssl.create_default_context())
    try:
        connection.request('GET','/cdn-cgi/trace?routervpn_proof='+nonce,
                           headers={'Cache-Control':'no-store','Connection':'close'})
        response=connection.getresponse()
        body=response.read(16385)
        ordered_require(response.status==200 and len(body)<=16384,'Actual application public TLS proof failed')
        fields=dict(line.split('=',1) for line in body.decode('ascii').splitlines() if '=' in line)
        ordered_require(fields.get('h')=='1.1.1.1' and ipaddress.ip_address(fields['ip']).is_global,
                        'Actual application TLS response has no public exit identity')
        return {'target':'1.1.1.1:443','production_tls_verified':True,'nonce':nonce,
                'body_sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body),
                'public_exit_sha256':hashlib.sha256(fields['ip'].encode()).hexdigest()}
    finally:
        connection.close()




def ordered_last(nodes,peers):
    record,info=OrderedNativeObserver.private(INSTALL/'state.json')
    chain=record.get('node_chain',{})
    ordered_require(record.get('path_kind')=='node-chain-v1' and record.get('router_id')==nodes[-1]['id'] and
                    record.get('runtime_mode')==nodes[-1]['mode'] and ordered_sha(record.get('profile_token')) and
                    chain.get('schema')==1 and chain.get('execution')=='local' and
                    chain.get('root_sha256')==hashlib.sha256(str(INSTALL).encode()).hexdigest() and
                    len(chain.get('nodes',[]))==len(nodes), 'Normal Last receipt lost the complete Local source')
    for row,node,member in zip(chain['nodes'],nodes,peers.members):
        ordered_require(row.get('id')==node['id'] and row.get('mode')==node['mode'] and
                        row.get('start_layer')=='off' and row.get('node_proof_id')==member.profile['node_proof_id'] and
                        ordered_sha(row.get('profile_token')) and row.get('sources'),
                        'Normal Last receipt changed a captured node, source or identity')
    return record,info[3]


def ordered_replay(work,user,password,nodes,peers,baseline,first,deadline):
    # The old controller must already be joined. This fresh launch alone invokes
    # serveClientHTTP -> scheduleStartupPolicy -> original owned Local Connect.
    ordered_require(deadline-time.monotonic()>185,
                    'No full original startup observation and cleanup reserve remains')
    replay_work=work/'startup-replay';replay_work.mkdir(mode=0o711)
    last,last_digest=ordered_last(nodes,peers)
    observer=None
    result={}
    primary=None
    errors=[]
    started=time.time_ns()//1000000
    try:
        with canary(peers.topology['peer'],'on-connect') as (armed,control,retire), \
                controller(replay_work,user,password,helpers=work.parent) as (owner,headers), \
                retire_failed_canary('on-connect',retire):
            try:
                until=min(deadline-20,time.monotonic()+70)
                status=None
                while time.monotonic()<until:
                    status=api('/api/multihop/status',headers=headers,timeout=3)
                    if status.get('connected') is True:
                        break
                    time.sleep(.1)
                ordered_require(status and status.get('connected') is True and status.get('execution')=='local' and
                                status.get('ordered_nodes')==3 and ordered_sha(status.get('ordered_capture')),
                                'A fresh real controller did not automatically replay its original Last path')
                observer=OrderedNativeObserver(owner,started,nodes,[member.profile['node_proof_id'] for member in peers.members],
                        [member.assets['wg'] for member in peers.members])
                current=observer.capture()
                ordered_require(current['identity']['source_sha256']==first['identity']['source_sha256'] and
                                current['config_file_sha256']==first['config_file_sha256'] and
                                current['original_rows']==first['original_rows'] and
                                current['identity']['session_id']!=first['identity']['session_id'] and
                                current['pid']!=first['pid'],
                                'Automatic startup substituted a source or reused the retired native owner')
                armed.set()
                before=peers.observation()
                challenge_private_router(peers.final.profile)
                probe_private_dns(peers.final.profile)
                public=ordered_public_application_probe()
                after=peers.observation()
                ordered_require(after['wg']['received']>before['wg']['received'] and
                                after['wg']['sent']>before['wg']['sent'] and
                                all(after[key]['bytes']>before[key]['bytes'] for key in before if key!='wg'),
                                'Automatic Last replay lacks fresh real encrypted application traffic')
                again,digest=ordered_last(nodes,peers)
                ordered_require(again['node_chain']==last['node_chain'],
                                'Automatic Last replay changed its exact original source inventory')
                result={'automatic':True,'connect_http_called':False,'native':current,
                        'last_before_sha256':last_digest,'last_after_sha256':digest,
                        'application_public_tls':public,'encrypted_before':before,'encrypted_after':after}
            except BaseException as error:
                primary=error
                raise
            finally:
                signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
                armed.clear();control.clear()
                try:
                    api('/api/disconnect',method='POST',headers=headers,timeout=30)
                    off=api('/api/status',headers=headers,timeout=10)
                    ordered_require(off.get('connected') is False,'Automatic Last owner did not disconnect normally')
                    if observer is not None:
                        result['native_retirement']=observer.retired()
                    ordered_require(control.wait(5),'Automatic Last did not restore the original physical control')
                    ordered_require(ordered_host_snapshot()==baseline,'Automatic Last did not restore client routing/DNS')
                except BaseException as error:
                    errors.append('disconnect:'+type(error).__name__)
                    if primary is None:primary=error
                try:
                    retire()
                except BaseException as error:
                    errors.append('canary:'+type(error).__name__)
                    if primary is None:primary=error
        if primary is not None:
            raise primary
        result['controller_retired']=True
        return result
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        if observer is not None:
            observer.close()
        if errors and primary is None:
            raise RuntimeError('Original automatic startup owner retirement failed')


def qualify_ordered(work,user,password,topology_file):
    # Leave the existing 650-second case enough time for the original 150-second
    # login retirement plus peer/socket joins. No shipping deadline is changed.
    deadline=time.monotonic()+440
    topology=read_json(topology_file)
    result={'schema':1,'kind':'installed-complete-node-chain-v1','case':'installed-local-wg-hy2-ss',
            'status':'failed','gtk_button_rendering':False,'cleanup_proved':False}
    observer=None
    primary=None
    cleanup_errors=[]
    connected_attempt=False
    def interrupted(signum,frame):
        signal.signal(signal.SIGINT,signal.SIG_IGN)
        signal.signal(signal.SIGTERM,signal.SIG_IGN)
        raise RuntimeError('Original installed ordered gate was interrupted')
    signal.signal(signal.SIGINT,interrupted)
    signal.signal(signal.SIGTERM,interrupted)
    try:
        with open_ordered_peers(topology,work) as peers:
            profiles=[member.profile for member in peers.members]
            nodes=[{'id':member.profile['id'],'mode':member.mode} for member in peers.members]
            device=profiles[0]['id']
            private_write(INSTALL/'routers.json',{'schema_version':4,'selected_id':device,'profiles':profiles})
            for member in peers.members:
                base=INSTALL/'generated'/member.profile['id']
                base.mkdir(mode=0o700)
                for mode,files in member.assets.items():
                    directory=base/mode;directory.mkdir(mode=0o700)
                    for name,body in files.items():
                        private_write(directory/name,body)
            baseline=ordered_host_snapshot()
            with canary(topology['peer'],'on-connect') as (armed,control,retire_canary), \
                    controller(work,user,password) as (owner,headers), \
                    retire_failed_canary('on-connect',retire_canary):
                def request(path,body=None,timeout=20):
                    remaining=deadline-time.monotonic()
                    ordered_require(remaining>timeout, 'Ordered case exhausted its original cleanup reserve')
                    return api(path,method='GET' if body is None else 'POST',headers=headers,timeout=timeout,body=body)
                try:
                    result['stage']='normal-completion'
                    catalog=request('/api/profiles')
                    ordered_require(catalog['selected_id']==device, 'Original independent device changed before completion')
                    tokens=ordered_profile_tokens(catalog,[node['id'] for node in nodes])
                    proposal={'schema':1,'purpose':'draft-last-ss-final','execution':'local',
                        'draft_revision':secrets.token_hex(16),'device_id':device,'device_revision':tokens[device],
                        'final_id':nodes[-1]['id'],'nodes':nodes,'expected_selected_node_id':device,
                        'expected_profile_tokens':tokens}
                    preview=request('/api/connection-profile/setup/complete-prefix',proposal)
                    ordered_require(preview.get('schema')==1 and preview.get('purpose')==proposal['purpose'] and
                                    preview.get('compiled') is True and preview.get('active_path_changed') is False and
                                    all(preview.get(key)==proposal[key] for key in
                                        ('draft_revision','device_id','device_revision','final_id','nodes')) and
                                    all(ordered_sha(preview.get(key)) for key in
                                        ('source_sha256','device_source_sha256','device_mtu_revision','completion_sha256')),
                                    'Normal completion preview lost its actual ordered/device sources')
                    name='Installed ordered '+secrets.token_hex(6)
                    saved=request('/api/connection-profile/setup/save-completed-prefix',
                                  dict(proposal,name=name,expected_completion_sha256=preview['completion_sha256']))
                    ordered_require(saved.get('profile_name')==name and saved.get('profile_id') and
                                    all(saved.get(key)==value for key,value in preview.items()),
                                    'Named Save did not retain its original complete preview')
                    store=request('/api/connection-profiles')
                    records=[row for row in store['profiles'] if row['id']==saved['profile_id']]
                    ordered_require(len(records)==1 and records[0]['name']==name and records[0]['mode']=='shadowsocks',
                                    'Normal saved complete profile is missing')
                    fresh=request('/api/profiles')
                    ordered_require(fresh['selected_id']==device and ordered_profile_tokens(fresh,tokens)==tokens,
                                    'Future-profile Save changed active selection or its captured sources')
                    result['load']=ordered_load(headers,saved,device,{device:tokens[device]},nodes,request)
                    fresh=request('/api/profiles')
                    ordered_require(fresh['selected_id']==nodes[-1]['id'], 'Finished Load did not select the actual saved final')
                    startup=request('/api/profile/startup')
                    ordered_require(startup.get('profile_id')==nodes[-1]['id'], 'Startup settings target changed')
                    settings=request('/api/profile/startup',{'profile_id':startup['profile_id'],
                        'profile_token':startup['profile_token'],'startup_mode':'last','auto_connect':True})
                    ordered_require(settings.get('startup_mode')=='last' and settings.get('auto_connect') is True,
                                    'Normal Last startup settings did not persist')
                    fresh=request('/api/profiles')
                    current=ordered_profile_tokens(fresh,[node['id'] for node in nodes])
                    result['completion']={key:preview[key] for key in
                        ('source_sha256','device_source_sha256','device_mtu_revision','completion_sha256')}
                    result['saved_profile']={'id':saved['profile_id'],'name':name,'nodes':nodes,'mode':'shadowsocks'}
                    result['stage']='protected-connect'
                    started=time.time_ns()//1000000
                    connected_attempt=True
                    response=request('/api/multihop/connect',{'nodes':nodes,'execution':'local',
                        'expected_selected_node_id':fresh['selected_id'],'expected_profile_tokens':current},timeout=105)
                    observer=OrderedNativeObserver(owner,started,nodes,[member.profile['node_proof_id'] for member in peers.members],
                        [member.assets['wg'] for member in peers.members])
                    result['native']=observer.capture()
                    status=request('/api/multihop/status')
                    ordered_require(status.get('connected') is True and status.get('execution')=='local' and
                                    status.get('ordered_nodes')==3 and ordered_sha(status.get('ordered_capture')),
                                    'Normal Connect did not retain the original complete graph')
                    capture=status['ordered_capture']
                    result['ordered_capture']=capture
                    armed.set()
                    result['stage']='application-traffic'
                    before=peers.observation()
                    # Fresh ordinary sockets use the actual kernel TUN; no native
                    # reader, synthetic dialer, TLS test root or route override.
                    challenge_private_router(peers.final.profile)
                    probe_private_dns(peers.final.profile)
                    result['application_public_tls']=ordered_public_application_probe()
                    result['physical_denials']=ordered_physical_denials(topology)
                    observer.capture()
                    result['stage']='per-hop-performance'
                    performance=request('/api/multihop/speed-test',
                        {'bytes':8<<20,'ordered_capture':capture},timeout=95)
                    ordered_performance(performance,capture,nodes)
                    total=request('/api/connection/live-latency',{'samples':5},timeout=25)
                    ordered_latency(total,nodes[-1]['id'],5)
                    after=peers.observation()
                    ordered_require(after['wg']['received']>before['wg']['received'] and
                                    after['wg']['sent']>before['wg']['sent'] and
                                    all(after[key]['bytes']>before[key]['bytes'] and
                                        after[key]['packets']>before[key]['packets'] for key in before if key!='wg'),
                                    'Fresh application/per-hop work lacks actual encrypted traffic in every transport')
                    result['encrypted_before'],result['encrypted_after']=before,after
                    result['performance'],result['whole_path_response']=performance,total
                    result['native_after']=observer.capture()
                    last,last_digest=ordered_last(nodes,peers)
                    result['last_record_sha256']=last_digest
                    again=request('/api/multihop/status')
                    ordered_require(again.get('connected') is True and again.get('ordered_capture')==capture,
                                    'Actual ordered source changed after its measured work drained')
                    result['stage']='normal-disconnect'
                except BaseException as error:
                    primary=error
                    raise
                finally:
                    cleanup_mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
                    armed.clear();control.clear()
                    if connected_attempt:
                        try:
                            api('/api/disconnect',method='POST',headers=headers,timeout=30)
                            off=api('/api/status',headers=headers,timeout=10)
                            ordered_require(off.get('connected') is False,
                                            'Normal Disconnect did not report the original route Off')
                            if observer is not None:
                                result['native_retirement']=observer.retired()
                            ordered_require(control.wait(5), 'Normal Disconnect did not restore the independent physical control')
                            ordered_require(ordered_host_snapshot()==baseline,
                                            'Normal Disconnect did not restore original client routes, TUN and DNS')
                        except BaseException as error:
                            cleanup_errors.append('disconnect:'+type(error).__name__)
                            if primary is None:
                                primary=error
                    try:
                        retire_canary()
                    except BaseException as error:
                        cleanup_errors.append('canary:'+type(error).__name__)
                        if primary is None:
                            primary=error
                    if primary is not None and not result.get('failure_stage'):
                        result['failure_stage']=result.get('stage')
            # controller() has now waited the original openvt/PAM retirement
            # marker and original resolver owners before any peer can retire.
            result['controller_retired']=True
            if primary is not None:
                raise primary
            observer.close()
            signal.pthread_sigmask(signal.SIG_SETMASK,cleanup_mask)
            result['automatic_startup']=ordered_replay(work,user,password,nodes,peers,baseline,result['native'],deadline)
            result['peer_retirement']=peers.close()
        if primary is not None:
            raise primary
        ordered_require(not cleanup_errors, 'An original installed owner failed cleanup')
        result.update(status='passed',stage='complete',cleanup_proved=True)
    except BaseException as error:
        if primary is None:
            primary=error
        elif error is not primary:
            primary.add_note('Another original installed owner failed during retirement: '+type(error).__name__)
        result.update(status='failed',cleanup_proved=False,
                      failure_type=type(primary).__name__,failure_stage=result.get('failure_stage',result.get('stage','setup')))
        raise primary
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        if observer is not None:
            try:
                observer.close()
            except BaseException as error:
                cleanup_errors.append('native-handle:'+type(error).__name__)
                result.update(status='failed',cleanup_proved=False)
        result['cleanup_errors']=cleanup_errors
        result['body_budget_seconds']=440
        result['case_budget_seconds']=650
        try:
            private_write(work/'ordered-result.json',result)
        except BaseException as evidence_error:
            if primary is None:
                raise
            primary.add_note('Original ordered result publication also failed: '+type(evidence_error).__name__)
        if cleanup_errors and primary is None:
            raise RuntimeError('Original ordered gate handle retirement failed')


def ordered_file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def ordered_package_admission(archive,template,source,admission_path):
    raw=admission_path.read_bytes()
    ordered_require(len(raw)<=16384,'Installed ordered admission exceeded its bound')
    admission=json.loads(raw)
    required={'schema','published_commit','repository','reviewed_parent_source_manifest_sha256',
              'archive_sha256','archive_bytes','native_manifest_sha256','native_binary_sha256',
              'harness_sha256','reference_agent_sha256'}
    ordered_require(set(admission)==required and admission['schema']==1 and
                    re.fullmatch('[0-9a-f]{40}',admission['published_commit']) and
                    admission['reviewed_parent_source_manifest_sha256']==
                    'd001dd50dcaaa754e05633db947ec6e38d1822c65b047c034e87dc4a4cd50bdf',
                    'Installed ordered gate has no exact reviewed source/package admission')
    ordered_require(archive.stat().st_size==admission['archive_bytes'] and
                    ordered_file_sha(archive)==admission['archive_sha256'],
                    'Installed archive differs from its admitted original bytes')
    publication=read_json(source/'ROUTER-VPN-SOURCE.json')
    ordered_require(publication.get('source_sha')==admission['published_commit'] and
                    publication.get('repository')==admission['repository'],
                    'Delivered package source is not the admitted actual publication')
    manifest=template/'runtime/native/NATIVE-RUNTIME.json'
    native=template/'runtime/native/sing-box-routervpn'
    ordered_require(hashlib.sha256(manifest.read_bytes()).hexdigest()==admission['native_manifest_sha256'],
                    'Original native runtime manifest changed')
    with native.open('rb') as stream:
        binary=hashlib.file_digest(stream,'sha256').hexdigest()
    receipt=read_json(manifest)
    ordered_require(binary==admission['native_binary_sha256']==receipt['sha256'] and native.stat().st_size==receipt['size'] and
                    receipt['schema_version']==1 and receipt['runtime']=='sing-box-routervpn' and
                    receipt['target'] in ('linux/amd64','linux/arm64'),
                    'Original installed native payload differs from its package receipt')
    for name,path in (('verify-linux-smart.py',HERE),('linux_smart_peers.py',HERE.with_name('linux_smart_peers.py'))):
        ordered_require(hashlib.sha256(path.read_bytes()).hexdigest()==admission['harness_sha256'][name],
                        'Installed ordered gate source changed after review')
    with Path(os.environ['ROUTERVPN_QUALIFICATION_ROUTER_AGENT']).open('rb') as stream:
        agent=hashlib.file_digest(stream,'sha256').hexdigest()
    ordered_require(agent==admission['reference_agent_sha256'], 'Original Router API peer binary changed')
    return admission


def ordered_installed_case(template,temp,user,password,retirement,admission,evidence):
    evidence.mkdir(mode=0o755)
    private_write(evidence/'admission.json',admission)
    (evidence/'admission.json').chmod(0o644)
    failed=True
    with fixture_directory('installed-ordered-',temp,retirement) as work:
        work.chmod(0o711)
        retirement['complete']=False
        try:
            with installed_case(template,work,retirement,namespace_factory=lambda:ordered_namespaces(work)) as topology:
                original=None
                owner_failure=None
                try:
                    with ExitStack() as owners:
                        log=owners.enter_context((evidence/'case.log').open('xb'))
                        os.fchmod(log.fileno(),0o644)
                        original=OrderedChild(owners,['ip','netns','exec',topology['client'],sys.executable,HERE,
                            '--ordered-case',work,user,password,work/'ordered-topology.json'],log=log,cwd=work)
                        try:
                            code=original.wait(650)
                            ordered_require(code==0,'Original installed complete-path case failed')
                        except BaseException as error:
                            owner_failure=error
                            raise
                        # ExitStack closes this original owner before closing its log.
                except BaseException as error:
                    if owner_failure is not None and error is not owner_failure:
                        owner_failure.add_note('Original case retirement also failed: '+type(error).__name__)
                        raise owner_failure from error
                    owner_failure=error
                    raise
                finally:
                    # Publish only after the retained owner's close path, including failure.
                    # Evidence I/O cannot skip its original waits or replace that owner.
                    if original is not None:
                        try:
                            private_write(evidence/'original-case-owner.json',original.receipt)
                            (evidence/'original-case-owner.json').chmod(0o644)
                        except BaseException as evidence_error:
                            if owner_failure is None:
                                raise
                            owner_failure.add_note('Original owner receipt also failed: '+type(evidence_error).__name__)
            result=read_json(work/'ordered-result.json')
            topology_result=read_json(work/'ordered-topology-result.json')
            ordered_require(result.get('status')=='passed' and result.get('cleanup_proved') and
                            topology_result.get('status')=='passed' and topology_result['relay']['public_connected']>0 and
                            topology_result['relay']['to_public']>0 and topology_result['relay']['from_public']>0,
                            'Installed complete-path traffic or original retirement was not proved')
            failed=False
        finally:
            for name in ('ordered-result.json','ordered-topology-result.json'):
                path=work/name
                if path.exists():
                    raw=path.read_bytes()
                    ordered_require(len(raw)<=(2<<20),'Ordered gate evidence exceeded its bound')
                    private_write(evidence/name,raw)
                    (evidence/name).chmod(0o644)
            if failed:
                retirement['complete']=False
                print('Retained original installed ordered failure:',work,flush=True)
        print('Installed protected ordered path accepted:',json.dumps({
            'case':'installed-local-wg-hy2-ss','hops':3,'latency_samples_per_hop':6,
            'bytes_per_hop_per_direction':8<<20,'total_bytes':48<<20,
            'whole_path_samples':5,'normal_disconnect':True,'evidence':str(evidence)}),flush=True)



def ordered_ci_archive(archive,evidence):
    """Admit the actual same-job package before entering the installed owner."""
    import tarfile
    commit=os.environ.get('GITHUB_SHA','')
    repository=os.environ.get('GITHUB_REPOSITORY','')
    ordered_require(re.fullmatch('[0-9a-f]{40}',commit) and
                    re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository),
                    'The installed CI gate needs its actual workflow source identity')
    head=subprocess.check_output(['git','-C',REPO,'rev-parse','HEAD'],text=True,timeout=10).strip()
    ordered_require(head==commit,'CI checkout and published package source identity differ')
    run('git','-C',REPO,'diff','--quiet',timeout=10)
    archive=archive.resolve()
    package=archive.name.removesuffix('.tar.gz')
    ordered_require(package in ('RouterVPN-linux-amd64','RouterVPN-linux-arm64'),
                    'Expected the same-run delivered Linux app archive')
    original=archive.stat()
    digest=ordered_file_sha(archive)
    with tarfile.open(archive,'r:gz') as tar:
        entries={}
        for member in tar.getmembers():
            ordered_require(member.name not in entries,'Delivered package has duplicate archive paths')
            entries[member.name]=member
        def small(relative):
            member=entries[package+'/'+relative]
            ordered_require(member.isfile() and member.size<=(1<<20),'Delivered small provenance file is invalid')
            stream=tar.extractfile(member)
            with stream:
                return stream.read((1<<20)+1)
        publication=json.loads(small('ROUTER-VPN-SOURCE.json'))
        native_raw=small('runtime/native/NATIVE-RUNTIME.json')
        native=json.loads(native_raw)
        payload=entries[package+'/runtime/native/sing-box-routervpn']
        ordered_require(payload.isfile() and payload.size==native['size'], 'Delivered native payload size differs')
        hasher=hashlib.sha256()
        with tar.extractfile(payload) as stream:
            while True:
                block=stream.read(1<<20)
                if not block:break
                hasher.update(block)
        native_digest=hasher.hexdigest()
    ordered_require(publication.get('source_sha')==commit and publication.get('repository')==repository and
                    native_digest==native['sha256'] and os.path.samestat(original,archive.stat()) and
                    archive.stat().st_size==original.st_size and ordered_file_sha(archive)==digest,
                    'Original same-run package changed during source/native admission')
    with tempfile.TemporaryDirectory(prefix='routervpn-ordered-reference-') as temp:
        tools=prepare_reference_tools(temp)
        agent=Path(tools['ROUTERVPN_QUALIFICATION_ROUTER_AGENT'])
        admission={'schema':1,'published_commit':commit,'repository':repository,
            'reviewed_parent_source_manifest_sha256':'d001dd50dcaaa754e05633db947ec6e38d1822c65b047c034e87dc4a4cd50bdf',
            'archive_sha256':digest,'archive_bytes':original.st_size,
            'native_manifest_sha256':hashlib.sha256(native_raw).hexdigest(),'native_binary_sha256':native_digest,
            'harness_sha256':{path.name:ordered_file_sha(path) for path in (HERE,HERE.with_name('linux_smart_peers.py'))},
            'reference_agent_sha256':ordered_file_sha(agent)}
        source=Path(temp)/'admission.json'
        private_write(source,admission)
        references=agent.parent
        run('sudo','--','unshare','--mount','--propagation','private','/usr/bin/python3',HERE,
            '--ordered-installed',archive,references,source,evidence.resolve())


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
    elif len(sys.argv) == 4 and sys.argv[1] == "--ordered-ci-archive":
        ordered_ci_archive(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 5 and sys.argv[1] == "--ordered-archive":
        with tempfile.TemporaryDirectory(prefix="routervpn-peer-tools-") as temp:
            tools = prepare_reference_tools(temp)
            references = Path(tools["ROUTERVPN_QUALIFICATION_ROSENPASS"]).parent
            run("sudo", "--", "unshare", "--mount", "--propagation", "private", "/usr/bin/python3",
                HERE, "--ordered-installed", Path(sys.argv[2]).resolve(), references,
                Path(sys.argv[3]).resolve(), Path(sys.argv[4]).resolve())
    elif len(sys.argv) == 6 and sys.argv[1] == "--ordered-installed":
        root_fixture(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]))
    elif len(sys.argv) == 6 and sys.argv[1] == "--ordered-case":
        qualify_ordered(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), Path(sys.argv[5]))
    else:
        raise SystemExit("usage: verify-linux-smart.py --archive PATH or --ordered-archive PATH ADMISSION EVIDENCE")


if __name__ == "__main__":
    main()
