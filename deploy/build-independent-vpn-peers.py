#!/usr/bin/env python3
"""Compile independent Linux VPN peers in the existing native CI job.

This produces compilation evidence, never a VPN/runtime qualification. The
compiler root is an actual retained child; its original join is required before
any accepted package index can exist. CI file identities are not local ones.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

LIMITS = {"GOMAXPROCS": "1", "GOGC": "20", "GOMEMLIMIT": "192MiB",
          "GOFLAGS": "-p=1", "GOTOOLCHAIN": "local"}
TRANSPORT = {"GOPROXY": "https://proxy.golang.org|direct",
             "GOSUMDB": "sum.golang.org https://sum.golang.org"}
COMPILER_SECONDS, OWNER_SECONDS, RETIREMENT_SECONDS = 900, 930, 15
CANCELLED = None

# BEGIN ORIGINAL COMPILER OWNER
OWNERS = []

def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def read_identity(pid):
    fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pgrp": int(fields[2]), "session": int(fields[3]), "starttime": int(fields[19])}

def group_members(h):
    original_pid = h["process"].pid
    rows = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit() or int(path.name) == original_pid:
            continue
        try:
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == original_pid:
                rows.append({"pid": int(path.name), "state": fields[0], "starttime": int(fields[19])})
        except (FileNotFoundError, ProcessLookupError):
            pass
    return rows

def original_retained(h):
    p = h["process"]
    if p.returncode is not None or h["pidfd"] is None:
        raise RuntimeError("original compiler owner is no longer retained")
    if read_identity(p.pid) != h["identity"]:
        raise RuntimeError("original compiler identity changed")
    if h["identity"]["pgrp"] != p.pid or h["identity"]["session"] != p.pid:
        raise RuntimeError("original compiler group differs")

def save_master(path, value):
    pending = path.with_name(path.name + ".pending-" + uuid.uuid4().hex)
    with pending.open("x") as out:
        json.dump(value, out, sort_keys=True, indent=2)
        out.write("\n")
    os.replace(pending, path)

def start(plan_path, plan_sha256, driver, argv, master_path, env):
    plan_path, driver, master_path = map(Path, (plan_path, driver, master_path))
    if digest(plan_path) != plan_sha256:
        raise ValueError("original compiler plan changed")
    plan = json.loads(plan_path.read_text())
    if list(argv) != [sys.executable, "-B", str(driver), str(plan_path), plan_sha256]:
        raise ValueError("compiler argument vector differs")
    if env.get("PYTHONDONTWRITEBYTECODE") != "1":
        raise ValueError("compiler must not write bytecode into the committed source")
    if digest(driver) != plan["driver_sha256"]:
        raise ValueError("compiler recipe changed")
    if any(h.get("join") is None for h in OWNERS):
        raise RuntimeError("an original phase is still owned")
    master = json.loads(master_path.read_text())
    if master["current_heavy_lease"] is not None:
        raise RuntimeError("another compiler or native group is owned")
    stage = Path(plan["stage"])
    h = {"stage": stage, "master": master_path, "plan_sha256": plan_sha256,
         "driver_sha256": plan["driver_sha256"], "phase_id": uuid.uuid4().hex,
         "argv": list(argv), "start": time.monotonic(), "budget": plan["root_budget_seconds"],
         "grace": plan["termination_grace_seconds"], "pidfd": None,
         "process": None, "join": None, "term_at": None, "kill_at": None}
    OWNERS.append(h)
    h["log_path"] = stage / "original-compiler.log"
    h["log"] = h["log_path"].open("xb")
    master["current_heavy_lease"] = {"kind": "new-independent-peer-compilation",
        "phase_id": h["phase_id"], "phase": "starting", "stage": str(stage),
        "plan_sha256": plan_sha256, "original_retained": False}
    save_master(master_path, master)
    try:
        h["process"] = subprocess.Popen(argv, cwd=str(stage), stdout=h["log"],
            stderr=subprocess.STDOUT, start_new_session=True, env=env)
    except BaseException:
        h["log"].close()
        h["start_failed"] = True
        raise
    h["pidfd"] = os.pidfd_open(h["process"].pid)
    h["identity"] = read_identity(h["process"].pid)
    original_retained(h)
    start_record = {"schema": 1, "phase_id": h["phase_id"], "argv": h["argv"],
        "original_pid": h["process"].pid, "identity": h["identity"],
        "plan_sha256": plan_sha256, "driver_sha256": h["driver_sha256"],
        "root_budget_seconds": h["budget"], "termination_grace_seconds": h["grace"]}
    with (stage / "original-compiler-start.json").open("x") as out:
        json.dump(start_record, out, sort_keys=True, indent=2)
        out.write("\n")
    master = json.loads(master_path.read_text())
    if master["current_heavy_lease"]["phase_id"] != h["phase_id"]:
        raise RuntimeError("compiler master lease changed")
    master["current_heavy_lease"].update(original_pid=h["process"].pid,
        identity=h["identity"], phase="running", original_retained=True)
    master["current_workspace_processes_started"] += 1
    save_master(master_path, master)
    return h

def observe(h):
    if h["join"] is not None:
        return h["join"]
    original_retained(h)
    p = h["process"]
    elapsed = time.monotonic() - h["start"]
    terminal = bool(select.select([h["pidfd"]], [], [], 0)[0])
    remaining = group_members(h) if terminal else None
    reason = None
    if elapsed >= h["budget"]:
        reason = "original compiler root deadline"
    elif terminal and remaining:
        reason = "original root exited with remaining original group members"
    if reason and h["term_at"] is None:
        original_retained(h)
        os.killpg(p.pid, signal.SIGTERM)
        h["term_at"] = time.monotonic()
        h["retirement_reason"] = reason
    if h["term_at"] is not None and h["kill_at"] is None and time.monotonic() - h["term_at"] >= h["grace"]:
        terminal = bool(select.select([h["pidfd"]], [], [], 0)[0])
        remaining = group_members(h)
        if not terminal or remaining:
            original_retained(h)
            os.killpg(p.pid, signal.SIGKILL)
            h["kill_at"] = time.monotonic()
    terminal = bool(select.select([h["pidfd"]], [], [], 0)[0])
    if not terminal:
        return {"status": "running", "original_pid": p.pid, "elapsed_seconds": elapsed,
            "term_sent": h["term_at"] is not None, "kill_sent": h["kill_at"] is not None}
    remaining = group_members(h)
    if remaining:
        return {"status": "draining", "original_pid": p.pid, "elapsed_seconds": elapsed,
            "original_group_members": remaining, "term_sent": h["term_at"] is not None,
            "kill_sent": h["kill_at"] is not None}
    # Keep the original unreaped child and its PID reserved until the original
    # process group has no remaining members; never use poll() before this join.
    original_retained(h)
    code = p.wait(timeout=0)
    h["log"].close()
    os.close(h["pidfd"])
    h["pidfd"] = None
    receipt = {"schema": 1, "phase_id": h["phase_id"], "original_pid": p.pid,
        "identity": h["identity"], "exit_code": code, "original_wait_returned": True,
        "pidfd_terminal": True, "pidfd_closed": True, "log_closed": h["log"].closed,
        "original_group_members": [], "elapsed_seconds": time.monotonic() - h["start"],
        "term_sent": h["term_at"] is not None, "kill_sent": h["kill_at"] is not None,
        "retirement_reason": h.get("retirement_reason"),
        "log_sha256": digest(h["log_path"]), "plan_sha256": h["plan_sha256"],
        "driver_sha256": h["driver_sha256"],
        "status": "passed" if code == 0 and h["term_at"] is None else "failed",
        "runtime_qualified": False}
    receipt_path = h["stage"] / "original-compiler-join.json"
    with receipt_path.open("x") as out:
        json.dump(receipt, out, sort_keys=True, indent=2)
        out.write("\n")
    h["join"] = receipt
    master = json.loads(h["master"].read_text())
    if master["current_heavy_lease"]["phase_id"] != h["phase_id"]:
        raise RuntimeError("original compiler lease changed before release")
    master["current_heavy_lease"] = None
    master.setdefault("completed_original_processes", []).append({
        "kind": "new-independent-peer-compilation", "original_pid": p.pid,
        "receipt": str(receipt_path), "receipt_sha256": digest(receipt_path),
        "exit_code": code, "status": receipt["status"]})
    save_master(h["master"], master)
    return receipt

# END ORIGINAL COMPILER OWNER

def write_new(path, value):
    with Path(path).open("x", encoding="utf-8") as out:
        json.dump(value, out, sort_keys=True, indent=2)
        out.write("\n")


def identity(info):
    return {key: getattr(info, key) for key in
            ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink",
             "st_size", "st_mtime_ns", "st_ctime_ns")}


def read_owned(path):
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_nlink != 1):
        raise ValueError("Expected one original owned regular file: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        if identity(os.fstat(source.fileno())) != identity(before):
            raise ValueError("Original file changed before readback")
        raw = source.read()
        if len(raw) != before.st_size or identity(os.fstat(source.fileno())) != identity(before):
            raise ValueError("Original file changed during readback")
    if identity(path.lstat()) != identity(before):
        raise ValueError("Original path changed during readback")
    return raw, before


def metadata(argv, cwd, env):
    result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=30, check=True)
    return result.stdout


def ordinary_env(go):
    value = {k: v for k, v in os.environ.items()
             if not k.startswith(("HOMEVPN_", "DYLD_", "LD_"))}
    # These are the actual setup-go path and runner caches, not old host paths.
    value["PATH"] = str(go.parent) + os.pathsep + value.get("PATH", os.defpath)
    value.update(LIMITS)
    value.update(TRANSPORT)
    value.update(PYTHONDONTWRITEBYTECODE="1", GOWORK="off",
                 GOOS="linux", GOARCH="amd64", GOAMD64="v1", CGO_ENABLED="1")
    return value


def ci_identity():
    required = ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID",
                "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_WORKFLOW_REF",
                "GITHUB_WORKFLOW_SHA", "GITHUB_WORKSPACE", "RUNNER_TEMP")
    if any(not os.environ.get(key) for key in required):
        raise ValueError("Actual GitHub workflow identity is required")
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("RUNNER_OS") != "Linux"
            or os.environ.get("RUNNER_ARCH") != "X64"
            or platform.system() != "Linux"
            or platform.machine() not in ("x86_64", "AMD64")):
        raise ValueError("Independent peer compilation is Linux/amd64 main CI only")
    commit = os.environ["GITHUB_SHA"]
    if (not re.fullmatch(r"[0-9a-f]{40}", commit)
            or os.environ["GITHUB_WORKFLOW_SHA"] != commit
            or os.environ["GITHUB_JOB"] != "native-runtimes"
            or os.environ["GITHUB_WORKFLOW_REF"] !=
               os.environ["GITHUB_REPOSITORY"] + "/.github/workflows/build-all.yml@refs/heads/main"
            or not re.fullmatch(r"[1-9][0-9]*", os.environ["GITHUB_RUN_ID"])
            or not re.fullmatch(r"[1-9][0-9]*", os.environ["GITHUB_RUN_ATTEMPT"])):
        raise ValueError("Current workflow identity does not match the compiler job")
    return {"repository": os.environ["GITHUB_REPOSITORY"], "source_commit": commit,
            "run_id": int(os.environ["GITHUB_RUN_ID"]),
            "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "job_key": os.environ["GITHUB_JOB"],
            "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
            "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
            "runner_os": os.environ["RUNNER_OS"],
            "runner_arch": os.environ["RUNNER_ARCH"], "target": "linux/amd64"}


def tracked_source(repo, ci, env, destination=None):
    repo = Path(repo)
    if str(repo.resolve()) != str(repo):
        raise ValueError("The original checkout path must be canonical")
    commit = metadata(["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"], repo, env).decode().strip()
    tree = metadata(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], repo, env).decode().strip()
    if commit != ci["source_commit"] or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise ValueError("The actual checkout differs from the workflow commit")
    entries = metadata(["git", "-C", str(repo), "ls-tree", "-r", "-z", "HEAD"], repo, env)
    files = {}
    if destination is not None:
        destination.mkdir(mode=0o700)
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        descriptor, raw_path = entry.split(b"\t", 1)
        mode, kind, blob = descriptor.decode("ascii").split()
        relative = raw_path.decode("utf-8")
        path = Path(relative)
        if (kind != "blob" or mode not in ("100644", "100755")
                or not re.fullmatch(r"[0-9a-f]{40}", blob)
                or path.is_absolute() or path.as_posix() != relative
                or any(part in ("", ".", "..", ".git") for part in path.parts)
                or relative in files):
            raise ValueError("Unsupported or ambiguous committed source entry")
        source = repo / relative
        if source.resolve() != source:
            raise ValueError("Committed source has a symlink parent")
        raw, info = read_owned(source)
        actual_mode = "100755" if info.st_mode & 0o111 else "100644"
        actual_blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        if actual_mode != mode or actual_blob != blob:
            raise ValueError("Actual checkout bytes/mode differ from its Git tree: " + relative)
        files[relative] = {"git_mode": mode, "git_blob": blob,
                           "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        if destination is not None:
            target = destination / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open("xb") as out:
                out.write(raw)
            target.chmod(int(mode, 8) & 0o777)
    if not files:
        raise ValueError("The committed source tree is empty")
    return {"schema": 1, "source_repository": ci["repository"],
            "source_commit": commit, "source_tree": tree,
            "checkout_path": str(repo), "files": files}


def check_source(repo, source_map, tree_record):
    actual = {}
    for path in repo.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        raw, info = read_owned(path)
        relative = path.relative_to(repo).as_posix()
        if relative not in tree_record["files"]:
            raise ValueError("The isolated source acquired an extra file")
        row = tree_record["files"][relative]
        mode = "100755" if info.st_mode & 0o111 else "100644"
        if mode != row["git_mode"]:
            raise ValueError("Isolated source executable mode changed")
        actual[relative] = hashlib.sha256(raw).hexdigest()
    if actual != source_map:
        raise ValueError("Exact committed source changed")


def checked_policy_sources(builder, repo, source_map):
    result = {}
    for path in builder.inputs():
        relative = path.relative_to(repo).as_posix()
        if relative not in source_map or digest(path) != source_map[relative]:
            raise ValueError("A shipping builder input is outside the exact source map")
    for path in builder.XRAY_SERVER.sources():
        relative = path.relative_to(repo).as_posix()
        if relative not in source_map or digest(path) != source_map[relative]:
            raise ValueError("An Xray policy input is outside the exact source map")
        result[relative] = source_map[relative]
    return result


def validate_environment(plan):
    expected = {**LIMITS, **TRANSPORT, **plan["cache_paths"],
                "PYTHONDONTWRITEBYTECODE": "1", "GOWORK": "off",
                "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "1"}
    if any(os.environ.get(key) != value for key, value in expected.items()):
        raise ValueError("Original compiler environment differs")
    go = Path(plan["go_executable"])
    if (str(Path(shutil.which("go") or "").resolve()) != str(go)
            or digest(go) != plan["go_executable_sha256"]):
        raise ValueError("Actual original Go executable differs")
    if plan["environment_limits"] != LIMITS or plan["dependency_transport_environment"] != TRANSPORT:
        raise ValueError("Compiler limits or dependency transport changed")
    if (plan["compiler_budget_seconds"], plan["root_budget_seconds"],
            plan["termination_grace_seconds"]) != (COMPILER_SECONDS, OWNER_SECONDS, RETIREMENT_SECONDS):
        raise ValueError("Original compiler budgets changed")
    if ci_identity() != plan["ci"]:
        raise ValueError("Actual workflow identity changed")


def interrupted(signum, frame):
    raise TimeoutError("original peer compiler was interrupted")


def load_builder(repo):
    path = repo/'deploy/build-native-runtime.py'
    spec = importlib.util.spec_from_file_location('rv_tun_current_builder', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def compile_peers(plan_path, plan_sha256):
    plan_path = Path(plan_path)
    if digest(plan_path) != plan_sha256:
        raise ValueError("peer compiler plan changed")
    plan = json.loads(plan_path.read_text())
    repo, work, stage = (Path(plan[key]) for key in ("repo", "work", "stage"))
    if work.exists() or work.is_symlink():
        raise ValueError("peer work directory already exists")
    source_map_path = Path(plan["source_map"])
    if digest(source_map_path) != plan["source_map_sha256"]:
        raise ValueError("source map changed")
    source_map = json.loads(source_map_path.read_text())
    tree_path = Path(plan["source_tree_record"])
    if digest(tree_path) != plan["source_tree_record_sha256"]:
        raise ValueError("Current source tree record changed")
    tree_record = json.loads(tree_path.read_text())
    validate_environment(plan)
    if (repo != Path(__file__).resolve().parents[1]
            or digest(__file__) != plan["driver_sha256"]
            or plan["driver_sha256"] != plan["owner_sha256"]
            or tree_record["source_commit"] != plan["source_commit"]
            or tree_record["source_tree"] != plan["source_tree"]):
        raise ValueError("Current compiler/source binding differs")
    def verify_source():
        check_source(repo, source_map, tree_record)
    verify_source()
    if digest(repo / "deploy/build-native-runtime.py") != plan["builder_sha256"]:
        raise ValueError("shipping peer builder changed")
    builder = load_builder(repo)
    if (builder.PIN != plan["core_pin"] or builder.TOOLCHAIN != plan["toolchain"]
            or builder.POLICY.XRAY.XRAY_PIN != plan["xray_pin"]
            or builder.digest() != plan["builder_policy_sha256"]
            or checked_policy_sources(builder, repo, source_map) != plan["xray_policy_sources"]
            or builder.XRAY_SERVER.digest() != plan["xray_server_policy_sha256"]):
        raise ValueError("Current shipping peer policy differs")
    env = os.environ.copy()
    work.mkdir(mode=0o700)
    started = time.monotonic()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.setitimer(signal.ITIMER_REAL, plan["compiler_budget_seconds"])
    try:
        awg = work / "passive-native-peer"
        builder.build_awg_smoke_peer(awg, env)
        core = work / "core"
        awg_record = {
            "schema": 1, "phase": "compilation", "new_compilation": True,
            "runtime_qualified": False, "binary_path": str(awg),
            "binary_bytes": awg.stat().st_size, "binary_sha256": digest(awg),
            "helper_source_sha256": hashlib.sha256(builder.AWG_SMOKE_PEER.encode()).hexdigest(),
            "adapter_sha256": digest(repo / "mobile/amnezia/tun.go.tmpl"),
            "builder_sha256": digest(repo / "deploy/build-native-runtime.py"),
            "core_pin": builder.PIN, "toolchain": builder.TOOLCHAIN,
            "prepared_go_mod_sha256": digest(core / "go.mod"),
            "prepared_go_sum_sha256": digest(core / "go.sum"),
        }
        if awg_record["helper_source_sha256"] != plan["awg_helper_sha256"] or awg_record["adapter_sha256"] != plan["awg_adapter_sha256"]:
            raise ValueError("actual AWG helper or adapter differs")
        verify_source()
        write_new(stage / "awg-compilation.json", awg_record)
        xray = work / "reference-xray"
        builder.build_xray_smoke_peer(xray, env)
        xray_source = work / "xray-reference"
        policy_sources = {str(path.relative_to(repo)): digest(path) for path in builder.XRAY_SERVER.sources()}
        if policy_sources != plan["xray_policy_sources"]:
            raise ValueError("actual Xray source policy differs")
        xray_record = {
            "schema": 1, "status": "passed", "phase": "compilation",
            "new_compilation": True, "runtime_qualified": False,
            "scope": "Independent Xray peer compiled with shipping server corrections; runtime not yet exercised in this workspace",
            "binary_path": str(xray), "binary_bytes": xray.stat().st_size,
            "binary_sha256": digest(xray), "builder_sha256": digest(repo / "deploy/build-native-runtime.py"),
            "xray_pin": builder.POLICY.XRAY.XRAY_PIN, "toolchain": builder.TOOLCHAIN,
            "server_policy_sha256": builder.XRAY_SERVER.digest(), "policy_sources": policy_sources,
            "prepared_go_mod_sha256": digest(xray_source / "go.mod"),
            "prepared_go_sum_sha256": digest(xray_source / "go.sum"),
        }
        for path in (awg, xray):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or not info.st_mode & 0o100:
                raise ValueError("new peer output ownership differs")
        verify_source()
        write_new(stage / "xray-compilation.json", xray_record)
        write_new(stage / "compiler-result.json", {
            "schema": 1, "status": "passed", "phase": "compilation",
            "elapsed_seconds": time.monotonic() - started,
            "plan_sha256": digest(plan_path), "source_commit": plan["source_commit"],
            "awg_receipt_sha256": digest(stage / "awg-compilation.json"),
            "xray_receipt_sha256": digest(stage / "xray-compilation.json"),
            "runtime_qualified": False, "original_root_join_required": True,
        })
        print(json.dumps({"phase": "compilation", "status": "passed", "runtime_qualified": False}))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def supervisor_signal(signum, frame):
    global CANCELLED
    CANCELLED = "original supervisor received signal " + str(signum)


def retire_original(h, reason):
    if h.get("join") is not None or h.get("process") is None:
        return h.get("join")
    # This is still the original retained Popen object, including a partial
    # start failure. No old PID or owner is reconstructed from an artifact.
    if h.get("pidfd") is None:
        h["pidfd"] = os.pidfd_open(h["process"].pid)
    if "identity" not in h:
        h["identity"] = read_identity(h["process"].pid)
    original_retained(h)
    if bool(select.select([h["pidfd"]], [], [], 0)[0]) and not group_members(h):
        return observe(h)
    if h["term_at"] is None:
        os.killpg(h["process"].pid, signal.SIGTERM)
        h["term_at"] = time.monotonic()
        h["retirement_reason"] = reason
    while h.get("join") is None:
        observe(h)
        if h.get("join") is None:
            time.sleep(0.2)
    return h["join"]


def accepted_join(receipt):
    if (receipt.get("status") != "passed" or receipt.get("exit_code") != 0
            or not all(receipt.get(key) is True for key in
                       ("original_wait_returned", "pidfd_terminal", "pidfd_closed", "log_closed"))
            or receipt.get("original_group_members") != []
            or receipt.get("term_sent") is not False
            or receipt.get("kill_sent") is not False
            or receipt.get("retirement_reason") is not None
            or receipt.get("runtime_qualified") is not False):
        raise ValueError("The original compiler root did not join successfully")


def deliver_binaries(output, plan, result):
    stage, work = Path(plan["stage"]), Path(plan["work"])
    destination = output / "bin"
    destination.mkdir(mode=0o700)
    binaries = {}
    for label, filename in (("awg", "passive-native-peer"), ("xray", "reference-xray")):
        receipt_path = stage / (label + "-compilation.json")
        receipt = json.loads(receipt_path.read_text())
        if (digest(receipt_path) != result[label + "_receipt_sha256"]
                or receipt.get("phase") != "compilation"
                or receipt.get("new_compilation") is not True
                or receipt.get("runtime_qualified") is not False
                or receipt.get("builder_sha256") != plan["builder_sha256"]
                or receipt.get("toolchain") != plan["toolchain"]
                or receipt.get("binary_path") != str(work / filename)):
            raise ValueError("Original peer compilation receipt differs")
        if label == "awg":
            if (receipt["helper_source_sha256"] != plan["awg_helper_sha256"]
                    or receipt["adapter_sha256"] != plan["awg_adapter_sha256"]
                    or receipt["core_pin"] != plan["core_pin"]):
                raise ValueError("Original AWG recipe binding differs")
        elif (receipt.get("status") != "passed"
                or receipt["xray_pin"] != plan["xray_pin"]
                or receipt["server_policy_sha256"] != plan["xray_server_policy_sha256"]
                or receipt["policy_sources"] != plan["xray_policy_sources"]):
            raise ValueError("Original Xray recipe binding differs")
        raw, info = read_owned(work / filename)
        if (not info.st_mode & 0o100 or not raw
                or len(raw) != receipt["binary_bytes"]
                or hashlib.sha256(raw).hexdigest() != receipt["binary_sha256"]):
            raise ValueError("Original freshly compiled executable differs")
        target = destination / filename
        with target.open("xb") as out:
            out.write(raw)
        target.chmod(0o755)
        delivered, delivered_info = read_owned(target)
        if delivered != raw:
            raise ValueError("The delivered peer copy differs")
        binaries[label] = {
            "member": target.relative_to(output).as_posix(),
            "bytes": len(raw), "sha256": receipt["binary_sha256"],
            "receipt_member": receipt_path.relative_to(output).as_posix(),
            "receipt_sha256": digest(receipt_path),
            "original_ci_binary_path": receipt["binary_path"],
            "original_ci_identity": identity(info),
            "delivered_ci_identity": identity(delivered_info),
            "required_executable_mode": "0755"}
    return binaries


def seal_package(output, plan, binaries):
    files = {}
    for path in sorted(output.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        raw, info = read_owned(path)
        files[path.relative_to(output).as_posix()] = {
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    required = {"source-map.json", "source-tree.json", "evidence/plan.json",
                "evidence/compiler-helper.py", "evidence/owner.json",
                "evidence/original-compiler-start.json", "evidence/original-compiler.log",
                "evidence/original-compiler-join.json", "evidence/compiler-result.json",
                "evidence/awg-compilation.json", "evidence/xray-compilation.json",
                "bin/passive-native-peer", "bin/reference-xray"}
    if set(files) != required:
        raise ValueError("The accepted peer payload does not have its exact member set")
    index = {
        "schema": 1, "kind": "routervpn-independent-vpn-peer-compilation",
        "status": "passed", "phase": "compilation", "runtime_qualified": False,
        "source_commit": plan["source_commit"], "source_tree": plan["source_tree"],
        "source_map_sha256": plan["source_map_sha256"],
        "source_tree_record_sha256": plan["source_tree_record_sha256"],
        "ci": plan["ci"], "binaries": binaries, "files": files,
        "original_root_join_member": "evidence/original-compiler-join.json",
        "plan_member": "evidence/plan.json", "helper_member": "evidence/compiler-helper.py",
        "identity_scope": "Original CI paths and inodes; local extraction requires a new verified relocation record."}
    raw = (json.dumps(index, sort_keys=True, indent=2) + "\n").encode("utf-8")
    sums = {name: row["sha256"] for name, row in files.items()}
    sums["package-index.json"] = hashlib.sha256(raw).hexdigest()
    checksum = "".join(sums[name] + "  " + name + "\n" for name in sorted(sums)).encode("ascii")
    with (output / "SHA256SUMS").open("xb") as out:
        out.write(checksum)
    if read_owned(output / "SHA256SUMS")[0] != checksum:
        raise ValueError("The peer checksum readback differs")
    # The acceptance marker is last. Partial/failure artifacts cannot acquire it.
    with (output / "package-index.json").open("xb") as out:
        out.write(raw)
    if read_owned(output / "package-index.json")[0] != raw:
        raise ValueError("The accepted peer index readback differs")


def supervise(output):
    if not sys.dont_write_bytecode:
        raise ValueError("Invoke the compiler helper with python -B")
    ci = ci_identity()
    repo = Path(__file__).resolve().parents[1]
    if Path(os.environ["GITHUB_WORKSPACE"]).resolve() != repo:
        raise ValueError("The helper is not in the actual workflow checkout")
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    output = Path(output)
    if (output.parent.resolve() != runner_temp
            or output.name != "routervpn-independent-vpn-peers-" + ci["source_commit"]
            or output.exists() or output.is_symlink()):
        raise ValueError("A fresh exact-current peer output path is required")
    output.mkdir(mode=0o700)
    stage = output / "evidence"
    stage.mkdir(mode=0o700)
    h = None
    try:
        found_go = shutil.which("go")
        if not found_go:
            raise ValueError("The actual setup-go compiler is unavailable")
        go = Path(found_go).resolve()
        env = ordinary_env(go)
        actual_go = json.loads(metadata(
            [str(go), "env", "-json", "GOVERSION", "GOCACHE", "GOMODCACHE", "GOOS", "GOARCH"], repo, env))
        if actual_go["GOOS"] != "linux" or actual_go["GOARCH"] != "amd64":
            raise ValueError("The actual Go compiler target differs")
        caches = {key: actual_go[key] for key in ("GOCACHE", "GOMODCACHE")}
        if any(not Path(value).is_absolute() for value in caches.values()):
            raise ValueError("Actual Go cache paths must be absolute")
        env.update(caches)
        private = Path(tempfile.mkdtemp(prefix="routervpn-independent-peer-work-", dir=runner_temp))
        source = private / "source"
        tree_record = tracked_source(repo, ci, env, source)
        source_map = {path: row["sha256"] for path, row in tree_record["files"].items()}
        tree_record["private_source_path"] = str(source)
        check_source(source, source_map, tree_record)
        map_path, tree_path = output / "source-map.json", output / "source-tree.json"
        write_new(map_path, source_map)
        write_new(tree_path, tree_record)
        builder = load_builder(source)
        if actual_go["GOVERSION"] != builder.TOOLCHAIN:
            raise ValueError("The actual setup-go version differs from the shipping builder")
        policy_sources = checked_policy_sources(builder, source, source_map)
        driver = source / "deploy/build-independent-vpn-peers.py"
        helper, _ = read_owned(driver)
        if helper != read_owned(Path(__file__).resolve())[0]:
            raise ValueError("The private compiler helper differs from its actual invocation")
        owner_block = helper.split(b"# BEGIN ORIGINAL COMPILER OWNER\n", 1)[1].split(
            b"\n# END ORIGINAL COMPILER OWNER", 1)[0]
        with (stage / "compiler-helper.py").open("xb") as out:
            out.write(helper)
        master = stage / "owner.json"
        write_new(master, {"schema": 1, "scope": "this original CI compiler invocation",
                          "current_heavy_lease": None, "current_workspace_processes_started": 0,
                          "completed_original_processes": []})
        plan = {
            "schema": 1, "kind": "routervpn-independent-vpn-peer-ci-compiler",
            "ci": ci, "source_commit": ci["source_commit"], "source_tree": tree_record["source_tree"],
            "source_map": str(map_path), "source_map_sha256": digest(map_path),
            "source_tree_record": str(tree_path), "source_tree_record_sha256": digest(tree_path),
            "checkout": str(repo), "repo": str(source), "work": str(private / "build"),
            "stage": str(stage), "master": str(master), "new_compilation_required": True,
            "runtime_qualified": False, "historical_process_or_inode_claim": False,
            "driver_sha256": hashlib.sha256(helper).hexdigest(),
            "owner_sha256": hashlib.sha256(helper).hexdigest(),
            "original_owner_body_sha256": hashlib.sha256(owner_block).hexdigest(),
            "builder_sha256": digest(source / "deploy/build-native-runtime.py"),
            "builder_policy_sha256": builder.digest(),
            "awg_helper_sha256": hashlib.sha256(builder.AWG_SMOKE_PEER.encode()).hexdigest(),
            "awg_adapter_sha256": digest(source / "mobile/amnezia/tun.go.tmpl"),
            "core_pin": builder.PIN, "xray_pin": builder.POLICY.XRAY.XRAY_PIN,
            "xray_server_policy_sha256": builder.XRAY_SERVER.digest(),
            "xray_policy_sources": policy_sources, "toolchain": builder.TOOLCHAIN,
            "go_executable": str(go), "go_executable_sha256": digest(go),
            "cache_paths": caches, "environment_limits": LIMITS,
            "dependency_transport_environment": TRANSPORT,
            "compiler_budget_seconds": COMPILER_SECONDS, "root_budget_seconds": OWNER_SECONDS,
            "termination_grace_seconds": RETIREMENT_SECONDS}
        plan_path = stage / "plan.json"
        write_new(plan_path, plan)
        check_source(source, source_map, tree_record)
        if CANCELLED:
            raise TimeoutError(CANCELLED)
        argv = [sys.executable, "-B", str(driver), str(plan_path), digest(plan_path)]
        h = start(plan_path, digest(plan_path), driver, argv, master, env)
        while h["join"] is None:
            if CANCELLED:
                retire_original(h, CANCELLED)
            else:
                observe(h)
            if h["join"] is None:
                time.sleep(0.2)
        accepted_join(h["join"])
        if CANCELLED:
            raise TimeoutError(CANCELLED)
        result = json.loads((stage / "compiler-result.json").read_text())
        if (result.get("status") != "passed" or result.get("phase") != "compilation"
                or result.get("runtime_qualified") is not False
                or result.get("original_root_join_required") is not True
                or result.get("plan_sha256") != digest(plan_path)
                or result.get("source_commit") != ci["source_commit"]
                or not 0 <= result.get("elapsed_seconds", -1) <= COMPILER_SECONDS):
            raise ValueError("The original compiler result does not bind this invocation")
        check_source(source, source_map, tree_record)
        actual = tracked_source(repo, ci, env)
        expected = {key: value for key, value in tree_record.items() if key != "private_source_path"}
        if actual != expected or ci_identity() != ci or digest(go) != plan["go_executable_sha256"]:
            raise ValueError("Current checkout, workflow or compiler changed before delivery")
        binaries = deliver_binaries(output, plan, result)
        seal_package(output, plan, binaries)
        print(json.dumps({"status": "passed", "phase": "compilation",
                          "runtime_qualified": False, "source_commit": ci["source_commit"],
                          "package_index_sha256": digest(output / "package-index.json")}))
    except BaseException as error:
        if h is None and OWNERS:
            h = OWNERS[-1]
        retirement_error = None
        if h is not None and h.get("join") is None and h.get("process") is not None:
            try:
                retire_original(h, "original supervisor failure: " + type(error).__name__)
            except BaseException as cleanup_error:
                retirement_error = type(cleanup_error).__name__
        write_new(stage / "failure.json", {
            "schema": 1, "status": "failed", "phase": "compilation",
            "runtime_qualified": False, "error_type": type(error).__name__,
            "error": str(error)[-8192:], "retirement_error": retirement_error,
            "original_join_available": bool(h is not None and h.get("join") is not None)})
        raise


def main():
    if len(sys.argv) == 3 and not sys.argv[1].startswith("-"):
        compile_peers(sys.argv[1], sys.argv[2])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, supervisor_signal)
    signal.signal(signal.SIGINT, supervisor_signal)
    supervise(args.output)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        parts = []
        for value in (error.stdout, error.stderr):
            if value:
                parts.append(value.encode("utf-8", errors="replace") if isinstance(value, str) else value)
        if parts:
            sys.stderr.write("Original dependency/compiler diagnostic (bounded tail):\n")
            sys.stderr.write(b"\n".join(parts)[-65536:].decode("utf-8", errors="replace")+"\n")
            sys.stderr.flush()
        raise
