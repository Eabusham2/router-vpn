#!/usr/bin/env python3
"""Birth-bound child ownership for native desktop platform wrappers.

The wrapper retains the returned token in memory. Stop never rereads a mutable
registry as its authority and never clears a replacement owner's records.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import select
import signal
import sys
import time

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().with_name("runtime-pids.py")
SPEC = importlib.util.spec_from_file_location("routervpn_native_wrapper_pids", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("native process identity helper is unavailable")
registry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registry)


def validate(value: str | dict) -> dict:
    record = json.loads(value) if isinstance(value, str) else value
    if not isinstance(record, dict) or set(record) != {"version", "pid", "start", "command_sha256"}:
        raise RuntimeError("invalid captured native process token")
    if record["version"] != 1 or type(record["pid"]) is not int or record["pid"] <= 1 or not isinstance(record["start"], str) or not record["start"] or len(record["start"]) > 256 or not isinstance(record["command_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", record["command_sha256"]):
        raise RuntimeError("invalid captured native process identity")
    return record


def matches(record: dict) -> bool:
    try:
        return registry.verified_records_strict([record], Path("captured-native-child")) == [record["pid"]] and not registry.process_is_zombie(record["pid"])
    except (OSError, RuntimeError):
        return False


def capture(pid: int) -> dict:
    start = registry.process_start(pid)
    command = registry.process_command_hash(pid)
    record = validate({"version": 1, "pid": pid, "start": start, "command_sha256": command})
    if not matches(record):
        raise RuntimeError("native child changed or exited during identity capture")
    return record


def stop(record: dict) -> None:
    record = validate(record)
    if not matches(record):
        return
    descriptor = None
    if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
        try:
            descriptor = os.pidfd_open(record["pid"])
        except ProcessLookupError:
            return
    try:
        # Linux signals a retained process descriptor. Other platforms reprove
        # birth + executable command immediately before each bounded signal.
        for kind, timeout in ((signal.SIGINT, 1.0), (signal.SIGTERM, 2.0)):
            if not matches(record):
                return
            try:
                if descriptor is not None:
                    signal.pidfd_send_signal(descriptor, kind)
                else:
                    os.kill(record["pid"], kind)
            except ProcessLookupError:
                return
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if not matches(record):
                    return
                if descriptor is not None:
                    if select.select([descriptor], [], [], min(0.05, max(0, deadline - time.monotonic())))[0]:
                        return
                else:
                    time.sleep(0.05)
        if matches(record):
            raise RuntimeError("captured native child did not finish shutdown")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def prune(root: str, mode: str) -> None:
    # Only a new launch prunes stale history. A retiring wrapper must never
    # write the mode registry after a replacement may have registered itself.
    path = registry.mode_file(root, mode)
    records = registry.read_registry(path)
    kept = [record for record in records if registry.verified_records_strict([record], path) == [record["pid"]]]
    if len(kept) != len(records):
        registry.atomic_write(path, kept)


def main(args: list[str]) -> None:
    if len(args) == 2 and args[0] == "capture":
        print(json.dumps(capture(int(args[1])), separators=(",", ":")))
    elif len(args) == 2 and args[0] == "stop":
        stop(validate(args[1]))
    elif len(args) == 3 and args[0] == "prune":
        prune(args[1], args[2])
    elif len(args) == 3 and args[0] == "recorded":
        path = registry.mode_file(args[1], args[2])
        for record in registry.read_registry(path):
            record = validate(record)
            if matches(record):
                print(json.dumps(record, separators=(",", ":")))
    else:
        raise RuntimeError("usage: native-wrapper-owner.py capture PID | stop TOKEN | prune ROOT MODE | recorded ROOT MODE")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, RuntimeError) as error:
        print(f"native child ownership: {error}", file=sys.stderr)
        raise SystemExit(1)
