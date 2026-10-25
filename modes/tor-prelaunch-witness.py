#!/usr/bin/env python3
"""Record a failed Unix wrapper only while no native process has been launched.

The wrapper invokes this exclusively from its own EXIT trap. A successful exec
replaces that shell and its trap, including when the native process later fails.
This is not a native drain receipt and grants no deletion or firewall authority.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys


INPUTS = {
    "tor-profile.json": "HOMEVPN_TOR_PROFILE_SHA256",
    "tor-capture.json": "HOMEVPN_TOR_CAPTURE_SHA256",
    "torrc": "HOMEVPN_TOR_TORRC_SHA256",
    "tor-defaults": "HOMEVPN_TOR_DEFAULTS_SHA256",
    "sing-box.json": "HOMEVPN_TOR_CONFIG_SHA256",
}
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
DIR_FLAGS = FILE_FLAGS | getattr(os, "O_DIRECTORY", 0)


def regular_at(directory: int, name: str, bound: int) -> bytes:
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077 or not 0 < before.st_size <= bound:
        raise ValueError("private input type or size changed")
    descriptor = os.open(name, FILE_FLAGS, dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        if not os.path.samestat(before, opened):
            raise ValueError("private input owner changed")
        chunks = []
        count = 0
        while count <= bound:
            block = os.read(descriptor, min(65536, bound + 1 - count))
            if not block:
                break
            chunks.append(block)
            count += len(block)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (count != before.st_size or not os.path.samestat(before, after)
                or not os.path.samestat(before, current) or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns or not stat.S_ISREG(current.st_mode)):
            raise ValueError("private input changed during capture")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def write_witness(target: str) -> None:
    session = os.environ.get("HOMEVPN_TOR_SESSION", "")
    source = os.environ.get("HOMEVPN_TOR_SOURCE_SHA256", "")
    if (not re.fullmatch(r"[a-f0-9]{32}", session)
            or not re.fullmatch(r"[a-f0-9]{64}", source)
            or os.environ.get("HOMEVPN_STANDARD_ENGINE") != "native"):
        raise ValueError("missing captured native identity")
    for variable in INPUTS.values():
        if not re.fullmatch(r"[a-f0-9]{64}", os.environ.get(variable, "")):
            raise ValueError("missing captured private digest")
    helper = Path(__file__).with_name("cleanup-private-runtime.py")
    if helper.is_symlink() or not helper.is_file():
        raise ValueError("private directory verifier is unavailable")
    spec = importlib.util.spec_from_file_location("routervpn_private_verifier", helper)
    verifier = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(verifier)
    root = os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client")
    directory = verifier.verify_directory(root, target)
    relative = directory.relative_to(verifier.lexical(root) / "run")
    if len(relative.parts) != 2 or relative.parts[0] != "tor-bridge":
        raise ValueError("no captured Tor session directory")
    expected = directory.lstat()
    if expected.st_mode & 0o077:
        raise ValueError("private session permissions changed")
    descriptor = verifier.open_directory(directory, expected, "Tor prelaunch workspace")
    try:
        names = set(os.listdir(descriptor))
        if names - set(INPUTS) - {"tor-data", "stop.json"} or not (set(INPUTS) | {"tor-data"}) <= names:
            raise ValueError("native admission or foreign files already exist")
        for name, variable in INPUTS.items():
            if hashlib.sha256(regular_at(descriptor, name, 4 << 20)).hexdigest() != os.environ[variable]:
                raise ValueError("private input digest changed")
        data_info = os.stat("tor-data", dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(data_info.st_mode) or data_info.st_mode & 0o077:
            raise ValueError("private Tor data owner changed")
        data = os.open("tor-data", DIR_FLAGS, dir_fd=descriptor)
        try:
            if not os.path.samestat(data_info, os.fstat(data)) or os.listdir(data):
                raise ValueError("native Tor data has already been used")
        finally:
            os.close(data)
        if "stop.json" in names:
            stop = json.loads(regular_at(descriptor, "stop.json", 4096))
            if (stop.get("schema") != 1 or stop.get("session_id") != session
                    or stop.get("source_sha256") != source or stop.get("closed", False)):
                raise ValueError("stop request belongs to another owner")
        if verifier.verify_directory(root, target) != directory or not os.path.samestat(expected, directory.lstat()):
            raise ValueError("private workspace changed before witness")
        record = json.dumps({"schema": 1, "session_id": session, "source_sha256": source,
                             "config_sha256": os.environ["HOMEVPN_TOR_CONFIG_SHA256"],
                             "no_native_process": True}, separators=(",", ":")).encode("ascii")
        output = os.open("prelaunch-failed.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=descriptor)
        try:
            while record:
                count = os.write(output, record)
                if count <= 0:
                    raise OSError("prelaunch witness write did not progress")
                record = record[count:]
            os.fsync(output)
        finally:
            os.close(output)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("expected one captured runtime")
        write_witness(sys.argv[1])
    except Exception:
        # Do not print private profiles, transports, paths, or captured values.
        print("Tor prelaunch witness could not be safely recorded.", file=sys.stderr)
        sys.exit(1)
