#!/usr/bin/env python3
"""Prepare only a disposable, disconnected namespace, then drop capabilities."""
import ctypes
import os
from pathlib import Path
import resource
import subprocess
import sys


def prepare_namespace():
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/self/net/dev").read_text().splitlines()[2:]}
    if interfaces != {"lo"}:
        raise RuntimeError("auxiliary fixture requires Docker --network none or an owned unshared network namespace")
    # RFC 5737 TEST-NET-1 is assigned only to this namespace's loopback. It lets
    # the unmodified server's private-destination guard remain enabled.
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=5)
    subprocess.run(["ip", "address", "add", "192.0.2.1/32", "dev", "lo"], check=True, timeout=5)
    drop_setup_capabilities()


def drop_setup_capabilities():
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]

    libc = ctypes.CDLL(None, use_errno=True)
    # no_new_privs prevents exec from restoring any dropped capability, even
    # when the fixture was launched as UID 0. capset only drops permissions and
    # does not require CAP_SETPCAP in addition to the setup-only CAP_NET_ADMIN.
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "could not prevent privilege restoration")
    header, data = Header(0x20080522, 0), (Data * 2)()  # Linux capability ABI v3
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), "could not drop setup capabilities")
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))


def main():
    prepare_namespace()
    driver = Path(__file__).resolve().with_name("test_aux_interoperability.py")
    os.execv(sys.executable, [sys.executable, str(driver), *sys.argv[1:]])


if __name__ == "__main__":
    main()
