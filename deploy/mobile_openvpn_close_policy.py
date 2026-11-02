"""Preserve real cleanup failures in the exact pinned native OpenVPN endpoint."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import stat

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = '03f8e07a0fb478220ad0a1860acb499dd3b797bb'
SERVER_SOURCE_SHA = 'cd8ccc66d6b05a9c733628ffba2c234dfa66e065'
SERVER_OLD = 'listenerErr = s.listener.Close()'
SERVER_NEW = 'listenerErr = routerVPNOpenVPNCloseError(s.listener.Close())'
OLD = 'err := E.Errors(c.client.Close(), c.device.Close())'
NEW = 'err := E.Errors(routerVPNOpenVPNCloseError(c.client.Close()), c.device.Close())'
_remote_spec = importlib.util.spec_from_file_location('openvpn_remote_close_composition', ROOT/'deploy/mobile_openvpn_remote_policy.py')
REMOTE = importlib.util.module_from_spec(_remote_spec)
_remote_spec.loader.exec_module(REMOTE)


def blobsha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def inputs():
    return [Path(__file__).resolve(), ROOT/'deploy/test_mobile_openvpn_close_policy.py',
            ROOT/'deploy/test_mobile_openvpn_pinned.sh',
            *REMOTE.inputs(),
            *sorted((ROOT / 'mobile/openvpn').glob('*.tmpl'))]


def patch(text):
    stripped, has_remote = REMOTE.unpatch(text)
    original = stripped
    if stripped.count(NEW) == 1:
        original = stripped.replace(NEW, OLD, 1)
    if original.count(OLD) != 1 or blobsha(original.encode()) != SOURCE_SHA:
        raise ValueError('Pinned OpenVPN endpoint differs; close policy patch refused')
    output = original.replace(OLD, NEW, 1)
    if stripped not in (original, output):
        raise ValueError('Partial OpenVPN close policy patch')
    return REMOTE.patch(output) if has_remote else output


def patch_server(text):
    original = text
    if text.count(SERVER_NEW) == 1:
        original = text.replace(SERVER_NEW, SERVER_OLD, 1)
    if original.count(SERVER_OLD) != 1 or blobsha(original.encode()) != SERVER_SOURCE_SHA:
        raise ValueError('Pinned OpenVPN server differs; listener close policy patch refused')
    output = original.replace(SERVER_OLD, SERVER_NEW, 1)
    if text not in (original, output):
        raise ValueError('Partial OpenVPN server listener close policy patch')
    return output


def target(vendor, name, *, required):
    path = vendor / 'protocol/openvpn' / name
    for parent in (vendor / 'protocol', vendor / 'protocol/openvpn'):
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError('Unsafe native OpenVPN close policy directory')
    if path.is_symlink():
        raise ValueError('Unsafe native OpenVPN close policy target')
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Native OpenVPN close policy target is not an owned regular file')
    elif required:
        raise ValueError('Missing native OpenVPN close policy target')
    return path


def planned_sources(vendor):
    vendor = Path(vendor).absolute()
    if vendor.is_symlink() or not vendor.is_dir():
        raise ValueError('Unsafe native OpenVPN close policy checkout')
    vendor = vendor.resolve()
    source = target(vendor, 'client.go', required=True)
    server = target(vendor, 'server.go', required=True)
    helper = target(vendor, 'routervpn_close_policy.go', required=False)
    template = ROOT / 'mobile/openvpn/close_policy.go.tmpl'
    if template.is_symlink() or not template.is_file():
        raise ValueError('Unsafe native OpenVPN close policy authority')
    data = template.read_bytes()
    # Validate all three owners and both complete original blobs before any
    # write. An unrelated server edit or helper cannot partially patch client.
    output = patch(source.read_text(encoding='utf-8')).encode()
    server_output = patch_server(server.read_text(encoding='utf-8')).encode()
    if helper.exists() and helper.read_bytes() != data:
        raise ValueError('Native OpenVPN close policy helper differs from its source')
    return vendor, {source: output, server: server_output, helper: data}


def verify(vendor):
    vendor, files = planned_sources(vendor)
    records = {}
    for path, expected in files.items():
        if not path.is_file() or path.read_bytes() != expected:
            raise ValueError('Native OpenVPN close policy is absent or incomplete')
        records[path.relative_to(vendor).as_posix()] = hashlib.sha256(expected).hexdigest()
    return records


def prepare(vendor):
    vendor, files = planned_sources(vendor)
    for path, data in files.items():
        path.write_bytes(data)
    verify(vendor)
    print('Verified native OpenVPN completed-close and server listener error policy')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    prepare(parser.parse_args().vendor)
