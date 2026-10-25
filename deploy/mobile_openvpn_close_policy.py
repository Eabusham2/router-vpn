"""Preserve real cleanup failures in the exact pinned native OpenVPN endpoint."""
from pathlib import Path
import argparse
import hashlib
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = '03f8e07a0fb478220ad0a1860acb499dd3b797bb'
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


def prepare(vendor):
    source = Path(vendor) / 'protocol/openvpn/client.go'
    helper = source.with_name('routervpn_close_policy.go')
    if source.is_symlink() or helper.is_symlink():
        raise ValueError('Unsafe native OpenVPN close policy target')
    output = patch(source.read_text())
    data = (ROOT / 'mobile/openvpn/close_policy.go.tmpl').read_bytes()
    source.write_text(output)
    helper.write_bytes(data)
    print('Verified native OpenVPN completed-close error policy')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    prepare(parser.parse_args().vendor)
