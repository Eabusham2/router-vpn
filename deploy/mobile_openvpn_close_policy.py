"""Preserve real cleanup failures in the exact pinned native OpenVPN endpoint."""
from pathlib import Path
import argparse
import hashlib

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = '03f8e07a0fb478220ad0a1860acb499dd3b797bb'
OLD = 'err := E.Errors(c.client.Close(), c.device.Close())'
NEW = 'err := E.Errors(routerVPNOpenVPNCloseError(c.client.Close()), c.device.Close())'


def blobsha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def inputs():
    return [Path(__file__).resolve(), ROOT/'deploy/test_mobile_openvpn_close_policy.py',
            ROOT/'deploy/test_mobile_openvpn_pinned.sh',
            *sorted((ROOT / 'mobile/openvpn').glob('*.tmpl'))]


def patch(text):
    original = text
    if text.count(NEW) == 1:
        original = text.replace(NEW, OLD, 1)
    if original.count(OLD) != 1 or blobsha(original.encode()) != SOURCE_SHA:
        raise ValueError('Pinned OpenVPN endpoint differs; close policy patch refused')
    output = original.replace(OLD, NEW, 1)
    if text not in (original, output):
        raise ValueError('Partial OpenVPN close policy patch')
    return output


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
