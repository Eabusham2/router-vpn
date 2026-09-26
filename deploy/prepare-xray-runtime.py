#!/usr/bin/env python3
"""Apply Router VPN transport corrections to one exact disposable Xray checkout.

Shared by native Apple, Android and packaged server/desktop builders. This does
not replace cryptography, disable pointer/race checks or mutate the module cache.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
XRAY_PIN = '50231eaff98ccc31b5cbd247a721c16e97fe5ec1'
VERSION = '26.7.11'

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

DATAGRAMS = module('xray_datagram_policy')
CONNECTIONS = module('xray_connection_policy')

def sources():
    return [Path(__file__).resolve(), ROOT/'deploy/xray_datagram_policy.py', ROOT/'deploy/xray_connection_policy.py']

def digest():
    value = hashlib.sha256()
    for path in sources():
        value.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes())
    return value.hexdigest()

def checkout(root):
    if subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip() != XRAY_PIN:
        raise ValueError('Shared Xray runtime requires its exact pinned source')
    if not (root/'go.mod').read_text().startswith('module github.com/xtls/xray-core\n'):
        raise ValueError('Unexpected Xray dependency module')

def patch_vision_buffers(text):
    # Keep a real GC-tracked pointer between reflection and the offset access.
    # A stored uintptr is not a pointer and fails Go's pointer-safety checker.
    before = 'var p uintptr'
    after = 'var p unsafe.Pointer'
    previous = '\t\t\ti, _ := t.FieldByName("input")\n\t\t\tr, _ := t.FieldByName("rawInput")'
    checked = '\t\t\ti, inputOK := t.FieldByName("input")\n\t\t\tr, rawOK := t.FieldByName("rawInput")\n\t\t\tif !inputOK || !rawOK || i.Type != reflect.TypeOf(bytes.Reader{}) || r.Type != reflect.TypeOf(bytes.Buffer{}) {\n\t\t\t\treturn errors.New("native Vision buffer layout differs from pinned transport")\n\t\t\t}'
    # Reapplying preparation is allowed only for this exact complete patch.
    if after in text:
        if before in text or text.count(after) != 1 or text.count(checked) != 1:
            raise ValueError('Native Vision pointer patch differs')
        if text.count('unsafe.Add(p, i.Offset)') != 1 or text.count('unsafe.Add(p, r.Offset)') != 1 or 'unsafe.Pointer(p +' in text:
            raise ValueError('Native Vision pointer access differs')
        return text
    if text.count(before) != 1 or text.count(previous) != 1:
        raise ValueError('Pinned Vision buffer reflection boundary changed')
    text = text.replace(before, after, 1).replace(previous, checked, 1)
    text, count = re.subn(r'p = uintptr\(unsafe.Pointer\(([^()]+)\)\)', r'p = unsafe.Pointer(\1)', text)
    if count != 4:
        raise ValueError('Pinned Vision pointer owners changed')
    for field in ('i', 'r'):
        old = 'unsafe.Pointer(p + '+field+'.Offset)'
        if text.count(old) != 1:
            raise ValueError('Pinned Vision buffer access changed')
        text = text.replace(old, 'unsafe.Add(p, '+field+'.Offset)', 1)
    return text


def prepare(root):
    root = Path(root).resolve()
    checkout(root)
    candidates = {}
    for policy in (DATAGRAMS, CONNECTIONS):
        for relative in policy.PATCHES:
            path = root/relative
            candidates[path] = policy.patch_text(relative, path.read_text())
    path = root/'proxy/vless/outbound/outbound.go'
    candidates[path] = patch_vision_buffers(path.read_text())
    # Validate every source boundary before any mutation; drift cannot produce
    # a partially prepared engine for another build step to unknowingly reuse.
    for path, text in candidates.items():
        path.write_text(text)
    return digest()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path,nargs='?')
    parser.add_argument('--digest',action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.source:
        print(prepare(args.source))
    else:
        parser.error('provide a pinned source checkout or --digest')
