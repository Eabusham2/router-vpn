#!/usr/bin/env python3
"""Compose the native Xray outbound into exact, disposable Apple core checkouts."""
from pathlib import Path
import argparse
import hashlib
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SING_PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
XRAY_PIN = '50231eaff98ccc31b5cbd247a721c16e97fe5ec1'

def sources():
    return sorted((ROOT/'internal/applexray').glob('*.go')) + sorted((ROOT/'mobile/applexray').glob('*.tmpl')) + [Path(__file__).resolve()]

def digest():
    h = hashlib.sha256()
    for path in sources():
        h.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return h.hexdigest()

def checkout(path, pin, module):
    if subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip() != pin:
        raise ValueError('Refusing a different native engine source revision')
    if not (path/'go.mod').read_text().startswith('module '+module+'\n'):
        raise ValueError('Refusing an unrelated dependency module')

def insert_once(text, anchor, extra, label):
    if text.count(anchor)!=1:
        raise ValueError('Pinned '+label+' boundary changed')
    if extra in text:
        if text.count(extra)!=1 or anchor+'\n'+extra not in text:
            raise ValueError('Existing '+label+' differs')
        return text
    return text.replace(anchor,anchor+'\n'+extra,1)

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

def prepare(sing, xray):
    sing=sing.resolve();xray=xray.resolve()
    checkout(sing,SING_PIN,'github.com/sagernet/sing-box')
    checkout(xray,XRAY_PIN,'github.com/xtls/xray-core')
    vision=xray/'proxy/vless/outbound/outbound.go'
    vision.write_text(patch_vision_buffers(vision.read_text()))
    policy=sing/'experimental/libbox/routervpn/applexray';policy.mkdir(parents=True,exist_ok=True)
    for source in (ROOT/'internal/applexray').glob('*.go'):
        if source.name == 'preparation_test.go':
            continue  # Parent-only composition test; native tests use the actual prepared cores.
        (policy/source.name).write_bytes(source.read_bytes())
    target=sing/'protocol/routervpnxray';target.mkdir(parents=True,exist_ok=True)
    for src,dst in [('outbound.go.tmpl','outbound.go'),('native_test.go.tmpl','native_test.go'),('traffic_test.go.tmpl','traffic_test.go')]:
        (target/dst).write_bytes((ROOT/'mobile/applexray'/src).read_bytes())
    (sing/'experimental/libbox/routervpn_xray_compiler.go').write_bytes((ROOT/'mobile/applexray/bridge.go.tmpl').read_bytes())
    (sing/'experimental/libbox/routervpn_xray_compiler_test.go').write_bytes((ROOT/'mobile/applexray/bridge_test.go.tmpl').read_bytes())
    (xray/'core/routervpn_packet.go').write_bytes((ROOT/'mobile/applexray/core_packet.go.tmpl').read_bytes())
    registry=sing/'include/registry.go'
    text=registry.read_text()
    anchor='\t"github.com/sagernet/sing-box/protocol/vless"'
    call='\tvless.RegisterOutbound(registry)'
    native_import='\t"github.com/sagernet/sing-box/protocol/routervpnxray"'
    native_call='\troutervpnxray.RegisterOutbound(registry)'
    text=insert_once(text,anchor,native_import,'native outbound import')
    text=insert_once(text,call,native_call,'native outbound registration')
    registry.write_text(text)
    # Upstream REALITY normally spawns a decoy HTTP crawler after receiving an
    # ordinary certificate instead of its authenticated REALITY response. A
    # native VPN must fail immediately, not retain a detached unverified socket.
    # Apply only to marked Router VPN instances; keep upstream code/cryptography.
    reality=xray/'transport/internet/reality/reality.go'
    text=reality.read_text()
    anchor='\tif !uConn.Verified {'
    guard='\tif !uConn.Verified && core.RouterVPNIsNativeContext(ctx) {\n\t\t_ = uConn.Close()\n\t\treturn nil, errors.New("REALITY: native tunnel rejected an unverified server")\n\t}\n'
    if text.count(anchor)!=1:
        raise ValueError('Pinned REALITY authentication boundary changed')
    if guard not in text:
        if 'RouterVPNIsNativeContext' in text:
            raise ValueError('Native REALITY authentication guard differs')
        text=text.replace(anchor,guard+anchor,1)
    elif text.count(guard)!=1 or guard+anchor not in text:
        raise ValueError('Native REALITY authentication guard moved')
    reality.write_text(text)
    print('Prepared native Apple Xray source:',digest())

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sing',type=Path,nargs='?');parser.add_argument('xray',type=Path,nargs='?');parser.add_argument('--digest',action='store_true')
    args=parser.parse_args()
    if args.digest: print(digest())
    elif args.sing and args.xray: prepare(args.sing,args.xray)
    else: parser.error('two pinned dependency checkouts or --digest are required')
