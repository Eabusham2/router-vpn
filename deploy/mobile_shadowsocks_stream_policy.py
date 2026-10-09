"""Guard lazy authenticated streams in one exact pinned Shadowsocks outbound."""
from pathlib import Path
import hashlib
ROOT=Path(__file__).resolve().parents[1]
SOURCE_SHA='10dd204d5f2516e5e7501c610484ed7103c8884f'
OLD='return h.method.DialEarlyConn(outConn, destination), nil'
NEW='return routerVPNGuardStream(outConn, h.method.DialEarlyConn(outConn, destination)), nil'
def blobsha(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def inputs():return [Path(__file__).resolve(),ROOT/'mobile/startwhitening/ss_stream_guard.go.tmpl']
def patch(text):
    original=text
    if text.count(NEW)==1:original=text.replace(NEW,OLD,1)
    if original.count(OLD)!=1 or blobsha(original.encode())!=SOURCE_SHA:raise ValueError('Pinned Shadowsocks outbound differs; lifecycle patch refused')
    output=original.replace(OLD,NEW,1)
    if text not in (original,output):raise ValueError('Partial Shadowsocks lifecycle patch')
    return output

def prepare(vendor):
    source=Path(vendor)/'protocol/shadowsocks/outbound.go'
    helper=source.with_name('routervpn_stream_guard.go')
    if source.is_symlink() or helper.is_symlink():raise ValueError('Unsafe native lifecycle target')
    output=patch(source.read_text())
    data=(ROOT/'mobile/startwhitening/ss_stream_guard.go.tmpl').read_bytes()
    source.write_text(output);helper.write_bytes(data)
    print('Verified authenticated Shadowsocks stream teardown ownership')
