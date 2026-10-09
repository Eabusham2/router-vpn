"""Synchronize the exact pinned WireGuard connection publication; no network or crypto change."""
from pathlib import Path
import hashlib
ROOT=Path(__file__).resolve().parents[1]
SOURCE_SHA="b423558e90f6aa2f1d14258ad9ea311c455cd038"
OLD='func (c *ClientBind) connect() (*wireConn, error) {\n\tserverConn := c.conn\n\tif serverConn != nil {\n\t\tselect {\n\t\tcase <-serverConn.done:\n\t\t\tserverConn = nil\n\t\tdefault:\n\t\t\treturn serverConn, nil\n\t\t}\n\t}\n\tc.connAccess.Lock()\n\tdefer c.connAccess.Unlock()\n\tselect {\n\tcase <-c.done:\n\t\treturn nil, net.ErrClosed\n\tdefault:\n\t}\n\tserverConn = c.conn'
NEW='func (c *ClientBind) connect() (*wireConn, error) {\n\t// Publication of the connection and its done channel shares the same lock\n\t// as connection replacement. The old unlocked fast path raced receive/send.\n\tc.connAccess.Lock()\n\tdefer c.connAccess.Unlock()\n\tselect {\n\tcase <-c.done:\n\t\treturn nil, net.ErrClosed\n\tdefault:\n\t}\n\tserverConn := c.conn'

def blobsha(data):return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
def inputs():return [Path(__file__).resolve(),ROOT/"mobile/wireguard/client_bind_test.go.tmpl"]
def patch(source):
    original=source
    if source.count(NEW)==1:
        original=source.replace(NEW,OLD,1)
    if blobsha(original.encode())!=SOURCE_SHA or original.count(OLD)!=1:
        raise ValueError("Pinned WireGuard bind source differs; refusing a partial or unrelated edit")
    result=original.replace(OLD,NEW,1)
    if source!=original and source!=result:raise ValueError("Partial WireGuard bind correction")
    return result

def prepare(vendor):
    file=Path(vendor)/"transport/wireguard/client_bind.go"
    if file.is_symlink():raise ValueError("WireGuard bind source is a symlink")
    result=patch(file.read_text())
    test=(ROOT/"mobile/wireguard/client_bind_test.go.tmpl").read_bytes()
    file.write_text(result)
    (file.parent/"routervpn_client_bind_test.go").write_bytes(test)
    print("Verified WireGuard connection publication synchronization")
