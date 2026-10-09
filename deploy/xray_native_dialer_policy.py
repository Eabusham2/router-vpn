"""Install context-scoped native dialing in one exact pinned Xray checkout."""
from pathlib import Path
import hashlib
ROOT=Path(__file__).resolve().parents[1]
SOURCE_SHA='475d0ff95255b72e8c447aca6ebc1020dcc2ddc5'
OLD='\tif sockopt == nil {\n\t\treturn effectiveSystemDialer.Dial(ctx, src, dest, sockopt)\n\t}'
NEW="\t// Router VPN native instances own their exact encrypted underlay. Handle\n\t// their requests before resolver/socket-option fallbacks, without replacing\n\t// the ordinary system dialer used by Android's legacy Xray service.\n\tif conn, err, owned := routerVPNScopedDial(ctx, src, dest, sockopt); owned {\n\t\treturn conn, err\n\t}\n\tif sockopt == nil {\n\t\treturn effectiveSystemDialer.Dial(ctx, src, dest, sockopt)\n\t}"

def blobsha(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def inputs():return [Path(__file__).resolve(),ROOT/'mobile/applexray/scoped_dialer.go.tmpl',ROOT/'mobile/applexray/scoped_dialer_test.go.tmpl']
def patch(text):
    source=text
    if text.count(NEW)==1:source=text.replace(NEW,OLD,1)
    if blobsha(source.encode())!=SOURCE_SHA or source.count(OLD)!=1:raise ValueError('Pinned Xray system-dial boundary differs')
    result=source.replace(OLD,NEW,1)
    if text not in (source,result):raise ValueError('Partial native system-dial policy')
    return result

def prepare(root):
    path=Path(root)/'transport/internet/dialer.go'
    if path.is_symlink():raise ValueError('Native dialer source may not be a symlink')
    output=patch(path.read_text())
    helpers={path:output}
    for name in ['scoped_dialer.go','scoped_dialer_test.go']:
        helpers[path.parent/('routervpn_'+name)]=(ROOT/'mobile/applexray'/(name+'.tmpl')).read_text()
    for target,text in helpers.items():target.write_text(text)
    print('Verified scoped native Xray system-dialer dispatch')
