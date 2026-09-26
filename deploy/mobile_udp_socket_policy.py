"""Append bounded UDP buffers without replacing native socket-protection hooks."""
from pathlib import Path

IMPORT = '\t"github.com/sagernet/sing-box/experimental/libbox/routervpn/startwhitening"'
PATCHES = {
 'common/dialer/default.go': [
  ('\t"github.com/sagernet/sing-box/common/listener"', '\t"github.com/sagernet/sing-box/common/listener"\n'+IMPORT),
  ('\tvar udpFragment bool', '\tdialer.Control = control.Append(dialer.Control, startwhitening.UDPControl)\n\tlistener.Control = control.Append(listener.Control, startwhitening.UDPControl)\n\tvar udpFragment bool'),
 ],
 'common/listener/listener_udp.go': [
  ('\t"github.com/sagernet/sing-box/common/redir"', '\t"github.com/sagernet/sing-box/common/redir"\n'+IMPORT),
  ('\tvar udpFragment bool', '\tlistenConfig.Control = control.Append(listenConfig.Control, startwhitening.UDPControl)\n\tvar udpFragment bool'),
  ('\t\treturn dialer.DialContext(ctx, network, address)', '\t\tdialer.Control = control.Append(dialer.Control, startwhitening.UDPControl)\n\t\treturn dialer.DialContext(ctx, network, address)'),
  ('\t\treturn listenConfig.ListenPacket(ctx, network, address)', '\t\tlistenConfig.Control = control.Append(listenConfig.Control, startwhitening.UDPControl)\n\t\treturn listenConfig.ListenPacket(ctx, network, address)'),
 ],
}

def patch_text(path, text):
    edits = PATCHES[path]
    if 'startwhitening.UDPControl' in text or IMPORT in text:
        # Accept only our complete exact prior edit, not a partial/moved guard.
        original = text
        for old, new in reversed(edits):
            if original.count(new) != 1:
                raise ValueError('Existing native UDP socket policy differs: '+path)
            original = original.replace(new, old, 1)
        if 'startwhitening.UDPControl' in original or IMPORT in original:
            raise ValueError('Unexpected duplicate native UDP socket policy')
        if patch_text(path, original) != text:
            raise ValueError('Native UDP socket policy was moved')
        return text
    for old, new in edits:
        if text.count(old) != 1:
            raise ValueError('Pinned UDP socket construction boundary changed: '+path)
        text = text.replace(old, new, 1)
    return text

def prepare(vendor):
    vendor = Path(vendor)
    if not (vendor/'experimental/libbox/routervpn/startwhitening/udp_buffers.go').is_file():
        raise ValueError('Native owned UDP socket policy must be composed first')
    candidates = {vendor/name: patch_text(name, (vendor/name).read_text()) for name in PATCHES}
    for path, text in candidates.items():
        path.write_text(text)
