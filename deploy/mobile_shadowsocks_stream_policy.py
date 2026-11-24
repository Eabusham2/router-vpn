"""Guard authenticated streams and whole datagrams in the pinned outbound."""
from pathlib import Path
import hashlib
ROOT=Path(__file__).resolve().parents[1]
SOURCE_SHA='10dd204d5f2516e5e7501c610484ed7103c8884f'
OLD='return h.method.DialEarlyConn(outConn, destination), nil'
LEGACY='return routerVPNGuardStream(outConn, h.method.DialEarlyConn(outConn, destination)), nil'
NEW='return routerVPNDialStream(ctx, outConn, h.method, destination)'
PACKET_OLD='h.method.DialPacketConn(outConn)'
PACKET_NEW='routerVPNGuardPacket(outConn, h.method)'
ORIGINAL_PEER_BINDING = '''	if options.RouterVPNOriginalPeerExclusions != nil {
		if options.Detour == "" || options.DomainResolver == nil {
			return nil, E.New("ordered hostname requires its saved detour and resolver")
		}
		outboundDialer, err = dialer.BindRouterVPNOriginalPeer(outboundDialer, options.ServerOptions.Build(), options.DomainResolver.Server, *options.RouterVPNOriginalPeerExclusions)
		if err != nil {
			return nil, err
		}
	}
'''
ORIGINAL_PEER_ANCHOR = '\toutbound := &Outbound{'

def bind_original_peer(text):
    if text.count(ORIGINAL_PEER_ANCHOR) != 1:
        raise ValueError('Original Shadowsocks peer constructor changed')
    attached = ORIGINAL_PEER_BINDING + ORIGINAL_PEER_ANCHOR
    if attached in text:
        original = text.replace(attached, ORIGINAL_PEER_ANCHOR, 1)
    else:
        original = text
    if 'RouterVPNOriginalPeerExclusions' in original or 'BindRouterVPNOriginalPeer' in original:
        raise ValueError('Partial or displaced Shadowsocks original peer binding')
    return original.replace(ORIGINAL_PEER_ANCHOR, attached, 1)

TEMPLATES={'ss_stream_guard.go.tmpl':'routervpn_stream_guard.go',
           'ss_packet_guard_test.go.tmpl':'routervpn_packet_guard_test.go'}
def blobsha(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def inputs():return [Path(__file__).resolve(),*(ROOT/'mobile/startwhitening'/name for name in TEMPLATES)]
def patch(text):
    # The ordered compiler can run between two lifecycle preparations. Undo
    # only its complete constructor edit before checking the pinned Git blob.
    attached = ORIGINAL_PEER_BINDING + ORIGINAL_PEER_ANCHOR
    bound = text.count(attached) == 1
    if bound:
        text = text.replace(attached, ORIGINAL_PEER_ANCHOR, 1)
    original=text
    if text.count(PACKET_NEW)==2:original=text.replace(PACKET_NEW,PACKET_OLD)
    elif text.count(PACKET_NEW)!=0:raise ValueError('Partial Shadowsocks packet lifecycle patch')
    if original.count(NEW)==1:original=original.replace(NEW,OLD,1)
    elif original.count(LEGACY)==1:original=original.replace(LEGACY,OLD,1)
    if original.count(OLD)!=1 or original.count(PACKET_OLD)!=2 or blobsha(original.encode())!=SOURCE_SHA:raise ValueError('Pinned Shadowsocks outbound differs; lifecycle patch refused')
    previous=original.replace(OLD,NEW,1)
    output=previous.replace(PACKET_OLD,PACKET_NEW)
    if text not in (original,output,previous,original.replace(OLD,LEGACY,1)):raise ValueError('Partial Shadowsocks lifecycle patch')
    return bind_original_peer(output) if bound else output

def prepare(vendor):
    source=Path(vendor)/'protocol/shadowsocks/outbound.go'
    helpers={source.with_name(target):(ROOT/'mobile/startwhitening'/name).read_bytes() for name,target in TEMPLATES.items()}
    if source.is_symlink() or any(helper.is_symlink() for helper in helpers):raise ValueError('Unsafe native lifecycle target')
    output=patch(source.read_text())
    source.write_bytes(output.encode())
    for helper,data in helpers.items():helper.write_bytes(data)
    print('Verified authenticated Shadowsocks stream/packet teardown and complete ciphertext reads')
