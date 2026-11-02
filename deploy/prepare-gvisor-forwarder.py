#!/usr/bin/env python3
"""Exact pinned TCP forwarder ownership correction used by the gVisor owner.

A newer SYN for an actively closed forwarded TCP tuple must re-enter the
same forwarder after the old TIME_WAIT owner is removed. Keep registered
listener precedence, TCP sequence eligibility, and the original flow judge.
Freeze and release only the retired endpoint queue so duplicate SYNs cannot
reset its replacement. Serialize forwarded registration against protocol
shutdown, never the remote handshake wait, then abort late registrations.

Every changed source is bound to its complete original git blob. The parent
materializer restores these exact edits plus its ARM64 scheduler instruction
before checking the complete original Go h1 checksum; the module pin stays
unchanged and the global module cache is never edited.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
TEST = 'pkg/tcpip/transport/tcp/routervpn_forwarder_test.go'
TEMPLATE = ROOT / 'mobile/gvisorforwarder/forwarder_test.go.tmpl'

# These are edits to the exact pinned source, not replacements for whole files.
PATCHES = {
    'pkg/tcpip/transport/tcp/accept.go': {
        'blob': 'baf2b93d7619bf78011918dfff9987e1018987b3',
        'changes': (
            (b'''	queue.EventRegister(&waitEntry)
	defer queue.EventUnregister(&waitEntry)

	h, err := l.startHandshake(s, opts, queue, owner)
	if err != nil {
		return nil, err
	}
''', b'''	queue.EventRegister(&waitEntry)
	defer queue.EventUnregister(&waitEntry)

	var h *handshake
	var err tcpip.Error
	if l.listenEP == nil {
		l.protocol.routerVPNForwarderMu.Lock()
		if l.protocol.routerVPNForwarderClosed {
			l.protocol.routerVPNForwarderMu.Unlock()
			return nil, &tcpip.ErrConnectionAborted{}
		}
		h, err = l.startHandshake(s, opts, queue, owner)
		l.protocol.routerVPNForwarderMu.Unlock()
	} else {
		h, err = l.startHandshake(s, opts, queue, owner)
	}
	if err != nil {
		return nil, err
	}
'''),
        ),
    },
    'pkg/tcpip/transport/tcp/connect.go': {
        'blob': 'a735d9dcf56bfaae85639900b63101b5db590952',
        'changes': (
            (b'''					}
				}
			}
		}
		if extTW {
			extendTimeWait = true
''', b'''					}
				}
			}
			// A forwarded flow has no registered listening endpoint. Retain
			// its original forwarder, and use the same validated newer-SYN
			// transition as listeners. handleTimeWait removes and drains
			// this exact old tuple before invoking the callback.
			if owner := e.routerVPNForwarder; owner != nil && owner.stack == e.stack &&
				s.id == info.ID && s.pkt.NetworkProtocolNumber == info.NetProto &&
				s.csumValid && s.flags.Contains(header.TCPFlagSyn) &&
				s.flags&(header.TCPFlagAck|header.TCPFlagRst|header.TCPFlagFin) == 0 {
				// Drain only the retired endpoint queue. A duplicate SYN must
				// not be reset by the closed-endpoint drain before the original
				// forwarder has admitted the replacement.
				e.segmentQueue.freeze()
				for queued := e.segmentQueue.dequeue(); queued != nil; queued = e.segmentQueue.dequeue() {
					queued.DecRef()
				}
				return false, func() {
					defer s.DecRef()
					owner.HandlePacket(s.id, s.pkt)
				}
			}
		}
		if extTW {
			extendTimeWait = true
'''),
        ),
    },
    'pkg/tcpip/transport/tcp/endpoint.go': {
        'blob': '5479212cf24eef5031f6a15473597812ba2d4de9',
        'changes': (
            (b'''	// listenCtx is used by listening endpoints to store state used while listening for
	// connections. Nil otherwise.
	listenCtx *listenContext `state:"nosave"`

	// limRdr is reused to avoid allocations.
	//
''', b'''	// listenCtx is used by listening endpoints to store state used while listening for
	// connections. Nil otherwise.
	listenCtx *listenContext `state:"nosave"`

	// routerVPNForwarder is the exact owner that created an accepted
	// forwarded endpoint. Only a valid newer SYN may return to this owner
	// after TIME-WAIT cleanup; arbitrary stack handlers are never selected.
	// +checklocks:mu
	routerVPNForwarder *Forwarder `state:"nosave"`

	// limRdr is reused to avoid allocations.
	//
'''),
        ),
    },
    'pkg/tcpip/transport/tcp/forwarder.go': {
        'blob': '646b23f468cfae533aff918154ce23b7c6fcd865',
        'changes': (
            (b'''
	// We only care about well-formed SYN packets (not SYN-ACK) packets.
	if !s.csumValid || !s.flags.Contains(header.TCPFlagSyn) || s.flags.Contains(header.TCPFlagAck) {
		return false
	}

''', b'''
	// We only care about well-formed SYN packets (not SYN-ACK) packets.
	if !s.csumValid || !s.flags.Contains(header.TCPFlagSyn) || s.flags.Contains(header.TCPFlagAck) {
		return false
	}

	f.listen.protocol.routerVPNForwarderMu.Lock()
	closed := f.listen.protocol.routerVPNForwarderClosed
	f.listen.protocol.routerVPNForwarderMu.Unlock()
	if closed {
		return false
	}

'''),
            (b'''		return nil, err
	}

	return ep, nil
}

''', b'''		return nil, err
	}

	ep.mu.Lock()
	ep.routerVPNForwarder = f
	ep.mu.Unlock()
	return ep, nil
}

'''),
        ),
    },
    'pkg/tcpip/transport/tcp/protocol.go': {
        'blob': 'eb75ec3c20fc6e194dcd9dae30bab31a5ac8e5e8',
        'changes': (
            (b'''	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
''', b'''	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
'''),
            (b'''// +stateify savable
type protocol struct {
	stack *stack.Stack

	mu                         protocolRWMutex `state:"nosave"`
	sackEnabled                bool
''', b'''// +stateify savable
type protocol struct {
	stack *stack.Stack

	// The forwarded handshake gate covers registration, never the remote
	// handshake wait. Close shuts admission before its final abort pass.
	routerVPNForwarderMu sync.Mutex `state:"nosave"`
	// +checklocks:routerVPNForwarderMu
	routerVPNForwarderClosed bool `state:"nosave"`

	mu                         protocolRWMutex `state:"nosave"`
	sackEnabled                bool
'''),
            (b'''
// Close implements stack.TransportProtocol.Close.
func (p *protocol) Close() {
	p.dispatcher.close()
}

''', b'''
// Close implements stack.TransportProtocol.Close.
func (p *protocol) Close() {
	p.routerVPNForwarderMu.Lock()
	p.routerVPNForwarderClosed = true
	p.routerVPNForwarderMu.Unlock()
	// Stack.Close enumerates endpoints before closing protocols. A
	// previously admitted forwarded registration may finish in between;
	// admission is now closed, so abort those exact TCP owners as well.
	// Stack.Wait joins their protocol workers after this close returns.
	for _, registered := range p.stack.RegisteredEndpoints() {
		if endpoint, ok := registered.(*Endpoint); ok && endpoint.protocol == p {
			endpoint.Abort()
		}
	}
	p.dispatcher.close()
}

'''),
        ),
    },
}


def inputs():
    return [Path(__file__).resolve(), TEMPLATE,
            ROOT / 'deploy/test_gvisor_forwarder_pinned.py',
            ROOT / 'deploy/test_gvisor_forwarder_runner.py']


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def patch(relative, data):
    specification = PATCHES[relative]
    if git_blob(data) != specification['blob']:
        raise ValueError('Pinned gVisor TCP forwarder source changed: ' + relative)
    for old, new in specification['changes']:
        if data.count(old) != 1 or new in data:
            raise ValueError('Pinned gVisor TCP forwarder edit boundary changed: ' + relative)
        data = data.replace(old, new, 1)
    return data


def original(relative, data):
    specification = PATCHES[relative]
    for old, new in reversed(specification['changes']):
        if data.count(new) != 1:
            raise ValueError('Prepared gVisor TCP forwarder edit boundary differs: ' + relative)
        data = data.replace(new, old, 1)
    if git_blob(data) != specification['blob']:
        raise ValueError('Prepared gVisor TCP forwarder has unrelated changes: ' + relative)
    return data


def test_source():
    if (TEMPLATE.is_symlink() or not TEMPLATE.is_file() or
            TEMPLATE.stat().st_nlink != 1 or not 0 < TEMPLATE.stat().st_size < 256 * 1024):
        raise ValueError('gVisor forwarder regression source is missing or unowned')
    return TEMPLATE.read_bytes()
