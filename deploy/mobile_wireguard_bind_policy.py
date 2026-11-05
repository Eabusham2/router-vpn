"""Retain the pinned WireGuard bind's original context and each Open/Close generation."""
from pathlib import Path
import hashlib
import importlib.util
ROOT=Path(__file__).resolve().parents[1]
_stack_spec=importlib.util.spec_from_file_location('routervpn_wireguard_stack',ROOT/'deploy/mobile_wireguard_stack_policy.py')
STACK=importlib.util.module_from_spec(_stack_spec)
_stack_spec.loader.exec_module(STACK)
SOURCE_SHA='b423558e90f6aa2f1d14258ad9ea311c455cd038'
LEGACY_OLD='''func (c *ClientBind) connect() (*wireConn, error) {
	serverConn := c.conn
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	serverConn = c.conn'''
LEGACY_NEW='''func (c *ClientBind) connect() (*wireConn, error) {
	// Publication of the connection and its done channel shares the same lock
	// as connection replacement. The old unlocked fast path raced receive/send.
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	serverConn := c.conn'''
OLD='''package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
)

var _ conn.Bind = (*ClientBind)(nil)

type ClientBind struct {
	ctx                 context.Context
	logger              logger.Logger
	pauseManager        pause.Manager
	bindCtx             context.Context
	bindDone            context.CancelFunc
	dialer              N.Dialer
	reservedAccess      sync.RWMutex
	reservedForEndpoint map[netip.AddrPort][3]uint8
	connAccess          sync.Mutex
	conn                *wireConn
	done                chan struct{}
	isConnect           bool
	connectAddr         netip.AddrPort
	reserved            [3]uint8
}

func NewClientBind(ctx context.Context, logger logger.Logger, dialer N.Dialer, isConnect bool, connectAddr netip.AddrPort, reserved [3]uint8) *ClientBind {
	return &ClientBind{
		ctx:                 ctx,
		logger:              logger,
		pauseManager:        service.FromContext[pause.Manager](ctx),
		dialer:              dialer,
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		done:                make(chan struct{}),
		isConnect:           isConnect,
		connectAddr:         connectAddr,
		reserved:            reserved,
	}
}

func (c *ClientBind) connect() (*wireConn, error) {
	serverConn := c.conn
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	serverConn = c.conn
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}
	if c.isConnect {
		udpConn, err := c.dialer.DialContext(c.bindCtx, N.NetworkUDP, M.SocksaddrFromNetIP(c.connectAddr))
		if err != nil {
			return nil, err
		}
		c.conn = &wireConn{
			PacketConn: bufio.NewUnbindPacketConn(udpConn),
			done:       make(chan struct{}),
		}
	} else {
		udpConn, err := c.dialer.ListenPacket(c.bindCtx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
		if err != nil {
			return nil, err
		}
		c.conn = &wireConn{
			PacketConn: bufio.NewPacketConn(udpConn),
			done:       make(chan struct{}),
		}
	}
	return c.conn, nil
}

func (c *ClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	select {
	case <-c.done:
		c.done = make(chan struct{})
	default:
	}
	c.bindCtx, c.bindDone = context.WithCancel(c.ctx)
	return []conn.ReceiveFunc{c.receive}, 0, nil
}

func (c *ClientBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (count int, err error) {
	udpConn, err := c.connect()
	if err != nil {
		select {
		case <-c.done:
			return
		default:
		}
		c.logger.Error(E.Cause(err, "connect to server"))
		err = nil
		c.pauseManager.WaitActive()
		time.Sleep(time.Second)
		return
	}
	n, addr, err := udpConn.ReadFrom(packets[0])
	if err != nil {
		udpConn.Close()
		select {
		case <-c.done:
		default:
			c.logger.Error(E.Cause(err, "read packet"))
			err = nil
		}
		return
	}
	sizes[0] = n
	if n > 3 {
		b := packets[0]
		clear(b[1:4])
	}
	eps[0] = remoteEndpoint(M.SocksaddrFromNet(addr).Unwrap().AddrPort())
	count = 1
	return
}

func (c *ClientBind) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	if c.bindDone != nil {
		c.bindDone()
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	common.Close(common.PtrOrNil(c.conn))
	return nil
}

func (c *ClientBind) SetMark(mark uint32) error {
	return nil
}

func (c *ClientBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	udpConn, err := c.connect()
	if err != nil {
		c.pauseManager.WaitActive()
		time.Sleep(time.Second)
		return err
	}
	destination := netip.AddrPort(ep.(remoteEndpoint))
	for _, buf := range bufs {
		if offset > 0 {
			buf = buf[offset:]
		}
		if len(buf) > 3 {
			c.reservedAccess.RLock()
			reserved, loaded := c.reservedForEndpoint[destination]
			c.reservedAccess.RUnlock()
			if !loaded {
				reserved = c.reserved
			}
			copy(buf[1:4], reserved[:])
		}
		_, err = udpConn.WriteToUDPAddrPort(buf, destination)
		if err != nil {
			udpConn.Close()
			return err
		}
	}
	return nil
}

'''
NEW='''package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
)

var _ conn.Bind = (*ClientBind)(nil)

type clientBindGeneration struct {
	ctx        context.Context
	cancel     context.CancelFunc
	connAccess sync.Mutex
	conn       *wireConn
}

type ClientBind struct {
	ctx                 context.Context
	logger              logger.Logger
	pauseManager        pause.Manager
	bindAccess          sync.Mutex
	generation          *clientBindGeneration
	dialer              N.Dialer
	reservedAccess      sync.RWMutex
	reservedForEndpoint map[netip.AddrPort][3]uint8
	isConnect           bool
	connectAddr         netip.AddrPort
	reserved            [3]uint8
}

func NewClientBind(ctx context.Context, logger logger.Logger, dialer N.Dialer, isConnect bool, connectAddr netip.AddrPort, reserved [3]uint8) *ClientBind {
	return &ClientBind{
		ctx:                 ctx,
		logger:              logger,
		pauseManager:        service.FromContext[pause.Manager](ctx),
		dialer:              dialer,
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		isConnect:           isConnect,
		connectAddr:         connectAddr,
		reserved:            reserved,
	}
}

func (c *ClientBind) currentGeneration() *clientBindGeneration {
	c.bindAccess.Lock()
	defer c.bindAccess.Unlock()
	return c.generation
}

func (c *ClientBind) connect() (*wireConn, error) {
	return c.connectGeneration(c.currentGeneration())
}

func (c *ClientBind) connectGeneration(g *clientBindGeneration) (*wireConn, error) {
	// A TUN-up event can expose deviceStateUp before WireGuard calls Open.
	// Never substitute a context or admit a physical dial before that Open.
	if g == nil {
		return nil, net.ErrClosed
	}
	g.connAccess.Lock()
	defer g.connAccess.Unlock()
	if err := g.ctx.Err(); err != nil {
		return nil, errors.Join(net.ErrClosed, err)
	}
	if g.conn != nil {
		select {
		case <-g.conn.done:
		default:
			return g.conn, nil
		}
	}
	var candidate net.PacketConn
	if c.isConnect {
		udpConn, err := c.dialer.DialContext(g.ctx, N.NetworkUDP, M.SocksaddrFromNetIP(c.connectAddr))
		if err != nil {
			if udpConn != nil {
				udpConn.Close()
			}
			return nil, err
		}
		candidate = bufio.NewUnbindPacketConn(udpConn)
	} else {
		udpConn, err := c.dialer.ListenPacket(g.ctx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
		if err != nil {
			if udpConn != nil {
				udpConn.Close()
			}
			return nil, err
		}
		candidate = bufio.NewPacketConn(udpConn)
	}
	// Close cancels this exact generation before waiting for its dial to join.
	// A late successful dial must be retired, never published into a reopen.
	if err := g.ctx.Err(); err != nil {
		candidate.Close()
		return nil, errors.Join(net.ErrClosed, err)
	}
	g.conn = &wireConn{PacketConn: candidate, done: make(chan struct{})}
	return g.conn, nil
}

func (c *ClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	c.bindAccess.Lock()
	defer c.bindAccess.Unlock()
	if c.generation != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if err := c.ctx.Err(); err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithCancel(c.ctx)
	g := &clientBindGeneration{ctx: ctx, cancel: cancel}
	c.generation = g
	return []conn.ReceiveFunc{func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		return c.receiveGeneration(g, packets, sizes, eps)
	}}, 0, nil
}

// Preserve the original pause/retry policy while allowing this bind's Close
// to join a receiver even when the shared owner remains paused and alive.
func (c *ClientBind) waitRetry(g *clientBindGeneration) error {
	if g == nil {
		return net.ErrClosed
	}
	if c.pauseManager != nil {
		wake := make(chan struct{}, 1)
		callback := c.pauseManager.RegisterCallback(func(int) {
			select {
			case wake <- struct{}{}:
			default:
			}
		})
		defer c.pauseManager.UnregisterCallback(callback)
		for c.pauseManager.IsDevicePaused() || c.pauseManager.IsNetworkPaused() {
			select {
			case <-g.ctx.Done():
				return errors.Join(net.ErrClosed, g.ctx.Err())
			case <-wake:
			}
		}
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-g.ctx.Done():
		return errors.Join(net.ErrClosed, g.ctx.Err())
	case <-timer.C:
		return nil
	}
}

func (c *ClientBind) receiveGeneration(g *clientBindGeneration, packets [][]byte, sizes []int, eps []conn.Endpoint) (count int, err error) {
	udpConn, err := c.connectGeneration(g)
	if err != nil {
		if g.ctx.Err() != nil {
			return 0, errors.Join(net.ErrClosed, g.ctx.Err(), err)
		}
		c.logger.Error(E.Cause(err, "connect to server"))
		return 0, c.waitRetry(g)
	}
	n, addr, err := udpConn.ReadFrom(packets[0])
	if g.ctx.Err() != nil {
		return 0, errors.Join(net.ErrClosed, g.ctx.Err(), err)
	}
	if err != nil {
		udpConn.Close()
		c.logger.Error(E.Cause(err, "read packet"))
		return 0, nil
	}
	sizes[0] = n
	if n > 3 {
		clear(packets[0][1:4])
	}
	eps[0] = remoteEndpoint(M.SocksaddrFromNet(addr).Unwrap().AddrPort())
	return 1, nil
}

func (c *ClientBind) Close() error {
	c.bindAccess.Lock()
	defer c.bindAccess.Unlock()
	g := c.generation
	if g == nil {
		return nil
	}
	// Cancel before joining connAccess: DialContext may be blocked on this ctx.
	g.cancel()
	g.connAccess.Lock()
	defer g.connAccess.Unlock()
	common.Close(common.PtrOrNil(g.conn))
	c.generation = nil
	return nil
}

func (c *ClientBind) SetMark(mark uint32) error {
	return nil
}

func (c *ClientBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	g := c.currentGeneration()
	udpConn, err := c.connectGeneration(g)
	if err != nil {
		if g == nil {
			return err
		}
		return errors.Join(err, c.waitRetry(g))
	}
	destination := netip.AddrPort(ep.(remoteEndpoint))
	for _, buf := range bufs {
		if err := g.ctx.Err(); err != nil {
			return errors.Join(net.ErrClosed, err)
		}
		if offset > 0 {
			buf = buf[offset:]
		}
		if len(buf) > 3 {
			c.reservedAccess.RLock()
			reserved, loaded := c.reservedForEndpoint[destination]
			c.reservedAccess.RUnlock()
			if !loaded {
				reserved = c.reserved
			}
			copy(buf[1:4], reserved[:])
		}
		_, err = udpConn.WriteToUDPAddrPort(buf, destination)
		if err != nil {
			udpConn.Close()
			return err
		}
	}
	return nil
}

'''

def blobsha(data):return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
def inputs():return [Path(__file__).resolve(),ROOT/"mobile/wireguard/client_bind_test.go.tmpl"]+STACK.inputs()
def patch(source):
    original=source
    if source.count(NEW)==1:
        original=source.replace(NEW,OLD,1)
    elif source.count(LEGACY_NEW)==1:
        original=source.replace(LEGACY_NEW,LEGACY_OLD,1)
    if blobsha(original.encode())!=SOURCE_SHA or original.count(OLD)!=1:
        raise ValueError("Pinned WireGuard bind source differs; refusing a partial or unrelated edit")
    result=original.replace(OLD,NEW,1)
    legacy=original.replace(LEGACY_OLD,LEGACY_NEW,1)
    if source not in (original,legacy,result):raise ValueError("Partial WireGuard bind correction")
    return result

def prepare(vendor):
    STACK.prepare(vendor)
    file=Path(vendor)/"transport/wireguard/client_bind.go"
    if file.is_symlink():raise ValueError("WireGuard bind source is a symlink")
    result=patch(file.read_text())
    test=(ROOT/"mobile/wireguard/client_bind_test.go.tmpl").read_bytes()
    file.write_text(result)
    (file.parent/"routervpn_client_bind_test.go").write_bytes(test)
    print("Verified WireGuard original bind lifecycle and connection publication")
