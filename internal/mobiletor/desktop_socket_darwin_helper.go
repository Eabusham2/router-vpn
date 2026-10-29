//go:build darwin

package mobiletor

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type desktopDarwinOwnedSocket struct {
	creation DesktopSocketCreation
	file     *os.File
	identity desktopDarwinKernelSocket
	bound    bool
	grants   map[string]DesktopSocketGrant
}

type desktopDarwinGuardian struct {
	capture DesktopSocketCapture
	options DesktopDarwinSocketOptions
	owner   DesktopSocketKernelOwner
	account string
	uid     uint32
	pf      *desktopDarwinPF
	sockets map[string]*desktopDarwinOwnedSocket
	tunnel  *os.File
}

// RunDesktopDarwinSocketHelper is called only by the packaged native command.
// An inherited channel and kernel sender credentials, rather than CLI JSON or
// stdout receipts, authenticate every operation and transferred descriptor.
func RunDesktopDarwinSocketHelper(role string) error {
	channel, err := desktopDarwinHelperChannel()
	if err != nil {
		return err
	}
	defer channel.Close()
	parent := uint32(os.Getppid())
	if parent <= 1 {
		return errors.New("Darwin physical helper has no retained parent")
	}
	if role == "creator" {
		return desktopDarwinCreator(channel, parent)
	}
	if role == "uid-observer" {
		return desktopDarwinUIDObserver(channel, parent)
	}
	if role != "guardian" || os.Geteuid() != 0 || !desktopDarwinKernelAvailable() {
		return errors.New("Darwin physical guardian requires its privileged role")
	}
	var request desktopDarwinRequest
	channel.SetDeadline(time.Now().Add(3 * time.Second))
	file, err := desktopDarwinReceive(channel, &request, parent, 0)
	if file != nil {
		file.Close()
		return errors.New("Darwin prepare included an unexpected descriptor")
	}
	if err != nil || request.Operation != "prepare" || request.Sequence != 1 || !request.Capture.valid() || request.Options.validate() != nil {
		return errors.Join(err, errors.New("Darwin physical preparation rejected"))
	}
	baselineCtx, baselineCancel := context.WithTimeout(context.Background(), 2*time.Second)
	err = desktopDarwinValidatePFBaseline(baselineCtx, request.Capture, request.Options)
	baselineCancel()
	if err != nil {
		return err
	}
	account, uid, err := desktopDarwinAllocateAccount(request.Capture)
	if err != nil {
		return err
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	generation := binary.BigEndian.Uint64(nonce[:])
	if generation == 0 {
		return errors.New("Darwin physical generation is empty")
	}
	g := &desktopDarwinGuardian{capture: request.Capture, options: request.Options, account: account, uid: uid, owner: desktopDarwinOwner(request.Capture, uid, account, generation), sockets: make(map[string]*desktopDarwinOwnedSocket)}
	// Every exceptional exit quarantines the managed account. Cleanup first
	// proves exact rules/sets absent, then closes retained sockets. It cannot
	// release UID ownership on an unacknowledged native crash.
	defer g.cleanup(false)
	g.pf, err = desktopDarwinNewPF(g.capture, g.uid, g.account, g.options)
	if err != nil {
		return err
	}
	reply := desktopDarwinReply{Sequence: request.Sequence, Capture: g.capture, Owner: g.owner, UID: uid, Account: account, PF: g.pf}
	channel.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err = desktopDarwinSend(channel, reply, nil); err != nil {
		return err
	}
	sequence := request.Sequence
	lastRequest := time.Now()
	for {
		channel.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		var next desktopDarwinRequest
		file, err := desktopDarwinReceive(channel, &next, parent, 0)
		if errors.Is(err, desktopDarwinIdle) && time.Since(lastRequest) < 6*time.Second {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err = g.pf.expire(ctx)
			cancel()
			if err != nil {
				return err
			}
			continue
		}
		if err != nil {
			if file != nil {
				file.Close()
			}
			return err
		}
		lastRequest = time.Now()
		if next.Sequence != sequence+1 || next.Capture != g.capture || file != nil && next.Operation != "bind" && next.Operation != "tunnel" {
			if file != nil {
				file.Close()
			}
			return errors.New("Darwin physical operation changed its capture, sequence, or descriptor authority")
		}
		sequence = next.Sequence
		reply := desktopDarwinReply{Sequence: sequence, Capture: g.capture}
		var transferred *os.File
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		switch next.Operation {
		case "probe":
			if file != nil {
				err = errors.New("probe descriptor rejected")
			} else {
				err = g.pf.verify(ctx, true)
				if err == nil {
					err = desktopDarwinVerifyAccount(g.account, g.uid)
				}
			}
		case "create":
			transferred, err = g.create(ctx, next.Creation)
			reply.Creation = next.Creation
		case "bind":
			err = g.bind(next.Creation, file)
		case "grant":
			reply.Receipt, err = g.grant(ctx, next.Grant)
		case "revoke":
			err = g.revoke(ctx, next.Grant)
		case "release":
			err = g.release(next.Creation)
		case "tunnel":
			err = g.bindTunnel(ctx, next.Tunnel, next.Index, file)
		case "retire-tunnel":
			err = g.retireTunnel(ctx, next.Tunnel, next.Index)
		case "finish":
			err = g.cleanup(true)
		default:
			err = errors.New("unknown Darwin physical operation")
		}
		cancel()
		if file != nil {
			file.Close()
		}
		if err != nil {
			reply.Error = err.Error()
		}
		channel.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if sendErr := desktopDarwinSend(channel, reply, transferred); sendErr != nil {
			return sendErr
		}
		if next.Operation == "finish" && err == nil {
			channel.SetReadDeadline(time.Now().Add(3 * time.Second))
			var ack desktopDarwinRequest
			unexpected, ackErr := desktopDarwinReceive(channel, &ack, parent, 0)
			if unexpected != nil {
				unexpected.Close()
				return errors.New("Darwin finish acknowledgment transferred a descriptor")
			}
			if ackErr != nil || ack.Operation != "finish-ack" || ack.Sequence != sequence+1 || ack.Capture != g.capture {
				return errors.Join(ackErr, errors.New("Darwin finish acknowledgment lost its exact native parent"))
			}
			return nil
		}
	}
}

func (g *desktopDarwinGuardian) release(c DesktopSocketCreation) error {
	if c.Capture != g.capture || c.Binding.Owner != g.owner || !desktopSocketHex(c.SocketID, 32) {
		return errors.New("Darwin physical release changed its owner")
	}
	owned := g.sockets[c.SocketID]
	if owned == nil {
		return nil
	}
	if c != owned.creation || len(owned.grants) != 0 {
		return errors.New("Darwin physical release precedes exact permit cleanup")
	}
	if err := owned.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	delete(g.sockets, c.SocketID)
	return nil
}

func desktopDarwinCreator(channel *net.UnixConn, parent uint32) error {
	if os.Geteuid() == 0 || os.Getuid() != os.Geteuid() {
		return errors.New("Darwin socket creator has no isolated identity")
	}
	channel.SetDeadline(time.Now().Add(3 * time.Second))
	var request desktopDarwinRequest
	file, err := desktopDarwinReceive(channel, &request, parent, 0)
	if file != nil {
		file.Close()
		return errors.New("creator received an unexpected descriptor")
	}
	c := request.Creation
	if err != nil || request.Operation != "create" || !c.Capture.valid() || !c.Binding.Owner.valid() || !desktopSocketHex(c.SocketID, 32) || c.Network != "tcp" && c.Network != "udp" {
		return errors.Join(err, errors.New("Darwin isolated creation rejected"))
	}
	family, kind := syscall.AF_INET6, syscall.SOCK_STREAM
	if c.Binding.LocalAddress.Is4() {
		family = syscall.AF_INET
	}
	if c.Network == "udp" {
		kind = syscall.SOCK_DGRAM
	}
	fd, err := syscall.Socket(family, kind, 0)
	if err != nil {
		return err
	}
	syscall.CloseOnExec(fd)
	socket := os.NewFile(uintptr(fd), "routervpn-isolated-physical")
	defer socket.Close()
	if err := desktopDarwinSend(channel, desktopDarwinReply{Sequence: request.Sequence, Capture: c.Capture, Creation: c}, socket); err != nil {
		return err
	}
	var ack desktopDarwinRequest
	unexpected, err := desktopDarwinReceive(channel, &ack, parent, 0)
	if unexpected != nil {
		unexpected.Close()
		return errors.New("Darwin creator acknowledgment transferred a descriptor")
	}
	if err != nil || ack.Operation != "created-ack" || ack.Sequence != request.Sequence+1 || ack.Capture != c.Capture || ack.Creation != c {
		return errors.Join(err, errors.New("Darwin isolated creator acknowledgment changed owner"))
	}
	return nil
}

func (g *desktopDarwinGuardian) create(ctx context.Context, c DesktopSocketCreation) (*os.File, error) {
	if c.Capture != g.capture || c.Binding.Owner != g.owner || !desktopSocketHex(c.SocketID, 32) || c.Network != "tcp" && c.Network != "udp" || len(g.sockets) >= DesktopSocketLimit || g.sockets[c.SocketID] != nil {
		return nil, errors.New("Darwin creator request changed ownership")
	}
	want, err := g.options.binding(g.owner, netip.AddrPortFrom(c.Binding.LocalAddress, 1))
	if err != nil || !desktopDarwinBindingEqual(want, c.Binding) {
		return nil, errors.New("Darwin creator binding changed")
	}
	channel, child, err := desktopDarwinSocketPair()
	if err != nil {
		return nil, err
	}
	defer channel.Close()
	defer child.Close()
	executable, err := desktopDarwinExecutable()
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, executable, "routervpn-owned-socket-helper", "creator")
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "GORACE=atexit_sleep_ms=0"}
	command.Stderr = os.Stderr
	command.ExtraFiles = []*os.File{child}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: g.uid, Gid: 65534, Groups: []uint32{}}}
	if err = command.Start(); err != nil {
		return nil, err
	}
	child.Close()
	channel.SetDeadline(time.Now().Add(2 * time.Second))
	request := desktopDarwinRequest{Operation: "create", Sequence: 1, Capture: g.capture, Creation: c}
	err = desktopDarwinSend(channel, request, nil)
	var reply desktopDarwinReply
	var file *os.File
	if err == nil {
		file, err = desktopDarwinReceive(channel, &reply, uint32(command.Process.Pid), g.uid)
	}
	if err == nil {
		err = desktopDarwinSend(channel, desktopDarwinRequest{Operation: "created-ack", Sequence: 2, Capture: c.Capture, Creation: c}, nil)
	}
	if err != nil {
		command.Process.Kill()
	}
	joinErr := command.Wait()
	if err != nil || joinErr != nil || file == nil || reply.Sequence != 1 || reply.Capture != g.capture || reply.Creation != c {
		if file != nil {
			file.Close()
		}
		return nil, errors.Join(err, joinErr, errors.New("Darwin isolated transfer did not join"))
	}
	identity, err := desktopDarwinSocketIdentity(file)
	if err != nil || identity.uid != g.uid || identity.network != c.Network {
		file.Close()
		return nil, errors.New("Darwin creator changed its actual kernel socket owner")
	}
	g.sockets[c.SocketID] = &desktopDarwinOwnedSocket{creation: c, file: file, identity: identity, grants: make(map[string]DesktopSocketGrant)}
	return file, nil
}

func (g *desktopDarwinGuardian) bind(c DesktopSocketCreation, file *os.File) error {
	if c.Capture != g.capture || c.Binding.Owner != g.owner || file == nil {
		return errors.New("Darwin bind has no captured socket")
	}
	identity, err := desktopDarwinSocketIdentity(file)
	if err != nil || identity.uid != g.uid {
		return errors.New("Darwin bind has another kernel creator")
	}
	var owned *desktopDarwinOwnedSocket
	for _, candidate := range g.sockets {
		if candidate.identity == identity {
			owned = candidate
			break
		}
	}
	if owned == nil || owned.bound || owned.creation.Binding != c.Binding || c.Network != identity.network+map[bool]string{true: "4", false: "6"}[c.Binding.LocalAddress.Is4()] {
		return errors.New("Darwin bind has another captured socket identity")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	if _, _, err = desktopSocketSourceRaw(file, identity.network, c.Binding.LocalAddress); err != nil {
		return err
	}
	if err = desktopDarwinCheckInterface(DesktopDarwinSocketInterface{Name: c.Binding.InterfaceName, Index: c.Binding.InterfaceIndex, Address: c.Binding.LocalAddress}); err != nil {
		return err
	}
	var failure error
	err = raw.Control(func(fd uintptr) {
		failure = desktopDarwinBindInterface(int(fd), identity.family, c.Binding.InterfaceIndex)
	})
	if err != nil || failure != nil {
		return errors.Join(err, failure)
	}
	owned.bound = true
	return nil
}

func (g *desktopDarwinGuardian) grant(ctx context.Context, grant DesktopSocketGrant) (DesktopSocketReceipt, error) {
	owned := g.sockets[grant.SocketID]
	if owned == nil || !owned.bound || grant.Capture != g.capture || grant.Binding != owned.creation.Binding || grant.Network != owned.creation.Network || grant.Sequence == 0 || !g.options.permits(grant.Network, grant.Remote) {
		return DesktopSocketReceipt{}, errors.New("Darwin grant has no exact source owner")
	}
	identity, err := desktopDarwinSocketIdentity(owned.file)
	if err != nil || identity != owned.identity {
		return DesktopSocketReceipt{}, errors.New("Darwin grant lost its retained kernel socket")
	}
	local, err := desktopSocketLocal(int(owned.file.Fd()))
	if err != nil || local != grant.Local || local.Addr() != grant.Binding.LocalAddress {
		return DesktopSocketReceipt{}, errors.New("Darwin grant changed its actual bound tuple")
	}
	if err = desktopDarwinCheckInterface(DesktopDarwinSocketInterface{Name: grant.Binding.InterfaceName, Index: grant.Binding.InterfaceIndex, Address: grant.Binding.LocalAddress}); err != nil {
		return DesktopSocketReceipt{}, err
	}
	bound, err := desktopDarwinBoundInterface(int(owned.file.Fd()), identity.family)
	if err != nil || bound != grant.Binding.InterfaceIndex {
		return DesktopSocketReceipt{}, errors.New("Darwin grant lost its device binding")
	}
	for _, option := range []int{syscall.SO_REUSEADDR, syscall.SO_REUSEPORT} {
		value, err := syscall.GetsockoptInt(int(owned.file.Fd()), syscall.SOL_SOCKET, option)
		if err != nil || value != 0 {
			return DesktopSocketReceipt{}, errors.New("Darwin grant socket permits address/port reuse")
		}
	}
	key := grant.Remote.String()
	previous, exists := owned.grants[key]
	if exists && grant.Sequence <= previous.Sequence || !exists && len(owned.grants) >= DesktopSocketPeerLimit {
		return DesktopSocketReceipt{}, errors.New("Darwin grant sequence/peer limit rejected")
	}
	// Retain unknown application outcomes before touching the kernel. Revoke
	// remains possible when acknowledgment/readback fails.
	owned.grants[key] = grant
	return g.pf.grant(ctx, grant)
}

func (g *desktopDarwinGuardian) revoke(ctx context.Context, grant DesktopSocketGrant) error {
	owned := g.sockets[grant.SocketID]
	if owned == nil || grant.Capture != g.capture || grant.Binding != owned.creation.Binding || grant.Network != owned.creation.Network {
		return errors.New("Darwin revoke changed its retained owner")
	}
	previous, exists := owned.grants[grant.Remote.String()]
	if !exists {
		return g.pf.absent(ctx, grant)
	}
	if previous != grant {
		return errors.New("Darwin revoke changed its exact operation")
	}
	if err := g.pf.revoke(ctx, grant); err != nil {
		return err
	}
	delete(owned.grants, grant.Remote.String())
	return nil
}

func (g *desktopDarwinGuardian) cleanup(release bool) error {
	if release && len(g.sockets) != 0 {
		return errors.New("Darwin physical finish precedes native descriptor retirement")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if g.pf != nil {
		if err := g.pf.close(ctx); err != nil {
			return err
		}
	}
	if g.tunnel != nil {
		if err := g.tunnel.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			return err
		}
		g.tunnel = nil
	}
	for id, owned := range g.sockets {
		if err := owned.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			return err
		}
		delete(g.sockets, id)
	}
	if release && g.account != "" {
		if err := desktopDarwinRetireAccount(g.account, g.uid); err != nil {
			return err
		}
		g.account = ""
	}
	return nil
}

func (g *desktopDarwinGuardian) bindTunnel(ctx context.Context, name string, index uint32, file *os.File) error {
	if file == nil || g.tunnel != nil {
		return errors.New("Darwin tunnel grant requires its exclusive native control descriptor")
	}
	actual, err := desktopDarwinReadTunnel(file)
	if err != nil || actual != name {
		return errors.Join(err, errors.New("Darwin tunnel descriptor has another kernel interface"))
	}
	for _, physical := range g.options.Interfaces {
		if physical.Index == index || physical.Name == name {
			return errors.New("Darwin tunnel cannot grant a physical interface")
		}
	}
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		return err
	}
	syscall.CloseOnExec(fd)
	g.tunnel = os.NewFile(uintptr(fd), "routervpn-retained-utun-control")
	return g.pf.bindTunnel(ctx, name, index)
}

func (g *desktopDarwinGuardian) retireTunnel(ctx context.Context, name string, index uint32) error {
	if g.tunnel == nil {
		return errors.New("Darwin tunnel retirement lost its retained descriptor")
	}
	actual, err := desktopDarwinReadTunnel(g.tunnel)
	if err != nil || actual != name {
		return errors.Join(err, errors.New("Darwin tunnel retirement changed its kernel control"))
	}
	if err := g.pf.retireTunnel(ctx, name, index); err != nil {
		return err
	}
	if err := g.tunnel.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	g.tunnel = nil
	return nil
}
