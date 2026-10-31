//go:build linux

package mobiletor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// These are captured native policy inputs. They cannot supply an account, UID,
// rule, executable, or pre-existing firewall permission to the guardian.
type DesktopLinuxSocketInterface struct {
	Name    string
	Index   uint32
	Address netip.Addr
}

type DesktopLinuxSocketDestination struct {
	Network string
	Address netip.AddrPort
}

type DesktopLinuxSocketOptions struct {
	Interfaces          []DesktopLinuxSocketInterface
	PrivateDestinations []DesktopLinuxSocketDestination
	LANPrefixes         []netip.Prefix
}

var desktopLinuxInterfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

func (o DesktopLinuxSocketOptions) validate() error {
	if len(o.Interfaces) < 1 || len(o.Interfaces) > 2 || len(o.PrivateDestinations) > 64 || len(o.LANPrefixes) > 32 {
		return errors.New("Linux physical policy has an invalid captured bound")
	}
	families := make(map[bool]bool)
	for _, v := range o.Interfaces {
		if !desktopLinuxInterfaceName.MatchString(v.Name) || v.Index == 0 || !v.Address.IsValid() || v.Address.IsUnspecified() || v.Address.IsMulticast() || v.Address.Is4In6() || v.Address.Zone() != "" || families[v.Address.Is4()] {
			return errors.New("Linux physical policy has an invalid or duplicate interface family")
		}
		families[v.Address.Is4()] = true
		if err := desktopLinuxCheckInterface(v); err != nil {
			return err
		}
	}
	for _, v := range o.PrivateDestinations {
		if v.Network != "tcp" && v.Network != "udp" || !v.Address.IsValid() || v.Address.Port() == 0 || v.Address.Addr().IsUnspecified() || v.Address.Addr().IsMulticast() || v.Address.Addr().Is4In6() || v.Address.Addr().Zone() != "" {
			return errors.New("Linux physical private destination is not an exact TCP/UDP tuple")
		}
	}
	for _, v := range o.LANPrefixes {
		contained := false
		for _, text := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
			allowed := netip.MustParsePrefix(text)
			if v.IsValid() && allowed.Contains(v.Addr()) && v.Bits() >= allowed.Bits() {
				contained = true
			}
		}
		if !v.IsValid() || v != v.Masked() || v.Addr().Is4In6() || !contained {
			return errors.New("Linux physical LAN allowance must be a captured private prefix")
		}
	}
	return nil
}

func desktopLinuxCheckInterface(v DesktopLinuxSocketInterface) error {
	i, err := net.InterfaceByIndex(int(v.Index))
	if err != nil || i.Name != v.Name || i.Flags&net.FlagUp == 0 {
		return errors.New("Linux physical interface changed its captured identity")
	}
	addresses, err := i.Addrs()
	if err != nil {
		return err
	}
	for _, a := range addresses {
		prefix, parseErr := netip.ParsePrefix(a.String())
		if parseErr == nil && prefix.Addr() == v.Address {
			return nil
		}
	}
	return errors.New("Linux physical interface lost its captured address")
}

func (o DesktopLinuxSocketOptions) permits(network string, remote netip.AddrPort) bool {
	if network != "tcp" && network != "udp" || !remote.IsValid() || remote.Port() == 0 || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() || remote.Addr().Is4In6() || remote.Addr().Zone() != "" {
		return false
	}
	for _, exact := range o.PrivateDestinations {
		if exact.Network == network && exact.Address == remote {
			return true
		}
	}
	for _, prefix := range o.LANPrefixes {
		if prefix.Contains(remote.Addr()) {
			return true
		}
	}
	a := remote.Addr()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, special := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001:2::/48"} {
		if netip.MustParsePrefix(special).Contains(a) {
			return false
		}
	}
	return true
}

func (o DesktopLinuxSocketOptions) binding(owner DesktopSocketKernelOwner, remote netip.AddrPort) (DesktopSocketBinding, error) {
	for _, v := range o.Interfaces {
		if v.Address.Is4() == remote.Addr().Is4() {
			if err := desktopLinuxCheckInterface(v); err != nil {
				return DesktopSocketBinding{}, err
			}
			return DesktopSocketBinding{Owner: owner, InterfaceName: v.Name, InterfaceIndex: v.Index, LocalAddress: v.Address}, nil
		}
	}
	return DesktopSocketBinding{}, errors.New("Linux physical source has no captured address for this family")
}

// DesktopLinuxSocketPolicy is usable only with the independently running root
// guardian. Each physical socket is created by an otherwise empty child under
// a dedicated locked account and transferred without changing kernel identity.
type DesktopLinuxSocketPolicy struct {
	capture  DesktopSocketCapture
	options  DesktopLinuxSocketOptions
	owner    DesktopSocketKernelOwner
	uid      uint32
	account  string
	nft      *desktopLinuxNFT
	channel  *net.UnixConn
	command  *exec.Cmd
	mu       sync.Mutex
	sequence uint64
	// socketActivity is monotonic under mu. Empty sets after an earlier socket
	// retires cannot turn an already used source into a fresh preparation.
	socketActivity    bool
	closeAcknowledged atomic.Bool
	current           atomic.Bool
	observed          atomic.Int64
	closing           atomic.Bool
	joined            chan struct{}
	monitorDone       chan struct{}
	joinErr           error
	parentStop        func() bool
}

var _ DesktopSocketPolicy = (*DesktopLinuxSocketPolicy)(nil)
var _ DesktopSocketSource = (*DesktopLinuxSocketPolicy)(nil)

func NewDesktopLinuxSocketPolicy(ctx context.Context, capture DesktopSocketCapture, options DesktopLinuxSocketOptions) (*DesktopLinuxSocketPolicy, error) {
	if ctx == nil || ctx.Err() != nil || !capture.valid() || os.Geteuid() != 0 || options.validate() != nil {
		return nil, errors.New("Linux owned physical sockets require captured policy and the privileged native host")
	}
	channel, child, err := desktopLinuxSocketPair()
	if err != nil {
		return nil, err
	}
	command := exec.Command("/proc/self/exe", "routervpn-owned-socket-helper", "guardian")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "GORACE=atexit_sleep_ms=0"}
	command.Stderr = os.Stderr
	command.ExtraFiles = []*os.File{child}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		channel.Close()
		child.Close()
		return nil, err
	}
	child.Close()
	p := &DesktopLinuxSocketPolicy{capture: capture, options: options, channel: channel, command: command, joined: make(chan struct{}), monitorDone: make(chan struct{})}
	go func() { p.joinErr = command.Wait(); p.current.Store(false); close(p.joined) }()
	request := desktopLinuxRequest{Operation: "prepare", Capture: capture, Options: options}
	reply, file, err := p.call(ctx, request, nil, false)
	if file != nil {
		file.Close()
		err = errors.New("Linux guardian prepare unexpectedly transferred a descriptor")
	}
	if err != nil || reply.UID == 0 || reply.Account == "" || !reply.Owner.valid() || reply.Owner.Kind != "unix-isolated-uid" || reply.Owner.ProcessID != uint32(command.Process.Pid) || reply.Capture != capture || reply.NFT == nil {
		channel.Close()
		close(p.monitorDone)
		return p, errors.Join(err, errors.New("Linux physical guardian did not establish its independent identity"))
	}
	p.owner, p.uid, p.account, p.nft = reply.Owner, reply.UID, reply.Account, reply.NFT
	readback, cancelReadback := context.WithTimeout(ctx, 2*time.Second)
	defer cancelReadback()
	if p.nft.Capture != capture || p.nft.UID != p.uid || desktopLinuxVerifyAccount(p.account, p.uid) != nil || p.nft.verify(readback, true) != nil {
		channel.Close()
		close(p.monitorDone)
		return p, errors.New("Linux physical identity/firewall independent readback failed")
	}
	p.current.Store(true)
	p.observed.Store(time.Now().UnixMilli())
	p.parentStop = context.AfterFunc(ctx, p.Cancel)
	go p.monitor()
	return p, nil
}

func (p *DesktopLinuxSocketPolicy) Owner() (DesktopSocketKernelOwner, error) {
	if p == nil || !p.Current(p.capture, p.owner) {
		return DesktopSocketKernelOwner{}, net.ErrClosed
	}
	return p.owner, nil
}

func (p *DesktopLinuxSocketPolicy) Current(c DesktopSocketCapture, o DesktopSocketKernelOwner) bool {
	if p == nil || c != p.capture || o != p.owner || !p.current.Load() || p.closing.Load() {
		return false
	}
	observed, now := p.observed.Load(), time.Now().UnixMilli()
	return observed > 0 && observed <= now && now-observed <= DesktopSocketReadbackAge.Milliseconds()
}

func (p *DesktopLinuxSocketPolicy) Select(ctx context.Context, c DesktopSocketCapture, network string, remote netip.AddrPort) (DesktopSocketBinding, error) {
	if ctx == nil || ctx.Err() != nil || !p.Current(c, p.owner) || !(p.options.permits(network, remote) || network == "udp" && remote.IsValid() && remote.Port() == 0 && remote.Addr().IsUnspecified()) {
		return DesktopSocketBinding{}, errors.New("Linux physical destination is outside the captured policy")
	}
	return p.options.binding(p.owner, remote)
}

func (p *DesktopLinuxSocketPolicy) CreateSocket(ctx context.Context, c DesktopSocketCreation) (DesktopSocketCreated, error) {
	if ctx == nil || ctx.Err() != nil || !p.Current(c.Capture, c.Binding.Owner) {
		return DesktopSocketCreated{}, net.ErrClosed
	}
	reply, file, err := p.call(ctx, desktopLinuxRequest{Operation: "create", Capture: p.capture, Creation: c}, nil, true)
	return DesktopSocketCreated{Creation: reply.Creation, File: file}, err
}

func (p *DesktopLinuxSocketPolicy) Bind(ctx context.Context, c DesktopSocketCapture, b DesktopSocketBinding, network string, raw syscall.RawConn) error {
	if ctx == nil || ctx.Err() != nil || !p.Current(c, b.Owner) || (network != "tcp4" && network != "tcp6" && network != "udp4" && network != "udp6") || raw == nil {
		return net.ErrClosed
	}
	var duplicate *os.File
	var failed error
	err := raw.Control(func(handle uintptr) {
		var st syscall.Stat_t
		if failed = syscall.Fstat(int(handle), &st); failed != nil {
			return
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK || st.Uid != p.uid {
			failed = errors.New("Linux physical descriptor has another kernel creator")
			return
		}
		fd, e := syscall.Dup(int(handle))
		if e != nil {
			failed = e
			return
		}
		syscall.CloseOnExec(fd)
		duplicate = os.NewFile(uintptr(fd), "routervpn-guardian-binding")
	})
	if duplicate != nil {
		defer duplicate.Close()
	}
	if err != nil || failed != nil {
		return errors.Join(err, failed)
	}
	_, file, err := p.call(ctx, desktopLinuxRequest{Operation: "bind", Capture: c, Creation: DesktopSocketCreation{Capture: c, Binding: b, Network: network}}, duplicate, true)
	if file != nil {
		file.Close()
		return errors.New("Linux bind unexpectedly returned a descriptor")
	}
	return err
}

func (p *DesktopLinuxSocketPolicy) Grant(ctx context.Context, g DesktopSocketGrant) (DesktopSocketReceipt, error) {
	if ctx == nil || ctx.Err() != nil || !p.Current(g.Capture, g.Binding.Owner) || !p.options.permits(g.Network, g.Remote) {
		return DesktopSocketReceipt{}, net.ErrClosed
	}
	reply, file, err := p.call(ctx, desktopLinuxRequest{Operation: "grant", Capture: p.capture, Grant: g}, nil, true)
	if file != nil {
		file.Close()
		return DesktopSocketReceipt{}, errors.New("Linux grant unexpectedly returned a descriptor")
	}
	return reply.Receipt, err
}

func (p *DesktopLinuxSocketPolicy) Revoke(ctx context.Context, g DesktopSocketGrant) error {
	if ctx == nil || ctx.Err() != nil || g.Capture != p.capture || g.Binding.Owner != p.owner {
		return net.ErrClosed
	}
	_, file, err := p.call(ctx, desktopLinuxRequest{Operation: "revoke", Capture: p.capture, Grant: g}, nil, false)
	if file != nil {
		file.Close()
		return errors.New("Linux revoke unexpectedly returned a descriptor")
	}
	if err == nil {
		return p.nft.absent(ctx, g)
	}
	// A dead guardian never lets a stale permit release a bound source port.
	// Kernel expiry may remove it, but the independent exact absent readback is
	// still required. Its dedicated account remains quarantined on this path.
	select {
	case <-p.joined:
		return p.nft.absent(ctx, g)
	default:
		return err
	}
}

func (p *DesktopLinuxSocketPolicy) Cancel() {
	if p != nil {
		p.closing.Store(true)
		p.current.Store(false)
	}
}

func (p *DesktopLinuxSocketPolicy) Close(ctx context.Context) (closeErr error) {
	if p == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return net.ErrClosed
	}
	defer func() {
		if closeErr == nil && p.nft != nil {
			p.closeAcknowledged.Store(true)
		}
	}()
	p.Cancel()
	if p.parentStop != nil {
		p.parentStop()
	}
	select {
	case <-p.monitorDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	if p.nft == nil {
		p.channel.Close()
		select {
		case <-p.joined:
			// Preparation could not transfer even one socket or install a tuple.
			// The helper's managed UID remains quarantined on exceptional exit.
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case <-p.joined:
		if err := p.nft.close(ctx); err != nil {
			return err
		}
		// An interrupted owner never deletes its quarantined account. Successful
		// kernel cleanup + creator/native descriptor join is sufficient to close
		// the source; retaining the identity prevents accidental reuse.
		return nil
	default:
	}
	_, file, err := p.call(ctx, desktopLinuxRequest{Operation: "finish", Capture: p.capture}, nil, false)
	if file != nil {
		file.Close()
		err = errors.New("Linux finish unexpectedly transferred a descriptor")
	}
	if err != nil {
		return err
	}
	p.channel.Close()
	select {
	case <-p.joined:
	case <-ctx.Done():
		return ctx.Err()
	}
	if p.joinErr != nil {
		return p.joinErr
	}
	return p.nft.allAbsent(ctx)
}

func (p *DesktopLinuxSocketPolicy) ReleaseSocket(ctx context.Context, c DesktopSocketCreation) error {
	if ctx == nil || ctx.Err() != nil || c.Capture != p.capture || c.Binding.Owner != p.owner {
		return net.ErrClosed
	}
	_, file, err := p.call(ctx, desktopLinuxRequest{Operation: "release", Capture: p.capture, Creation: c}, nil, false)
	if file != nil {
		file.Close()
		return errors.New("Linux socket release transferred a descriptor")
	}
	if err == nil {
		return nil
	}
	select {
	case <-p.joined:
		return p.nft.close(ctx)
	default:
		return err
	}
}

func (p *DesktopLinuxSocketPolicy) monitor() {
	defer close(p.monitorDone)
	tick := time.NewTicker(750 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-p.joined:
			return
		case <-tick.C:
		}
		if p.closing.Load() {
			return
		}
		if !p.Current(p.capture, p.owner) {
			p.current.Store(false)
			return
		}
		if _, err := p.probe(); err != nil {
			p.current.Store(false)
			return
		}
	}
}

func (p *DesktopLinuxSocketPolicy) probe() (bool, error) {
	// The monitor shares the captured request stream with foreground socket
	// operations. Start its bounded readback only after fair serialized
	// admission; waiting for another owner supplies no fresh observation.
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing.Load() {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, file, err := p.callLocked(ctx, desktopLinuxRequest{Operation: "probe", Capture: p.capture}, nil, true)
	if file != nil {
		file.Close()
		err = errors.New("Linux heartbeat transferred a descriptor")
	}
	if err == nil {
		p.observed.Store(time.Now().UnixMilli())
	}
	return true, err
}

func (p *DesktopLinuxSocketPolicy) call(ctx context.Context, request desktopLinuxRequest, file *os.File, requireCurrent bool) (desktopLinuxReply, *os.File, error) {
	if ctx == nil || ctx.Err() != nil {
		return desktopLinuxReply{}, nil, net.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.callLocked(ctx, request, file, requireCurrent)
}

// callLocked retains one complete captured request/receipt under mu. Ordinary
// caller cancellation and the existing channel deadline remain authoritative.
func (p *DesktopLinuxSocketPolicy) callLocked(ctx context.Context, request desktopLinuxRequest, file *os.File, requireCurrent bool) (desktopLinuxReply, *os.File, error) {
	if ctx.Err() != nil || requireCurrent && !p.Current(p.capture, p.owner) {
		return desktopLinuxReply{}, nil, net.ErrClosed
	}
	if request.Operation == "create" || request.Operation == "bind" || request.Operation == "grant" {
		// The request may complete after a lost receipt. Mark admission before
		// sending, even if the resulting native owner needs exceptional cleanup.
		p.socketActivity = true
	}
	p.sequence++
	request.Sequence = p.sequence
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := p.channel.SetDeadline(deadline); err != nil {
		return desktopLinuxReply{}, nil, err
	}
	if err := desktopLinuxSend(p.channel, request, file); err != nil {
		p.current.Store(false)
		return desktopLinuxReply{}, nil, err
	}
	var reply desktopLinuxReply
	received, err := desktopLinuxReceive(p.channel, &reply, uint32(p.command.Process.Pid), 0)
	if err != nil || reply.Sequence != request.Sequence || reply.Capture != p.capture || reply.Error != "" {
		p.current.Store(false)
		if err != nil || reply.Sequence != request.Sequence || reply.Capture != p.capture {
			// An unknown result cannot be followed by another request on a
			// shifted sequence. EOF makes the independent guardian retire all
			// permits/handles; Revoke still requires actual absent readback.
			p.channel.Close()
		}
		return reply, received, errors.Join(err, fmt.Errorf("Linux physical guardian rejected or lost %s: %s", request.Operation, reply.Error))
	}
	return reply, received, nil
}

func desktopLinuxOwner(c DesktopSocketCapture, uid uint32, account string, generation uint64) DesktopSocketKernelOwner {
	identity := sha256.Sum256([]byte(fmt.Sprintf("routervpn-linux-physical-v1:%s:%s:%s:%d:%s:%d:%d", c.SessionID, c.SourceSHA256, c.NetworkID, uid, account, generation, os.Getpid())))
	return DesktopSocketKernelOwner{Kind: "unix-isolated-uid", IdentitySHA256: hex.EncodeToString(identity[:]), Generation: generation, ProcessID: uint32(os.Getpid())}
}

func desktopLinuxBindingEqual(a, b DesktopSocketBinding) bool {
	return a == b && strings.TrimSpace(a.InterfaceName) == a.InterfaceName
}
