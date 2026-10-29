//go:build windows

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// DesktopWindowsSocketInspection is read from the held original kernel socket
// and a separately opened WFP session after the broker binds the transferred
// duplicate. Raw permits interface set/readback on that same retained endpoint.
// It cannot create, connect, send, or substitute a socket.
type DesktopWindowsSocketInspection struct {
	EndpointID, TokenModifiedID uint64
	Family                      int
	Protocol                    uint8
	Local, Remote               netip.AddrPort
	AppID                       []byte
	Raw                         syscall.RawConn
}

type desktopWindowsIdentitySocket struct {
	creation  DesktopSocketCreation
	original  DesktopSocketNative
	returned  DesktopSocketNative
	handedOut bool
	endpoint  uint64
}

// DesktopWindowsSocketIdentity owns a fresh, immediately disabled local account
// and its one memory-only logon token. The native host never becomes that user:
// only a dedicated, verified impersonation thread creates the original socket.
// The account/SID is never reused. Once prepared it is disabled; creation also
// atomically limits new logons to two minutes if the process crashes before
// disabling it. An ambiguous cleanup retains the token/account until exact
// descriptor retirement is proved.
type DesktopWindowsSocketIdentity struct {
	capture DesktopSocketCapture
	ctx     context.Context
	cancel  context.CancelFunc
	api     *desktopWindowsIdentityAPI
	gate    chan struct{}

	// All native resources below are accessed only while holding gate. Blocking
	// Win32 calls run on a joined operation goroutine; a cancelled caller cannot
	// drop their eventual resources or make Close reuse the isolated identity.
	account, marker string
	expires         uint32
	sid             []byte
	statistics      desktopWindowsTokenStatistics
	token           syscall.Token
	engine          syscall.Handle
	appID           []byte
	sockets         map[string]*desktopWindowsIdentitySocket
	closed          bool

	mu        sync.Mutex // owner/SID publication only; no native calls while held
	owner     DesktopSocketKernelOwner
	publicSID []byte
	current   atomic.Bool
	closing   atomic.Bool
	observed  atomic.Int64
}

var _ DesktopSocketSource = (*DesktopWindowsSocketIdentity)(nil)
var _ DesktopSocketSourceRelease = (*DesktopWindowsSocketIdentity)(nil)

// A non-nil result owns all partially acquired resources even when err is set.
// The caller must retain it and retry Close with a fresh cleanup deadline.
func NewDesktopWindowsSocketIdentity(ctx context.Context, capture DesktopSocketCapture) (*DesktopWindowsSocketIdentity, error) {
	if ctx == nil || ctx.Err() != nil || !capture.valid() {
		return nil, errors.New("Windows isolated sockets require a live captured native source")
	}
	if err := desktopWindowsRequireElevation(); err != nil {
		return nil, err
	}
	api, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	p := &DesktopWindowsSocketIdentity{capture: capture, ctx: lifetime, cancel: cancel, api: api, gate: make(chan struct{}, 1), sockets: make(map[string]*desktopWindowsIdentitySocket)}
	p.gate <- struct{}{}
	err = p.call(ctx, false, func() error {
		if err := p.prepare(); err != nil {
			return err
		}
		if p.ctx.Err() != nil || p.closing.Load() {
			return net.ErrClosed
		}
		p.observed.Store(time.Now().UnixMilli())
		p.current.Store(true)
		return nil
	})
	if err != nil {
		p.Cancel()
		return p, err
	}
	go p.monitor()
	return p, nil
}

// call serializes native operations without extending the caller's deadline.
// A late completion retains gate and every acquired resource until it finishes;
// no later cleanup can run concurrently with an outstanding Win32 mutation.
func (p *DesktopWindowsSocketIdentity) call(ctx context.Context, cleanup bool, action func() error) error {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return errors.Join(net.ErrClosed, desktopWindowsIdentityContextError(ctx))
	}
	var cancelled <-chan struct{}
	if !cleanup {
		cancelled = p.ctx.Done()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-cancelled:
		return net.ErrClosed
	case <-p.gate:
	}
	if ctx.Err() != nil || (!cleanup && p.ctx.Err() != nil) {
		p.gate <- struct{}{}
		return errors.Join(ctx.Err(), net.ErrClosed)
	}
	done := make(chan error, 1)
	go func() {
		defer func() { p.gate <- struct{}{} }()
		done <- action()
	}()
	select {
	case err := <-done:
		return errors.Join(err, ctx.Err())
	case <-ctx.Done():
		return ctx.Err()
	case <-cancelled:
		return net.ErrClosed
	}
}

func desktopWindowsIdentityContextError(ctx context.Context) error {
	if ctx != nil {
		return ctx.Err()
	}
	return errors.New("missing operation context")
}

func (p *DesktopWindowsSocketIdentity) prepare() (resultErr error) {
	secret, err := desktopWindowsPassword()
	if err != nil {
		return err
	}
	defer desktopWindowsErasePassword(secret)
	var nonce [24]byte
	for attempts := 0; attempts < 4; attempts++ {
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		p.account = "rvpn_" + hex.EncodeToString(nonce[:8])[:15]
		p.marker = "RouterVPN isolated socket " + p.capture.SessionID + " " + hex.EncodeToString(nonce[:])
		name, _ := syscall.UTF16PtrFromString(p.account)
		comment, _ := syscall.UTF16PtrFromString(p.marker)
		seconds := time.Now().Add(2 * time.Minute).Unix()
		if seconds <= 0 || seconds >= int64(^uint32(0)) {
			p.account, p.marker = "", ""
			return errors.New("Windows isolated account expiry is outside the native timestamp range")
		}
		p.expires = uint32(seconds)
		var hours [21]byte
		for i := range hours {
			hours[i] = 0xff
		}
		info := desktopWindowsUser2{Name: name, Password: &secret[0], Privilege: 1 /* USER_PRIV_USER */, Comment: comment, Flags: 0x201 /* UF_SCRIPT | UF_NORMAL_ACCOUNT */, Expires: p.expires, MaxStorage: ^uint32(0), UnitsPerWeek: 168, LogonHours: &hours[0]}
		var parameter uint32
		status, _, _ := p.api.userAdd.Call(0, 2, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
		if status == uintptr(desktopWindowsUserExists) {
			// A collision is never adopted, modified, or deleted.
			p.account, p.marker = "", ""
			continue
		}
		if status != 0 {
			return desktopWindowsCallFailure("isolated account creation", syscall.Errno(status))
		}
		break
	}
	if p.account == "" {
		return errors.New("Windows isolated account name allocation exhausted")
	}
	account, err := p.api.account(p.account)
	if err != nil || account.Comment != p.marker {
		return errors.Join(err, errors.New("Windows isolated account creation was not independently confirmed"))
	}
	p.sid = append([]byte(nil), account.SID...)
	// Every failure after creation attempts quarantine; an uncertain result
	// remains owned by this partial identity and is retried by Close.
	defer func() {
		if p.account != "" {
			resultErr = errors.Join(resultErr, p.api.disableAccount(p.account, desktopWindowsAccount{SID: p.sid, Comment: p.marker}))
		}
	}()
	if account.Flags&desktopWindowsAccountDisabled != 0 || account.Expires != p.expires || int64(account.Expires) <= time.Now().Unix() {
		return errors.New("Windows isolated account lost its atomic bounded creation window")
	}
	name, _ := syscall.UTF16PtrFromString(p.account)
	domain, _ := syscall.UTF16PtrFromString(".")
	status, _, logonErr := p.api.logon.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(&secret[0])), 3 /* LOGON32_LOGON_NETWORK */, 0, uintptr(unsafe.Pointer(&p.token)))
	// Quarantine is required even if logon fails; no background helper retains
	// the password and no interactive user profile is created.
	disableErr := p.api.disableAccount(p.account, account)
	if status == 0 || p.token == 0 {
		return errors.Join(desktopWindowsCallFailure("isolated network logon", logonErr), disableErr)
	}
	if disableErr != nil {
		return disableErr
	}
	actualSID, statistics, err := desktopWindowsTokenIdentity(p.token)
	if err != nil || !bytes.Equal(actualSID, p.sid) || statistics.TokenType != 2 /* TokenImpersonation */ || statistics.ImpersonationLevel != 2 /* SecurityImpersonation */ {
		return errors.Join(err, errors.New("Windows isolated logon returned another token identity or privilege level"))
	}
	p.statistics = statistics
	if err := syscall.SetHandleInformation(syscall.Handle(p.token), syscall.HANDLE_FLAG_INHERIT, 0); err != nil {
		return err
	}
	status, _, _ = p.api.engineOpen.Call(0, 10 /* RPC_C_AUTHN_WINNT */, 0, 0, uintptr(unsafe.Pointer(&p.engine)))
	if status != 0 || p.engine == 0 {
		return desktopWindowsCallFailure("independent WFP read session", syscall.Errno(status))
	}
	p.appID, err = p.api.executableAppID()
	if err != nil {
		return err
	}
	if err := p.verifyIdentity(); err != nil {
		return err
	}
	identity := sha256.New()
	_, _ = fmt.Fprintf(identity, "%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%d\x00", p.capture.SessionID, p.capture.SourceSHA256, p.capture.NetworkID, p.account, statistics.TokenID, statistics.AuthenticationID, statistics.ModifiedID, os.Getpid())
	_, _ = identity.Write(p.sid)
	_, _ = identity.Write(p.appID)
	generation := binary.LittleEndian.Uint64(nonce[8:16])
	if generation == 0 {
		return errors.New("Windows isolated identity has an invalid generation")
	}
	p.mu.Lock()
	p.owner = DesktopSocketKernelOwner{Kind: "windows-isolated-token", IdentitySHA256: hex.EncodeToString(identity.Sum(nil)), Generation: generation, ProcessID: uint32(os.Getpid())}
	p.publicSID = append([]byte(nil), p.sid...)
	p.mu.Unlock()
	return nil
}

func (p *DesktopWindowsSocketIdentity) verifyIdentity() error {
	if p.token == 0 || p.account == "" || len(p.sid) == 0 || p.closed {
		return errors.New("Windows isolated token ownership is incomplete")
	}
	account, err := p.api.account(p.account)
	if err != nil || !bytes.Equal(account.SID, p.sid) || account.Comment != p.marker || account.Flags&desktopWindowsAccountDisabled == 0 || account.Expires != p.expires {
		return errors.Join(err, errors.New("Windows isolated account is not the captured disabled identity"))
	}
	sid, statistics, err := desktopWindowsTokenIdentity(p.token)
	if err != nil || !bytes.Equal(sid, p.sid) || statistics != p.statistics {
		return errors.Join(err, errors.New("Windows isolated token changed its kernel identity"))
	}
	return nil
}

func (p *DesktopWindowsSocketIdentity) Owner() (DesktopSocketKernelOwner, error) {
	if p == nil {
		return DesktopSocketKernelOwner{}, net.ErrClosed
	}
	p.mu.Lock()
	owner := p.owner
	p.mu.Unlock()
	if !p.Current(p.capture, owner) {
		return DesktopSocketKernelOwner{}, net.ErrClosed
	}
	return owner, nil
}

func (p *DesktopWindowsSocketIdentity) Current(capture DesktopSocketCapture, owner DesktopSocketKernelOwner) bool {
	if p == nil || p.ctx.Err() != nil || p.closing.Load() || !p.current.Load() || capture != p.capture {
		return false
	}
	p.mu.Lock()
	expected := p.owner
	p.mu.Unlock()
	age := time.Now().UnixMilli() - p.observed.Load()
	return owner == expected && owner.valid() && age >= 0 && age <= DesktopSocketReadbackAge.Milliseconds()
}

func (p *DesktopWindowsSocketIdentity) SID() ([]byte, error) {
	owner, err := p.Owner()
	if err != nil || !p.Current(p.capture, owner) {
		return nil, net.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.publicSID...), nil
}

// AppID returns the WFP identifier of the normalized, independently held actual
// process image. Policy filters must use this captured copy, not derive a new
// identity from an 8.3 alias or a caller-supplied executable spelling.
func (p *DesktopWindowsSocketIdentity) AppID() ([]byte, error) {
	owner, err := p.Owner()
	if err != nil || !p.Current(p.capture, owner) {
		return nil, net.ErrClosed
	}
	return append([]byte(nil), p.appID...), nil
}

func (p *DesktopWindowsSocketIdentity) Cancel() {
	if p != nil {
		p.closing.Store(true)
		p.current.Store(false)
		p.cancel()
	}
}

func (p *DesktopWindowsSocketIdentity) monitor() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(p.ctx, 2*time.Second)
			err := p.call(ctx, false, func() error {
				if err := p.verifyIdentity(); err != nil {
					return err
				}
				p.observed.Store(time.Now().UnixMilli())
				return nil
			})
			cancel()
			if err != nil {
				p.Cancel()
				return
			}
		}
	}
}

func (p *DesktopWindowsSocketIdentity) validCreation(c DesktopSocketCreation) bool {
	return p.Current(c.Capture, c.Binding.Owner) && desktopSocketHex(c.SocketID, 32) && (c.Network == "tcp" || c.Network == "udp") && c.Binding.InterfaceIndex > 0 && c.Binding.InterfaceName != "" && len(c.Binding.InterfaceName) <= 256 && c.Binding.LocalAddress.IsValid() && !c.Binding.LocalAddress.IsUnspecified() && !c.Binding.LocalAddress.IsMulticast() && !c.Binding.LocalAddress.Is4In6() && c.Binding.LocalAddress.Zone() == ""
}

func (p *DesktopWindowsSocketIdentity) CreateSocket(ctx context.Context, creation DesktopSocketCreation) (DesktopSocketCreated, error) {
	return p.createSocket(ctx, creation, func(family, kind, protocol int) (DesktopSocketNative, error) {
		return p.api.createUnderToken(p.token, p.sid, p.statistics, family, kind, protocol)
	})
}

// createSocket keeps the complete ownership/handoff implementation independent
// of the one synchronous OS acquisition. Tests hold that acquisition boundary
// to exercise cancellation without timing guesses; public callers cannot
// supply a creator, token, socket handle, or alternate dialer.
func (p *DesktopWindowsSocketIdentity) createSocket(ctx context.Context, creation DesktopSocketCreation, acquire func(int, int, int) (DesktopSocketNative, error)) (DesktopSocketCreated, error) {
	var result DesktopSocketCreated
	if ctx == nil || ctx.Err() != nil || p == nil || acquire == nil || !p.validCreation(creation) {
		return result, net.ErrClosed
	}
	// The handoff lock covers the race between a native completion and the
	// caller's deadline. An already published socket is returned even with an
	// error; a later one stays owned here for ReleaseSocket to retire.
	var handoff sync.Mutex
	abandoned := false
	err := p.call(ctx, false, func() error {
		if !p.validCreation(creation) || len(p.sockets) >= DesktopSocketLimit {
			return errors.New("Windows isolated socket exceeds its live captured bound")
		}
		if _, exists := p.sockets[creation.SocketID]; exists {
			return errors.New("Windows isolated socket identity is already owned")
		}
		if err := p.verifyIdentity(); err != nil {
			p.Cancel()
			return err
		}
		record := &desktopWindowsIdentitySocket{creation: creation}
		p.sockets[creation.SocketID] = record
		family, kind, protocol := syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP
		if creation.Binding.LocalAddress.Is4() {
			family = syscall.AF_INET
		}
		if creation.Network == "udp" {
			kind, protocol = syscall.SOCK_DGRAM, syscall.IPPROTO_UDP
		}
		var err error
		record.original, err = acquire(family, kind, protocol)
		if err != nil {
			p.Cancel()
			return err
		}
		raw, err := record.original.SyscallConn()
		if err != nil {
			return err
		}
		record.returned, err = desktopWindowsNativeDuplicate(raw)
		handoff.Lock()
		if !abandoned {
			result = DesktopSocketCreated{Creation: creation, Native: record.returned}
			record.handedOut = record.returned != nil
		}
		handoff.Unlock()
		return err
	})
	handoff.Lock()
	abandoned = true
	copy := result
	handoff.Unlock()
	if err == nil && (!p.Current(creation.Capture, creation.Binding.Owner) || ctx.Err() != nil) {
		err = errors.Join(ctx.Err(), net.ErrClosed)
	}
	return copy, err
}

func desktopWindowsRawHandle(raw syscall.RawConn) (uintptr, error) {
	if raw == nil {
		return 0, net.ErrClosed
	}
	var value uintptr
	err := raw.Control(func(handle uintptr) { value = handle })
	if err == nil && (value == 0 || syscall.Handle(value) == syscall.InvalidHandle) {
		err = errors.New("Windows captured socket has no live handle")
	}
	return value, err
}

func (p *DesktopWindowsSocketIdentity) MatchSocket(ctx context.Context, capture DesktopSocketCapture, binding DesktopSocketBinding, network string, raw syscall.RawConn) (DesktopSocketCreation, error) {
	var result DesktopSocketCreation
	if ctx == nil || ctx.Err() != nil || p == nil || !p.Current(capture, binding.Owner) || raw == nil {
		return result, net.ErrClosed
	}
	base := strings.TrimSuffix(strings.TrimSuffix(network, "4"), "6")
	if base != "tcp" && base != "udp" || network != base+map[bool]string{true: "4", false: "6"}[binding.LocalAddress.Is4()] {
		return result, errors.New("Windows socket binding changed its captured network family")
	}
	var resultMu sync.Mutex
	err := p.call(ctx, false, func() error {
		if !p.Current(capture, binding.Owner) {
			return net.ErrClosed
		}
		actual, err := desktopWindowsRawHandle(raw)
		if err != nil {
			return err
		}
		for _, record := range p.sockets {
			if record.creation.Capture != capture || record.creation.Binding != binding || record.creation.Network != base || !record.handedOut || record.returned == nil {
				continue
			}
			ownedRaw, err := record.returned.SyscallConn()
			if err != nil {
				continue
			}
			owned, err := desktopWindowsRawHandle(ownedRaw)
			if err == nil && owned == actual {
				resultMu.Lock()
				result = record.creation
				resultMu.Unlock()
				return nil
			}
		}
		return errors.New("Windows physical socket is not an exact transferred isolated handle")
	})
	resultMu.Lock()
	copy := result
	resultMu.Unlock()
	return copy, err
}

func (p *DesktopWindowsSocketIdentity) InspectSocket(ctx context.Context, creation DesktopSocketCreation) (DesktopWindowsSocketInspection, error) {
	var result DesktopWindowsSocketInspection
	var resultMu sync.Mutex
	if ctx == nil || ctx.Err() != nil || p == nil || !p.validCreation(creation) {
		return result, net.ErrClosed
	}
	err := p.call(ctx, false, func() error {
		record := p.sockets[creation.SocketID]
		if record == nil || record.creation != creation || record.original == nil || record.returned == nil || !record.handedOut || !p.validCreation(creation) {
			return errors.New("Windows ALE proof lost its exact socket creation")
		}
		if err := p.verifyIdentity(); err != nil {
			p.Cancel()
			return err
		}
		raw, err := record.original.SyscallConn()
		if err != nil {
			return err
		}
		endpoint, err := desktopWindowsALEEndpoint(raw)
		if err != nil {
			return err
		}
		otherRaw, err := record.returned.SyscallConn()
		if err != nil {
			return err
		}
		other, err := desktopWindowsALEEndpoint(otherRaw)
		if err != nil || other != endpoint || (record.endpoint != 0 && record.endpoint != endpoint) {
			return errors.Join(err, errors.New("Windows socket transfer changed its retained ALE endpoint"))
		}
		properties, appID, err := p.api.endpointProperties(p.engine, endpoint)
		if err != nil {
			return err
		}
		if properties.TokenModifiedID != p.statistics.ModifiedID || !bytes.Equal(appID, p.appID) {
			return errors.New("Windows ALE endpoint does not belong to the captured isolated token and process")
		}
		localAddress, err := desktopWindowsALEAddress(properties.IPVersion, properties.LocalAddress)
		if err != nil {
			return err
		}
		remoteAddress, err := desktopWindowsALEAddress(properties.IPVersion, properties.RemoteAddress)
		if err != nil {
			return err
		}
		local := netip.AddrPortFrom(localAddress, properties.LocalPort)
		remote := netip.AddrPortFrom(remoteAddress, properties.RemotePort)
		protocol, family := uint8(syscall.IPPROTO_TCP), syscall.AF_INET6
		if creation.Network == "udp" {
			protocol = syscall.IPPROTO_UDP
		}
		if creation.Binding.LocalAddress.Is4() {
			family = syscall.AF_INET
		}
		if properties.Protocol != protocol || local.Addr() != creation.Binding.LocalAddress || local.Port() == 0 || local.Addr().Is4() != creation.Binding.LocalAddress.Is4() {
			return errors.New("Windows ALE endpoint changed its bound family, protocol, or local tuple")
		}
		var socketErr error
		err = raw.Control(func(handle uintptr) {
			address, readErr := syscall.Getsockname(syscall.Handle(handle))
			if readErr != nil {
				socketErr = readErr
				return
			}
			actual, readErr := desktopWindowsIdentitySocketAddress(address)
			if readErr != nil || actual != local {
				socketErr = errors.Join(readErr, errors.New("Windows ALE local tuple disagrees with the retained socket"))
				return
			}
			peer, readErr := syscall.Getpeername(syscall.Handle(handle))
			if errors.Is(readErr, desktopSocketNotConnected) || errors.Is(readErr, syscall.Errno(10022)) {
				if remote.Port() != 0 || !remote.Addr().IsUnspecified() {
					socketErr = errors.New("Windows unconnected socket has a conflicting ALE remote tuple")
				}
				return
			}
			if readErr != nil {
				socketErr = readErr
				return
			}
			actual, readErr = desktopWindowsIdentitySocketAddress(peer)
			if readErr != nil || actual != remote {
				socketErr = errors.Join(readErr, errors.New("Windows ALE remote tuple disagrees with the retained socket"))
			}
		})
		if err != nil || socketErr != nil {
			return errors.Join(err, socketErr)
		}
		record.endpoint = endpoint
		p.observed.Store(time.Now().UnixMilli())
		resultMu.Lock()
		result = DesktopWindowsSocketInspection{EndpointID: endpoint, TokenModifiedID: properties.TokenModifiedID, Family: family, Protocol: protocol, Local: local, Remote: remote, AppID: appID, Raw: raw}
		resultMu.Unlock()
		return nil
	})
	resultMu.Lock()
	copy := result
	resultMu.Unlock()
	return copy, err
}

func desktopWindowsIdentitySocketAddress(address syscall.Sockaddr) (netip.AddrPort, error) {
	switch address := address.(type) {
	case *syscall.SockaddrInet4:
		if address.Port > 0 && address.Port <= 65535 {
			return netip.AddrPortFrom(netip.AddrFrom4(address.Addr), uint16(address.Port)), nil
		}
	case *syscall.SockaddrInet6:
		if address.Port > 0 && address.Port <= 65535 && address.ZoneId == 0 {
			return netip.AddrPortFrom(netip.AddrFrom16(address.Addr), uint16(address.Port)), nil
		}
	}
	return netip.AddrPort{}, errors.New("Windows isolated socket has no exact numeric tuple")
}

func (p *DesktopWindowsSocketIdentity) ReleaseSocket(ctx context.Context, creation DesktopSocketCreation) error {
	if p == nil || creation.Capture != p.capture {
		return errors.New("Windows socket retirement changed its captured owner")
	}
	return p.call(ctx, true, func() error {
		record := p.sockets[creation.SocketID]
		if record == nil {
			// No acquisition started, or this exact identity already retired.
			return nil
		}
		if record.creation != creation {
			return errors.New("Windows socket retirement changed its exact creation")
		}
		if record.returned != nil {
			if record.handedOut {
				if _, err := record.returned.SyscallConn(); !errors.Is(err, net.ErrClosed) {
					return errors.New("Windows socket retirement precedes transferred descriptor closure")
				}
			} else if err := record.returned.Close(); err != nil {
				return err
			}
		}
		if record.original != nil {
			if err := record.original.Close(); err != nil {
				return err
			}
		}
		if record.endpoint != 0 {
			if _, _, err := p.api.endpointProperties(p.engine, record.endpoint); !errors.Is(err, desktopWindowsEndpointNotFound) {
				return errors.Join(err, errors.New("Windows socket ALE endpoint has not independently retired"))
			}
		}
		// The broker has already independently revoked every permit and joined
		// all native I/O/keepers before this callback. A returned descriptor must
		// also be closed here before the source's final original is released.
		delete(p.sockets, creation.SocketID)
		return nil
	})
}

func (p *DesktopWindowsSocketIdentity) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.Cancel()
	return p.call(ctx, true, func() error {
		if p.closed {
			return nil
		}
		// Cancellation may precede the native creation reply. The broker cannot
		// call per-socket Release when it never received a descriptor. Once this
		// operation gate joins, only those never handed out can be closed here:
		// no Bind, Grant, or I/O could have observed them.
		for id, record := range p.sockets {
			if record.handedOut {
				continue
			}
			if record.returned != nil {
				if err := record.returned.Close(); err != nil {
					return err
				}
			}
			if record.original != nil {
				if err := record.original.Close(); err != nil {
					return err
				}
			}
			delete(p.sockets, id)
		}
		if len(p.sockets) != 0 {
			return errors.New("Windows isolated identity still owns unretired sockets")
		}
		if p.account != "" {
			account, err := p.api.account(p.account)
			if errors.Is(err, desktopWindowsUserNotFound) {
				// There are no outstanding sockets. Independently observed absence
				// also covers a successful earlier deletion whose readback failed.
				// Held token/engine handles are still closed below before success.
				p.account = ""
			} else {
				if err != nil || account.Comment != p.marker || (len(p.sid) != 0 && !bytes.Equal(account.SID, p.sid)) {
					return errors.Join(err, errors.New("Windows isolated account changed before cleanup"))
				}
				if len(p.sid) == 0 {
					p.sid = append([]byte(nil), account.SID...)
				}
				if err := p.api.disableAccount(p.account, account); err != nil {
					return err
				}
			}
		}
		if p.engine != 0 {
			status, _, _ := p.api.engineClose.Call(uintptr(p.engine))
			if status != 0 {
				return syscall.Errno(status)
			}
			p.engine = 0
		}
		if p.token != 0 {
			if err := p.token.Close(); err != nil {
				return err
			}
			p.token = 0
		}
		if p.account != "" {
			// Read identity again immediately before deleting the disabled
			// account. A different SID/name replacement must remain untouched.
			account, err := p.api.account(p.account)
			if err != nil || account.Comment != p.marker || !bytes.Equal(account.SID, p.sid) || account.Flags&desktopWindowsAccountDisabled == 0 {
				return errors.Join(err, errors.New("Windows isolated account deletion lost its exact disabled SID"))
			}
			name, _ := syscall.UTF16PtrFromString(p.account)
			status, _, _ := p.api.userDelete.Call(0, uintptr(unsafe.Pointer(name)))
			if status != 0 {
				return syscall.Errno(status)
			}
			if _, err := p.api.account(p.account); !errors.Is(err, desktopWindowsUserNotFound) {
				return errors.New("Windows isolated account deletion was not independently confirmed")
			}
			p.account = ""
		}
		p.closed = true
		return nil
	})
}
