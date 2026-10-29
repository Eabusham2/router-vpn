//go:build windows && routervpn_windows_identity

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// These are actual local Windows account, token, Winsock and WFP operations.
// Connections and byte exchanges use only owned loopback peers. These tests
// install no firewall permission and change no existing account. Lack of
// elevation/BFE/IPv6 is a failed required gate, not a skipped identity proof.
// Every created account is fresh and expires atomically.
func desktopWindowsIdentityTestNew(t *testing.T) *DesktopWindowsSocketIdentity {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	p, err := NewDesktopWindowsSocketIdentity(ctx, desktopSocketFixtureCapture())
	if p != nil {
		t.Cleanup(func() {
			defer cancel()
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if err := p.Close(cleanup); err != nil {
				t.Error("isolated Windows identity did not join and retire", err)
				// A deliberately broken production mutant must still retire only
				// its exact test-owned handles and account. This recovery is never
				// used as an acceptance result or a production cleanup substitute.
				if recoveryErr := desktopWindowsIdentityTestRecover(p); recoveryErr != nil {
					t.Error("isolated test-owned recovery failed", recoveryErr)
				}
			}
		})
	} else {
		t.Cleanup(cancel)
	}
	if err != nil {
		t.Fatal("actual Windows isolated identity preparation", err)
	}
	return p
}

func desktopWindowsIdentityTestRecover(p *DesktopWindowsSocketIdentity) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.call(ctx, true, func() error {
		for id, record := range p.sockets {
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
		if p.token != 0 {
			if err := p.token.Close(); err != nil {
				return err
			}
			p.token = 0
		}
		if p.engine != 0 {
			status, _, _ := p.api.engineClose.Call(uintptr(p.engine))
			if status != 0 {
				return syscall.Errno(status)
			}
			p.engine = 0
		}
		if p.account != "" {
			account, err := p.api.account(p.account)
			if errors.Is(err, desktopWindowsUserNotFound) {
				p.account = ""
				return nil
			}
			if err != nil || account.Comment != p.marker || (len(p.sid) != 0 && !bytes.Equal(p.sid, account.SID)) {
				return errors.Join(err, errors.New("test recovery refused another account identity"))
			}
			if err := p.api.disableAccount(p.account, account); err != nil {
				return err
			}
			name, _ := syscall.UTF16PtrFromString(p.account)
			status, _, _ := p.api.userDelete.Call(0, uintptr(unsafe.Pointer(name)))
			if status != 0 {
				return syscall.Errno(status)
			}
			if _, err := p.api.account(p.account); !errors.Is(err, desktopWindowsUserNotFound) {
				return errors.New("test recovery could not confirm owned account removal")
			}
			p.account = ""
		}
		return nil
	})
}

func desktopWindowsIdentityTestRelease(p *DesktopWindowsSocketIdentity, creation DesktopSocketCreation) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		err := p.ReleaseSocket(ctx, creation)
		if err == nil || !strings.Contains(err.Error(), "ALE endpoint has not independently retired") {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func desktopWindowsIdentityTestCreation(t *testing.T, p *DesktopWindowsSocketIdentity, network, address string) DesktopSocketCreation {
	t.Helper()
	owner, err := p.Owner()
	if err != nil {
		t.Fatal(err)
	}
	local := netip.MustParseAddr(address)
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var binding DesktopSocketBinding
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, candidate := range addresses {
			prefix, err := netip.ParsePrefix(candidate.String())
			if err == nil && prefix.Addr() == local {
				binding = DesktopSocketBinding{Owner: owner, InterfaceName: iface.Name, InterfaceIndex: uint32(iface.Index), LocalAddress: local}
			}
		}
	}
	if binding.InterfaceIndex == 0 {
		t.Fatal("required Windows loopback address has no real interface", address)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return DesktopSocketCreation{Capture: p.capture, Binding: binding, SocketID: hex.EncodeToString(id[:]), Network: network}
}

func desktopWindowsIdentityTestCreate(t *testing.T, p *DesktopWindowsSocketIdentity, creation DesktopSocketCreation) DesktopSocketCreated {
	t.Helper()
	ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
	defer cancel()
	result, err := p.CreateSocket(ctx, creation)
	if result.Native != nil {
		t.Cleanup(func() {
			if err := result.Native.Close(); err != nil {
				t.Error("close transferred identity socket", err)
			}
			if err := desktopWindowsIdentityTestRelease(p, creation); err != nil {
				t.Error("release retained identity socket", err)
			}
		})
	}
	if err != nil || result.Native == nil || result.File != nil || result.Creation != creation {
		t.Fatal("actual isolated Winsock creation", err)
	}
	return result
}

func desktopWindowsIdentityTestBind(t *testing.T, native DesktopSocketNative, local netip.Addr) (syscall.RawConn, netip.AddrPort) {
	t.Helper()
	raw, err := native.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := desktopSocketExclusive(raw); err != nil {
		t.Fatal(err)
	}
	var result error
	var bound netip.AddrPort
	err = raw.Control(func(handle uintptr) {
		fd := syscall.Handle(handle)
		var target syscall.Sockaddr
		if local.Is4() {
			target = &syscall.SockaddrInet4{Addr: local.As4()}
		} else {
			target = &syscall.SockaddrInet6{Addr: local.As16()}
			if result = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); result != nil {
				return
			}
		}
		if result = syscall.Bind(fd, target); result != nil {
			return
		}
		bound, result = desktopSocketLocal(fd)
	})
	if err != nil || result != nil || !bound.IsValid() {
		t.Fatal("actual isolated socket bind", err, result)
	}
	return raw, bound
}

func desktopWindowsIdentityTestAccount(t *testing.T, p *DesktopWindowsSocketIdentity) desktopWindowsAccount {
	t.Helper()
	var account desktopWindowsAccount
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.call(ctx, true, func() error {
		var err error
		account, err = p.api.account(p.account)
		return err
	}); err != nil {
		t.Fatal("independent account readback", err)
	}
	return account
}

func desktopWindowsIdentityTestDiagnoseALE(t *testing.T, phase string, p *DesktopWindowsSocketIdentity, socket DesktopSocketNative) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.call(ctx, true, func() error {
		raw, err := socket.SyscallConn()
		if err != nil {
			return err
		}
		endpoint, err := desktopWindowsALEEndpoint(raw)
		if err != nil {
			return err
		}
		var properties *desktopWindowsALEProperties
		status, _, _ := p.api.endpoint.Call(uintptr(p.engine), uintptr(endpoint), uintptr(unsafe.Pointer(&properties)))
		if properties != nil {
			defer p.api.freeWFP.Call(uintptr(unsafe.Pointer(&properties)))
		}
		if status != 0 || properties == nil {
			return desktopWindowsCallFailure("diagnostic ALE properties", syscall.Errno(status))
		}
		process, err := syscall.OpenCurrentProcessToken()
		if err != nil {
			return err
		}
		processSID, processStatistics, tokenErr := desktopWindowsTokenIdentity(process)
		closeErr := process.Close()
		if tokenErr != nil || closeErr != nil {
			return errors.Join(tokenErr, closeErr)
		}
		var appID []byte
		if properties.AppID.Data != nil && properties.AppID.Size <= 65536 {
			appID = append([]byte(nil), unsafe.Slice(properties.AppID.Data, int(properties.AppID.Size))...)
		}
		// Ephemeral LUIDs and hashes distinguish the actual kernel field that
		// disagrees; no SID bytes, password, account name, or local path is logged.
		t.Logf("ALE identity diagnostic phase=%s endpoint=%x kernel_modified=%x captured_modified=%x ordinary_modified=%x ordinary_sid_differs=%t app_matches=%t app_bytes=%d/%d app_sha256=%x/%x protocol=%d local_port=%d", phase, endpoint, properties.TokenModifiedID, p.statistics.ModifiedID, processStatistics.ModifiedID, !bytes.Equal(processSID, p.sid), bytes.Equal(appID, p.appID), len(appID), len(p.appID), sha256.Sum256(appID), sha256.Sum256(p.appID), properties.Protocol, properties.LocalPort)
		states := []struct {
			name string
			raw  syscall.RawConn
		}{{"returned", raw}}
		for _, record := range p.sockets {
			if record.returned == socket && record.original != nil {
				original, err := record.original.SyscallConn()
				if err != nil {
					return err
				}
				states = append(states, struct {
					name string
					raw  syscall.RawConn
				}{"original", original})
			}
		}
		for _, state := range states {
			stateEndpoint, endpointErr := desktopWindowsALEEndpoint(state.raw)
			properties, appID, propertiesErr := p.api.endpointProperties(p.engine, stateEndpoint)
			localAddress, _ := desktopWindowsALEAddress(properties.IPVersion, properties.LocalAddress)
			remoteAddress, _ := desktopWindowsALEAddress(properties.IPVersion, properties.RemoteAddress)
			t.Logf("ALE handle diagnostic phase=%s handle=%s endpoint=%x endpoint_error=%v properties_error=%v kernel_modified=%x captured_modified=%x app_matches=%t local=%v remote=%v", phase, state.name, stateEndpoint, endpointErr, propertiesErr, properties.TokenModifiedID, p.statistics.ModifiedID, bytes.Equal(appID, p.appID), netip.AddrPortFrom(localAddress, properties.LocalPort), netip.AddrPortFrom(remoteAddress, properties.RemotePort))
			if err := state.raw.Control(func(handle uintptr) {
				local, localErr := syscall.Getsockname(syscall.Handle(handle))
				peer, peerErr := syscall.Getpeername(syscall.Handle(handle))
				var localCode, peerCode syscall.Errno
				_ = errors.As(localErr, &localCode)
				_ = errors.As(peerErr, &peerCode)
				t.Logf("Winsock bind diagnostic phase=%s handle=%s getsockname_errno=%d getpeername_errno=%d local=%v peer=%v", phase, state.name, localCode, peerCode, local, peer)
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Logf("ALE identity diagnostic phase=%s unavailable: %v", phase, err)
	}
}

func TestDesktopSocketWindowsIdentitySDKLayout(t *testing.T) {
	var properties desktopWindowsALEProperties
	if unsafe.Sizeof(properties) != 104 || unsafe.Offsetof(properties.Protocol) != 44 || unsafe.Offsetof(properties.LocalPort) != 46 || unsafe.Offsetof(properties.RemotePort) != 48 || unsafe.Offsetof(properties.TokenModifiedID) != 56 || unsafe.Offsetof(properties.AppID) != 88 {
		t.Fatal("FWPS_ALE_ENDPOINT_PROPERTIES0 no longer matches the 64-bit Windows SDK")
	}
	var user desktopWindowsUser2
	if unsafe.Sizeof(user) != 152 || unsafe.Offsetof(user.Flags) != 40 || unsafe.Offsetof(user.AuthFlags) != 56 || unsafe.Offsetof(user.Expires) != 104 || unsafe.Offsetof(user.LogonHours) != 120 || unsafe.Offsetof(user.LogonServer) != 136 {
		t.Fatal("USER_INFO_2 no longer matches the 64-bit Windows SDK")
	}
	var token desktopWindowsTokenStatistics
	if unsafe.Sizeof(token) != 56 || unsafe.Offsetof(token.ModifiedID) != 48 {
		t.Fatal("TOKEN_STATISTICS no longer matches the Windows SDK")
	}
	if _, err := desktopWindowsALEAddress(2, [16]byte{}); err == nil {
		t.Fatal("unknown native address family was accepted")
	}
}

func TestDesktopSocketWindowsIdentityBoundKernelEndpoints(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network+"-"+address, func(t *testing.T) {
				p := desktopWindowsIdentityTestNew(t)
				creation := desktopWindowsIdentityTestCreation(t, p, network, address)
				result := desktopWindowsIdentityTestCreate(t, p, creation)
				account := desktopWindowsIdentityTestAccount(t, p)
				if account.Flags&desktopWindowsAccountDisabled == 0 || account.Expires != p.expires || int64(account.Expires) > time.Now().Add(2*time.Minute).Unix() || account.Comment != p.marker {
					t.Fatal("created account lacks independently verified disabled/expiry ownership")
				}
				processToken, err := syscall.OpenCurrentProcessToken()
				if err != nil {
					t.Fatal(err)
				}
				processSID, processStatistics, tokenErr := desktopWindowsTokenIdentity(processToken)
				closeErr := processToken.Close()
				if tokenErr != nil || closeErr != nil || bytes.Equal(processSID, p.sid) || processStatistics.ModifiedID == p.statistics.ModifiedID {
					t.Fatal("isolated socket identity reused the ordinary host token", tokenErr, closeErr)
				}
				copySID, err := p.SID()
				if err != nil || !bytes.Equal(copySID, account.SID) {
					t.Fatal("SID did not match independent account readback", err)
				}
				copySID[0] ^= 0xff
				again, err := p.SID()
				if err != nil || !bytes.Equal(again, account.SID) {
					t.Fatal("caller could mutate captured SID authority", err)
				}
				raw, err := result.Native.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				family := "6"
				if creation.Binding.LocalAddress.Is4() {
					family = "4"
				}
				matched, err := p.MatchSocket(p.ctx, creation.Capture, creation.Binding, network+family, raw)
				if err != nil || matched != creation {
					t.Fatal("exact transferred unbound handle did not match", err)
				}
				if _, err := p.InspectSocket(p.ctx, creation); err == nil {
					t.Fatal("unbound socket acquired a post-bind ALE proof")
				}
				desktopWindowsIdentityTestDiagnoseALE(t, "before-bind", p, result.Native)
				_, bound := desktopWindowsIdentityTestBind(t, result.Native, creation.Binding.LocalAddress)
				desktopWindowsIdentityTestDiagnoseALE(t, "after-bind", p, result.Native)
				inspection, err := p.InspectSocket(p.ctx, creation)
				if err != nil {
					t.Fatal("actual post-bind ALE endpoint/token proof", err)
				}
				protocol, nativeFamily := uint8(syscall.IPPROTO_TCP), syscall.AF_INET6
				if network == "udp" {
					protocol = syscall.IPPROTO_UDP
				}
				if family == "4" {
					nativeFamily = syscall.AF_INET
				}
				if inspection.EndpointID == 0 || inspection.TokenModifiedID != p.statistics.ModifiedID || inspection.Local != bound || inspection.Remote.Port() != 0 || !inspection.Remote.Addr().IsUnspecified() || inspection.Protocol != protocol || inspection.Family != nativeFamily || !bytes.Equal(inspection.AppID, p.appID) {
					t.Fatal("ALE proof failed to match actual isolated token and complete tuple", inspection)
				}
				var retained uint64
				err = p.call(p.ctx, false, func() error {
					original, err := p.sockets[creation.SocketID].original.SyscallConn()
					if err != nil {
						return err
					}
					retained, err = desktopWindowsALEEndpoint(original)
					return err
				})
				transferred, otherErr := desktopWindowsALEEndpoint(raw)
				boundHandle, boundErr := desktopWindowsALEEndpoint(inspection.Raw)
				if err != nil || otherErr != nil || boundErr != nil || retained != inspection.EndpointID || transferred != retained || boundHandle != retained {
					t.Fatal("socket duplication replaced the original ALE endpoint", err, otherErr)
				}
				returnedHandle, returnedErr := desktopWindowsRawHandle(raw)
				inspectionHandle, inspectionErr := desktopWindowsRawHandle(inspection.Raw)
				if returnedErr != nil || inspectionErr != nil || returnedHandle != inspectionHandle {
					t.Fatal("interface readback did not retain the exact bound transferred descriptor", returnedErr, inspectionErr)
				}
			})
		}
	}
}

func TestDesktopSocketWindowsIdentityRejectsOrdinaryTokenSocket(t *testing.T) {
	p := desktopWindowsIdentityTestNew(t)
	creation := desktopWindowsIdentityTestCreation(t, p, "tcp", "127.0.0.1")
	ordinary, err := desktopWindowsNativeTestSocket("tcp", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ordinary.Close() })
	raw, _ := ordinary.SyscallConn()
	if _, err := p.MatchSocket(p.ctx, creation.Capture, creation.Binding, "tcp4", raw); err == nil {
		t.Fatal("ordinary host socket passed isolated transferred-handle matching")
	}
	duplicate, err := desktopWindowsNativeDuplicate(raw)
	if duplicate != nil {
		t.Cleanup(func() { _ = duplicate.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	desktopWindowsIdentityTestBind(t, duplicate, creation.Binding.LocalAddress)
	endpoint, err := desktopWindowsALEEndpoint(raw)
	if err != nil {
		t.Fatal("ordinary socket must supply a real ALE endpoint for negative control", err)
	}
	properties, _, err := p.api.endpointProperties(p.engine, endpoint)
	if err != nil || properties.TokenModifiedID == p.statistics.ModifiedID {
		t.Fatal("ordinary endpoint negative control was not independently distinguished", err)
	}
	// Deliberately put false transfer metadata around the real ordinary-token
	// socket. The independent kernel token check must still reject it.
	if err := p.call(p.ctx, false, func() error {
		p.sockets[creation.SocketID] = &desktopWindowsIdentitySocket{creation: creation, original: ordinary, returned: duplicate, handedOut: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = duplicate.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.ReleaseSocket(cleanup, creation); err != nil {
			t.Error(err)
		}
	})
	if _, err := p.InspectSocket(p.ctx, creation); err == nil || !strings.Contains(err.Error(), "captured isolated token") {
		t.Fatal("false transfer metadata bypassed independent ordinary-token rejection", err)
	}
}

func TestDesktopSocketWindowsIdentityRejectsTupleAndCaptureReplacement(t *testing.T) {
	p := desktopWindowsIdentityTestNew(t)
	creation := desktopWindowsIdentityTestCreation(t, p, "tcp", "127.0.0.1")
	result := desktopWindowsIdentityTestCreate(t, p, creation)
	raw, _ := result.Native.SyscallConn()
	for _, change := range []func(*DesktopSocketCreation){
		func(c *DesktopSocketCreation) { c.Capture.SessionID = strings.Repeat("b", 32) },
		func(c *DesktopSocketCreation) { c.Capture.SourceSHA256 = strings.Repeat("c", 64) },
		func(c *DesktopSocketCreation) { c.Capture.NetworkID = strings.Repeat("d", 32) },
		func(c *DesktopSocketCreation) { c.Binding.Owner.Generation++ },
	} {
		wrong := creation
		change(&wrong)
		if _, err := p.MatchSocket(p.ctx, wrong.Capture, wrong.Binding, "tcp4", raw); err == nil {
			t.Fatal("replacement capture/owner matched an old native socket")
		}
		if _, err := p.InspectSocket(p.ctx, wrong); err == nil {
			t.Fatal("replacement capture/owner inspected an old native socket")
		}
	}
	if duplicate, err := p.CreateSocket(p.ctx, creation); err == nil || duplicate.Native != nil {
		t.Fatal("duplicate socket identity was reused", err)
	}
	desktopWindowsIdentityTestBind(t, result.Native, creation.Binding.LocalAddress)
	wrong := creation
	wrong.Binding.LocalAddress = netip.MustParseAddr("127.0.0.2")
	if err := p.call(p.ctx, false, func() error {
		p.sockets[creation.SocketID].creation = wrong
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, inspectErr := p.InspectSocket(p.ctx, wrong)
	if err := p.call(p.ctx, false, func() error {
		p.sockets[creation.SocketID].creation = creation
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if inspectErr == nil || !strings.Contains(inspectErr.Error(), "bound family, protocol, or local tuple") {
		t.Fatal("metadata changed the independently read bound tuple", inspectErr)
	}
}

func TestDesktopSocketWindowsIdentityRetainsTransferredSocketUntilRelease(t *testing.T) {
	p := desktopWindowsIdentityTestNew(t)
	creation := desktopWindowsIdentityTestCreation(t, p, "udp", "127.0.0.1")
	result := desktopWindowsIdentityTestCreate(t, p, creation)
	_, bound := desktopWindowsIdentityTestBind(t, result.Native, creation.Binding.LocalAddress)
	if err := p.ReleaseSocket(p.ctx, creation); err == nil {
		t.Fatal("source retired while the transferred socket remained open")
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Close(cleanup); err == nil || !strings.Contains(err.Error(), "unretired sockets") {
		t.Fatal("identity was released before its transferred descriptor", err)
	}
	if p.Current(creation.Capture, creation.Binding.Owner) {
		t.Fatal("closing identity remained current")
	}
	raw, err := result.Native.SyscallConn()
	if err != nil {
		t.Fatal("failed cleanup discarded transferred ownership", err)
	}
	var actual netip.AddrPort
	var nativeErr error
	if err := raw.Control(func(handle uintptr) { actual, nativeErr = desktopSocketLocal(syscall.Handle(handle)) }); err != nil || nativeErr != nil || actual != bound {
		t.Fatal("failed cleanup changed the retained local tuple", err, nativeErr)
	}
	accountName := p.account
	if err := result.Native.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.ReleaseSocket(cleanup, creation); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(cleanup); err != nil {
		t.Fatal("retryable identity cleanup", err)
	}
	if _, err := p.api.account(accountName); !errors.Is(err, desktopWindowsUserNotFound) {
		t.Fatal("owned account survived confirmed descriptor retirement", err)
	}
}

func TestDesktopSocketWindowsIdentityRetainsLateCreationUntilJoin(t *testing.T) {
	p := desktopWindowsIdentityTestNew(t)
	creation := desktopWindowsIdentityTestCreation(t, p, "tcp", "127.0.0.1")
	started, release := make(chan struct{}), make(chan struct{})
	acquired := make(chan DesktopSocketNative, 1)
	ctx, cancel := context.WithCancel(p.ctx)
	t.Cleanup(cancel)
	result := make(chan DesktopSocketCreated, 1)
	failure := make(chan error, 1)
	go func() {
		created, err := p.createSocket(ctx, creation, func(family, kind, protocol int) (DesktopSocketNative, error) {
			close(started)
			<-release
			socket, err := p.api.createUnderToken(p.token, p.sid, p.statistics, family, kind, protocol)
			acquired <- socket
			return socket, err
		})
		result <- created
		failure <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("held native creation did not start")
	}
	cancel()
	select {
	case created := <-result:
		if created.Native != nil || <-failure == nil {
			close(release)
			t.Fatal("cancelled uncompleted acquisition escaped as a transferred socket")
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("creation ignored explicit cancellation")
	}
	short, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err := p.Close(short)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatal("identity cleanup bypassed the actual held native operation", err)
	}
	close(release)
	var socket DesktopSocketNative
	select {
	case socket = <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("released native creation never joined")
	}
	if socket == nil {
		t.Fatal("late resource control did not create a real isolated socket")
	}
	cleanup, finish := context.WithTimeout(context.Background(), 5*time.Second)
	defer finish()
	if err := p.Close(cleanup); err != nil {
		t.Fatal("late never-transferred socket was not retired after joining", err)
	}
	if _, err := socket.SyscallConn(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late original socket leaked after identity cleanup", err)
	}
}

func TestDesktopSocketWindowsIdentityRetainsPartialCreationError(t *testing.T) {
	p := desktopWindowsIdentityTestNew(t)
	creation := desktopWindowsIdentityTestCreation(t, p, "udp", "127.0.0.1")
	var original DesktopSocketNative
	created, err := p.createSocket(p.ctx, creation, func(family, kind, protocol int) (DesktopSocketNative, error) {
		var err error
		original, err = p.api.createUnderToken(p.token, p.sid, p.statistics, family, kind, protocol)
		return original, errors.Join(err, errors.New("controlled failure after actual socket acquisition"))
	})
	if err == nil || created.Native != nil || original == nil {
		t.Fatal("partial native acquisition control did not fail with retained ownership", err)
	}
	cleanup, finish := context.WithTimeout(context.Background(), 5*time.Second)
	defer finish()
	if err := p.Close(cleanup); err != nil {
		t.Fatal("partial creation error stranded its owned resource", err)
	}
	if _, err := original.SyscallConn(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("partial native acquisition leaked its original handle", err)
	}
}

func TestDesktopSocketWindowsIdentityRejectsUnjoinedDuplicate(t *testing.T) {
	p := desktopWindowsIdentityTestNew(t)
	creation := desktopWindowsIdentityTestCreation(t, p, "udp", "127.0.0.1")
	result := desktopWindowsIdentityTestCreate(t, p, creation)
	raw, _ := desktopWindowsIdentityTestBind(t, result.Native, creation.Binding.LocalAddress)
	inspection, err := p.InspectSocket(p.ctx, creation)
	if err != nil {
		t.Fatal("post-bind proof before held duplicate", err)
	}
	extra, err := desktopWindowsNativeDuplicate(raw)
	if extra != nil {
		t.Cleanup(func() { _ = extra.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Native.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.ReleaseSocket(p.ctx, creation); err == nil || !strings.Contains(err.Error(), "ALE endpoint has not independently retired") {
		t.Fatal("retirement ignored a real unjoined duplicate of the ALE endpoint", err)
	}
	if err := p.call(p.ctx, false, func() error {
		properties, _, err := p.api.endpointProperties(p.engine, inspection.EndpointID)
		if err != nil || properties.EndpointID != inspection.EndpointID || properties.TokenModifiedID != inspection.TokenModifiedID {
			return errors.Join(err, errors.New("held duplicate no longer independently preserves the same kernel endpoint"))
		}
		return nil
	}); err != nil {
		t.Fatal("live duplicate did not retain independently queryable ownership", err)
	}
	if err := extra.Close(); err != nil {
		t.Fatal(err)
	}
	if err := desktopWindowsIdentityTestRelease(p, creation); err != nil {
		t.Fatal("closed duplicate did not permit independent endpoint retirement", err)
	}
	var lookupErr error
	if err := p.call(p.ctx, false, func() error {
		_, _, lookupErr = p.api.endpointProperties(p.engine, inspection.EndpointID)
		return nil
	}); err != nil {
		t.Fatal("could not independently read retired endpoint status", err)
	}
	var status syscall.Errno
	if !errors.As(lookupErr, &status) || status != syscall.Errno(1168) {
		t.Fatal("retirement did not return the actual user-mode ERROR_NOT_FOUND status", lookupErr)
	}
	t.Logf("retired ALE endpoint has independent native status=%d (%#x)", uint32(status), uint32(status))
}

func TestDesktopSocketWindowsIdentityRejectsTokenStatisticsReplacement(t *testing.T) {
	p := desktopWindowsIdentityTestNew(t)
	creation := desktopWindowsIdentityTestCreation(t, p, "tcp", "127.0.0.1")
	result := desktopWindowsIdentityTestCreate(t, p, creation)
	desktopWindowsIdentityTestBind(t, result.Native, creation.Binding.LocalAddress)
	var verifyErr error
	if err := p.call(p.ctx, false, func() error {
		original := p.statistics
		p.statistics.ModifiedID++
		verifyErr = p.verifyIdentity()
		p.statistics = original
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if verifyErr == nil || !strings.Contains(verifyErr.Error(), "kernel identity") {
		t.Fatal("caller token statistics replaced actual GetTokenInformation authority", verifyErr)
	}
}

func TestDesktopSocketWindowsIdentityRejectsOtherExecutableAppID(t *testing.T) {
	p := desktopWindowsIdentityTestNew(t)
	creation := desktopWindowsIdentityTestCreation(t, p, "tcp", "127.0.0.1")
	result := desktopWindowsIdentityTestCreate(t, p, creation)
	desktopWindowsIdentityTestBind(t, result.Native, creation.Binding.LocalAddress)
	if _, err := p.InspectSocket(p.ctx, creation); err != nil {
		t.Fatal("actual normalized process image must pass before the alternate-file control", err)
	}
	captured, err := p.AppID()
	if err != nil || !bytes.Equal(captured, p.appID) {
		t.Fatal("captured WFP process identity was not available", err)
	}
	captured[0] ^= 0xff
	immutable, err := p.AppID()
	if err != nil || !bytes.Equal(immutable, p.appID) {
		t.Fatal("caller changed the captured process appId", err)
	}
	executable, held, err := p.api.canonicalExecutable()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	otherPath := filepath.Join(t.TempDir(), "identical-bytes-other-executable.exe")
	other, err := os.OpenFile(otherPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	count, copyErr := io.Copy(other, held)
	closeErr := other.Close()
	heldInfo, statErr := held.Stat()
	otherInfo, otherErr := os.Stat(otherPath)
	if copyErr != nil || closeErr != nil || statErr != nil || otherErr != nil || count != heldInfo.Size() || os.SameFile(heldInfo, otherInfo) || executable == otherPath {
		t.Fatal("alternate executable control did not copy the actual bytes to a distinct file", copyErr, closeErr, statErr, otherErr)
	}
	path, _ := syscall.UTF16PtrFromString(otherPath)
	var blob *desktopWindowsBlob
	status, _, _ := p.api.appID.Call(uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&blob)))
	if blob != nil {
		defer p.api.freeWFP.Call(uintptr(unsafe.Pointer(&blob)))
	}
	if status != 0 || blob == nil || blob.Data == nil || blob.Size < 2 || blob.Size > 65536 {
		t.Fatal("alternate real file did not provide its own WFP appId", syscall.Errno(status))
	}
	wrong := append([]byte(nil), unsafe.Slice(blob.Data, int(blob.Size))...)
	if bytes.Equal(wrong, p.appID) {
		t.Fatal("alternate executable control reused the real process appId")
	}
	if err := p.call(p.ctx, false, func() error { p.appID = wrong; return nil }); err != nil {
		t.Fatal(err)
	}
	_, inspectErr := p.InspectSocket(p.ctx, creation)
	if err := p.call(p.ctx, false, func() error { p.appID = immutable; return nil }); err != nil {
		t.Fatal(err)
	}
	if inspectErr == nil || !strings.Contains(inspectErr.Error(), "captured isolated token and process") {
		t.Fatal("identical file bytes replaced the independently read process appId", inspectErr)
	}
}

// These cases exercise the shipping native import and I/O composition with an
// actual isolated creator. Firewall authorization is tested separately; the
// narrow admission callbacks below require the real captured handle and ALE
// proof before an importer can connect or a packet can be transmitted.
func TestDesktopSocketWindowsIdentityImportedTCPAndUDP(t *testing.T) {
	for _, family := range []string{"4", "6"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network+family, func(t *testing.T) {
				address := "127.0.0.1"
				if family == "6" {
					address = "::1"
				}
				p := desktopWindowsIdentityTestNew(t)
				creation := desktopWindowsIdentityTestCreation(t, p, network, address)
				created := desktopWindowsIdentityTestCreate(t, p, creation)
				ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
				defer cancel()
				deadline := time.Now().Add(5 * time.Second)
				match := func(actual string, raw syscall.RawConn) error {
					matched, err := p.MatchSocket(ctx, creation.Capture, creation.Binding, actual, raw)
					if err != nil || matched != creation {
						return errors.Join(err, errors.New("native import changed the captured isolated descriptor"))
					}
					return nil
				}
				if network == "tcp" {
					listener, err := net.ListenTCP(network+family, net.TCPAddrFromAddrPort(netip.AddrPortFrom(creation.Binding.LocalAddress, 0)))
					if err != nil {
						t.Fatal("actual identity TCP peer", err)
					}
					t.Cleanup(func() { _ = listener.Close() })
					if err := listener.SetDeadline(deadline); err != nil {
						t.Fatal(err)
					}
					remote := listener.Addr().(*net.TCPAddr).AddrPort()
					var before DesktopWindowsSocketInspection
					connection, err := desktopSocketImportNativeTCP(ctx, network+family, remote, created.Native, func(_ context.Context, actual, destination string, raw syscall.RawConn) error {
						if destination != remote.String() {
							return errors.New("native TCP import replaced its captured peer")
						}
						if err := match(actual, raw); err != nil {
							return err
						}
						keeper, local, err := desktopSocketBindTCP(raw, creation.Binding.LocalAddress)
						if keeper != nil {
							t.Cleanup(func() {
								if err := keeper.Close(); err != nil {
									t.Error("retained imported TCP keeper", err)
								}
							})
						}
						if err != nil {
							return err
						}
						before, err = p.InspectSocket(ctx, creation)
						if err != nil || before.Local != local || before.Remote.Port() != 0 || !before.Remote.Addr().IsUnspecified() {
							return errors.Join(err, errors.New("native TCP connect has no exact pre-connect ALE proof"))
						}
						return nil
					})
					if connection != nil {
						t.Cleanup(func() {
							if err := connection.Close(); err != nil {
								t.Error("imported TCP owner did not close", err)
							}
						})
					}
					if err != nil {
						t.Fatal("actual isolated native TCP import", err)
					}
					owned, ok := connection.(*desktopWindowsSocket)
					if !ok {
						t.Fatal("native TCP import lost its shipping Winsock owner")
					}
					raw := desktopWindowsRaw{owned}
					desktopWindowsIdentityTestIOProof(t, "after-connect", p, creation, created.Native, before, raw, remote)
					peer, err := listener.AcceptTCP()
					if err != nil {
						t.Fatal("native TCP connection did not reach its owned peer", err)
					}
					t.Cleanup(func() { _ = peer.Close() })
					if err := errors.Join(connection.SetDeadline(deadline), peer.SetDeadline(deadline)); err != nil {
						t.Fatal(err)
					}
					if n, err := connection.Write([]byte("ping")); err != nil || n != 4 {
						t.Fatal("native isolated TCP did not send exact bytes", n, err)
					}
					var data [4]byte
					if _, err := io.ReadFull(peer, data[:]); err != nil || string(data[:]) != "ping" {
						t.Fatal("owned TCP peer did not receive exact bytes", err)
					}
					if n, err := peer.Write(data[:]); err != nil || n != 4 {
						t.Fatal("owned TCP peer did not echo exact bytes", n, err)
					}
					if _, err := io.ReadFull(connection, data[:]); err != nil || string(data[:]) != "ping" {
						t.Fatal("native isolated TCP did not receive exact bytes", err)
					}
					desktopWindowsIdentityTestIOProof(t, "after-TCP-I/O", p, creation, created.Native, before, raw, remote)
				} else {
					peer, err := net.ListenUDP(network+family, net.UDPAddrFromAddrPort(netip.AddrPortFrom(creation.Binding.LocalAddress, 0)))
					if err != nil {
						t.Fatal("actual identity UDP peer", err)
					}
					t.Cleanup(func() { _ = peer.Close() })
					packet, err := desktopSocketImportNativePacket(ctx, network+family, created.Native, creation.Binding.LocalAddress, func(actual, _ string, raw syscall.RawConn) error {
						if err := match(actual, raw); err != nil {
							return err
						}
						return desktopSocketExclusive(raw)
					})
					if packet != nil {
						t.Cleanup(func() {
							if err := packet.Close(); err != nil {
								t.Error("imported UDP owner did not close", err)
							}
						})
					}
					if err != nil {
						t.Fatal("actual isolated native UDP import", err)
					}
					before, err := p.InspectSocket(ctx, creation)
					if err != nil || before.Local.String() != packet.LocalAddr().String() || before.Remote.Port() != 0 || !before.Remote.Addr().IsUnspecified() {
						t.Fatal("native UDP send has no exact bound ALE proof", err)
					}
					rawOwner, ok := packet.(syscall.Conn)
					if !ok {
						t.Fatal("native UDP import lost its shipping Winsock owner")
					}
					raw, err := rawOwner.SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					if err := errors.Join(packet.SetDeadline(deadline), peer.SetDeadline(deadline)); err != nil {
						t.Fatal(err)
					}
					if n, err := packet.WriteTo([]byte("ping"), peer.LocalAddr()); err != nil || n != 4 {
						t.Fatal("native isolated UDP did not send exact bytes", n, err)
					}
					var data [4]byte
					n, sender, err := peer.ReadFromUDP(data[:])
					if err != nil || n != 4 || string(data[:]) != "ping" || sender.String() != packet.LocalAddr().String() {
						t.Fatal("owned UDP peer did not receive exact bytes and tuple", n, err)
					}
					if n, err := peer.WriteToUDP(data[:], sender); err != nil || n != 4 {
						t.Fatal("owned UDP peer did not echo exact bytes", n, err)
					}
					n, senderAddress, err := packet.ReadFrom(data[:])
					if err != nil || n != 4 || string(data[:]) != "ping" || senderAddress.String() != peer.LocalAddr().String() {
						t.Fatal("native isolated UDP did not receive exact bytes and peer", n, err)
					}
					desktopWindowsIdentityTestIOProof(t, "after-UDP-I/O", p, creation, created.Native, before, raw, before.Remote)
				}
			})
		}
	}
}

func desktopWindowsIdentityTestIOProof(t *testing.T, phase string, p *DesktopWindowsSocketIdentity, creation DesktopSocketCreation, source DesktopSocketNative, before DesktopWindowsSocketInspection, raw syscall.RawConn, remote netip.AddrPort) {
	t.Helper()
	endpoint, err := desktopWindowsALEEndpoint(raw)
	if err != nil {
		t.Fatal("native I/O import has no independently queryable ALE endpoint", phase, err)
	}
	if err := raw.Control(func(handle uintptr) {
		local, localErr := syscall.Getsockname(syscall.Handle(handle))
		peer, peerErr := syscall.Getpeername(syscall.Handle(handle))
		var localCode, peerCode syscall.Errno
		_ = errors.As(localErr, &localCode)
		_ = errors.As(peerErr, &peerCode)
		t.Logf("native I/O diagnostic phase=%s getsockname_errno=%d getpeername_errno=%d local=%v peer=%v", phase, localCode, peerCode, local, peer)
	}); err != nil {
		t.Fatal("native I/O descriptor cannot be independently inspected", phase, err)
	}
	if err := p.call(p.ctx, false, func() error {
		properties, appID, err := p.api.endpointProperties(p.engine, endpoint)
		localAddress, _ := desktopWindowsALEAddress(properties.IPVersion, properties.LocalAddress)
		remoteAddress, _ := desktopWindowsALEAddress(properties.IPVersion, properties.RemoteAddress)
		t.Logf("ALE I/O diagnostic phase=%s endpoint=%x pre_connect_endpoint=%x properties_error=%v kernel_modified=%x captured_modified=%x app_matches=%t local=%v remote=%v", phase, endpoint, before.EndpointID, err, properties.TokenModifiedID, p.statistics.ModifiedID, bytes.Equal(appID, p.appID), netip.AddrPortFrom(localAddress, properties.LocalPort), netip.AddrPortFrom(remoteAddress, properties.RemotePort))
		return nil
	}); err != nil {
		t.Fatal("native I/O kernel diagnostics could not join", phase, err)
	}
	desktopWindowsIdentityTestDiagnoseALE(t, phase, p, source)
	if endpoint != before.EndpointID {
		t.Fatal("native I/O import replaced the independently proved ALE endpoint", phase, endpoint, before.EndpointID)
	}
	inspection, err := p.InspectSocket(p.ctx, creation)
	if err != nil {
		t.Fatal("actual native I/O lost the captured ALE token, application, or tuple proof", phase, err)
	}
	if inspection.EndpointID != before.EndpointID || inspection.TokenModifiedID != before.TokenModifiedID || inspection.Local != before.Local || inspection.Protocol != before.Protocol || inspection.Family != before.Family || !bytes.Equal(inspection.AppID, before.AppID) || inspection.Remote != remote {
		t.Fatal("native I/O substituted the actual endpoint ownership or complete tuple", phase, inspection)
	}
}

func TestDesktopSocketWindowsIdentityNativeProtocolAdmission(t *testing.T) {
	for _, family := range []string{"4", "6"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network+family, func(t *testing.T) {
				address := netip.IPv6Loopback()
				if family == "4" {
					address = netip.MustParseAddr("127.0.0.1")
				}
				source, err := desktopWindowsNativeTestSocket(network, family == "4")
				if err != nil {
					t.Fatal("real native protocol fixture", err)
				}
				t.Cleanup(func() { _ = source.Close() })
				raw, actual, err := desktopSocketNativeRaw(source, network, address)
				if err != nil || actual != network+family || raw == nil {
					t.Fatal("real unbound protocol was not admitted", err)
				}
				wrong := "tcp"
				if network == "tcp" {
					wrong = "udp"
				}
				if _, _, err := desktopSocketNativeRaw(source, wrong, address); err == nil || !strings.Contains(err.Error(), "kernel family or protocol") {
					t.Fatal("native import accepted a real socket with the wrong protocol", err)
				}
				desktopWindowsIdentityTestBind(t, source, address)
				if network == "tcp" {
					var listenErr error
					if err := raw.Control(func(handle uintptr) { listenErr = syscall.Listen(syscall.Handle(handle), 1) }); err != nil || listenErr != nil {
						t.Fatal("actual native listener fixture", err, listenErr)
					}
					if _, _, err := desktopSocketNativeRaw(source, network, address); err == nil || !strings.Contains(err.Error(), "listener or unproved listening state") {
						t.Fatal("native TCP listener was admitted as an unbound source", err)
					}
				} else if _, _, err := desktopSocketNativeRaw(source, network, address); err == nil || !strings.Contains(err.Error(), "already bound a tuple") {
					t.Fatal("native UDP source with an existing bind was admitted", err)
				}
			})
		}
	}
}
