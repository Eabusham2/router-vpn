package mobiletor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Creator and socket transfer are real Winsock operations. The permission
// policy is the explicit shared fixture; the separate Windows identity/WFP
// gate must prove its actual kernel SID and firewall enforcement.
type desktopWindowsNativeFixture struct {
	*desktopSocketPolicyFixture
	mu       sync.Mutex
	sockets  map[string][2]DesktopSocketNative
	created  atomic.Int32
	released atomic.Int32
	closed   atomic.Int32
	alter    func(DesktopSocketCreated) DesktopSocketCreated
}

func desktopWindowsNativeTestSocket(network string, ipv4 bool) (DesktopSocketNative, error) {
	desktopSocketStartupOnce.Do(func() {
		var data syscall.WSAData
		desktopSocketStartupError = syscall.WSAStartup(0x0202, &data)
	})
	if desktopSocketStartupError != nil {
		return nil, desktopSocketStartupError
	}
	family, kind, protocol := syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP
	if ipv4 {
		family = syscall.AF_INET
	}
	if network == "udp" {
		kind, protocol = syscall.SOCK_DGRAM, syscall.IPPROTO_UDP
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	handle, _, _ := desktopSocketCreateProc.Call(uintptr(family), uintptr(kind), uintptr(protocol), 0, 0, 0x81)
	if handle == ^uintptr(0) {
		return nil, desktopSocketWinsockError()
	}
	return desktopWindowsNativeOwn(syscall.Handle(handle)), nil
}

func (p *desktopWindowsNativeFixture) CreateSocket(ctx context.Context, q DesktopSocketCreation) (DesktopSocketCreated, error) {
	original, err := desktopWindowsNativeTestSocket(q.Network, q.Binding.LocalAddress.Is4())
	if err != nil {
		return DesktopSocketCreated{}, err
	}
	raw, err := original.SyscallConn()
	if err != nil {
		original.Close()
		return DesktopSocketCreated{}, err
	}
	returned, err := desktopWindowsNativeDuplicate(raw)
	if returned == nil {
		original.Close()
		return DesktopSocketCreated{}, err
	}
	p.mu.Lock()
	p.sockets[q.SocketID] = [2]DesktopSocketNative{original, returned}
	p.mu.Unlock()
	p.created.Add(1)
	reply := DesktopSocketCreated{Creation: q, Native: returned}
	if p.alter != nil {
		reply = p.alter(reply)
	}
	return reply, err
}
func (p *desktopWindowsNativeFixture) Cancel() {}
func (p *desktopWindowsNativeFixture) Close(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sockets) != 0 {
		return errors.New("native source still owns socket handles")
	}
	p.closed.Add(1)
	return nil
}
func (p *desktopWindowsNativeFixture) ReleaseSocket(_ context.Context, q DesktopSocketCreation) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	pair, ok := p.sockets[q.SocketID]
	if !ok {
		return nil
	}
	if _, err := pair[1].SyscallConn(); !errors.Is(err, net.ErrClosed) {
		return errors.New("source released before the native imported descriptor closed")
	}
	if err := pair[0].Close(); err != nil {
		return err
	}
	delete(p.sockets, q.SocketID)
	p.released.Add(1)
	return nil
}
func (p *desktopWindowsNativeFixture) Grant(ctx context.Context, q DesktopSocketGrant) (DesktopSocketReceipt, error) {
	p.mu.Lock()
	pair := p.sockets[q.SocketID]
	p.mu.Unlock()
	if pair[0] == nil || pair[1] == nil {
		return DesktopSocketReceipt{}, errors.New("grant has no retained creator endpoint")
	}
	// Winsock providers cache bind state per duplicated handle. The returned
	// handle is the one actually bound by the broker; the pre-bind original
	// remains retained for endpoint/port lifetime and cannot supply this local
	// name readback. The separate identity suite proves their ALE equality.
	raw, err := pair[1].SyscallConn()
	if err != nil {
		return DesktopSocketReceipt{}, err
	}
	var local netip.AddrPort
	var result error
	err = raw.Control(func(fd uintptr) { local, result = desktopSocketLocal(syscall.Handle(fd)) })
	if err != nil || result != nil || local != q.Local {
		return DesktopSocketReceipt{}, errors.New("the import recreated or rebound the creator endpoint")
	}
	return p.desktopSocketPolicyFixture.Grant(ctx, q)
}
func desktopWindowsNativeFixtureBroker(t *testing.T) (*DesktopSocketBroker, *desktopWindowsNativeFixture) {
	t.Helper()
	p := &desktopWindowsNativeFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy(), sockets: make(map[string][2]DesktopSocketNative)}
	b, err := NewDesktopSocketBroker(context.Background(), desktopSocketFixtureCapture(), p, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := b.Close(ctx); err != nil {
			t.Error("native imported socket did not retire", err)
		}
		if p.created.Load() != p.released.Load() || p.closed.Load() == 0 {
			t.Error("native source lifetime was not fully joined", p.created.Load(), p.released.Load(), p.closed.Load())
		}
	})
	return b, p
}

func TestDesktopSocketWindowsNativeImportedTCPAndUDP(t *testing.T) {
	for _, family := range []string{"4", "6"} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(transport+family, func(t *testing.T) {
				b, p := desktopWindowsNativeFixtureBroker(t)
				host := "127.0.0.1"
				if family == "6" {
					host = "::1"
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if transport == "tcp" {
					listener, err := net.Listen("tcp"+family, net.JoinHostPort(host, "0"))
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					echoed := make(chan error, 1)
					go func() {
						peer, err := listener.Accept()
						if err != nil {
							echoed <- err
							return
						}
						defer peer.Close()
						peer.SetDeadline(time.Now().Add(5 * time.Second))
						_, err = io.CopyN(peer, peer, 4)
						echoed <- err
					}()
					connection, err := b.DialContext(ctx, "tcp"+family, listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					connection.SetDeadline(time.Now().Add(5 * time.Second))
					if _, err := connection.Write([]byte("ping")); err != nil {
						t.Fatal(err)
					}
					var result [4]byte
					if _, err := io.ReadFull(connection, result[:]); err != nil || string(result[:]) != "ping" {
						t.Fatal("imported TCP did not transfer exact bytes", err, result)
					}
					if err := connection.Close(); err != nil {
						t.Fatal(err)
					}
					if err := <-echoed; err != nil {
						t.Fatal(err)
					}
				} else {
					peer, err := net.ListenPacket("udp"+family, net.JoinHostPort(host, "0"))
					if err != nil {
						t.Fatal(err)
					}
					defer peer.Close()
					peer.SetDeadline(time.Now().Add(5 * time.Second))
					packet, err := b.ListenPacket(ctx, "udp"+family, net.JoinHostPort(host, "0"))
					if err != nil {
						t.Fatal(err)
					}
					packet.SetDeadline(time.Now().Add(5 * time.Second))
					if _, err := packet.WriteTo([]byte("ping"), peer.LocalAddr()); err != nil {
						t.Fatal(err)
					}
					var data [4]byte
					n, address, err := peer.ReadFrom(data[:])
					if err != nil || n != 4 || string(data[:]) != "ping" {
						t.Fatal("imported UDP did not transmit exact bytes", err, n)
					}
					if _, err := peer.WriteTo(data[:], address); err != nil {
						t.Fatal(err)
					}
					n, address, err = packet.ReadFrom(data[:])
					if err != nil || n != 4 || string(data[:]) != "ping" || address.String() != peer.LocalAddr().String() {
						t.Fatal("imported UDP did not receive its granted peer", err, n)
					}
					if err := packet.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if p.created.Load() != 1 || p.released.Load() != 1 || p.count() != 0 {
					t.Fatal("imported socket retained a grant or lost source ownership")
				}
			})
		}
	}
}

func TestDesktopSocketWindowsNativeRejectsChangedCreationAndBoundSources(t *testing.T) {
	for _, change := range []string{"source", "network", "already-bound", "wrong-family", "wrong-protocol"} {
		t.Run(change, func(t *testing.T) {
			b, p := desktopWindowsNativeFixtureBroker(t)
			p.alter = func(reply DesktopSocketCreated) DesktopSocketCreated {
				switch change {
				case "source":
					reply.Creation.Capture.SourceSHA256 = ""
				case "network":
					reply.Creation.Network = "udp"
				case "already-bound":
					raw, _ := reply.Native.SyscallConn()
					var result error
					err := raw.Control(func(handle uintptr) {
						result = syscall.Bind(syscall.Handle(handle), &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
					})
					if err != nil || result != nil {
						t.Fatal(err, result)
					}
				case "wrong-family", "wrong-protocol":
					kind, ipv4 := "tcp", false
					if change == "wrong-protocol" {
						kind, ipv4 = "udp", true
					}
					other, err := desktopWindowsNativeTestSocket(kind, ipv4)
					if err != nil {
						t.Fatal(err)
					}
					if err := reply.Native.Close(); err != nil {
						t.Fatal(err)
					}
					p.mu.Lock()
					pair := p.sockets[reply.Creation.SocketID]
					pair[1] = other
					p.sockets[reply.Creation.SocketID] = pair
					p.mu.Unlock()
					reply.Native = other
				}
				return reply
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if connection, err := b.DialContext(ctx, "tcp4", "127.0.0.1:9"); err == nil || connection != nil {
				t.Fatal("malformed native source reached TCP connect")
			}
			if p.bindCount.Load() != 0 || p.count() != 0 {
				t.Fatal("malformed native source acquired a physical grant")
			}
		})
	}
}

func TestDesktopSocketWindowsNativeCancellationJoinsEnteredRead(t *testing.T) {
	b, _ := desktopWindowsNativeFixtureBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	packet, err := b.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := packet.ReadFrom(make([]byte, 16)); done <- err }()
	actual := packet.(*desktopSocketPacket).socket.packet.(*desktopWindowsPacket)
	for actual.read.TryLock() {
		actual.read.Unlock()
		select {
		case <-ctx.Done():
			t.Fatal("imported UDP never entered its real socket read")
		default:
			runtime.Gosched()
		}
	}
	b.Cancel()
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled imported UDP read succeeded")
		}
	case <-ctx.Done():
		t.Fatal("imported UDP cancellation left entered I/O running")
	}
}
