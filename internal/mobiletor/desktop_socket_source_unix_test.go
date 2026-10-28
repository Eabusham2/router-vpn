//go:build linux || darwin

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The socket and SCM_RIGHTS transfer are real. The privileged filter adapter
// remains the explicit boundary doubled by desktopSocketPolicyFixture.
type desktopSocketSourceFixture struct {
	*desktopSocketPolicyFixture
	create       func(context.Context, DesktopSocketCreation) (DesktopSocketCreated, error)
	closeSource  func(context.Context) error
	cancelSource func()
	created      atomic.Int32
	canceled     atomic.Int32
	joined       atomic.Int32
	uid          uint32
	boundMu      sync.Mutex
	bound        []syscall.RawConn
}

func desktopSocketNewSourceFixture(t *testing.T) *desktopSocketSourceFixture {
	t.Helper()
	p := &desktopSocketSourceFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy(), uid: uint32(os.Getuid())}
	p.create = func(_ context.Context, q DesktopSocketCreation) (DesktopSocketCreated, error) {
		file, err := desktopSocketSCMFile(q.Network, q.Binding.LocalAddress.Is4())
		return DesktopSocketCreated{Creation: q, File: file}, err
	}
	return p
}

func (p *desktopSocketSourceFixture) CreateSocket(ctx context.Context, q DesktopSocketCreation) (DesktopSocketCreated, error) {
	p.created.Add(1)
	return p.create(ctx, q)
}

func (p *desktopSocketSourceFixture) Cancel() {
	p.canceled.Add(1)
	if p.cancelSource != nil {
		p.cancelSource()
	}
}

func (p *desktopSocketSourceFixture) Close(ctx context.Context) error {
	if p.closeSource != nil {
		if err := p.closeSource(ctx); err != nil {
			return err
		}
	}
	p.joined.Add(1)
	return nil
}

func desktopSocketFileUID(raw syscall.RawConn) (uint32, error) {
	var stat syscall.Stat_t
	var result error
	err := raw.Control(func(fd uintptr) { result = syscall.Fstat(int(fd), &stat) })
	return stat.Uid, errors.Join(err, result)
}

func (p *desktopSocketSourceFixture) Bind(ctx context.Context, c DesktopSocketCapture, b DesktopSocketBinding, network string, raw syscall.RawConn) error {
	if err := p.desktopSocketPolicyFixture.Bind(ctx, c, b, network, raw); err != nil {
		return err
	}
	uid, err := desktopSocketFileUID(raw)
	if err != nil || uid != p.uid {
		return errors.New("fixture rejected actual kernel creator UID")
	}
	p.boundMu.Lock()
	p.bound = append(p.bound, raw)
	p.boundMu.Unlock()
	return nil
}

func (p *desktopSocketSourceFixture) Grant(ctx context.Context, q DesktopSocketGrant) (DesktopSocketReceipt, error) {
	p.boundMu.Lock()
	bound := append([]syscall.RawConn(nil), p.bound...)
	p.boundMu.Unlock()
	matched := false
	for _, raw := range bound {
		var address netip.AddrPort
		var result error
		err := raw.Control(func(fd uintptr) { address, result = desktopSocketLocal(int(fd)) })
		if err == nil && result == nil && address == q.Local {
			uid, err := desktopSocketFileUID(raw)
			matched = err == nil && uid == p.uid
			break
		}
	}
	if !matched {
		return DesktopSocketReceipt{}, errors.New("fixture kernel creator/tuple readback rejected")
	}
	return p.desktopSocketPolicyFixture.Grant(ctx, q)
}

func desktopSocketSourceBroker(t *testing.T, p DesktopSocketPolicy) (*DesktopSocketBroker, *atomic.Bool) {
	t.Helper()
	current := &atomic.Bool{}
	current.Store(true)
	broker, err := NewDesktopSocketBroker(context.Background(), desktopSocketFixtureCapture(), p, current.Load)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := broker.Close(ctx); err != nil {
			t.Error("source broker retained its exact owner", err)
		}
	})
	return broker, current
}

// This fixture creates no host policy or account. The privileged test file
// separately replaces the sending end with an actual forked UID helper.
func desktopSocketSCMFile(network string, ipv4 bool) (*os.File, error) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(pair[0])
	defer syscall.Close(pair[1])
	for _, fd := range pair {
		syscall.CloseOnExec(fd)
	}
	typeValue := syscall.SOCK_STREAM
	if network == "udp" {
		typeValue = syscall.SOCK_DGRAM
	}
	family := syscall.AF_INET
	if !ipv4 {
		family = syscall.AF_INET6
	}
	fd, err := syscall.Socket(family, typeValue, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	syscall.CloseOnExec(fd)
	if err := syscall.Sendmsg(pair[0], []byte("owned-created-socket"), syscall.UnixRights(fd), nil, 0); err != nil {
		return nil, err
	}
	return desktopSocketSCMReceive(pair[1], []byte("owned-created-socket"))
}

func desktopSocketSCMReceive(fd int, expected []byte) (*os.File, error) {
	data := make([]byte, 4096)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	n, oobn, flags, _, err := syscall.Recvmsg(fd, data, oob, 0)
	if err != nil {
		return nil, err
	}
	var files []*os.File
	messages, parseErr := syscall.ParseSocketControlMessage(oob[:oobn])
	for _, message := range messages {
		rights, readErr := syscall.ParseUnixRights(&message)
		if readErr != nil {
			parseErr = errors.Join(parseErr, readErr)
			continue
		}
		for _, received := range rights {
			syscall.CloseOnExec(received)
			files = append(files, os.NewFile(uintptr(received), "fixture-actual-transferred-socket"))
		}
	}
	if parseErr != nil || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || string(data[:n]) != string(expected) || len(files) != 1 {
		for _, file := range files {
			_ = file.Close()
		}
		return nil, errors.New("fixture SCM_RIGHTS reply changed its exact identity")
	}
	return files[0], nil
}

func TestDesktopSocketSourceTCPActualImportedBytes(t *testing.T) {
	p := desktopSocketNewSourceFixture(t)
	broker, _ := desktopSocketSourceBroker(t, p)
	listener := desktopSocketListener(t)
	accepted := make(chan *net.TCPConn, 1)
	go func() { connection, _ := listener.AcceptTCP(); accepted <- connection }()
	connection, err := broker.DialContext(context.Background(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := desktopSocketAwait(t, accepted)
	if peer == nil {
		t.Fatal("imported socket did not reach actual TCP peer")
	}
	defer peer.Close()
	if p.created.Load() != 1 || p.bindCount.Load() != 1 || p.count() != 1 {
		t.Fatal("source was bypassed or TCP transmitted without its exact permit")
	}
	if _, err := connection.Write([]byte("imported creator TCP")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("imported creator TCP"))
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(peer, buffer); err != nil || string(buffer) != "imported creator TCP" {
		t.Fatal("actual imported TCP bytes differ", err)
	}
	p.revoke = func(_ context.Context, q DesktopSocketGrant) error {
		desktopSocketAssertReserved(t, "tcp", q.Local)
		return nil
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopSocketSourceUDPNoPermitUntilRealPeer(t *testing.T) {
	p := desktopSocketNewSourceFixture(t)
	broker, _ := desktopSocketSourceBroker(t, p)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	packet, err := broker.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	if p.created.Load() != 1 || p.count() != 0 {
		t.Fatal("UDP source bypassed or broad permit installed at bind")
	}
	if _, err := packet.WriteTo([]byte("owned UDP"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	n, actual, err := peer.ReadFromUDP(buffer)
	if err != nil || string(buffer[:n]) != "owned UDP" || actual.String() != packet.LocalAddr().String() || p.count() != 1 {
		t.Fatal("actual imported UDP/permit differs", err)
	}
	if _, err := peer.WriteToUDP([]byte("reply"), actual); err != nil {
		t.Fatal(err)
	}
	if n, _, err := packet.ReadFrom(buffer); err != nil || string(buffer[:n]) != "reply" {
		t.Fatal("actual imported UDP reply differs", err)
	}
	p.revoke = func(_ context.Context, q DesktopSocketGrant) error {
		desktopSocketAssertReserved(t, "udp", q.Local)
		return nil
	}
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopSocketSourceRejectsEveryCreationIdentity(t *testing.T) {
	mutations := map[string]func(*DesktopSocketCreation){
		"capture-session":   func(q *DesktopSocketCreation) { q.Capture.SessionID = "changed" },
		"capture-source":    func(q *DesktopSocketCreation) { q.Capture.SourceSHA256 = "changed" },
		"capture-network":   func(q *DesktopSocketCreation) { q.Capture.NetworkID = "changed" },
		"kernel-kind":       func(q *DesktopSocketCreation) { q.Binding.Owner.Kind = "linux-cgroup" },
		"kernel-source":     func(q *DesktopSocketCreation) { q.Binding.Owner.IdentitySHA256 = "changed" },
		"kernel-generation": func(q *DesktopSocketCreation) { q.Binding.Owner.Generation++ },
		"kernel-process":    func(q *DesktopSocketCreation) { q.Binding.Owner.ProcessID++ },
		"interface-name":    func(q *DesktopSocketCreation) { q.Binding.InterfaceName = "replacement" },
		"interface-index":   func(q *DesktopSocketCreation) { q.Binding.InterfaceIndex++ },
		"local-address":     func(q *DesktopSocketCreation) { q.Binding.LocalAddress = netip.MustParseAddr("127.0.0.2") },
		"socket":            func(q *DesktopSocketCreation) { q.SocketID = "changed" },
		"protocol":          func(q *DesktopSocketCreation) { q.Network = "udp" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := desktopSocketNewSourceFixture(t)
			original := p.create
			var transferred *os.File
			p.create = func(ctx context.Context, q DesktopSocketCreation) (DesktopSocketCreated, error) {
				reply, err := original(ctx, q)
				transferred = reply.File
				mutate(&reply.Creation)
				return reply, err
			}
			broker, _ := desktopSocketSourceBroker(t, p)
			listener := desktopSocketListener(t)
			connection, err := broker.DialContext(context.Background(), "tcp4", listener.Addr().String())
			if connection != nil || err == nil || p.bindCount.Load() != 0 || p.count() != 0 {
				t.Fatal("foreign helper identity reached the policy", err)
			}
			if err := broker.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if transferred == nil {
				t.Fatal("no real returned descriptor was exercised")
			}
			if _, err := transferred.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("rejected transferred descriptor leaked", err)
			}
		})
	}
}

func TestDesktopSocketSourceRejectsKernelStateWithoutPermit(t *testing.T) {
	for _, name := range []string{"wrong-type", "wrong-family", "bound", "connected", "listening", "wrong-uid", "ordinary-file"} {
		t.Run(name, func(t *testing.T) {
			p := desktopSocketNewSourceFixture(t)
			listener := desktopSocketListener(t)
			var transferred *os.File
			p.create = func(_ context.Context, q DesktopSocketCreation) (DesktopSocketCreated, error) {
				var file *os.File
				var err error
				if name == "ordinary-file" {
					file, err = os.CreateTemp(t.TempDir(), "not-a-socket")
				} else {
					network := q.Network
					if name == "wrong-type" {
						network = "udp"
					}
					file, err = desktopSocketSCMFile(network, name != "wrong-family")
				}
				if err == nil && (name == "bound" || name == "connected" || name == "listening") {
					raw, rawErr := file.SyscallConn()
					err = rawErr
					if rawErr == nil {
						var result error
						err = raw.Control(func(fd uintptr) {
							if name == "connected" {
								result = syscall.Connect(int(fd), &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: listener.Addr().(*net.TCPAddr).Port})
							} else {
								result = syscall.Bind(int(fd), &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
								if result == nil && name == "listening" {
									result = syscall.Listen(int(fd), 1)
								}
							}
						})
						err = errors.Join(err, result)
					}
				}
				transferred = file
				return DesktopSocketCreated{Creation: q, File: file}, err
			}
			if name == "wrong-uid" {
				p.uid++
			}
			broker, _ := desktopSocketSourceBroker(t, p)
			connection, err := broker.DialContext(context.Background(), "tcp4", listener.Addr().String())
			if err == nil || connection != nil || p.count() != 0 {
				t.Fatal("invalid actual kernel state gained a permit", err)
			}
			if err := broker.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if transferred == nil {
				t.Fatal("invalid state test created no actual descriptor")
			}
			if _, err := transferred.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("invalid descriptor was not drained", err)
			}
		})
	}
}

func TestDesktopSocketSourceLateReplyRetainedUntilCreatorJoined(t *testing.T) {
	for _, action := range []string{"cancel", "source-replaced"} {
		t.Run(action, func(t *testing.T) {
			p := desktopSocketNewSourceFixture(t)
			entered, release, joinRelease := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var transferred *os.File
			p.create = func(_ context.Context, q DesktopSocketCreation) (DesktopSocketCreated, error) {
				file, err := desktopSocketSCMFile(q.Network, true)
				transferred = file
				close(entered)
				<-release
				// This is an otherwise successful late reply. Cancellation/source
				// replacement, not a fabricated helper error, must disqualify it.
				return DesktopSocketCreated{Creation: q, File: file}, err
			}
			p.closeSource = func(ctx context.Context) error {
				select {
				case <-joinRelease:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			broker, current := desktopSocketSourceBroker(t, p)
			listener := desktopSocketListener(t)
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				connection, err := broker.DialContext(caller, "tcp4", listener.Addr().String())
				if connection != nil {
					_ = connection.Close()
					err = errors.New("late creator published data")
				}
				result <- err
			}()
			desktopSocketAwait(t, entered)
			if action == "source-replaced" {
				current.Store(false)
			} else {
				cancel()
			}
			wait, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
			if err := broker.Close(wait); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("pending creation was falsely joined", err)
			}
			stop()
			if _, err := transferred.Stat(); err != nil {
				t.Fatal("pending helper descriptor released before transfer joined", err)
			}
			close(release)
			if err := desktopSocketAwait(t, result); err == nil {
				t.Fatal("late/error creator accepted")
			}
			wait, stop = context.WithTimeout(context.Background(), 30*time.Millisecond)
			if err := broker.Close(wait); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("creator process was falsely joined", err)
			}
			stop()
			if p.count() != 0 || p.bindCount.Load() != 0 || p.joined.Load() != 0 || p.canceled.Load() != 1 {
				t.Fatal("late creator mutated/reused an owner")
			}
			close(joinRelease)
			if err := broker.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if p.joined.Load() != 1 {
				t.Fatal("helper drain was not acknowledged")
			}
			if _, err := transferred.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("returned error descriptor leaked", err)
			}
		})
	}
}

func TestDesktopSocketSourceErrorReplyCannotReachBindAndFailedJoinStaysOwned(t *testing.T) {
	p := desktopSocketNewSourceFixture(t)
	create := p.create
	var transferred *os.File
	p.create = func(ctx context.Context, q DesktopSocketCreation) (DesktopSocketCreated, error) {
		reply, err := create(ctx, q)
		transferred = reply.File
		return reply, errors.Join(err, errors.New("actual creator transfer error"))
	}
	joined := make(chan struct{})
	retried := make(chan struct{})
	var attempts atomic.Int32
	p.closeSource = func(ctx context.Context) error {
		if attempts.Add(1) == 1 {
			return errors.New("creator has not actually exited")
		}
		select {
		case <-retried:
		default:
			close(retried)
		}
		select {
		case <-joined:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	broker, _ := desktopSocketSourceBroker(t, p)
	listener := desktopSocketListener(t)
	connection, err := broker.DialContext(context.Background(), "tcp4", listener.Addr().String())
	if err == nil || connection != nil || p.bindCount.Load() != 0 || p.count() != 0 {
		t.Fatal("creator error was discarded before independent bind", err)
	}
	broker.Cancel()
	desktopSocketAwait(t, retried)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	if err := broker.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("failed creator join released its identity", err)
	}
	cancel()
	if p.joined.Load() != 0 {
		t.Fatal("creator failure falsely acknowledged join")
	}
	close(joined)
	if err := broker.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transferred == nil {
		t.Fatal("actual creator error did not retain its partial FD")
	}
	if _, err := transferred.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("creator error descriptor leaked", err)
	}
}

func TestDesktopSocketSourcePermitBeforeConnectAndRemovalBeforeRelease(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			p := desktopSocketNewSourceFixture(t)
			issued, allow, remove, drain := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var issueOnce, removeOnce sync.Once
			p.grant = func(_ context.Context, _ DesktopSocketGrant, r DesktopSocketReceipt) (DesktopSocketReceipt, error) {
				issueOnce.Do(func() { close(issued) })
				<-allow
				return r, nil
			}
			p.revoke = func(_ context.Context, q DesktopSocketGrant) error {
				removeOnce.Do(func() { close(remove) })
				<-drain
				desktopSocketAssertReserved(t, network, q.Local)
				return nil
			}
			broker, _ := desktopSocketSourceBroker(t, p)
			listener := desktopSocketListener(t)
			result := make(chan error, 1)
			go func() {
				connection, err := broker.DialContext(context.Background(), network+"4", listener.Addr().String())
				if connection != nil {
					_ = connection.Close()
				}
				result <- err
			}()
			desktopSocketAwait(t, issued)
			q := desktopSocketAwait(t, p.requests)
			desktopSocketAssertReserved(t, network, q.Local)
			if network == "tcp" {
				_ = listener.SetDeadline(time.Now().Add(30 * time.Millisecond))
				connection, err := listener.AcceptTCP()
				if connection != nil {
					_ = connection.Close()
				}
				if err == nil {
					t.Fatal("imported TCP connected before readback")
				}
			}
			broker.Cancel()
			close(allow)
			if err := desktopSocketAwait(t, result); err == nil {
				t.Fatal("canceled permit published a socket")
			}
			desktopSocketAwait(t, remove)
			wait, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			if err := broker.Close(wait); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("pending removal released helper identity", err)
			}
			cancel()
			if p.joined.Load() != 0 {
				t.Fatal("helper identity released before absent readback")
			}
			desktopSocketAssertReserved(t, network, q.Local)
			close(drain)
			if err := broker.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func desktopSocketSourceEncode(q DesktopSocketCreation) []byte {
	data, err := json.Marshal(q)
	if err != nil {
		panic(err)
	}
	return data
}
