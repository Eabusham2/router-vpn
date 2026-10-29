//go:build windows && routervpn_windows_wfp && routervpn_windows_wfp_traffic

package mobiletor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

type desktopWindowsWFPPeerRecord struct {
	AppID       []byte
	Endpoints   map[string]string
	Metadata    []byte
	Sublayer    syscall.GUID
	Lock        syscall.GUID
	DynamicRule desktopWFPRule
}

type desktopWindowsWFPPeerProcess struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Reader
	done    chan error
	record  desktopWindowsWFPPeerRecord
}

// A different actual executable hosts the peer. The subject's test-only WFP
// scope cannot block the peer listener or make a same-process listener bypass
// the subject's socket/SID conditions. Only local test traffic is generated.
func desktopWindowsWFPStartPeer(t *testing.T, mode string) *desktopWindowsWFPPeerProcess {
	t.Helper()
	actual, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(actual)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "wfp-owned-peer.test.exe")
	if err := os.WriteFile(copyPath, contents, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	command := exec.CommandContext(ctx, copyPath, "-test.run=^TestDesktopSocketWindowsWFPPeerProcess$", "-test.count=1", "-test.timeout=85s")
	command.Env = append(os.Environ(), "ROUTERVPN_WFP_TEST_HELPER="+mode)
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	peer := &desktopWindowsWFPPeerProcess{command: command, input: input, output: bufio.NewReader(output), done: make(chan error, 1)}
	go func() { peer.done <- command.Wait() }()
	var ownedScope []byte
	t.Cleanup(func() {
		defer cancel()
		_ = input.Close()
		select {
		case err := <-peer.done:
			if err != nil {
				t.Errorf("owned WFP peer did not join: %v; %s", err, diagnostics.String())
			}
		case <-time.After(10 * time.Second):
			_ = command.Process.Kill()
			<-peer.done
			t.Error("owned WFP peer ignored anonymous input EOF")
		}
		if len(ownedScope) > 0 {
			desktopWindowsWFPTestRecovery(t, ownedScope)
		}
	})
	readRecord := func() desktopWindowsWFPPeerRecord {
		type result struct {
			record desktopWindowsWFPPeerRecord
			err    error
		}
		ready := make(chan result, 1)
		go func() {
			line, err := peer.output.ReadBytes('\n')
			var record desktopWindowsWFPPeerRecord
			if err == nil {
				err = json.Unmarshal(line, &record)
			}
			ready <- result{record, err}
		}()
		select {
		case result := <-ready:
			if result.err != nil {
				t.Fatal("owned WFP peer did not publish its exact readiness record", result.err)
			}
			return result.record
		case <-time.After(10 * time.Second):
			t.Fatal("owned WFP peer readiness deadline expired")
			return desktopWindowsWFPPeerRecord{}
		}
	}
	peer.record = readRecord()
	if mode == "crash" {
		// Capture recovery identity before the helper mutates BFE, so a
		// failed partial startup is cleaned after the helper has joined too.
		ownedScope = append([]byte(nil), peer.record.AppID...)
		peer.record = readRecord()
		if !bytes.Equal(ownedScope, peer.record.AppID) {
			t.Fatal("crash helper replaced its captured executable scope")
		}
	}
	api, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		t.Fatal(err)
	}
	subject, err := api.executableAppID()
	if err != nil || len(peer.record.AppID) == 0 || bytes.Equal(subject, peer.record.AppID) {
		t.Fatal("local peer did not have a separate actual executable identity", err)
	}
	return peer
}

func TestDesktopSocketWindowsWFPPeerProcess(t *testing.T) {
	mode := os.Getenv("ROUTERVPN_WFP_TEST_HELPER")
	if mode == "" {
		return
	}
	if mode == "crash" {
		desktopWindowsWFPDeathProcess(t)
		return
	}
	if mode != "peer" {
		t.Fatal("unknown private WFP peer fixture")
	}
	api, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := api.executableAppID()
	if err != nil {
		t.Fatal(err)
	}
	record := desktopWindowsWFPPeerRecord{AppID: scope, Endpoints: make(map[string]string)}
	var listeners []io.Closer
	var workers sync.WaitGroup
	var mutex sync.Mutex
	connections := make(map[net.Conn]bool)
	stopping := false
	stop := make(chan struct{})
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		address := "127.0.0.1:0"
		if network[len(network)-1] == '6' {
			address = "[::1]:0"
		}
		if network[:3] == "udp" {
			packet, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatal(err)
			}
			listeners = append(listeners, packet)
			record.Endpoints[network] = packet.LocalAddr().String()
			workers.Add(1)
			go func() {
				defer workers.Done()
				buffer := make([]byte, 4096)
				for {
					n, peer, err := packet.ReadFrom(buffer)
					if err != nil {
						return
					}
					if _, err := packet.WriteTo(buffer[:n], peer); err != nil {
						return
					}
				}
			}()
			continue
		}
		for _, hold := range []bool{false, true} {
			listener, err := net.Listen(network, address)
			if err != nil {
				t.Fatal(err)
			}
			listeners = append(listeners, listener)
			key := network
			if hold {
				key += "-hold"
			}
			record.Endpoints[key] = listener.Addr().String()
			workers.Add(1)
			go func() {
				defer workers.Done()
				for {
					connection, err := listener.Accept()
					if err != nil {
						return
					}
					mutex.Lock()
					if stopping {
						mutex.Unlock()
						_ = connection.Close()
						continue
					}
					connections[connection] = true
					workers.Add(1)
					mutex.Unlock()
					go func() {
						defer workers.Done()
						defer connection.Close()
						defer func() { mutex.Lock(); delete(connections, connection); mutex.Unlock() }()
						if hold {
							if tcp, ok := connection.(*net.TCPConn); ok {
								_ = tcp.SetReadBuffer(4096)
							}
							<-stop
							return
						}
						_, _ = io.Copy(connection, connection)
					}()
				}
			}()
		}
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(encoded))
	_, _ = io.Copy(io.Discard, os.Stdin)
	mutex.Lock()
	stopping = true
	close(stop)
	for connection := range connections {
		_ = connection.Close()
	}
	mutex.Unlock()
	for _, listener := range listeners {
		_ = listener.Close()
	}
	workers.Wait()
}

func desktopWindowsWFPBroker(t *testing.T, p *DesktopWindowsSocketPolicy) *DesktopSocketBroker {
	t.Helper()
	broker, err := NewDesktopSocketBroker(p.ctx, p.capture, p, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := broker.Close(ctx); err != nil {
			t.Error("actual WFP broker failed to retire sockets and join native operations", err)
		}
	})
	return broker
}

func TestDesktopSocketWindowsWFPOwnedTrafficAndRenewal(t *testing.T) {
	peer := desktopWindowsWFPStartPeer(t, "peer")
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			p := desktopWindowsWFPTestOwner(t, "on-connect", true)
			broker := desktopWindowsWFPBroker(t, p)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			connection, err := broker.DialContext(ctx, network, peer.record.Endpoints[network])
			if err != nil {
				t.Fatal("captured isolated socket could not cross actual scoped WFP", err)
			}
			defer connection.Close()
			payload := []byte("exact captured Windows WFP socket bytes/" + network)
			deadline := time.Now().Add(8 * time.Second)
			for {
				if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if n, err := connection.Write(payload); err != nil || n != len(payload) {
					t.Fatal("owned WFP write lost real transfer", n, err)
				}
				answer := make([]byte, len(payload))
				if _, err := io.ReadFull(connection, answer); err != nil || !bytes.Equal(answer, payload) {
					t.Fatal("owned WFP returned bytes differ", err)
				}
				broker.mu.Lock()
				var socket *desktopSocket
				for current := range broker.sockets {
					socket = current
				}
				broker.mu.Unlock()
				if socket == nil {
					t.Fatal("real WFP traffic lost its captured socket")
				}
				socket.mu.Lock()
				var receipt DesktopSocketReceipt
				for _, current := range socket.peers {
					receipt, _ = current.snapshot()
				}
				socket.mu.Unlock()
				if receipt.Grant.Sequence > 1 {
					if !validDesktopSocketReceipt(receipt, receipt.Grant, time.Now()) {
						t.Fatal("connected renewal returned a stale physical proof")
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("actual connected WFP tuple was never renewed")
				}
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(50 * time.Millisecond):
				}
			}
			ordinary, err := (&net.Dialer{Timeout: 750 * time.Millisecond}).DialContext(ctx, network, peer.record.Endpoints[network])
			if network[:3] == "tcp" {
				if err == nil {
					_ = ordinary.Close()
					t.Fatal("ordinary process socket bypassed the captured WFP baseline")
				}
			} else if err == nil {
				_ = ordinary.SetDeadline(time.Now().Add(750 * time.Millisecond))
				_, writeErr := ordinary.Write(payload)
				answer := make([]byte, len(payload))
				_, readErr := io.ReadFull(ordinary, answer)
				_ = ordinary.Close()
				if writeErr == nil && readErr == nil {
					t.Fatal("ordinary UDP socket bypassed the captured WFP baseline")
				}
			}
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			if err := broker.Close(ctx); err != nil {
				t.Fatal("real WFP transfer did not join all source descriptors", err)
			}
			_, err = desktopWindowsPolicyCall(p, ctx, true, func() (struct{}, error) {
				if len(p.permits) != 0 || len(p.bindings) != 0 {
					return struct{}{}, errors.New("retired transfer retained a live tuple grant")
				}
				return struct{}{}, nil
			})
			if err != nil {
				t.Fatal("real WFP transfer cleanup lacks an absent kernel readback", err)
			}
			reader, err := desktopWFPOpen(false)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if err := errors.Join(reader.SublayerAbsent(p.sublayer), reader.SublayerAbsent(p.lockKey)); err != nil {
				t.Fatal("joined real transfer retained kernel protection ownership", err)
			}
		})
	}
}

func desktopWindowsWFPExclusivePortRetained(local netip.AddrPort) error {
	family := syscall.AF_INET6
	var target syscall.Sockaddr = &syscall.SockaddrInet6{Addr: local.Addr().As16(), Port: int(local.Port())}
	if local.Addr().Is4() {
		family = syscall.AF_INET
		target = &syscall.SockaddrInet4{Addr: local.Addr().As4(), Port: int(local.Port())}
	}
	handle, err := syscall.Socket(family, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	defer syscall.Closesocket(handle)
	if err := desktopSocketNoReuse(handle); err != nil {
		return err
	}
	err = syscall.Bind(handle, target)
	if errors.Is(err, syscall.Errno(10048)) || errors.Is(err, syscall.Errno(10013)) {
		return nil // WSAEADDRINUSE or exclusive-bind WSAEACCES.
	}
	return errors.Join(err, errors.New("unretired WFP source port became reusable"))
}

// The controlled operation stalls inside the real owner's native-operation
// gate, after the actual BFE permit and Winsock flow exist. Data expiry must
// not depend on joining that operation or obtaining another firewall reply.
func TestDesktopSocketWindowsWFPBlockedControlRetainsEnteredIO(t *testing.T) {
	peer := desktopWindowsWFPStartPeer(t, "peer")
	p := desktopWindowsWFPTestOwner(t, "on-connect", true)
	broker := desktopWindowsWFPBroker(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	connection, err := broker.DialContext(ctx, "tcp4", peer.record.Endpoints["tcp4-hold"])
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	owned, ok := connection.(*desktopSocketConn)
	if !ok {
		t.Fatal("blocked-I/O fixture did not enter the shipping socket broker")
	}
	socket := owned.socket
	native, ok := socket.conn.(*desktopWindowsSocket)
	if !ok {
		t.Fatal("blocked-I/O fixture did not enter the shipping Winsock importer")
	}
	raw := desktopWindowsRaw{native}
	var configured error
	if err := raw.Control(func(handle uintptr) {
		configured = syscall.SetsockoptInt(syscall.Handle(handle), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4096)
	}); err != nil || configured != nil {
		t.Fatal("could not bound the actual queued send buffer", err, configured)
	}
	type writeResult struct {
		n   int
		err error
	}
	written := make(chan writeResult, 1)
	payload := make([]byte, 64<<20)
	go func() { n, err := connection.Write(payload); written <- writeResult{n, err} }()
	blockedUntil := time.Now().Add(5 * time.Second)
	for {
		select {
		case result := <-written:
			t.Fatal("queued-I/O fixture did not reach real kernel backpressure", result.n, result.err)
		default:
		}
		entered := !native.write.TryLock()
		if !entered {
			native.write.Unlock()
		}
		poll := desktopSocketPollFD{handle: native.handle, events: desktopSocketPollWrite}
		if err := desktopSocketPoll(&poll, 0); err != nil {
			t.Fatal(err)
		}
		if entered && poll.revents&desktopSocketPollWrite == 0 {
			break
		}
		if time.Now().After(blockedUntil) {
			t.Fatal("actual Winsock send never reached queued backpressure")
		}
		time.Sleep(10 * time.Millisecond)
	}
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseOperation := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseOperation()
	controlCtx, stopControl := context.WithTimeout(context.Background(), time.Second)
	defer stopControl()
	controlReply := make(chan error, 1)
	go func() {
		_, err := desktopWindowsPolicyCall(p, controlCtx, false, func() (struct{}, error) {
			close(entered)
			<-release
			close(joined)
			return struct{}{}, nil
		})
		controlReply <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("controlled native call never acquired its owned operation gate")
	}
	select {
	case err := <-controlReply:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("blocked native call did not report its bounded caller deadline", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked native call retained its caller past the declared deadline")
	}
	select {
	case result := <-written:
		if result.err == nil || result.n >= len(payload) {
			t.Fatal("stalled policy did not interrupt already-entered kernel I/O", result.n, result.err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("stalled policy left already-entered kernel I/O alive past physical proof expiry")
	}
	if broker.Current() {
		t.Fatal("stalled WFP owner remained current after its independent observation expired")
	}
	// A live actual source handle and a failed independent rebind establish
	// ownership, without assuming that TCP TIME_WAIT alone proves retention.
	retained, err := socket.sourceNative.SyscallConn()
	if err != nil {
		t.Fatal("source handle closed while its native operation remained unjoined", err)
	}
	var actual netip.AddrPort
	var readErr error
	if err := retained.Control(func(handle uintptr) { actual, readErr = desktopSocketLocal(syscall.Handle(handle)) }); err != nil || readErr != nil || actual != socket.local {
		t.Fatal("stalled cleanup lost its exact live kernel source tuple", actual, err, readErr)
	}
	if err := desktopWindowsWFPExclusivePortRetained(socket.local); err != nil {
		t.Fatal(err)
	}
	reader, err := desktopWFPOpen(false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	// The held operation excludes all map mutations. Every remaining filter
	// must still refer to this same retained socket until cleanup can join.
	for _, permit := range p.permits {
		for _, rule := range permit.rules {
			if err := reader.Assert(rule); err != nil {
				t.Fatal("held control fixture lost the actual retained WFP permit", err)
			}
		}
	}
	bounded, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = broker.Close(bounded)
	stop()
	if err == nil {
		t.Fatal("broker acknowledged cleanup before its retained native operation joined")
	}
	releaseOperation()
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("released native operation failed to join")
	}
	if err := broker.Close(ctx); err != nil {
		t.Fatal("released WFP cleanup failed to retire retained source ownership", err)
	}
	if err := errors.Join(reader.SublayerAbsent(p.sublayer), reader.SublayerAbsent(p.lockKey)); err != nil {
		t.Fatal("released cleanup retained its old WFP source authority", err)
	}
}

func desktopWindowsWFPDeathProcess(t *testing.T) {
	options, scope := desktopWindowsWFPTestOptions(t, "always")
	initial, err := json.Marshal(desktopWindowsWFPPeerRecord{AppID: scope})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(initial))
	p, err := newDesktopWindowsPolicyOwner(context.Background(), desktopWindowsWFPTestCapture(t), options, scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.prepareBaseline(); err != nil {
		t.Fatal(err)
	}
	rule := p.rule("test-process-death", 4, false, 50, true, false)
	if err := p.leaseEngine.Add(&rule); err != nil {
		t.Fatal(err)
	}
	record := desktopWindowsWFPPeerRecord{AppID: scope, Metadata: p.metadata, Sublayer: p.sublayer, Lock: p.lockKey, DynamicRule: rule}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(encoded))
	var input [1]byte
	_, _ = os.Stdin.Read(input[:])
	// The parent kills this process while it owns real BFE handles. No Go
	// cancellation, defer, Close or recovery may impersonate process rundown.
	select {}
}

func TestDesktopSocketWindowsWFPActualProcessDeath(t *testing.T) {
	peer := desktopWindowsWFPStartPeer(t, "crash")
	record := peer.record
	joined := false
	t.Cleanup(func() {
		if !joined {
			_ = peer.command.Process.Kill()
			select {
			case <-peer.done:
				peer.done <- nil
			case <-time.After(10 * time.Second):
				t.Error("crash fixture cleanup could not join its exact process")
			}
		}
		desktopWindowsWFPTestRecovery(t, record.AppID)
	})
	reader, err := desktopWFPOpen(false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.Assert(record.DynamicRule); err != nil {
		t.Fatal("crash fixture never installed its actual dynamic filter", err)
	}
	if err := reader.AssertSublayer(record.Sublayer, record.Metadata); err != nil {
		t.Fatal("crash fixture never installed its actual persistent baseline", err)
	}
	if err := peer.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-peer.done:
		if err == nil {
			t.Fatal("native crash fixture exited normally")
		}
		// The shared peer cleanup still performs exactly one joined receipt.
		joined = true
		peer.done <- nil
	case <-time.After(10 * time.Second):
		t.Fatal("killed native BFE owner did not join")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		filterErr := reader.Absent(record.DynamicRule.Key)
		lockErr := reader.SublayerAbsent(record.Lock)
		if filterErr == nil && lockErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dead native process retained its dynamic WFP authority", filterErr, lockErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := reader.AssertSublayer(record.Sublayer, record.Metadata); err != nil {
		t.Fatal("native crash removed the persistent Always drop baseline", err)
	}
	desktopWindowsWFPTestRecovery(t, record.AppID)
	if err := reader.SublayerAbsent(record.Sublayer); err != nil {
		t.Fatal("explicit crash recovery did not retire its exact baseline", err)
	}
}
