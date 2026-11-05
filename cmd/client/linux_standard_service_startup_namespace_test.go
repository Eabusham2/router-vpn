//go:build linux && routervpn_controller_privileged && routervpn_standard_service_native

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The packaging runner first verifies the complete built bundle and copies it
// into this namespace's private /opt. This fixture then installs those actual
// exact bytes; production preparation must independently verify the payload.
func linuxStandardInstallRuntimeFixture(t *testing.T) {
	t.Helper()
	source := os.Getenv("ROUTERVPN_STANDARD_RUNTIME_BUNDLE")
	if source != "/opt/routervpn-runtime-proof" {
		t.Fatal("installed service omitted its actual staged native runtime")
	}
	raw, err := readPrivateRegular(filepath.Join(source, "NATIVE-RUNTIME.json"), 32768)
	if err != nil {
		t.Fatal(err)
	}
	var receipt bundledNativeReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(linuxOwnedControllerRoot, "runtime", "native")
	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	for name, wanted := range receipt.Files {
		if filepath.Base(name) != name || wanted.Size < 1 || wanted.Size > 512<<20 {
			t.Fatal("runtime bundle name/size invalid")
		}
		path := filepath.Join(source, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || !ownedDesktopInfo(info) || info.Size() != wanted.Size {
			t.Fatal("staged original native file changed", name, err)
		}
		original, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := original.Stat()
		if err != nil || !os.SameFile(info, opened) {
			original.Close()
			t.Fatal("native source descriptor changed", err)
		}
		target, err := os.OpenFile(filepath.Join(destination, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
		if err != nil {
			original.Close()
			t.Fatal(err)
		}
		hash := sha256.New()
		count, copyErr := io.Copy(io.MultiWriter(target, hash), io.LimitReader(original, wanted.Size+1))
		after, statErr := original.Stat()
		closeErr := errors.Join(original.Close(), target.Close())
		if copyErr != nil || statErr != nil || closeErr != nil || !os.SameFile(info, after) || count != wanted.Size || hex.EncodeToString(hash.Sum(nil)) != wanted.SHA256 {
			t.Fatal("native payload did not retain its actual captured build", name, copyErr, statErr, closeErr)
		}
	}
	if err := os.WriteFile(filepath.Join(destination, "NATIVE-RUNTIME.json"), raw, 0400); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := verifyBundledNativeContext(ctx, linuxOwnedControllerRoot); err != nil {
		t.Fatal("installed service fixture is not a valid actual native build", err)
	}
}

// A private actual SOCKS5 peer accepts only the selected TCP resolver and
// exchanges real uncached DNS frames. No outbound or compiled TUN option is
// replaced. Public Internet reachability is outside this local gate.
func linuxStandardNativePeerFixture(t *testing.T, custom ...func(net.Conn, *atomic.Int64) error) *atomic.Int64 {
	if len(custom) > 1 {
		t.Fatal("ambiguous private peer")
	}
	serve := linuxStandardNativeSOCKSDNS
	if len(custom) == 1 {
		serve = custom[0]
	}
	t.Helper()
	for _, args := range [][]string{{"link", "add", "rvphysical", "type", "dummy"}, {"address", "add", "203.0.113.10/24", "dev", "rvphysical"}, {"link", "set", "rvphysical", "up"}, {"route", "add", "default", "via", "203.0.113.1", "dev", "rvphysical"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("original physical fixture: %v %s", err, output)
		}
	}
	listener, err := net.Listen("tcp4", "203.0.113.10:443")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var workers sync.WaitGroup
	queries := &atomic.Int64{}
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				stopped := make(chan struct{})
				stop := context.AfterFunc(ctx, func() { connection.Close(); close(stopped) })
				defer func() {
					if !stop() {
						<-stopped
					}
				}()
				_ = connection.SetDeadline(time.Now().Add(50 * time.Second))
				_ = serve(connection, queries)
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		<-done
		workers.Wait()
		if output, err := exec.Command("ip", "link", "delete", "rvphysical").CombinedOutput(); err != nil {
			t.Errorf("original native fixture retirement: %v %s", err, output)
		}
	})
	return queries
}

func linuxStandardNativeSOCKSDNS(connection net.Conn, queries *atomic.Int64) error {
	var greeting [2]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 5 || greeting[1] < 1 || greeting[1] > 8 {
		return errors.New("bad SOCKS greeting")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return err
	}
	found := false
	for _, method := range methods {
		found = found || method == 2
	}
	if !found {
		return errors.New("original SOCKS authentication omitted")
	}
	if _, err := connection.Write([]byte{5, 2}); err != nil {
		return err
	}
	if _, err := io.ReadFull(connection, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 1 || greeting[1] != 1 {
		return errors.New("bad SOCKS credentials")
	}
	var credentials [3]byte
	if _, err := io.ReadFull(connection, credentials[:]); err != nil {
		return err
	}
	if credentials != ([3]byte{'u', 1, 'p'}) {
		return errors.New("foreign SOCKS credentials")
	}
	if _, err := connection.Write([]byte{1, 0}); err != nil {
		return err
	}
	var request [10]byte
	if _, err := io.ReadFull(connection, request[:]); err != nil {
		return err
	}
	if request[0] != 5 || request[1] != 1 || request[2] != 0 || request[3] != 1 || request[4] != 203 || request[5] != 0 || request[6] != 113 || request[7] != 53 || binary.BigEndian.Uint16(request[8:]) != 5353 {
		return errors.New("SOCKS route did not select original TCP resolver")
	}
	if _, err := connection.Write([]byte{5, 0, 0, 1, 203, 0, 113, 10, 1, 187}); err != nil {
		return err
	}
	for {
		var size [2]byte
		if _, err := io.ReadFull(connection, size[:]); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint16(size[:]))
		if length < 17 || length > 16*1024 {
			return errors.New("unbounded selected DNS question")
		}
		query := make([]byte, length)
		if _, err := io.ReadFull(connection, query); err != nil {
			return err
		}
		queries.Add(1)
		response := append([]byte(nil), query[:2]...)
		response = append(response, []byte{0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}...)
		response = append(response, query[12:]...)
		response = append(response, []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 203, 0, 113, 20}...)
		frame := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(frame, uint16(len(response)))
		copy(frame[2:], response)
		if _, err := connection.Write(frame); err != nil {
			return err
		}
	}
}

func TestLinuxStandardServiceStartupNativeSOCKSDNSFrames(t *testing.T) {
	for _, scenario := range []string{"selected", "foreign-resolver", "foreign-auth"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			queries := &atomic.Int64{}
			go func() {
				peer, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer peer.Close()
				peer.SetDeadline(time.Now().Add(3 * time.Second))
				done <- linuxStandardNativeSOCKSDNS(peer, queries)
			}()
			client, err := net.DialTimeout("tcp4", listener.Addr().String(), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := client.Write([]byte{5, 1, 2}); err != nil {
				t.Fatal(err)
			}
			var reply [2]byte
			if _, err := io.ReadFull(client, reply[:]); err != nil || reply != ([2]byte{5, 2}) {
				t.Fatal("real SOCKS method exchange failed", err)
			}
			auth := []byte{1, 1, 'u', 1, 'p'}
			if scenario == "foreign-auth" {
				auth[4] = 'x'
			}
			if _, err := client.Write(auth); err != nil {
				t.Fatal(err)
			}
			if scenario == "foreign-auth" {
				if err := <-done; err == nil || queries.Load() != 0 {
					t.Fatal("foreign SOCKS credentials produced DNS", err)
				}
				return
			}
			if _, err := io.ReadFull(client, reply[:]); err != nil || reply != ([2]byte{1, 0}) {
				t.Fatal("real SOCKS credential exchange failed", err)
			}
			request := []byte{5, 1, 0, 1, 203, 0, 113, 53, 20, 233}
			if scenario == "foreign-resolver" {
				request[7] = 54
			}
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			if scenario == "foreign-resolver" {
				if err := <-done; err == nil || queries.Load() != 0 {
					t.Fatal("foreign DNS target produced response", err)
				}
				return
			}
			var connected [10]byte
			if _, err := io.ReadFull(client, connected[:]); err != nil || connected[1] != 0 {
				t.Fatal("real SOCKS target exchange failed", err)
			}
			query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'x', 0, 0, 1, 0, 1}
			frame := make([]byte, len(query)+2)
			binary.BigEndian.PutUint16(frame, uint16(len(query)))
			copy(frame[2:], query)
			if _, err := client.Write(frame); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(client, reply[:]); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, int(binary.BigEndian.Uint16(reply[:])))
			if _, err := io.ReadFull(client, response); err != nil {
				t.Fatal(err)
			}
			if len(response) <= len(query) || response[0] != 0x12 || response[1] != 0x34 || response[2] != 0x81 || queries.Load() != 1 {
				t.Fatal("selected DNS response did not traverse actual authenticated SOCKS stream")
			}
			client.Close()
			<-done
		})
	}
}

// Only the tagged test image supplies this observer to the unchanged utility
// driver. Capture the first actually proved owner once, then signal its original
// creation pidfd after the exact-session trigger; never look up a PID or follow
// a later replacement. Utility lifetime cancellation joins this observer.
func linuxStandardNativeExitObserver(ctx context.Context, s *linuxStandardService) (func() error, error) {
	if ctx == nil || s == nil {
		return nil, errors.New("native exit fixture has no original service")
	}
	done := make(chan struct{})
	var failure error
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		var session *linuxStandardServiceSession
		var owner *linuxLegacyStandardExitOwner
		var pidfd *os.File
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			select {
			case <-ctx.Done():
				return
			case <-s.gate:
			}
			if session != nil && (s.session != session || session.owner != owner) {
				s.gate <- struct{}{}
				failure = errors.New("native exit trigger lost its exact captured owner")
				return
			}
			if session == nil && s.session != nil && s.session.owner != nil && !s.session.joined && !s.session.cleanupPending {
				candidate := s.session.owner
				proved := false
				if candidate.dns != nil {
					candidate.dns.mu.Lock()
					proved = candidate.dns.proof != nil
					candidate.dns.mu.Unlock()
				}
				if candidate.native != nil && candidate.native.ready && proved {
					session, owner, pidfd = s.session, candidate, candidate.originalPIDFD
					if err := os.WriteFile(filepath.Join(s.root, "run", "standard-service-fixture-captured"), []byte(session.request.Session), 0600); err != nil {
						s.gate <- struct{}{}
						failure = err
						return
					}
				}
			}
			if session == nil {
				s.gate <- struct{}{}
				continue
			}
			trigger, err := readPrivateRegular(filepath.Join(s.root, "run", "standard-service-fixture-exit"), 64)
			if errors.Is(err, os.ErrNotExist) {
				s.gate <- struct{}{}
				continue
			}
			if err != nil || string(trigger) != session.request.Session {
				s.gate <- struct{}{}
				failure = errors.New("native exit trigger changed its original session")
				return
			}
			check, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = owner.legacyDNSCurrent(check)
			if err == nil {
				err = s.networkCurrent(check, session, true)
			}
			if err == nil {
				owner.mu.Lock()
				if owner.originalPIDFD != pidfd || owner.pidFile != pidfd || pidfd == nil || owner.processRetired || session.joined {
					err = errors.New("native exit trigger lost original created pidfd")
				} else {
					info, statErr := pidfd.Stat()
					if statErr != nil || owner.pidInfo == nil || !os.SameFile(info, owner.pidInfo) {
						err = errors.New("native exit trigger pidfd was replaced")
					} else {
						raw, rawErr := pidfd.SyscallConn()
						err = rawErr
						if err == nil {
							var signalErr error
							err = raw.Control(func(fd uintptr) {
								if signalErr = check.Err(); signalErr != nil {
									return
								}
								_, _, errno := syscall.Syscall6(424, fd, uintptr(syscall.SIGTERM), 0, 0, 0, 0)
								if errno != 0 {
									signalErr = errno
								}
							})
							err = errors.Join(err, signalErr)
						}
					}
				}
				owner.mu.Unlock()
			}
			cancel()
			if err == nil {
				err = os.WriteFile(filepath.Join(s.root, "run", "standard-service-fixture-signaled"), []byte(session.request.Session), 0600)
			}
			s.gate <- struct{}{}
			failure = err
			return
		}
	}()
	return func() error { <-done; return failure }, nil
}

// Actual original child/pidfd and joined observer; only fixture DNS readiness
// and the native routing observer are modeled in these local callback cases.
func TestLinuxStandardServiceStartupExitObserverKeepsOriginalOwner(t *testing.T) {
	for _, scenario := range []string{"original-exit", "cancelled", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			s, f, _ := linuxStandardStartupFixture(t, "complete")
			peer, _, _ := linuxStandardPeerFixture(t)
			request, directory := linuxStandardServiceRequestFixture(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := s.handle(ctx, peer, request, []*os.File{directory}); err != nil {
				t.Fatal(err)
			}
			original := s.session
			owner := original.owner
			owner.dns.mu.Lock()
			owner.dns.proof = &legacyStandardDNSReceipt{owner: owner, session: owner.session}
			owner.dns.mu.Unlock()
			lifetime, stop := context.WithCancel(context.Background())
			join, err := linuxStandardNativeExitObserver(lifetime, s)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { stop(); _ = join() }()
			for {
				raw, err := os.ReadFile(filepath.Join(f.root, "run", "standard-service-fixture-captured"))
				if err == nil && string(raw) == request.Session {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("observer did not capture original proved owner")
				case <-time.After(time.Millisecond):
				}
			}
			if scenario == "cancelled" {
				stop()
			} else {
				if scenario == "replacement" {
					<-s.gate
					s.session = &linuxStandardServiceSession{request: request, peer: peer, owner: owner}
					s.gate <- struct{}{}
				}
				if err := os.WriteFile(filepath.Join(f.root, "run", "standard-service-fixture-exit"), []byte(request.Session), 0600); err != nil {
					t.Fatal(err)
				}
			}
			joined := make(chan error, 1)
			go func() { joined <- join() }()
			select {
			case err = <-joined:
			case <-ctx.Done():
				t.Fatal("original exit observer did not join")
			}
			if scenario == "replacement" {
				if err == nil {
					t.Fatal("late observer followed replacement session")
				}
				<-s.gate
				s.session = original
				s.gate <- struct{}{}
			} else if err != nil {
				t.Fatal(err)
			}
			if scenario == "original-exit" {
				select {
				case <-owner.done:
				case <-ctx.Done():
					t.Fatal("exact original creation pidfd did not retire actual engine")
				}
			} else {
				if err := owner.legacyDNSCurrent(ctx); err != nil {
					t.Fatal("cancelled or stale observer signaled original/replacement runtime", err)
				}
				if _, err := os.Lstat(filepath.Join(f.root, "run", "standard-service-fixture-signaled")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("stale observer produced a signal witness", err)
				}
			}
			if err := s.retire(ctx, false); err != nil {
				t.Fatal(err)
			}
			if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}
