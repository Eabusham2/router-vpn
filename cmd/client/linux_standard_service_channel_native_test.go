//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
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

func TestLinuxStandardServiceChannelFixture(t *testing.T) {
	if os.Getenv("ROUTERVPN_STANDARD_CHANNEL_FIXTURE") != "1" {
		return
	}
	transport := standardServiceTestConnection(t, os.NewFile(3, "original-channel-control"))
	defer transport.Close()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	channel := standardServiceTestConnection(t, os.NewFile(uintptr(pair[0]), "actual-controller-channel"))
	defer channel.Close()
	transfer := os.NewFile(uintptr(pair[1]), "original-server-channel")
	_, _, err = transport.WriteMsgUnix([]byte("R"), syscall.UnixRights(int(transfer.Fd())), nil)
	_ = transfer.Close()
	if err != nil {
		t.Fatal(err)
	}
	body, files, err := linuxStandardServiceRead(transport)
	if err != nil {
		t.Fatal(err)
	}
	var rights []byte
	if len(files) == 1 {
		rights = syscall.UnixRights(int(files[0].Fd()))
	}
	_, _, err = channel.WriteMsgUnix(body, rights, nil)
	for _, file := range files {
		_ = file.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	_, _ = transport.Write([]byte("S"))
	var control [1]byte
	_, _ = transport.Read(control[:])
	_ = channel.Close()
	_, _ = transport.Write([]byte("C"))
	// Keep the authenticated original controller alive after cancelling only
	// this RPC, so process death cannot substitute for channel cancellation.
	_, _ = transport.Read(control[:])
}

func linuxStandardChannelFixture(t *testing.T) (*net.UnixConn, *net.UnixConn, []string) {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	transport := standardServiceTestConnection(t, os.NewFile(uintptr(pair[0]), "original-fixture-control"))
	inherited := os.NewFile(uintptr(pair[1]), "original-fixture-child")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{executable, "-test.run=^TestLinuxStandardServiceChannelFixture$"}
	command := exec.Command(args[0], args[1:]...)
	command.ExtraFiles = []*os.File{inherited}
	command.Env = append(os.Environ(), "ROUTERVPN_STANDARD_CHANNEL_FIXTURE=1")
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = inherited.Close()
	joined := make(chan struct{})
	go func() { _ = command.Wait(); close(joined) }()
	t.Cleanup(func() {
		_ = transport.Close()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-joined
		}
	})
	_ = transport.SetDeadline(time.Now().Add(10 * time.Second))
	body, files, err := linuxStandardServiceRead(transport)
	if err != nil || string(body) != "R" || len(files) != 1 {
		t.Fatal("original channel transfer", err)
	}
	channel := standardServiceTestConnection(t, files[0])
	t.Cleanup(func() { _ = channel.Close() })
	return transport, channel, args
}

func TestLinuxStandardServiceOriginalChannelCancellationJoinsStartAndDNS(t *testing.T) {
	for _, action := range []string{"start", "start-held", "prove-dns"} {
		t.Run(action, func(t *testing.T) {
			s, f, m := linuxStandardServiceRuntimeFixture(t, "on-connect")
			transport, channel, args := linuxStandardChannelFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			peer, err := captureLinuxStandardServicePeer(ctx, channel, s.image, args, s.namespace)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			request, directory := linuxStandardServiceRequestFixture(t, f)
			entered := make(chan struct{})
			if action == "start" || action == "start-held" {
				prepare := s.prepare
				s.prepare = func(a *app, cmd *exec.Cmd, mode, base, id string) (legacyStandardExitLaunch, error) {
					owner, err := prepare(a, cmd, mode, base, id)
					if err != nil {
						return owner, err
					}
					if action == "start-held" {
						original := owner.(*linuxLegacyStandardExitOwner)
						operation := a.connectionOperationContextOrBackground()
						network := original.dns.network
						var enteredOnce sync.Once
						original.dns.network = func() string {
							// Stop precisely after the real guard and saved inode
							// have been published, before child creation. The lost
							// original channel must cancel this original operation.
							if original.protection != nil && original.protection.persisted {
								enteredOnce.Do(func() { close(entered) })
								<-operation.Done()
							}
							return network()
						}
						return owner, nil
					}
					owner.(*linuxLegacyStandardExitOwner).protectionFactory = func(ctx context.Context, _ string, _ string, _ []netip.Addr, _ bool, _ *os.File) (legacyExitKernelProtection, error) {
						close(entered)
						<-ctx.Done()
						return nil, ctx.Err()
					}
					return owner, nil
				}
			} else {
				if err = s.handle(ctx, peer, request, []*os.File{directory}); err != nil {
					t.Fatal(err)
				}
				waitLegacyOffEngine(t, f)
				request = linuxStandardServiceTestAction(request, "prove-dns", false)
				directory = nil
				close(entered)
			}
			if err = linuxStandardServiceWrite(transport, request, directory); err != nil {
				t.Fatal(err)
			}
			var ack [1]byte
			if _, err = transport.Read(ack[:]); err != nil || ack[0] != 'S' {
				t.Fatal("child did not send original request", err)
			}
			joined := make(chan struct{})
			s.workers.Add(1)
			go func() { s.connectionWithArguments(channel, args); close(joined) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("actual service work never entered")
			}
			if action == "prove-dns" {
				// The stock fixture has no listener; the real selected-DNS proof is
				// waiting for its original child, never an ambient replacement.
				deadline := time.Now().Add(time.Second)
				for time.Now().Before(deadline) {
					s.app.mu.Lock()
					active := s.app.connectionContext != nil
					s.app.mu.Unlock()
					if active {
						break
					}
					time.Sleep(time.Millisecond)
				}
			}
			if _, err = transport.Write([]byte("C")); err != nil {
				t.Fatal(err)
			}
			if _, err = transport.Read(ack[:]); err != nil || ack[0] != 'C' {
				t.Fatal("original channel not closed", err)
			}
			select {
			case <-joined:
			case <-time.After(2 * time.Second):
				t.Fatal("lost original channel did not cancel and join request")
			}
			if err = peer.Current(ctx); err != nil {
				t.Fatal("test accidentally used controller exit instead of channel cancellation", err)
			}
			if s.session == nil {
				t.Fatal("service forgot original attempted owner")
			}
			if action == "start" || action == "start-held" {
				if !s.session.joined {
					t.Fatal("cancelled Start did not retire original preparation", s.session.cleanupError)
				}
				if _, err = os.Stat(filepath.Join(f.root, "engine-started")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("late engine executed after channel cancellation")
				}
				if action == "start-held" {
					original := s.session.owner
					m.mu.Lock()
					count := len(m.tables)
					m.mu.Unlock()
					if count != 1 || original.protection == nil || original.protection.removed || !original.protection.detached {
						t.Fatal("lost Start channel released the acknowledged original On-connect guard")
					}
					if err = original.currentProtection(ctx); err != nil {
						t.Fatal("lost Start channel discarded original saved/native guard identity", err)
					}
					if err = s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
						t.Fatal("explicit Stop could not release the held original preparation", err)
					}
					if !original.protection.removed || !original.protection.stateRemoved {
						t.Fatal("explicit Stop left its original On-connect guard behind")
					}
				}
			} else {
				s.session.owner.dns.mu.Lock()
				proof := s.session.owner.dns.proof
				s.session.owner.dns.mu.Unlock()
				if proof != nil {
					t.Fatal("cancelled original DNS request installed a receipt")
				}
				if err = s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
					t.Fatal(err)
				}
				assertLegacyOffJoined(t, s.session.owner)
			}
		})
	}
}
