//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLinuxStandardServiceIdleUpgradeRequiresJoinedNativeAbsence(t *testing.T) {
	for _, kind := range []string{"idle", "joined-off", "closed-boot", "unjoined", "cleanup-pending", "off-save-pending", "engine-owner", "always-owner", "boot-owner", "saved-state", "tun-present", "native-present", "state-created-during-readback", "foreign-namespace", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			image, _ := os.Stat("/proc/self/exe")
			namespace, _ := os.Stat("/proc/thread-self/ns/net")
			s := newLinuxStandardService(root, image, namespace)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			defer legacyStandardExitOwners.Delete(s.app)
			defer legacyStandardProtectionOwners.Delete(s.app)
			tun := func() error { return nil }
			native := func(context.Context) error { return nil }
			switch kind {
			case "joined-off":
				s.session = &linuxStandardServiceSession{joined: true}
			case "closed-boot":
				s.boot = &legacyExitProtectionSlot{closed: true, removed: true, stateRemoved: true}
			case "unjoined":
				s.session = &linuxStandardServiceSession{}
			case "cleanup-pending":
				s.session = &linuxStandardServiceSession{joined: true, cleanupPending: true}
			case "off-save-pending":
				s.protectionView = &linuxStandardServiceProtection{data: linuxStandardServiceProtectionData{Pending: true, Removed: true, AbsenceProved: true}}
			case "engine-owner":
				legacyStandardExitOwners.Store(s.app, &linuxLegacyStandardExitOwner{})
			case "always-owner":
				legacyStandardProtectionOwners.Store(s.app, &legacyExitProtectionSlot{detached: true})
			case "boot-owner":
				s.boot = &legacyExitProtectionSlot{}
			case "saved-state":
				if err := os.Mkdir(filepath.Join(root, "run"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "run", "kill-switch.json"), []byte(`{"handle":1}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "tun-present":
				tun = func() error { return errors.New("actual TUN is present") }
			case "native-present":
				native = func(context.Context) error { return errors.New("actual nft table is present") }
			case "state-created-during-readback":
				native = func(context.Context) error {
					return os.WriteFile(filepath.Join(root, "run", "kill-switch.json"), []byte(`{"handle":1}`), 0600)
				}
			case "foreign-namespace":
				s.namespace, _ = os.Stat("/proc/thread-self/ns/pid")
			case "cancelled":
				cancel()
			}
			err := s.prepareIdleShutdownWithObservers(ctx, tun, native)
			allowed := kind == "idle" || kind == "joined-off" || kind == "closed-boot"
			if (err == nil) != allowed || s.quiescing != allowed {
				t.Fatalf("idle admission=%v quiescing=%v error=%v", allowed, s.quiescing, err)
			}
			if kind == "saved-state" || kind == "state-created-during-readback" {
				if body, readErr := os.ReadFile(filepath.Join(root, "run", "kill-switch.json")); readErr != nil || string(body) != `{"handle":1}` {
					t.Fatal("upgrade deleted unowned persisted state", readErr)
				}
			}
		})
	}
}

func TestLinuxStandardServiceUpgradeAfterActualAlwaysToOffCleanup(t *testing.T) {
	s, f, model := linuxStandardServiceRuntimeFixture(t, "always")
	absent := func(context.Context) error {
		model.mu.Lock()
		defer model.mu.Unlock()
		if len(model.tables) != 0 {
			return errors.New("native model still retains original protection")
		}
		return nil
	}
	prepare := s.prepare
	s.prepare = func(a *app, command *exec.Cmd, mode, base, id string) (legacyStandardExitLaunch, error) {
		prepared, err := prepare(a, command, mode, base, id)
		if err != nil || prepared == nil {
			return prepared, err
		}
		owner := prepared.(*linuxLegacyStandardExitOwner)
		owner.offProtectionCheck = func(ctx context.Context) error {
			lease, err := acquireLegacyExitMutationLease(ctx, owner.protectionRoot)
			if err != nil {
				return err
			}
			defer lease.Close()
			if err := legacyExitStateAbsent(lease); err != nil {
				return err
			}
			return absent(ctx)
		}
		return owner, nil
	}
	firstPeer, _, firstExit := linuxStandardPeerFixture(t)
	first, directory := linuxStandardServiceRequestFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.handle(ctx, firstPeer, first, []*os.File{directory}); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	if err := s.handle(ctx, firstPeer, linuxStandardServiceTestAction(first, "stop", true), nil); err != nil {
		t.Fatal(err)
	}
	old := s.session.owner.protection
	assertLegacyOffJoined(t, s.session.owner)
	if err := s.prepareIdleShutdownWithObservers(ctx, func() error { return nil }, absent); err == nil || s.quiescing || old.removed {
		t.Fatal("normal Always Stop authorized upgrade or released original protection", err)
	}
	firstExit()
	f.a.profiles.Profiles[0].KillSwitchPolicy = "off"
	if err := f.a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	secondPeer, _, _ := linuxStandardPeerFixture(t)
	second, workspace := linuxStandardServiceRequestFixture(t, f)
	if err := s.handle(ctx, secondPeer, second, []*os.File{workspace}); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	if err := s.handle(ctx, secondPeer, linuxStandardServiceTestAction(second, "stop", true), nil); err != nil {
		t.Fatal(err)
	}
	assertLegacyOffJoined(t, s.session.owner)
	if !old.closed || !old.removed || !old.stateRemoved {
		t.Fatal("explicit Off did not retire original Always authority")
	}
	s.boot = old // A historical pointer is not a live creator.
	if err := s.prepareIdleShutdownWithObservers(ctx, func() error { return nil }, absent); err != nil || !s.quiescing {
		t.Fatal("actual Always to Off cleanup permanently blocked idle upgrade", err)
	}
}

func TestLinuxStandardServiceUpgradePeerFixture(t *testing.T) {
	mode := os.Getenv("ROUTERVPN_STANDARD_UPGRADE_FIXTURE")
	if mode == "" {
		return
	}
	transport := standardServiceTestConnection(t, os.NewFile(3, "original-upgrade-transfer"))
	defer transport.Close()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	connection := standardServiceTestConnection(t, os.NewFile(uintptr(pair[0]), "original-upgrade-service"))
	defer connection.Close()
	transfer := os.NewFile(uintptr(pair[1]), "original-upgrade-helper")
	_, _, err = transport.WriteMsgUnix([]byte("R"), syscall.UnixRights(int(transfer.Fd())), nil)
	_ = transfer.Close()
	if err != nil {
		t.Fatal(err)
	}
	body, files, err := linuxStandardServiceRead(connection)
	for _, f := range files {
		_ = f.Close()
	}
	var request linuxStandardServiceRequest
	if err != nil || len(files) != 0 || linuxStandardServiceDecode(body, &request) != nil {
		t.Fatal("upgrade fixture request", err)
	}
	if mode == "lost-reply" {
		_ = connection.CloseWrite()
	} else {
		response := linuxStandardServiceResponse{Schema: 1, Session: request.Session, Action: request.Action, Complete: true}
		if mode == "wrong-reply" {
			response.Session = strings.Repeat("f", 32)
		}
		if err := linuxStandardServiceWrite(connection, response, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := transport.Write([]byte("A")); err != nil {
		t.Fatal(err)
	}
	var release [1]byte
	if _, err := transport.Read(release[:]); err != nil {
		t.Fatal(err)
	}
	if mode != "listener-retained" {
		if err := os.Remove(os.Getenv("ROUTERVPN_STANDARD_UPGRADE_LISTENER")); err != nil {
			t.Fatal(err)
		}
	}
}

// The Unix peer, actual process, SO_PEERPIDFD and wait are native. The pathname
// below models the listener entry; the full named service listener runs in CI.
func TestLinuxStandardServiceUpgradeJoinsActualPeerBeforeSuccess(t *testing.T) {
	for _, mode := range []string{"complete", "lost-reply", "wrong-reply", "listener-retained", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "listener")
			if err := os.WriteFile(path, []byte("original listener fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			transport := standardServiceTestConnection(t, os.NewFile(uintptr(pair[0]), "original-upgrade-parent"))
			defer transport.Close()
			inherited := os.NewFile(uintptr(pair[1]), "original-upgrade-child")
			defer inherited.Close()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			arguments := []string{executable, "-test.run=^TestLinuxStandardServiceUpgradePeerFixture$"}
			command := exec.Command(arguments[0], arguments[1:]...)
			command.ExtraFiles = []*os.File{inherited}
			command.Env = append(os.Environ(), "ROUTERVPN_STANDARD_UPGRADE_FIXTURE="+mode, "ROUTERVPN_STANDARD_UPGRADE_LISTENER="+path)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			_ = inherited.Close()
			joined := make(chan error, 1)
			joinedDone := make(chan struct{})
			go func() { joined <- command.Wait(); close(joinedDone) }()
			t.Cleanup(func() { _ = command.Process.Kill(); <-joinedDone })
			_ = transport.SetDeadline(time.Now().Add(5 * time.Second))
			body, files, err := linuxStandardServiceRead(transport)
			if err != nil || string(body) != "R" || len(files) != 1 {
				t.Fatal("actual child transfer", err)
			}
			connection := standardServiceTestConnection(t, files[0])
			defer connection.Close()
			image, _ := os.Stat("/proc/self/exe")
			namespace, _ := os.Stat("/proc/thread-self/ns/net")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- linuxStandardServiceUpgradeChannel(ctx, connection, path, image, namespace, arguments)
			}()
			var acknowledged [1]byte
			if _, err := transport.Read(acknowledged[:]); err != nil || acknowledged[0] != 'A' {
				t.Fatal("actual reply", err)
			}
			select {
			case early := <-result:
				t.Fatal("protocol response replaced original service retirement", early)
			case <-time.After(30 * time.Millisecond):
			}
			if mode == "cancelled" {
				cancel()
				if err := <-result; !errors.Is(err, context.Canceled) {
					t.Fatal("upgrade renewed its cancellation budget", err)
				}
				select {
				case <-joined:
					t.Fatal("cancelled helper killed its unjoined service")
				default:
				}
			}
			if _, err := transport.Write([]byte("X")); err != nil {
				t.Fatal(err)
			}
			if err := <-joined; err != nil {
				t.Fatal("actual original service join", err)
			}
			if mode != "cancelled" {
				err := <-result
				if (err == nil) != (mode == "complete") {
					t.Fatal("upgrade result lost reply/listener constraints", err)
				}
			}
		})
	}
}
