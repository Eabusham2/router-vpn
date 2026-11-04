//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// The engine, original pidfds, peer processes, files and flock are real. Only
// nft/TUN/physical-network observations use the explicit existing model seam.
func linuxStandardServiceRuntimeFixture(t *testing.T, policy string) (*linuxStandardService, *legacyExitFixture, *legacyProtectionModel) {
	t.Helper()
	f := newLegacyExitFixture(t, policy)
	applyProfileDefaults(&f.a.profiles.Profiles[0])
	if err := f.a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	image, err := os.Stat("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	s := newLinuxStandardService(f.root, image, namespace)
	m := newLegacyProtectionModel()
	s.tunAbsent = func() error { return nil }
	s.protectionAbsence = func(context.Context) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if len(m.tables) != 0 {
			return errors.New("native fixture still has original protection")
		}
		return nil
	}
	s.prepare = func(a *app, command *exec.Cmd, mode, base, id string) (legacyStandardExitLaunch, error) {
		prepared, err := prepareLegacyStandardExitOwnerWithObservers(a, command, mode, base, id, func() error { return nil }, func() string { return "captured-test-network" })
		if err != nil || prepared == nil {
			return prepared, err
		}
		owner := prepared.(*linuxLegacyStandardExitOwner)
		owner.protectionFactory = m.create
		owner.protectionAbsence = func(context.Context) error {
			m.mu.Lock()
			defer m.mu.Unlock()
			if len(m.tables) != 0 {
				return errors.New("unexpected native policy")
			}
			return nil
		}
		return owner, nil
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.retire(ctx, true)
		if raw, exists := legacyStandardProtectionOwners.LoadAndDelete(s.app); exists {
			slot := raw.(*legacyExitProtectionSlot)
			_ = slot.saved.Close()
			_ = slot.kernel.Close(ctx)
		}
	})
	return s, f, m
}

func linuxStandardServiceRequestFixture(t *testing.T, f *legacyExitFixture) (linuxStandardServiceRequest, *os.File) {
	t.Helper()
	command, err := nativeStandardExitCommand(f.a, f.a.profiles.Profiles[0], common.RouterProfile{}, f.exit, true)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareLegacyStandardExitOwnerWithObservers(f.a, command, "standard-"+f.exit.Protocol, "external", "standard:"+f.exit.ID, func() error { return nil }, func() string { return "captured-test-network" })
	if err != nil || prepared == nil {
		t.Fatal(err)
	}
	owner := prepared.(*linuxLegacyStandardExitOwner)
	t.Cleanup(func() { copies := &linuxStandardServiceLaunch{prepared: owner}; _ = copies.closeCopies() })
	digest, err := linuxStandardProfileDigest(f.a.profiles.Profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	request := linuxStandardServiceRequest{Schema: 1, Action: "start", Session: owner.session, BudgetMS: 30000, DeadlineNS: time.Now().Add(30 * time.Second).UnixNano(),
		Directory: owner.launch.directory, ConfigSHA256: owner.digest, ProfileID: owner.protectionProfileID, ProfileSHA256: digest, NetworkID: owner.dns.networkID,
		Endpoint: owner.protectionEndpoint, RuntimeMode: owner.runtimeMode, Base: owner.base, RouterID: owner.routerID}
	return request, owner.directory
}

func linuxStandardServiceTestAction(request linuxStandardServiceRequest, action string, release bool) linuxStandardServiceRequest {
	return linuxStandardServiceRequest{Schema: 1, Action: action, Session: request.Session, BudgetMS: 30000, DeadlineNS: time.Now().Add(30 * time.Second).UnixNano(), Release: release}
}

func TestLinuxStandardServiceRetainsActualEngineAndAlwaysAcrossController(t *testing.T) {
	s, f, m := linuxStandardServiceRuntimeFixture(t, "always")
	firstPeer, _, firstExit := linuxStandardPeerFixture(t)
	first, directory := linuxStandardServiceRequestFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.handle(ctx, firstPeer, first, []*os.File{directory}); err != nil {
		t.Fatal("actual service engine Start", err)
	}
	old := s.session.owner
	waitLegacyOffEngine(t, f)
	if old.command.Process == nil || old.originalPIDFD == nil {
		t.Fatal("service did not create and retain its actual engine")
	}
	if err := s.handle(ctx, firstPeer, linuxStandardServiceTestAction(first, "stop", true), nil); err != nil {
		t.Fatal(err)
	}
	assertLegacyOffJoined(t, old)
	if !old.protection.detached || old.protection.removed {
		t.Fatal("normal controller Stop discarded Always creator")
	}
	secondPeer, _, _ := linuxStandardPeerFixture(t)
	f.a.profiles.Profiles[0].KillSwitchPolicy = "on-connect"
	if err := f.a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	second, nextDirectory := linuxStandardServiceRequestFixture(t, f)
	if err := s.handle(ctx, secondPeer, second, []*os.File{nextDirectory}); err == nil {
		t.Fatal("another live controller acquired original held protection")
	}
	firstExit()
	if err := s.handle(ctx, secondPeer, second, []*os.File{nextDirectory}); err != nil {
		t.Fatal("new authenticated controller could not continue live service", err)
	}
	current := s.session.owner
	if current == old || !old.protection.removed || !old.protection.closed {
		t.Fatal("new original creator did not retire its held predecessor")
	}
	if err := s.handle(ctx, firstPeer, linuxStandardServiceTestAction(first, "stop", true), nil); err == nil {
		t.Fatal("stale controller released newer service engine")
	}
	if err := s.handle(ctx, secondPeer, linuxStandardServiceTestAction(second, "current", false), nil); err != nil {
		t.Fatal("stale cleanup affected current engine", err)
	}
	if err := s.handle(ctx, secondPeer, linuxStandardServiceTestAction(second, "stop", true), nil); err != nil {
		t.Fatal(err)
	}
	assertLegacyOffJoined(t, current)
	if _, err := os.Stat(filepath.Join(f.root, "run", "kill-switch.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new On-connect source did not retire its own state", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tables) != 0 || !strings.Contains(strings.Join(m.events, "\n"), "supersede:"+old.session+":"+current.session) {
		t.Fatal("service did not use original creator succession", m.events)
	}
}

func TestLinuxStandardServiceStopRejectsDelayedStart(t *testing.T) {
	s, f, m := linuxStandardServiceRuntimeFixture(t, "on-connect")
	peer, _, _ := linuxStandardPeerFixture(t)
	request, directory := linuxStandardServiceRequestFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.handle(ctx, peer, request, []*os.File{directory}); err == nil {
		t.Fatal("late Start ran after acknowledged original Stop")
	}
	if _, err := os.Stat(filepath.Join(f.root, "engine-started")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled service request started an engine")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) != 0 {
		t.Fatal("cancelled service request mutated native protection", m.events)
	}
}

func TestLinuxStandardServiceDeadControllerKeepsOnConnectUntilSuccessorCreated(t *testing.T) {
	s, f, m := linuxStandardServiceRuntimeFixture(t, "on-connect")
	firstPeer, _, firstExit := linuxStandardPeerFixture(t)
	first, directory := linuxStandardServiceRequestFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.handle(ctx, firstPeer, first, []*os.File{directory}); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	original := s.session.owner
	firstExit()
	secondPeer, _, _ := linuxStandardPeerFixture(t)
	second, nextDirectory := linuxStandardServiceRequestFixture(t, f)
	if err := s.handle(ctx, secondPeer, second, []*os.File{nextDirectory}); err != nil {
		t.Fatal("authenticated successor did not join the dead controller's original engine", err)
	}
	current := s.session.owner
	assertLegacyOffJoined(t, original)
	if current == original || !original.protection.removed || !original.protection.closed || current.protection.removed {
		t.Fatal("successor did not retain the actual predecessor creator until replacement")
	}
	m.mu.Lock()
	events := strings.Join(m.events, "\n")
	count := len(m.tables)
	m.mu.Unlock()
	created := strings.Index(events, "create:"+current.session)
	superseded := strings.Index(events, "supersede:"+original.session+":"+current.session)
	if count != 1 || created < 0 || superseded <= created || strings.Contains(events, "delete:"+original.session) {
		t.Fatal("dead controller cleanup opened protection before the successor creator", events)
	}
	if err := current.currentProtection(ctx); err != nil {
		t.Fatal("replacement guard lost its original native or saved identity", err)
	}
	if err := s.handle(ctx, secondPeer, linuxStandardServiceTestAction(second, "stop", true), nil); err != nil {
		t.Fatal("explicit successor Stop failed", err)
	}
	assertLegacyOffJoined(t, current)
	if !current.protection.removed || !current.protection.stateRemoved {
		t.Fatal("explicit successor Stop retained original On-connect protection")
	}
}

func TestLinuxStandardServiceJoinedHoldReleasesOnlyOriginalOnConnect(t *testing.T) {
	s, f, m := linuxStandardServiceRuntimeFixture(t, "on-connect")
	peer, _, _ := linuxStandardPeerFixture(t)
	request, directory := linuxStandardServiceRequestFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.handle(ctx, peer, request, []*os.File{directory}); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", false), nil); err != nil {
		t.Fatal(err)
	}
	original := s.session.owner
	assertLegacyOffJoined(t, original)
	if original.protection.removed || !original.protection.detached {
		t.Fatal("hold Stop did not preserve exact original policy")
	}
	if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
		t.Fatal(err)
	}
	if !original.protection.removed || !original.protection.stateRemoved {
		t.Fatal("joined=true falsely completed later original release")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tables) != 0 {
		t.Fatal("original On-connect table remained after complete release")
	}
}

func TestLinuxStandardServiceObservesActualEngineExitAfterRequest(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			s, f, m := linuxStandardServiceRuntimeFixture(t, policy)
			peer, _, _ := linuxStandardPeerFixture(t)
			request, directory := linuxStandardServiceRequestFixture(t, f)
			operation, finish := context.WithTimeout(context.Background(), 10*time.Second)
			if err := s.handle(operation, peer, request, []*os.File{directory}); err != nil {
				t.Fatal(err)
			}
			finish()
			waitLegacyOffEngine(t, f)
			original := s.session.owner
			if err := original.command.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			joined := make(chan struct{})
			go func() { defer close(joined); s.watch(ctx) }()
			defer func() { cancel(); <-joined }()
			for {
				<-s.gate
				done := s.session.joined
				cleanupError := s.session.cleanupError
				s.gate <- struct{}{}
				if done {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("service did not join original retired engine", cleanupError)
				case <-time.After(5 * time.Millisecond):
				}
			}
			assertLegacyOffJoined(t, original)
			if err := peer.Current(ctx); err != nil {
				t.Fatal("controller death substituted for engine retirement", err)
			}
			if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "observe", false), nil); err == nil {
				t.Fatal("joined original engine stayed observable")
			}
			m.mu.Lock()
			count := len(m.tables)
			m.mu.Unlock()
			if count != 1 || original.protection.removed || !original.protection.detached {
				t.Fatal("unexpected engine exit discarded the original guard", policy)
			}
			if err := original.currentProtection(ctx); err != nil {
				t.Fatal("engine failure lost the original saved/native protection identity", err)
			}
			if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
				t.Fatal("authenticated explicit Stop could not finish original retirement", err)
			}
			m.mu.Lock()
			count = len(m.tables)
			m.mu.Unlock()
			if policy == "always" {
				if count != 1 || original.protection.removed || !original.protection.detached {
					t.Fatal("explicit Disconnect discarded original Always")
				}
			} else if count != 0 || !original.protection.removed || !original.protection.stateRemoved {
				t.Fatal("explicit Disconnect did not release its held original On-connect")
			}
		})
	}
}
