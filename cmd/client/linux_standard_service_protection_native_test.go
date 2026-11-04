//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func linuxStandardProtectionViewRequest() linuxStandardServiceRequest {
	token, _ := randomHex(16)
	return linuxStandardServiceRequest{Schema: 1, Action: "protection-view", Session: token}
}
func linuxStandardProtectionChange(view *linuxStandardServiceProtectionData, action string) linuxStandardServiceRequest {
	return linuxStandardServiceRequest{Schema: 1, Action: action, Session: view.Token, ProfileID: view.ProfileID, ProfileRevision: view.ProfileRevision, ResultRevision: view.ResultRevision}
}

func TestLinuxStandardServiceProtectionViewRejectsLiveForeignControllerAfterRevision(t *testing.T) {
	s, f, m := linuxStandardServiceRuntimeFixture(t, "always")
	peer, _, _ := linuxStandardPeerFixture(t)
	request, dir := linuxStandardServiceRequestFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.handle(ctx, peer, request, []*os.File{dir}); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
		t.Fatal(err)
	}
	view, err := s.protectionRequest(ctx, peer, linuxStandardProtectionViewRequest())
	if err != nil || !view.Owned {
		t.Fatal("original retained view missing", err)
	}
	original := s.protectionView
	f.a.profiles.Profiles[0].HomeLANAccess = !f.a.profiles.Profiles[0].HomeLANAccess
	if err = f.a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	foreign, _, _ := linuxStandardPeerFixture(t)
	if _, err = s.protectionRequest(ctx, foreign, linuxStandardProtectionViewRequest()); err == nil {
		t.Fatal("source revision change transferred live original controller authority")
	}
	if s.protectionView != original || original.peer != peer {
		t.Fatal("foreign view erased original retained capability")
	}
	if err = peer.Current(ctx); err != nil {
		t.Fatal("rejected view closed original peer", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tables) != 1 || original.slot.removed {
		t.Fatal("read-only foreign request changed original protection")
	}
}

func TestLinuxStandardServicePendingOffBlocksBootReassertUntilSave(t *testing.T) {
	s, f, m := linuxStandardServiceRuntimeFixture(t, "always")
	peer, _, _ := linuxStandardPeerFixture(t)
	request, dir := linuxStandardServiceRequestFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.handle(ctx, peer, request, []*os.File{dir}); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
		t.Fatal(err)
	}
	s.boot = s.session.owner.protection
	originalFailure := errors.New("original readiness notification still pending")
	s.bootFailure = originalFailure
	view, err := s.protectionRequest(ctx, peer, linuxStandardProtectionViewRequest())
	if err != nil {
		t.Fatal(err)
	}
	released, err := s.protectionRequest(ctx, peer, linuxStandardProtectionChange(view, "protection-release"))
	if err != nil {
		t.Fatal(err)
	}
	if !released.Pending || !released.Removed || !released.AbsenceProved || s.boot != nil {
		t.Fatal("Off did not retain exact unsaved release milestone")
	}
	lifetime, stop := context.WithCancel(context.Background())
	joined := make(chan struct{})
	go func() { defer close(joined); s.watch(lifetime) }()
	time.Sleep(550 * time.Millisecond)
	stop()
	<-joined
	if s.bootFailure != originalFailure || !s.bootRetryAfter.IsZero() || s.boot != nil {
		t.Fatal("watcher retried old saved Always during accepted unsaved Off")
	}
	if _, err = s.protectionRequest(ctx, peer, linuxStandardProtectionChange(view, "protection-complete")); !errors.Is(err, errDesktopProtectionOffUnsaved) {
		t.Fatal("native release fabricated durable Off preference", err)
	}
	if !s.protectionView.data.Pending {
		t.Fatal("failed save lost original Off retry")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tables) != 0 {
		t.Fatal("boot retry recreated protection after explicit original release")
	}
}
