//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
	"strings"
	"testing"
	"time"
)

// These admission checks use a real original child/Unix peer/pidfd. No native
// firewall is modeled as successfully created; actual boot-to-Node admission is
// separately required in the installed namespace scenarios below.
func TestLinuxStandardServiceBootTransferAdmissionKeepsOriginalPeer(t *testing.T) {
	for _, name := range []string{"no-boot", "failed-boot", "live-engine", "pending-transfer", "history-full", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			peer, channel, _ := linuxStandardPeerFixture(t)
			defer channel.Close()
			defer peer.Close()
			image, _ := os.Stat("/proc/self/exe")
			namespace, _ := os.Stat("/proc/thread-self/ns/net")
			service := newLinuxStandardService(t.TempDir(), image, namespace)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			intent := bootTransferTestIntent()
			intent.DeadlineNS = time.Now().Add(time.Second).UnixNano()
			q := linuxStandardServiceTransferRequest{Boot: true, ID: intent.ID, DeadlineNS: intent.DeadlineNS, Destination: intent.Destination, ProfileID: intent.ProfileID, ProfileRevision: intent.ProfileRevision}
			request := linuxStandardServiceRequest{Schema: 1, Action: "transfer-reserve", Session: strings.Repeat("9", 32), BudgetMS: 1500, DeadlineNS: time.Now().Add(1500 * time.Millisecond).UnixNano(), Transfer: &q}
			switch name {
			case "failed-boot":
				service.bootFailure = errors.New("original startup remains incomplete")
			case "live-engine":
				service.session = &linuxStandardServiceSession{}
			case "pending-transfer":
				service.transfer = &linuxStandardServiceTransfer{}
			case "history-full":
				service.boot = &legacyExitProtectionSlot{detached: true}
				service.transferHistory = make(map[string]linuxStandardServiceTransferResponse)
				for i := 0; i < 128; i++ {
					service.transferHistory[fmt.Sprint(i)] = linuxStandardServiceTransferResponse{}
				}
			case "cancelled":
				cancel()
			}
			original := service.transfer
			out, err := service.transferRequest(ctx, peer, request)
			if name == "no-boot" {
				if err != nil || out == nil || !out.NoBoot || !out.Boot || out.Phase != "no-boot" || out.Committed {
					t.Fatal("missing boot creator became fabricated source", out, err)
				}
			} else if err == nil || out != nil && out.Committed {
				t.Fatal("unadmitted boot request became authority", out, err)
			}
			if service.transfer != original {
				t.Fatal("rejected boot request replaced original reservation")
			}
		})
	}
}
func TestLinuxStandardServiceBootTransferRetiredIntentRejectsReplay(t *testing.T) {
	for _, name := range []string{"original-result", "renewed-deadline", "other-session", "other-selection", "other-kind", "late-reserve"} {
		t.Run(name, func(t *testing.T) {
			peer, channel, _ := linuxStandardPeerFixture(t)
			defer channel.Close()
			defer peer.Close()
			image, _ := os.Stat("/proc/self/exe")
			namespace, _ := os.Stat("/proc/thread-self/ns/net")
			service := newLinuxStandardService(t.TempDir(), image, namespace)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			intent := bootTransferTestIntent()
			intent.DeadlineNS = time.Now().Add(-time.Second).UnixNano()
			q := linuxStandardServiceTransferRequest{Boot: true, ID: intent.ID, DeadlineNS: intent.DeadlineNS, Destination: intent.Destination, ProfileID: intent.ProfileID, ProfileRevision: intent.ProfileRevision}
			request := linuxStandardServiceRequest{Schema: 1, Action: "transfer-resolve", Session: strings.Repeat("9", 32), BudgetMS: 1500, DeadlineNS: time.Now().Add(1500 * time.Millisecond).UnixNano(), Transfer: &q}
			// Only terminal record comparison is modeled here. It is not native
			// Finish evidence; the actual namespace scenario must create that result.
			service.transferHistory = map[string]linuxStandardServiceTransferResponse{q.ID: {Boot: true, Intent: intent, Phase: "aborted", history: &linuxStandardServiceTransferHistory{Peer: peer.record, Session: request.Session, Request: q}}}
			switch name {
			case "renewed-deadline":
				q.DeadlineNS = time.Now().Add(time.Minute).UnixNano()
			case "other-session":
				request.Session = strings.Repeat("8", 32)
			case "other-selection":
				q.Destination.HomeLAN = !q.Destination.HomeLAN
			case "other-kind":
				q.Boot = false
			case "late-reserve":
				request.Action = "transfer-reserve"
			}
			out, err := service.transferRequest(ctx, peer, request)
			if name == "original-result" {
				if err != nil || out == nil || out.Phase != "aborted" {
					t.Fatal("original bounded cleanup result lost", out, err)
				}
			} else if err == nil {
				t.Fatal("retired boot identity re-admitted work", out)
			}
			if service.transfer != nil {
				t.Fatal("terminal replay allocated another native reservation")
			}
		})
	}
}

var linuxHostTUNBootTransferCases = []string{"service-boot-transfer", "service-boot-transfer-cancel", "service-boot-transfer-lost-reply", "service-boot-hostname"}

func init() { linuxHostTUNCases = append(linuxHostTUNCases, linuxHostTUNBootTransferCases...) }
func linuxHostTUNBootTransferCase(scenario string) bool {
	for _, name := range linuxHostTUNBootTransferCases {
		if scenario == name {
			return true
		}
	}
	return false
}

// Prior-boot metadata selects the ordinary reassert path only. The installed
// service must create the real guard before notifying READY; no old native
// handle is adopted. The hostname case separately installs its captured
// machine resolver outside the original guard endpoint exceptions.
func linuxHostTUNBootTransferService(t *testing.T, installed string, peer *linuxHostTUNPeer) {
	t.Helper()
	path := filepath.Join(linuxOwnedControllerRoot, "routers.json")
	raw, err := readPrivateRegular(path, 64<<10)
	var store common.RouterProfileStore
	if err != nil || json.Unmarshal(raw, &store) != nil || len(store.Profiles) != 1 {
		t.Fatal("boot fixture lost original private profile", err)
	}
	profile := &store.Profiles[0]
	profile.KillSwitch = true
	profile.KillSwitchPolicy = "always"
	body, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	linuxStandardServicePreviousBootState(t, linuxOwnedControllerRoot, profile.ID, peer.address.Addr().String())
	linuxHostTUNTransferService(t, installed, peer)
	raw, err = readPrivateRegular(filepath.Join(linuxOwnedControllerRoot, "run", "kill-switch.json"), 64<<10)
	var state legacyExitProtectionState
	boot, bootErr := readDesktopLinuxNodeBootID()
	if err != nil || bootErr != nil || json.Unmarshal(raw, &state) != nil || state.Owner.BootID != boot || state.Owner.Receipt.Session == strings.Repeat("1", 32) || state.Policy != "always" {
		t.Fatal("installed boot did not create its original new guard", err, bootErr)
	}
}

func linuxHostTUNBootTransferPreflight(ctx context.Context, a *app, scenario string) (failure error) {
	if !linuxHostTUNBootTransferCase(scenario) || (scenario == "service-boot-transfer" || scenario == "service-boot-hostname") {
		return nil
	}
	operation, finish, err := a.beginConnectionTransaction()
	if err != nil {
		return err
	}
	defer finish()
	call, cancel := context.WithTimeout(operation, 15*time.Second)
	defer cancel()
	a.mu.Lock()
	profile := cloneRouterProfile(a.profiles.Profiles[0])
	a.mu.Unlock()
	host, err := prepareDesktopLinuxNodeHost(operation, a, profile, linuxHostTUNMode(scenario), 0)
	if err != nil {
		return err
	}
	defer func() {
		if host.standardTransfer != nil && !host.standardTransfer.resolved.Load() {
			failure = errors.Join(failure, host.standardTransfer.resolve(ctx))
		}
		failure = errors.Join(failure, host.Close(ctx))
	}()
	original, err := captureLinuxStandardServiceNodeTransfer(call, host)
	if err != nil || original == nil || original.boot == nil || original.owner != nil || original.intent.Load() == nil {
		return errors.Join(err, errors.New("boot preflight omitted its actual source capability"))
	}
	expected := *original.intent.Load()
	if scenario == "service-boot-transfer-cancel" {
		cancel()
		if err = original.current(call, true); !errors.Is(err, context.Canceled) {
			return errors.New("cancelled boot operation admitted a destination")
		}
	}
	fired := false
	if scenario == "service-boot-transfer-lost-reply" {
		if original.boot.protection != nil {
			return errors.New("lost-reply fixture unexpectedly borrowed another service view")
		}
		b := original.boot
		b.exchange = func(ctx context.Context, q linuxStandardServiceRequest, _ *os.File, before func()) (linuxStandardServiceResponse, error) {
			response, err := linuxStandardServiceRPC(ctx, b.image, b.namespace, &b.peer, q, nil, before)
			if q.Action == "transfer-resolve" && !fired && err == nil {
				fired = true
				return linuxStandardServiceResponse{}, io.ErrUnexpectedEOF
			}
			return response, err
		}
		if err = original.resolve(ctx); !errors.Is(err, io.ErrUnexpectedEOF) || !fired || original.resolved.Load() {
			return errors.New("lost boot cleanup reply discarded original pending capture")
		}
	}
	if err = original.resolve(ctx); err != nil {
		return err
	}
	if !original.resolved.Load() || original.committed.Load() || *original.intent.Load() != expected {
		return errors.New("boot abort changed original source or claimed commit")
	}
	view := a.captureLinuxStandardServiceProtection(ctx)
	if view == nil || view.Failure != nil || !view.Owned || !view.Active || view.Policy != "always" {
		return errors.New("boot abort lost its actual retained protection")
	}
	raw, err := readPrivateRegular(filepath.Join(linuxOwnedControllerRoot, "run", "kill-switch.json"), 64<<10)
	var saved legacyExitProtectionState
	if err != nil || json.Unmarshal(raw, &saved) != nil {
		return errors.Join(err, errors.New("boot abort lost original durable guard"))
	}
	receipt, _ := json.Marshal(saved.Owner.Receipt)
	digest := sha256.Sum256(receipt)
	if hex.EncodeToString(digest[:]) != expected.SourceReceiptSHA256 {
		return errors.New("boot abort substituted another native source receipt")
	}
	return nil
}

func linuxHostTUNTransferredBoot(host *desktopLinuxNodeHost) error {
	if host == nil || host.standardTransfer == nil {
		return errors.New("public Node Connect omitted boot transfer")
	}
	transfer := host.standardTransfer
	if bootstrap := host.bootBootstrap; bootstrap != nil {
		binding := transfer.request.Bootstrap
		if !bootstrap.consumed.Load() || binding == nil || binding.ID != bootstrap.request.ID || binding.Address != host.launch.endpoint {
			return errors.New("public hostname Connect lost original lookup-to-transfer binding")
		}
		if _, exists := linuxStandardBootBootstraps.Load(bootstrap.app); exists {
			return errors.New("completed hostname transfer retained lookup admission")
		}
	}

	if transfer.boot == nil || transfer.owner != nil || !transfer.request.Boot || !transfer.resolved.Load() || !transfer.committed.Load() || transfer.intent.Load() == nil || host.transaction == nil || host.transaction.head.Record.Transfer == nil || *host.transaction.head.Record.Transfer != *transfer.intent.Load() {
		return errors.New("public boot succession omitted original durable/native settlement")
	}
	if _, exists := linuxStandardBootTransfers.Load(transfer.boot.app); exists {
		return errors.New("settled boot transfer retained controller admission")
	}
	if _, exists := linuxStandardServiceOwners.Load(transfer.boot.app); exists {
		return errors.New("boot succession fabricated a source engine launch")
	}
	if _, err := os.Stat(filepath.Join(linuxOwnedControllerRoot, "run", "kill-switch.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("boot succession did not retire original saved guard")
	}
	return nil
}

// Only the positive native Finish result is modeled. The original Unix peer,
// private state descriptor, registry removal and Close/retry are actual. The
// installed namespace scenarios remain the gate for native guard transfer.
type bootTransferReleaseCancelModel struct {
	legacyExitKernelProtection
	cancel context.CancelFunc
	closes int
}

func (m *bootTransferReleaseCancelModel) Close(ctx context.Context) error {
	m.closes++
	if err := m.legacyExitKernelProtection.Close(ctx); err != nil {
		return err
	}
	m.cancel()
	return nil
}
func TestLinuxStandardServiceBootTransferRetriesReleasedOriginal(t *testing.T) {
	for _, kind := range []string{"boot", "active"} {
		t.Run(kind, func(t *testing.T) {
			s, f, peer, original, ctx := standardNetworkSession(t, "always")
			if err := s.handle(ctx, peer, linuxStandardServiceTestAction(original, "stop", false), nil); err != nil {
				t.Fatal(err)
			}
			slot := s.session.owner.protection
			lease, err := acquireLegacyExitMutationLease(ctx, s.root)
			if err != nil {
				t.Fatal(err)
			}
			if err = slot.kernel.Release(ctx, lease.lock); err != nil {
				lease.Close()
				t.Fatal(err)
			}
			slot.removed = true
			call, cancel := context.WithCancel(ctx)
			defer cancel()
			model := &bootTransferReleaseCancelModel{legacyExitKernelProtection: slot.kernel, cancel: cancel}
			slot.kernel = model
			q := linuxStandardServiceTransferRequest{Boot: kind == "boot", ID: strings.Repeat("7", 32), DeadlineNS: time.Now().Add(time.Second).UnixNano(), Destination: bootTransferTestIntent().Destination, ProfileID: f.a.profiles.Profiles[0].ID, ProfileRevision: desktopOwnedNodeProfileToken(f.a.profiles.Profiles[0])}
			intent := bootTransferTestIntent()
			intent.ID = q.ID
			intent.DeadlineNS = q.DeadlineNS
			intent.SourceSession = original.Session
			intent.ProfileID = q.ProfileID
			intent.ProfileRevision = q.ProfileRevision
			tr := &linuxStandardServiceTransfer{peer: peer, session: s.session, slot: slot, request: q, requestSession: original.Session, native: &mobiletor.DesktopLinuxStandardNodeTransfer{}, nativeFinished: true, result: linuxStandardServiceTransferResponse{Boot: q.Boot, Intent: intent, Committed: true, Phase: "committed"}}
			if q.Boot {
				s.boot = slot
				s.session = nil
				tr.session = nil
				tr.result.history = &linuxStandardServiceTransferHistory{Peer: peer.record, Session: original.Session, Request: q}
			}
			s.transfer = tr
			s.transferHistory = make(map[string]linuxStandardServiceTransferResponse)
			if err = tr.persist(ctx, lease, "committed"); err != nil {
				lease.Close()
				t.Fatal(err)
			}
			lease.Close()
			request := linuxStandardServiceRequest{Schema: 1, Action: "transfer-resolve", Session: original.Session, BudgetMS: 5000, DeadlineNS: time.Now().Add(5 * time.Second).UnixNano(), Transfer: &q}
			response, err := s.transferRequest(call, peer, request)
			if !errors.Is(err, context.Canceled) || response == nil || !slot.closed || !slot.stateRemoved || tr.result.Phase != "settled" || model.closes != 1 {
				t.Fatal("post-release cancellation did not retain exact closed milestone", response, err, slot.closed, model.closes)
			}
			if q.Boot && !s.transferPending() {
				t.Fatal("boot peer closure disappeared before settlement")
			}
			if _, exists := legacyStandardProtectionOwners.Load(slot.app); exists {
				t.Fatal("original release did not remove its registry entry")
			}
			changed := request
			changed.Session = strings.Repeat("8", 32)
			if _, err = s.transferRequest(ctx, peer, changed); err == nil {
				t.Fatal("closed milestone accepted another original request")
			}
			changedQ := q
			changedQ.DeadlineNS += int64(time.Minute)
			changed.Transfer = &changedQ
			changed.Session = request.Session
			if _, err = s.transferRequest(ctx, peer, changed); err == nil {
				t.Fatal("closed milestone renewed original admission")
			}
			// A successor registry entry is not authority for this cleanup. It must
			// remain byte-for-byte selected while the old operation joins its peer.
			successor := &legacyExitProtectionSlot{app: slot.app}
			legacyStandardProtectionOwners.Store(slot.app, successor)
			defer legacyStandardProtectionOwners.CompareAndDelete(slot.app, successor)
			response, err = s.transferRequest(ctx, peer, request)
			if err != nil || response == nil || response.Phase != "settled" || !response.Committed || model.closes != 1 || s.transferPending() {
				t.Fatal("retry rejected exact released original or repeated native close", response, err, model.closes)
			}
			if actual, _ := legacyStandardProtectionOwners.Load(slot.app); actual != successor {
				t.Fatal("retired cleanup selected or removed successor")
			}
			if q.Boot && s.boot != nil {
				t.Fatal("settled boot retained closed source selection")
			}
		})
	}
}
