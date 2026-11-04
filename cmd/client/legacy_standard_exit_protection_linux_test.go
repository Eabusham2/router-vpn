//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

// Kernel policy is explicitly modeled here; process, pidfd, config sealing,
// saved-state transactions and cross-process locks use production mechanisms.
// Separate tagged native tests exercise the real nft/netlink creator.
type legacyProtectionModel struct {
	mu           sync.Mutex
	tables       map[string]*legacyProtectionModelOwner
	events       []string
	next         uint64
	afterCreate  func()
	beforeDelete func()
	blockDelete  bool
}
type legacyProtectionModelOwner struct {
	model           *legacyProtectionModel
	receipt         mobiletor.DesktopLinuxStandardProtectionReceipt
	removed, closed bool
}

func newLegacyProtectionModel() *legacyProtectionModel {
	return &legacyProtectionModel{tables: make(map[string]*legacyProtectionModelOwner), next: 100}
}
func (m *legacyProtectionModel) create(ctx context.Context, session, digest string, endpoints []netip.Addr, lan bool, lease *os.File) (legacyExitKernelProtection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lease == nil || len(endpoints) != 1 {
		return nil, errors.New("missing original policy capture")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	info, _ := os.Stat("/proc/thread-self/ns/net")
	ns := info.Sys().(*syscall.Stat_t)
	baseline := json.RawMessage(`{"10":[{"accept":null}],"11":[{"accept":null}],"12":[{"accept":null}],"13":[{"accept":null}],"14":[{"accept":null}]}`)
	hash := sha256.Sum256(baseline)
	p := &legacyProtectionModelOwner{model: m, receipt: mobiletor.DesktopLinuxStandardProtectionReceipt{CreationGeneration: uint32(m.next), NamespaceDevice: uint64(ns.Dev), NamespaceInode: ns.Ino, Baseline: baseline, Session: session, ConfigSHA256: digest, Table: "router_vpn_standard_" + session, TableHandle: m.next, ChainHandle: 1, BaselineSHA256: hex.EncodeToString(hash[:])}}
	if m.tables[session] != nil {
		return p, errors.New("exclusive create refused existing table")
	}
	m.tables[session] = p
	m.events = append(m.events, "create:"+session)
	if m.afterCreate != nil {
		m.afterCreate()
	}
	return p, ctx.Err()
}
func (p *legacyProtectionModelOwner) Receipt(ctx context.Context) (mobiletor.DesktopLinuxStandardProtectionReceipt, error) {
	if err := ctx.Err(); err != nil {
		return p.receipt, err
	}
	return p.receipt, nil
}
func (p *legacyProtectionModelOwner) Current(ctx context.Context, _ *os.File) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.model.mu.Lock()
	defer p.model.mu.Unlock()
	if p.closed || p.removed || p.model.tables[p.receipt.Session] != p {
		return errors.New("original native table was replaced")
	}
	return nil
}
func (p *legacyProtectionModelOwner) Release(ctx context.Context, lease *os.File) error {
	if p.model.blockDelete {
		<-ctx.Done()
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.model.mu.Lock()
	defer p.model.mu.Unlock()
	if p.removed {
		return nil
	}
	if p.model.tables[p.receipt.Session] != p {
		return errors.New("conditional native handle deletion refused replacement")
	}
	if p.model.beforeDelete != nil {
		p.model.beforeDelete()
	}
	delete(p.model.tables, p.receipt.Session)
	p.removed = true
	p.model.events = append(p.model.events, "delete:"+p.receipt.Session)
	return nil
}
func (p *legacyProtectionModelOwner) Supersede(ctx context.Context, next legacyExitKernelProtection, lease *os.File) error {
	q, ok := next.(*legacyProtectionModelOwner)
	if !ok || q.model != p.model || q == p {
		return errors.New("different original creators required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.model.mu.Lock()
	defer p.model.mu.Unlock()
	if p.model.tables[q.receipt.Session] != q || q.removed {
		return errors.New("successor changed before conditional predecessor deletion")
	}
	if p.removed {
		return nil
	}
	if p.model.tables[p.receipt.Session] != p {
		return errors.New("predecessor handle changed")
	}
	p.model.events = append(p.model.events, "supersede:"+p.receipt.Session+":"+q.receipt.Session)
	delete(p.model.tables, p.receipt.Session)
	p.removed = true
	return nil
}
func (p *legacyProtectionModelOwner) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.closed = true
	return nil
}
func (f *legacyExitFixture) prepareProtected(t *testing.T, m *legacyProtectionModel) (*linuxLegacyStandardExitOwner, context.Context, func()) {
	t.Helper()
	operation, finish, err := f.a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	originalFinish := finish
	var finishOnce sync.Once
	finish = func() { finishOnce.Do(originalFinish) }
	command, err := nativeStandardExitCommand(f.a, f.a.profiles.Profiles[0], common.RouterProfile{}, f.exit, true)
	if err != nil {
		finish()
		t.Fatal(err)
	}
	retained, err := prepareLegacyStandardExitOwnerWithObservers(f.a, command, "standard-"+f.exit.Protocol, "external", "standard:"+f.exit.ID, func() error { return nil }, func() string { return "captured-test-network" })
	if err != nil || retained == nil {
		finish()
		t.Fatal("captured protected preparation unavailable", err)
	}
	owner := retained.(*linuxLegacyStandardExitOwner)
	owner.protectionFactory = m.create
	owner.protectionAbsence = func(context.Context) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if len(m.tables) != 0 {
			return errors.New("unexpected native table exists")
		}
		return nil
	}
	owner.offProtectionCheck = func(ctx context.Context) error {
		l, err := acquireLegacyExitMutationLease(ctx, f.root)
		if err != nil {
			return err
		}
		defer l.Close()
		if err = legacyExitStateAbsent(l); err != nil {
			return err
		}
		return owner.protectionAbsence(ctx)
	}
	t.Cleanup(func() {
		_ = owner.Discard()
		finish()
		if raw, ok := legacyStandardProtectionOwners.LoadAndDelete(f.a); ok {
			p := raw.(*legacyExitProtectionSlot)
			_ = p.saved.Close()
			_ = p.kernel.Close(context.Background())
		}
	})
	return owner, operation, finish
}
func startProtected(t *testing.T, f *legacyExitFixture, m *legacyProtectionModel) (*linuxLegacyStandardExitOwner, func()) {
	t.Helper()
	owner, ctx, finish := f.prepareProtected(t, m)
	if err := owner.Start(ctx); err != nil {
		t.Fatal("protected original Start failed", err)
	}
	waitLegacyOffEngine(t, f)
	if err := owner.Current(ctx); err != nil {
		t.Fatal(err)
	}
	return owner, finish
}
func TestLegacyStandardProtectedPolicyLifecycle(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			f := newLegacyExitFixture(t, policy)
			m := newLegacyProtectionModel()
			owner, _ := startProtected(t, f, m)
			p := owner.protection
			if p == nil || !p.persisted || p.receipt.Session != owner.session || p.receipt.ConfigSHA256 != owner.digest {
				t.Fatal("engine started without original acknowledged persisted protection")
			}
			if err := f.a.stopMode(); err != nil {
				t.Fatal("shipping retained protected Stop failed", err)
			}
			assertLegacyOffJoined(t, owner)
			raw, err := os.ReadFile(filepath.Join(f.root, "run", "kill-switch.json"))
			if policy == "always" {
				if err != nil || !p.detached || p.removed || !strings.Contains(string(raw), `"policy":"always"`) {
					t.Fatal("Always lost original deny policy", err)
				}
			} else {
				if !errors.Is(err, os.ErrNotExist) || !p.removed || !p.closed {
					t.Fatal("On-connect original policy was not retired", err)
				}
			}
			if _, err := os.Stat(filepath.Join(f.root, "firewall-observed")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("protected adapter used generic helper mutation", err)
			}
		})
	}
}
func TestLegacyStandardProtectedAlwaysSuccessorAndExplicitOff(t *testing.T) {
	for _, nextPolicy := range []string{"on-connect", "always", "off"} {
		t.Run(nextPolicy, func(t *testing.T) {
			f := newLegacyExitFixture(t, "always")
			m := newLegacyProtectionModel()
			first, finish := startProtected(t, f, m)
			if err := f.a.stopMode(); err != nil {
				t.Fatal(err)
			}
			finish()
			f.a.profiles.Profiles[0].KillSwitchPolicy = nextPolicy
			f.exit.Server = "203.0.113.11"
			next, finishNext := startProtected(t, f, m)
			defer finishNext()
			if !first.protection.removed || !first.protection.closed {
				t.Fatal("original predecessor was not retired through its creator")
			}
			if nextPolicy == "off" {
				if len(m.events) != 2 || !strings.HasPrefix(m.events[1], "delete:") {
					t.Fatal("explicit Off did not release only original detached owner", m.events)
				}
			} else {
				if len(m.events) != 3 || !strings.HasPrefix(m.events[1], "create:") || !strings.HasPrefix(m.events[2], "supersede:") {
					t.Fatal("successor was not established before predecessor retirement", m.events)
				}
				if next.protection == first.protection || next.protection.receipt.TableHandle == first.protection.receipt.TableHandle {
					t.Fatal("successor adopted prior creation")
				}
			}
			if err := f.a.stopMode(); err != nil {
				t.Fatal(err)
			}
			assertLegacyOffJoined(t, next)
		})
	}
}
func TestLegacyStandardProtectedChangedSavedOwnerIsPreserved(t *testing.T) {
	f := newLegacyExitFixture(t, "on-connect")
	m := newLegacyProtectionModel()
	owner, _ := startProtected(t, f, m)
	path := filepath.Join(f.root, "run", "kill-switch.json")
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	replacement := []byte(`{"policy":"always","owner":"newer"}`)
	if err := os.WriteFile(path, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.a.stopMode(); err == nil {
		t.Fatal("changed saved owner authorized release")
	}
	assertLegacyOffJoined(t, owner)
	if owner.protection.removed || len(m.events) != 1 {
		t.Fatal("changed saved owner released native table", m.events)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != string(replacement) {
		t.Fatal("replacement saved owner changed", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".original", path); err != nil {
		t.Fatal(err)
	}
	if err := f.a.stopMode(); err != nil {
		t.Fatal("exact saved original could not retry", err)
	}
}
func TestLegacyStandardProtectedReplacementTableCannotBeReleased(t *testing.T) {
	f := newLegacyExitFixture(t, "on-connect")
	m := newLegacyProtectionModel()
	owner, _ := startProtected(t, f, m)
	original := owner.protection.kernel.(*legacyProtectionModelOwner)
	foreign := &legacyProtectionModelOwner{model: m, receipt: original.receipt}
	foreign.receipt.TableHandle++
	m.tables[owner.session] = foreign
	if err := f.a.stopMode(); err == nil {
		t.Fatal("recreated same-name native table became original deletion authority")
	}
	assertLegacyOffJoined(t, owner)
	if m.tables[owner.session] != foreign || foreign.removed {
		t.Fatal("foreign native replacement was deleted")
	}
	m.tables[owner.session] = original
	if err := f.a.stopMode(); err != nil {
		t.Fatal("original native capability could not retry", err)
	}
}
func TestLegacyStandardProtectedCancelledCreateJoinsBeforePolicyRetirement(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			f := newLegacyExitFixture(t, policy)
			m := newLegacyProtectionModel()
			owner, ctx, _ := f.prepareProtected(t, m)
			m.afterCreate = f.a.cancelConnectionOperation
			if err := owner.Start(ctx); err == nil {
				t.Fatal("cancelled acknowledged apply started engine")
			}
			if owner.started || owner.command.Process != nil {
				t.Fatal("engine launched after cancelled creation")
			}
			m.afterCreate = nil
			if err := f.a.stopMode(); err != nil {
				t.Fatal("original acknowledged creator could not finish cancellation cleanup", err)
			}
			if policy == "always" {
				if owner.protection.removed || !owner.protection.detached {
					t.Fatal("cancelled Always lost original protection")
				}
			} else if !owner.protection.removed {
				t.Fatal("cancelled On-connect failed original release")
			}
		})
	}
}
func TestLegacyStandardProtectedDeleteUsesStopDeadline(t *testing.T) {
	f := newLegacyExitFixture(t, "on-connect")
	m := newLegacyProtectionModel()
	owner, _ := startProtected(t, f, m)
	m.blockDelete = true
	stop, err := captureLegacyStandardExitStop(f.a)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	began := time.Now()
	if err = stop.Retire(ctx, owner.command, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("native deletion escaped original Stop budget", err)
	}
	if time.Since(began) > time.Second || owner.protection.removed {
		t.Fatal("deadline failure changed native protection")
	}
	m.blockDelete = false
	if err := f.a.stopMode(); err != nil {
		t.Fatal("bounded original deletion retry failed", err)
	}
}
func TestLegacyStandardProtectedColdStateNeverCreatesAuthority(t *testing.T) {
	f := newLegacyExitFixture(t, "always")
	m := newLegacyProtectionModel()
	owner, ctx, _ := f.prepareProtected(t, m)
	path := filepath.Join(f.root, "run", "kill-switch.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	cold := []byte(`{"policy":"always","owner":"expired-boot-helper"}`)
	if err := os.WriteFile(path, cold, 0600); err != nil {
		t.Fatal(err)
	}
	if err := owner.Start(ctx); err == nil {
		t.Fatal("cold state reconstructed native creator")
	}
	if len(m.events) != 0 || owner.command.Process != nil {
		t.Fatal("unowned cold protection triggered mutation or engine launch")
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != string(cold) {
		t.Fatal("cold owner was overwritten", err)
	}
}

func TestLegacyStandardProtectedHandlerLateCancellationRetiresCapturedPolicy(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			f := newLegacyExitFixture(t, policy)
			m := newLegacyProtectionModel()
			var owner *linuxLegacyStandardExitOwner
			adapter := platformStandardExitRuntime{
				prepareLegacy: func(a *app, cmd *exec.Cmd, mode, base, id string) (legacyStandardExitLaunch, error) {
					captured, err := prepareLegacyStandardExitOwnerWithObservers(a, cmd, mode, base, id, func() error { return nil }, func() string { return "captured-test-network" })
					if err != nil || captured == nil {
						return captured, err
					}
					owner = captured.(*linuxLegacyStandardExitOwner)
					owner.protectionFactory = m.create
					owner.protectionAbsence = func(context.Context) error {
						if len(m.tables) != 0 {
							return errors.New("unexpected native table")
						}
						return nil
					}
					return owner, nil
				},
				prove: func(*app, string) error { return nil },
				current: func(captured legacyStandardExitLaunch, ctx context.Context) error {
					if err := captured.Current(ctx); err != nil {
						return err
					}
					f.a.mu.Lock()
					f.a.connectionCancelIntent = ctx
					f.a.mu.Unlock()
					return nil
				},
			}
			body, _ := json.Marshal(standardExitConnectRequest{StandardExitID: f.exit.ID, Direct: true})
			response := httptest.NewRecorder()
			f.a.platformStandardExitConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/standard-exit/connect", bytes.NewReader(body)), adapter)
			if response.Code != http.StatusConflict || owner == nil || f.a.state.Connected || f.a.cmd != nil {
				t.Fatal("protected late cancellation adopted Connected", response.Code, response.Body.String())
			}
			assertLegacyOffJoined(t, owner)
			if policy == "always" {
				if owner.protection.removed || !owner.protection.detached {
					t.Fatal("late cancellation lost Always")
				}
				t.Cleanup(func() {
					legacyStandardProtectionOwners.Delete(f.a)
					_ = owner.protection.saved.Close()
					_ = owner.protection.kernel.Close(context.Background())
				})
			} else if !owner.protection.removed {
				t.Fatal("late cancellation did not retire original On-connect")
			}
		})
	}
}
func TestLegacyStandardProtectedNewStateAfterNativeAckIsNotUnlinked(t *testing.T) {
	f := newLegacyExitFixture(t, "on-connect")
	m := newLegacyProtectionModel()
	owner, _ := startProtected(t, f, m)
	path := filepath.Join(f.root, "run", "kill-switch.json")
	replacement := []byte(`{"policy":"always","owner":"new-after-native-ack"}`)
	m.beforeDelete = func() {
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, replacement, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.a.stopMode(); err == nil {
		t.Fatal("new persisted state was treated as original post-native cleanup")
	}
	assertLegacyOffJoined(t, owner)
	if !owner.protection.removed {
		t.Fatal("original native acknowledgement was not retained")
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != string(replacement) {
		t.Fatal("new saved owner was unlinked after native acknowledgement", err)
	}
	// Restoring the exact comparison inode permits state-only retry. The native
	// command's committed deletion is never sent again.
	m.beforeDelete = nil
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".original", path); err != nil {
		t.Fatal(err)
	}
	before := len(m.events)
	if err := f.a.stopMode(); err != nil {
		t.Fatal("original post-ack state retry failed", err)
	}
	if len(m.events) != before {
		t.Fatal("state retry replayed acknowledged native deletion")
	}
}
