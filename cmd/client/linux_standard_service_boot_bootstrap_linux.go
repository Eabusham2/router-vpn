//go:build linux

package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

type linuxStandardBootBootstrapRequest struct {
	ID              string `json:"id"`
	DeadlineNS      int64  `json:"deadline_ns"`
	ProfileID       string `json:"profile_id"`
	ProfileRevision string `json:"profile_revision"`
	Mode            string `json:"mode"`
	Hostname        string `json:"hostname"`
	NetworkID       string `json:"network_id"`
}
type linuxStandardBootBootstrapResponse struct {
	ID        string   `json:"id"`
	NoBoot    bool     `json:"no_boot,omitempty"`
	Clean     bool     `json:"clean"`
	Addresses []string `json:"addresses,omitempty"`
}
type linuxStandardBootBootstrapBinding struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}
type linuxStandardBootBootstrapHistory struct {
	Request linuxStandardBootBootstrapRequest
	Session string
	Peer    linuxprocess.Observation
}
type linuxStandardServiceBootBootstrap struct {
	request            linuxStandardBootBootstrapRequest
	session            string
	peer               *linuxStandardServicePeer
	slot               *legacyExitProtectionSlot
	resolver           *linuxBootResolver
	complete           bool
	addresses          []string
	retirementDeadline time.Time
}

func (s *linuxStandardService) bootstrapPending() bool { return s.bootstrap != nil }
func (s *linuxStandardService) bootBootstrapProfile(ctx context.Context, q linuxStandardBootBootstrapRequest) (common.RouterProfile, error) {
	var zero common.RouterProfile
	if e := s.loadProfilesContext(ctx); e != nil {
		return zero, e
	}
	if e := desktopnetwork.LockContext(ctx, &s.app.mu); e != nil {
		return zero, e
	}
	p, ok := s.app.profileByIDLocked(q.ProfileID)
	s.app.mu.Unlock()
	if !ok || desktopOwnedNodeProfileToken(p) != q.ProfileRevision || p.Endpoint != q.Hostname || !mobilemultihop.DesktopLinuxNodePhysicalGraphSupported(q.Mode, p.StartLayer) || desktopOwnedNodeProtectionPolicy(p) == "off" {
		return zero, errors.New("bootstrap changed its captured protected Node profile")
	}
	network, e := physicalNetworkIdentityContext(ctx)
	if e != nil || network != q.NetworkID {
		return zero, errors.Join(e, errors.New("bootstrap changed its original physical network"))
	}
	return p, ctx.Err()
}
func (s *linuxStandardService) bootstrapCurrentLocked(ctx context.Context, t *linuxStandardServiceBootBootstrap, lease *legacyExitMutationLease) error {
	if t == nil || s.bootstrap != t || s.boot != t.slot || t.slot == nil || t.slot.closed || t.slot.removed || s.bootFailure != nil {
		return errors.New("bootstrap lost its original retained boot creator")
	}
	if e := t.peer.Current(ctx); e != nil {
		return e
	}
	if _, e := s.bootBootstrapProfile(ctx, t.request); e != nil {
		return e
	}
	if t.resolver != nil {
		if e := t.resolver.current(ctx); e != nil {
			return e
		}
	}
	return t.slot.current(ctx, lease)
}
func (s *linuxStandardService) cleanupBootBootstrapLocked(ctx context.Context, t *linuxStandardServiceBootBootstrap) error {
	if t == nil || s.bootstrap != t || t.slot == nil || s.boot != t.slot {
		return errors.New("bootstrap cleanup lost its retained owner")
	}
	native, ok := t.slot.kernel.(*legacyExitNativeProtection)
	if !ok || native == nil {
		return errors.New("bootstrap cleanup has no native creator")
	}
	lease, e := acquireLegacyExitMutationLease(ctx, s.root)
	if e != nil {
		return e
	}
	defer lease.Close()
	// Cleanup must remain possible after source/profile/resolver changes, but
	// only under the original private mutation lease and actual creator.
	if e = lease.Current(); e != nil {
		return e
	}
	if e = native.CleanupBootstrap(ctx, lease.lock); e != nil {
		return e
	}
	if e = t.slot.current(ctx, lease); e != nil {
		return e
	}
	if e = t.peer.CloseContext(ctx); e != nil {
		return e
	}
	if t.resolver != nil {
		if e = t.resolver.closeContext(ctx); e != nil {
			return e
		}
	}
	s.recordBootBootstrapRetirement(t.request, t.session, t.peer)
	s.bootstrap = nil
	return ctx.Err()
}
func (s *linuxStandardService) bootBootstrapRequest(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest) (out *linuxStandardBootBootstrapResponse, failure error) {
	q := request.Bootstrap
	if ctx == nil || ctx.Err() != nil || q == nil || request.Schema != 1 || !validControllerOwnerToken(request.Session) || !validControllerOwnerToken(q.ID) || !validProfileID(q.ProfileID) || len(q.ProfileRevision) != 64 || q.NetworkID == "" || q.DeadlineNS <= 0 {
		return nil, errors.New("bootstrap lacks its exact original operation")
	}
	if request.Action != "boot-bootstrap" && request.Action != "boot-bootstrap-cleanup" {
		return nil, errors.New("bootstrap action unavailable")
	}
	plain := request
	plain.Bootstrap = nil
	expected := linuxStandardServiceRequest{Schema: 1, Action: request.Action, Session: request.Session, BudgetMS: request.BudgetMS, DeadlineNS: request.DeadlineNS}
	if !reflect.DeepEqual(plain, expected) || request.BudgetMS < 1 || request.BudgetMS > 120000 {
		return nil, errors.New("bootstrap request supplied another operation scope")
	}
	if _, e := dnsmeasure.TransportBootstrapQuery(strings.TrimSuffix(q.Hostname, "."), false); e != nil {
		return nil, e
	}
	if e := peer.Current(ctx); e != nil {
		return nil, e
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.quiescing || s.imageUpgrade != nil && s.imageUpgrade.phase != "aborted" && s.imageUpgrade.phase != "settled" {
		return nil, errors.New("original image handoff freezes bootstrap requests")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ns, e := os.Stat("/proc/thread-self/ns/net")
	if e != nil || !os.SameFile(ns, s.namespace) {
		return nil, errors.Join(e, errors.New("bootstrap left its original namespace"))
	}
	if e = peer.Current(ctx); e != nil {
		return nil, e
	}
	if _, retired := s.retired[q.ID]; retired {
		old, ok := s.bootstrapHistory[q.ID]
		if !ok || old.Request != *q || old.Session != request.Session || old.Peer != peer.record {
			return nil, errors.New("retired bootstrap changed its original peer or operation")
		}
		if request.Action == "boot-bootstrap-cleanup" {
			return &linuxStandardBootBootstrapResponse{ID: q.ID, Clean: true}, nil
		}
		return nil, errors.New("bootstrap operation was retired")
	}

	t := s.bootstrap
	if t != nil && (t.request != *q || t.session != request.Session || t.peer.record != peer.record) {
		return nil, errors.New("bootstrap retains a different original peer or question")
	}
	if request.Action == "boot-bootstrap-cleanup" {
		if t == nil {
			if s.retired == nil {
				s.retired = map[string]struct{}{}
			}
			if len(s.retired) >= 4096 {
				return nil, errors.New("bootstrap cancellation history is full")
			}
			s.recordBootBootstrapRetirement(*q, request.Session, peer)
			return &linuxStandardBootBootstrapResponse{ID: q.ID, Clean: true}, nil
		}
		if e = s.cleanupBootBootstrapLocked(ctx, t); e != nil {
			return nil, e
		}
		return &linuxStandardBootBootstrapResponse{ID: q.ID, Clean: true}, nil
	}
	deadline, ok := ctx.Deadline()
	if !ok || q.DeadlineNS > deadline.UnixNano() || time.Now().UnixNano() >= q.DeadlineNS {
		return nil, context.DeadlineExceeded
	}
	if s.reversePending() || s.transfer != nil && !s.transfer.terminal() {
		return nil, errors.New("bootstrap cannot overlap an original protection transfer")
	}
	if s.bootFailure != nil {
		return nil, errors.Join(s.bootFailure, errors.New("bootstrap has no proved boot guard"))
	}
	if s.boot == nil || s.boot.closed {
		return &linuxStandardBootBootstrapResponse{ID: q.ID, NoBoot: true, Clean: true}, nil
	}
	if s.session != nil && (!s.session.joined || s.session.cleanupPending) {
		return nil, errors.New("boot bootstrap cannot borrow an engine's authority")
	}
	work, cancel := context.WithDeadline(ctx, time.Unix(0, q.DeadlineNS))
	defer cancel()
	profile, e := s.bootBootstrapProfile(work, *q)
	if e != nil {
		return nil, e
	}
	if t == nil {
		if len(s.retired) >= 4096 {
			return nil, errors.New("bootstrap operation history is full")
		}
		files, e := readDesktopNodeAssets(s.root, profile.ID, q.Mode)
		if e != nil {
			return nil, e
		}
		defer func() {
			for _, b := range files {
				clear(b)
			}
		}()
		start, e := readDesktopNodeStartAssets(s.root, profile, q.Mode)
		if e != nil {
			return nil, e
		}
		defer func() {
			for _, b := range start {
				clear(b)
			}
		}()
		// Compile validation uses a never-executed reserved literal, so malformed
		// private sources cannot trigger even the narrowly owned resolver query.
		if _, _, e = compileDesktopNode(work, profile, q.Mode, files, start, func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.254")}, nil
		}); e != nil {
			return nil, e
		}
		t = &linuxStandardServiceBootBootstrap{request: *q, session: request.Session, peer: peer, slot: s.boot}
		s.bootstrap = t
	}
	lease, e := acquireLegacyExitMutationLease(work, s.root)
	if e != nil {
		return nil, e
	}
	defer lease.Close()
	if e = s.bootstrapCurrentLocked(work, t, lease); e != nil {
		return nil, e
	}
	if t.complete {
		return &linuxStandardBootBootstrapResponse{ID: q.ID, Clean: true, Addresses: append([]string(nil), t.addresses...)}, work.Err()
	}
	if t.resolver == nil {
		t.resolver, e = captureLinuxBootResolver(work, q.Hostname)
		if e != nil {
			return nil, e
		}
	}
	native, ok := t.slot.kernel.(*legacyExitNativeProtection)
	if !ok || native == nil {
		return nil, errors.New("bootstrap lacks actual native creator")
	}
	resolved, e := t.resolver.policy.ResolveIPv6(work, &linuxBootBootstrapExchange{operation: work, service: s, original: t, lease: lease, native: native}, profile.IPv6Mode != "off")
	if e != nil {
		return nil, e
	}
	addresses := make([]string, 0, len(resolved.Addresses))
	for _, address := range resolved.Addresses {
		addresses = append(addresses, address.String())
	}
	if len(addresses) == 0 || len(addresses) > 32 {
		return nil, errors.New("captured bootstrap produced no bounded usable addresses")
	}
	if e = s.bootstrapCurrentLocked(work, t, lease); e != nil {
		return nil, e
	}
	if e = work.Err(); e != nil {
		return nil, e
	}
	t.complete = true
	t.addresses = addresses
	return &linuxStandardBootBootstrapResponse{ID: q.ID, Clean: true, Addresses: append([]string(nil), addresses...)}, nil
}

// A completed lookup still belongs to its exact peer and destination profile.
// Only the succeeding original boot transfer may consume it.
func (s *linuxStandardService) validateBootBootstrapTransfer(ctx context.Context, peer *linuxStandardServicePeer, q *linuxStandardServiceTransferRequest, retiring bool) error {
	binding := q.Bootstrap
	if binding == nil {
		if s.bootstrapPending() {
			return errors.New("original bootstrap must settle before transfer")
		}
		return nil
	}
	t := s.bootstrap
	if !q.Boot || t == nil || !t.complete || t.peer.record != peer.record || t.request.ID != binding.ID || t.request.ProfileID != q.ProfileID || t.request.ProfileRevision != q.ProfileRevision || !retiring && time.Now().UnixNano() >= t.request.DeadlineNS {
		return errors.New("transfer lost its original completed bootstrap")
	}
	found := false
	for _, address := range t.addresses {
		found = found || address == binding.Address
	}
	if !found {
		return errors.New("transfer selected an address outside its original answer")
	}
	lease, e := acquireLegacyExitMutationLease(ctx, s.root)
	if e != nil {
		return e
	}
	defer lease.Close()
	if retiring {
		native, ok := t.slot.kernel.(*legacyExitNativeProtection)
		if !ok || native == nil {
			return errors.New("bootstrap cleanup lost native creator")
		}
		if e = native.CleanupBootstrap(ctx, lease.lock); e != nil {
			return e
		}
		return t.slot.current(ctx, lease)
	}
	return s.bootstrapCurrentLocked(ctx, t, lease)
}

// Kept here to ensure the native capability remains a compile-time shipping
// dependency, rather than a method supplied by an unbounded fixture fallback.
var _ interface {
	BootstrapDNSExchange(context.Context, *os.File, netip.Addr, []byte) ([]byte, error)
	CleanupBootstrap(context.Context, *os.File) error
} = (*mobiletor.DesktopLinuxStandardProtection)(nil)

func (s *linuxStandardService) recordBootBootstrapRetirement(q linuxStandardBootBootstrapRequest, session string, peer *linuxStandardServicePeer) {
	if s.retired == nil {
		s.retired = map[string]struct{}{}
	}
	if s.bootstrapHistory == nil {
		s.bootstrapHistory = map[string]linuxStandardBootBootstrapHistory{}
	}
	s.retired[q.ID] = struct{}{}
	s.bootstrapHistory[q.ID] = linuxStandardBootBootstrapHistory{Request: q, Session: session, Peer: peer.record}
}

// The service's original native creator may retire an interrupted controller's
// exact grant, never repeat its DNS work. Only actual original pidfd retirement
// activates this once-only cleanup clock; observations and retries cannot renew it.
func (t *linuxStandardServiceBootBootstrap) retirementContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	if parent == nil {
		return nil, nil, errors.New("bootstrap retirement omitted original caller")
	}
	if e := parent.Err(); e != nil {
		return nil, nil, e
	}
	if t.retirementDeadline.IsZero() {
		dead, e := t.peer.Retired()
		if e != nil {
			return nil, nil, e
		}
		if !dead {
			return nil, nil, nil
		}
		if e := parent.Err(); e != nil {
			return nil, nil, e
		}
		t.retirementDeadline = time.Now().Add(30 * time.Second)
	}
	ctx, cancel := context.WithDeadline(parent, t.retirementDeadline)
	if e := ctx.Err(); e != nil {
		cancel()
		return nil, nil, e
	}
	return ctx, cancel, nil
}

// Caller holds s.gate, so the original conversation cannot be replaced while
// its rule, socket, resolver capture and peer descriptors are being joined.
func (s *linuxStandardService) retireBootBootstrap(parent context.Context) {
	t := s.bootstrap
	if t == nil {
		return
	}
	ctx, cancel, e := t.retirementContext(parent)
	if e != nil || ctx == nil {
		return
	}
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = s.cleanupBootBootstrapLocked(ctx, t)
}
