//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"router-vpn/internal/desktopnetwork"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/mobiletor"
)

type linuxStandardReversePin interface {
	Snapshot(context.Context) (mobiletor.DesktopLinuxClosedTransferSnapshot, error)
	Resolve(context.Context, mobiletor.DesktopLinuxClosedTransferSnapshot, bool) error
}

type linuxStandardServiceReverse struct {
	peer                *linuxStandardServicePeer
	request             linuxStandardServiceReverseRequest
	launch              linuxStandardServiceRequest
	session             *linuxStandardServiceSession
	pin                 linuxStandardReversePin
	destination         *mobiletor.DesktopLinuxClosedTransferSnapshot
	phase               string
	committed, resolved bool
}

func (s *linuxStandardService) reversePending() bool {
	return s.reverse != nil && s.reverse.phase != "committed" && s.reverse.phase != "aborted"
}
func (t *linuxStandardServiceReverse) response() *linuxStandardServiceReverseResponse {
	out := &linuxStandardServiceReverseResponse{Intent: t.request.Intent, Phase: t.phase, Committed: t.committed}
	if t.destination != nil {
		copy := *t.destination
		copy.Inventory = append([]byte(nil), copy.Inventory...)
		copy.Endpoints = append([]netip.Addr(nil), copy.Endpoints...)
		out.Destination = &copy
	}
	return out
}
func reverseServiceLaunch(request linuxStandardServiceRequest) linuxStandardServiceRequest {
	request.Action = "start"
	request.Reverse = nil
	return request
}
func sameReverseServiceLaunch(a, b linuxStandardServiceRequest) bool {
	a.BudgetMS, b.BudgetMS = 0, 0
	a.DeadlineNS, b.DeadlineNS = 0, 0
	return reflect.DeepEqual(a, b)
}
func (s *linuxStandardService) reverseSourceCurrent(ctx context.Context, source mobiletor.DesktopLinuxClosedTransferSnapshot) error {
	if s.reverseSourceOnly != nil {
		return s.reverseSourceOnly(ctx, source)
	}
	return mobiletor.ReadDesktopLinuxClosedTransferExclusive(ctx, source)
}
func (s *linuxStandardService) reverseSourceStillPresent(ctx context.Context, source mobiletor.DesktopLinuxClosedTransferSnapshot) error {
	if s.reverseSourcePresent != nil {
		return s.reverseSourcePresent(ctx, source)
	}
	return mobiletor.ReadDesktopLinuxClosedTransferCurrent(ctx, source)
}

func (s *linuxStandardService) reverseRequest(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest, files []*os.File) (out *linuxStandardServiceReverseResponse, failure error) {
	if ctx == nil {
		return nil, errors.New("reverse request has no original context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	q := request.Reverse
	if peer == nil || q == nil || q.Intent.Validate() != nil || q.Parent.Validate() != nil || q.Source.Validate() != nil || q.Source.Standard || request.Schema != 1 || request.Session != q.Intent.DestinationSession || request.BudgetMS < 1 || request.BudgetMS > 120000 || request.DeadlineNS <= time.Now().UnixNano() || request.Release || request.MTU != nil || request.Transfer != nil || request.ProfileRevision != "" || request.ResultRevision != "" {
		return nil, errors.New("reverse transfer changed its fixed authenticated scope")
	}
	switch request.Action {
	case "reverse-prepare", "reverse-current", "reverse-commit", "reverse-abort":
	default:
		return nil, errors.New("unknown reverse transfer action")
	}
	if !desktopLinuxParentObservationMatches(peer.record, q.Parent) || q.Source.Capture.SessionID != q.Intent.Source.SessionID || q.Source.Capture.SourceSHA256 != q.Intent.Source.SourceSHA256 || q.Source.HomeLAN != q.Intent.Source.HomeLAN || q.Source.NamespaceDevice != peer.record.NetworkNamespace.Device || q.Source.NamespaceInode != peer.record.NetworkNamespace.Inode {
		return nil, errors.New("reverse transfer substituted its original parent or source")
	}
	raw, err := json.Marshal(q.Source)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != q.Intent.SourceReceiptSHA256 {
		return nil, errors.New("reverse source changed its immutable inventory")
	}
	if request.Action == "reverse-prepare" {
		if len(files) != 1 || request.Session != q.Intent.DestinationSession || request.ConfigSHA256 != q.Intent.DestinationConfigSHA256 || request.ProfileID != q.Intent.DestinationProfileID || request.ProfileSHA256 != q.Intent.DestinationProfileSHA256 || request.Endpoint != q.Intent.Endpoint {
			return nil, errors.New("reverse preparation changed its captured destination")
		}
	} else if len(files) != 0 || request.Directory != "" || request.ConfigSHA256 != "" || request.ProfileID != "" || request.ProfileSHA256 != "" || request.NetworkID != "" || request.RouterID != "" || request.Endpoint != "" || request.RuntimeMode != "" || request.Base != "" {
		return nil, errors.New("reverse resolution supplied new launch authority")
	}
	if err = peer.Current(ctx); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.imageUpgrade != nil && s.imageUpgrade.phase != "aborted" && s.imageUpgrade.phase != "settled" {
		return nil, errors.New("original image handoff freezes ordinary service requests")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ns, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(ns, s.namespace) {
		return nil, errors.Join(err, errors.New("reverse transfer left its original namespace"))
	}
	rootInfo, rootErr := os.Stat(s.root)
	if rootErr != nil {
		return nil, rootErr
	}
	rootObject, rootErr := desktopLinuxNodeObjectOf(rootInfo)
	if rootErr != nil {
		return nil, rootErr
	}
	if rootObject != q.Parent.Root {
		return nil, errors.New("reverse parent belongs to another installation")
	}
	if s.quiescing {
		return nil, errors.New("reverse transfer cannot enter retiring service")
	}
	if s.reverseHistory == nil {
		s.reverseHistory = make(map[string]*linuxStandardServiceReverse)
	}
	t := s.reverseHistory[q.Intent.ID]
	if t != nil {
		if t.peer.record != peer.record || !reflect.DeepEqual(t.request, *q) {
			return nil, errors.New("reverse request substituted its retained original")
		}
		if request.Action == "reverse-prepare" && !sameReverseServiceLaunch(t.launch, reverseServiceLaunch(request)) {
			return nil, errors.New("reverse preparation changed its retained launch")
		}
	} else {
		if request.Action != "reverse-prepare" && request.Action != "reverse-abort" {
			return nil, errors.New("reverse resolution has no retained original reservation")
		}
		if len(s.reverseHistory) >= 128 {
			return nil, errors.New("reverse transfer history is full; retain original guards")
		}
		if s.reversePending() || s.transferPending() {
			return nil, errors.New("another original transfer remains unresolved")
		}
		copy := *q
		copy.Source.Inventory = append([]byte(nil), q.Source.Inventory...)
		copy.Source.Endpoints = append([]netip.Addr(nil), q.Source.Endpoints...)
		t = &linuxStandardServiceReverse{peer: peer, request: copy, phase: "retained"}
		if request.Action == "reverse-prepare" {
			t.launch = reverseServiceLaunch(request)
		}
		// Reserve before native observation or preparation. A lost/failed reply
		// never turns an attempted native acquisition into inferred absence.
		s.reverseHistory[q.Intent.ID] = t
		s.reverse = t
	}
	defer func() { out = t.response() }()
	if t.phase == "aborted" {
		if request.Action == "reverse-abort" || request.Action == "reverse-current" {
			return nil, nil
		}
		return nil, errors.New("reverse request was permanently aborted")
	}
	if t.committed {
		if request.Action == "reverse-current" {
			if t.session == nil || s.session != t.session || t.session.owner == nil || t.session.owner.protection == nil {
				return nil, errors.New("reverse current lost its retained original guard")
			}
			lease, e := acquireLegacyExitMutationLease(ctx, s.root)
			if e != nil {
				return nil, e
			}
			err = t.session.owner.protection.current(ctx, lease)
			lease.Close()
			if err != nil {
				return nil, err
			}
		}
		if request.Action == "reverse-abort" {
			return nil, errors.New("committed source cannot be restored from metadata")
		}
		return nil, peer.Current(ctx)
	}
	if s.reverse != t {
		return nil, errors.New("reverse mutation does not own active reservation")
	}
	switch request.Action {
	case "reverse-current":
		if t.pin != nil && !t.resolved {
			if _, err = t.pin.Snapshot(ctx); err != nil {
				return nil, err
			}
		}
		return nil, peer.Current(ctx)
	case "reverse-prepare":
		if time.Now().UnixNano() >= q.Intent.DeadlineNS {
			return nil, context.DeadlineExceeded
		}
		if q.Intent.DeadlineNS > time.Now().Add(120*time.Second).UnixNano() {
			return nil, errors.New("reverse work exceeds original maximum admission")
		}
		work, cancel := context.WithDeadline(ctx, time.Unix(0, q.Intent.DeadlineNS))
		defer cancel()
		if t.phase == "prepared" {
			_, err = t.pin.Snapshot(work)
			return nil, err
		}
		if t.session != nil {
			return nil, errors.New("partial reverse preparation remains owned; resolve before new work")
		}
		if err = s.loadProfilesContext(work); err != nil {
			return nil, err
		}
		if err := desktopnetwork.LockContext(work, &s.app.mu); err != nil {
			return nil, err
		}
		source, sourceOK := s.app.profileByIDLocked(q.Intent.SourceProfileID)
		destination, destinationOK := s.app.profileByIDLocked(q.Intent.DestinationProfileID)
		s.app.mu.Unlock()
		if !sourceOK || !destinationOK || desktopOwnedNodeProfileToken(source) != q.Intent.SourceProfileRevision || desktopOwnedNodeProtectionPolicy(source) != q.Intent.Source.Policy || source.HomeLANAccess != q.Intent.Source.HomeLAN || desktopOwnedNodeProtectionPolicy(destination) != q.Intent.Policy || destination.HomeLANAccess != q.Intent.HomeLAN {
			return nil, errors.New("reverse transfer changed original source or destination policy")
		}
		if err = s.reverseSourceCurrent(work, q.Source); err != nil {
			return nil, err
		}
		err = s.startPreparedMode(work, peer, t.launch, files[0], true)
		if s.session != nil && s.session.request.Session == request.Session && s.session.peer.record == peer.record {
			t.session = s.session
		}
		return nil, err
	case "reverse-commit":
		if t.pin == nil || t.phase != "prepared" {
			return nil, errors.New("reverse commit has no exact pinned successor")
		}
		if err = t.pin.Resolve(ctx, t.request.Source, true); err != nil {
			return nil, err
		}
		t.resolved = true
		t.committed = true
		t.phase = "committed"
		return nil, peer.Current(ctx)
	case "reverse-abort":
		if t.pin != nil && !t.resolved {
			if err = t.pin.Resolve(ctx, t.request.Source, false); err != nil {
				return nil, err
			}
			t.resolved = true
		}
		if err = s.reverseSourceStillPresent(ctx, t.request.Source); err != nil {
			return nil, err
		}
		t.phase = "aborting"
		if t.session != nil {
			if s.session != t.session || t.session.owner == nil || t.session.owner.started {
				return nil, errors.New("reverse abort cannot retire another or started engine")
			}
			slot := t.session.owner.protection
			if err = s.retire(ctx, false); err != nil {
				return nil, err
			}
			if slot != nil && !slot.closed {
				if err = s.reverseSourceStillPresent(ctx, t.request.Source); err != nil {
					return nil, err
				}
				lease, e := acquireLegacyExitMutationLease(ctx, s.root)
				if e != nil {
					return nil, e
				}
				err = slot.release(ctx, lease)
				lease.Close()
				if err != nil {
					return nil, err
				}
			}
		}
		t.phase = "aborted"
		return nil, peer.Current(ctx)
	}
	return nil, errors.New("unhandled reverse phase")
}

func (s *linuxStandardService) prepareReverseGuard(ctx context.Context, owner *linuxLegacyStandardExitOwner) error {
	t := s.reverse
	if t == nil || t.phase != "retained" || s.session == nil || s.session.owner != owner || owner.protectionPolicy != t.request.Intent.Policy || owner.protectionLAN != t.request.Intent.HomeLAN || owner.started {
		return errors.New("reverse guard lost exact prepared owner")
	}
	t.session = s.session
	// This exception accepts only the original live Node deny inventory, never
	// generic foreign state. It is consulted at the actual creation boundary.
	owner.protectionAbsence = func(call context.Context) error { return s.reverseSourceCurrent(call, t.request.Source) }
	if err := owner.prepareProtection(ctx); err != nil {
		return err
	}
	var pin linuxStandardReversePin
	var err error
	if s.reversePin != nil {
		pin, err = s.reversePin(ctx, owner, t.request.Intent.ID)
	} else {
		slot := owner.protection
		if slot == nil {
			return errors.New("reverse preparation created no original guard")
		}
		native, ok := slot.kernel.(*legacyExitNativeProtection)
		if !ok || native == nil {
			return errors.New("reverse preparation lost actual native creator")
		}
		endpoint, e := netip.ParseAddr(strings.Trim(t.request.Intent.Endpoint, "[]"))
		if e != nil {
			return e
		}
		lease, e := acquireLegacyExitMutationLease(ctx, s.root)
		if e != nil {
			return e
		}
		pin, err = native.PinNodePredecessor(ctx, t.request.Intent.ID, []netip.Addr{endpoint}, lease.lock)
		lease.Close()
	}
	if pin != nil {
		t.pin = pin
	}
	if err != nil {
		return err
	}
	if pin == nil {
		return errors.New("reverse guard omitted actual successor pin")
	}
	snapshot, err := pin.Snapshot(ctx)
	if err != nil {
		return err
	}
	endpoint, endpointErr := netip.ParseAddr(strings.Trim(t.request.Intent.Endpoint, "[]"))
	if endpointErr != nil {
		return endpointErr
	}
	if snapshot.Validate() != nil || len(snapshot.Endpoints) != 1 || snapshot.Endpoints[0] != endpoint || snapshot.NamespaceDevice != t.peer.record.NetworkNamespace.Device || snapshot.NamespaceInode != t.peer.record.NetworkNamespace.Inode || !snapshot.Standard || snapshot.Capture.SessionID != owner.session || snapshot.Capture.SourceSHA256 != owner.digest || snapshot.HomeLAN != owner.protectionLAN {
		return errors.New("reverse pin changed actual successor identity")
	}
	t.destination = &snapshot
	t.phase = "prepared"
	return ctx.Err()
}

// Original service gate serializes intent publication. An expired completion
// cannot wait for another app-lock owner; the retained expired intent remains
// fail-closed until a later authenticated operation replaces it under this gate.
func (s *linuxStandardService) operationContext(ctx context.Context) (func(), error) {
	if err := desktopnetwork.LockContext(ctx, &s.app.mu); err != nil {
		return nil, err
	}
	s.app.connectionContext = ctx
	s.app.connectionCancelIntent = nil
	s.app.mu.Unlock()
	return func() {
		if desktopnetwork.LockContext(ctx, &s.app.mu) != nil {
			return
		}
		defer s.app.mu.Unlock()
		if s.app.connectionContext == ctx {
			s.app.connectionContext = nil
			s.app.connectionCancelIntent = nil
		}
	}, nil
}
