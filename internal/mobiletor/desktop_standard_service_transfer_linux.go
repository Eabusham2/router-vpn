//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"sort"
)

// Image transfers retain both original creators. Snapshots are comparison data,
// never a way to reconstruct a creator or acquire removal authority.
type DesktopLinuxStandardImageTransfer struct {
	source      *DesktopLinuxNodeBaseline
	id          string
	snapshot    DesktopLinuxClosedTransferSnapshot
	destination *DesktopLinuxClosedTransferSnapshot
	lease       *desktopLinuxImageLease
	finished    bool
}
type DesktopLinuxStandardImageSuccessorPin struct {
	owner             *DesktopLinuxStandardProtection
	id                string
	snapshot          DesktopLinuxClosedTransferSnapshot
	lease             *desktopLinuxImageLease
	released          bool
	resolvedSource    *DesktopLinuxClosedTransferSnapshot
	resolvedCommitted bool
}

// Keep the original inode alive without retaining its flock open description.
// The caller releases the mutation lease between authenticated service phases.
type desktopLinuxImageLease struct {
	file *os.File
	info os.FileInfo
}

func desktopLinuxImageLeaseCapture(ctx context.Context, lease *os.File) (*desktopLinuxImageLease, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return nil, err
	}
	if err := desktopLinuxStandardLease(lease); err != nil {
		return nil, err
	}
	before, err := lease.Stat()
	if err != nil {
		return nil, err
	}
	retained, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", lease.Fd()))
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*desktopLinuxImageLease, error) { _ = retained.Close(); return nil, err }
	observed, err := retained.Stat()
	if err != nil {
		return fail(err)
	}
	after, err := lease.Stat()
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(before, observed) || !os.SameFile(before, after) {
		return fail(errors.New("image mutation lease changed during capture"))
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	return &desktopLinuxImageLease{retained, before}, nil
}
func (l *desktopLinuxImageLease) current(ctx context.Context, lease *os.File) error {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return err
	}
	if l == nil || l.file == nil {
		return errors.New("image transfer lost original mutation lease")
	}
	if err := desktopLinuxStandardLease(lease); err != nil {
		return err
	}
	retained, err := l.file.Stat()
	if err != nil {
		return err
	}
	actual, err := lease.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(l.info, retained) || !os.SameFile(l.info, actual) {
		return errors.New("image transfer substituted mutation lease")
	}
	return ctx.Err()
}
func (l *desktopLinuxImageLease) close() {
	if l != nil && l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}

// Read endpoint comparison data only from the original acknowledged rule map.
// The unchanged full snapshot validator proves that these are the complete
// literal allowances, with no widened rule, runtime tuple, or altered policy.
func desktopLinuxImageEndpoints(n *desktopLinuxNFT) ([]netip.Addr, error) {
	if n == nil {
		return nil, errors.New("image transfer lost original inventory")
	}
	raw, err := json.Marshal(n.Baseline)
	if err != nil {
		return nil, err
	}
	var rules map[uint64]any
	if err = json.Unmarshal(raw, &rules); err != nil {
		return nil, err
	}
	var endpoints []netip.Addr
	for _, rule := range rules {
		expr, ok := rule.([]any)
		if !ok || len(expr) != 2 {
			continue
		}
		first, ok := expr[0].(map[string]any)
		if !ok {
			continue
		}
		match, ok := first["match"].(map[string]any)
		if !ok {
			continue
		}
		left, ok := match["left"].(map[string]any)
		if !ok {
			continue
		}
		payload, ok := left["payload"].(map[string]any)
		if !ok || payload["field"] != "daddr" {
			continue
		}
		right, ok := match["right"].(string)
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(right)
		if err != nil {
			continue
		}
		endpoints = append(endpoints, addr)
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].Compare(endpoints[j]) < 0 })
	return endpoints, nil
}
func desktopLinuxImagePair(source, next DesktopLinuxClosedTransferSnapshot) error {
	if !source.Standard || !next.Standard {
		return errors.New("image transfer requires two standard original creators")
	}
	if err := source.Validate(); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if source.Capture.SessionID == next.Capture.SessionID || source.NamespaceDevice != next.NamespaceDevice || source.NamespaceInode != next.NamespaceInode || source.HomeLAN != next.HomeLAN {
		return errors.New("image transfer changed creator or captured closed policy")
	}
	a := append([]netip.Addr(nil), source.Endpoints...)
	b := append([]netip.Addr(nil), next.Endpoints...)
	sort.Slice(a, func(i, j int) bool { return a[i].Compare(a[j]) < 0 })
	sort.Slice(b, func(i, j int) bool { return b[i].Compare(b[j]) < 0 })
	if !reflect.DeepEqual(a, b) {
		return errors.New("image transfer changed captured endpoints")
	}
	return nil
}

func (p *DesktopLinuxStandardProtection) reserveImage(ctx context.Context, id string, lease *os.File) (DesktopLinuxClosedTransferSnapshot, *desktopLinuxImageLease, error) {
	empty := DesktopLinuxClosedTransferSnapshot{}
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return empty, nil, err
	}
	if p == nil || p.baseline == nil || !desktopSocketHex(id, 32) {
		return empty, nil, errors.New("image transfer omitted original creator or reservation")
	}
	if err := p.Current(ctx, lease); err != nil {
		return empty, nil, err
	}
	b := p.baseline
	if err := b.enter(ctx); err != nil {
		return empty, nil, err
	}
	defer func() { b.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	if !p.acknowledged || !b.standard || !b.complete || b.removed || b.closed || b.successor != nil || b.crossTransfer != "" {
		return empty, nil, errors.New("image transfer requires unused original standard creator")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := b.observe(ctx, false); err != nil {
		return empty, nil, err
	}
	endpoints, err := desktopLinuxImageEndpoints(b.nft)
	if err != nil {
		return empty, nil, err
	}
	snapshot, err := desktopLinuxClosedSnapshot(b, endpoints)
	if err != nil {
		return empty, nil, err
	}
	captured, err := desktopLinuxImageLeaseCapture(ctx, lease)
	if err != nil {
		return empty, nil, err
	}
	if err = ctx.Err(); err != nil {
		captured.close()
		return empty, nil, err
	}
	b.crossTransfer = id
	return snapshot, captured, nil
}
func (p *DesktopLinuxStandardProtection) ReserveImageTransfer(ctx context.Context, id string, lease *os.File) (*DesktopLinuxStandardImageTransfer, error) {
	snapshot, captured, err := p.reserveImage(ctx, id, lease)
	if err != nil {
		return nil, err
	}
	return &DesktopLinuxStandardImageTransfer{source: p.baseline, id: id, snapshot: snapshot, lease: captured}, nil
}
func (p *DesktopLinuxStandardProtection) PinImagePredecessor(ctx context.Context, id string, lease *os.File) (*DesktopLinuxStandardImageSuccessorPin, error) {
	snapshot, captured, err := p.reserveImage(ctx, id, lease)
	if err != nil {
		return nil, err
	}
	return &DesktopLinuxStandardImageSuccessorPin{owner: p, id: id, snapshot: snapshot, lease: captured}, nil
}

func (t *DesktopLinuxStandardImageTransfer) Snapshot(ctx context.Context) (DesktopLinuxClosedTransferSnapshot, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	if t == nil || t.source == nil {
		return DesktopLinuxClosedTransferSnapshot{}, errors.New("image source lost original creator")
	}
	b := t.source
	if err := b.enter(ctx); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	defer func() { b.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	if t.finished || b.crossTransfer != t.id || b.removed {
		return DesktopLinuxClosedTransferSnapshot{}, errors.New("image source reservation ended")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := b.observe(ctx, false); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	s := t.snapshot
	s.Inventory = append([]byte(nil), s.Inventory...)
	s.Endpoints = append([]netip.Addr(nil), s.Endpoints...)
	return s, nil
}
func (p *DesktopLinuxStandardImageSuccessorPin) Snapshot(ctx context.Context) (DesktopLinuxClosedTransferSnapshot, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	if p == nil || p.owner == nil {
		return DesktopLinuxClosedTransferSnapshot{}, errors.New("image successor lost original pin")
	}
	b := p.owner.baseline
	if err := b.enter(ctx); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	defer func() { b.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	if p.released || b.crossTransfer != p.id || b.removed {
		return DesktopLinuxClosedTransferSnapshot{}, errors.New("image successor pin ended")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := b.observe(ctx, false); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	s := p.snapshot
	s.Inventory = append([]byte(nil), s.Inventory...)
	s.Endpoints = append([]netip.Addr(nil), s.Endpoints...)
	return s, nil
}
func (t *DesktopLinuxStandardImageTransfer) Commit(ctx context.Context, next DesktopLinuxClosedTransferSnapshot, lease *os.File) error {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return err
	}
	if t == nil || t.source == nil || !next.Standard {
		return errors.New("image transfer omitted standard successor")
	}
	if err := desktopLinuxImagePair(t.snapshot, next); err != nil {
		return err
	}
	b := t.source
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.finished || b.crossTransfer != t.id || !b.standard || !b.complete || b.successor != nil {
		return errors.New("image transfer replaced original reservation")
	}
	if err := t.lease.current(ctx, lease); err != nil {
		return err
	}
	if t.destination != nil && !reflect.DeepEqual(*t.destination, next) {
		return errors.New("image transfer redirected entered deletion")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := b.currentNamespace(ctx); err != nil {
		return err
	}
	if !b.removed {
		before, err := b.netlink.generation(ctx)
		if err != nil {
			return err
		}
		if err = b.read(ctx, false); err != nil {
			return err
		}
		if err = desktopLinuxClosedTransferRead(ctx, next, false); err != nil {
			return err
		}
		after, err := b.netlink.generation(ctx)
		if err != nil {
			return err
		}
		if before != after {
			return errors.New("image transfer inventories changed generation")
		}
		copy := next
		copy.Inventory = append([]byte(nil), next.Inventory...)
		copy.Endpoints = append([]netip.Addr(nil), next.Endpoints...)
		t.destination = &copy
		if err = b.remove(ctx, after); err != nil {
			return err
		}
	}
	return b.absence(ctx)
}
func (t *DesktopLinuxStandardImageTransfer) Result(ctx context.Context) (bool, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return false, err
	}
	if t == nil || t.source == nil {
		return false, errors.New("image transfer lost source")
	}
	b := t.source
	if err := b.enter(ctx); err != nil {
		return false, err
	}
	defer func() { b.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if b.crossTransfer != t.id && !t.finished {
		return false, errors.New("image transfer changed reservation")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := b.currentNamespace(ctx); err != nil {
		return false, err
	}
	before, err := b.netlink.generation(ctx)
	if err != nil {
		return false, err
	}
	if b.removed {
		if t.destination == nil {
			return false, errors.New("image removal lost original successor")
		}
		if err = b.absence(ctx); err == nil {
			err = desktopLinuxClosedTransferRead(ctx, *t.destination, false)
		}
	} else {
		_, err = b.observe(ctx, false)
	}
	if err != nil {
		return false, err
	}
	after, err := b.netlink.generation(ctx)
	if err != nil {
		return false, err
	}
	if before != after {
		return false, errors.New("image result changed generation")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return b.removed, nil
}

func (t *DesktopLinuxStandardImageTransfer) Finish(ctx context.Context) (bool, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return false, err
	}
	if t == nil || t.source == nil {
		return false, errors.New("image transfer lost source")
	}
	b := t.source
	if err := b.enter(ctx); err != nil {
		return false, err
	}
	defer func() { b.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if b.crossTransfer != t.id && !t.finished {
		return false, errors.New("image transfer changed reservation")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := b.currentNamespace(ctx); err != nil {
		return false, err
	}
	before, err := b.netlink.generation(ctx)
	if err != nil {
		return false, err
	}
	if b.removed {
		if t.destination == nil {
			return false, errors.New("image removal lost original successor")
		}
		if err = b.absence(ctx); err == nil {
			err = desktopLinuxClosedTransferRead(ctx, *t.destination, false)
		}
	} else {
		err = ReadDesktopLinuxClosedTransferExclusive(ctx, t.snapshot)
	}
	if err != nil {
		return false, err
	}
	after, err := b.netlink.generation(ctx)
	if err != nil {
		return false, err
	}
	if before != after {
		return false, errors.New("image result changed generation")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !t.finished {
		b.crossTransfer = ""
		t.finished = true
		t.lease.close()
	}
	return b.removed, nil
}

// Resolve observes the exact source after the original controller reports its
// result. It never deletes the source or derives a creator from that report.
func (p *DesktopLinuxStandardImageSuccessorPin) Resolve(ctx context.Context, source DesktopLinuxClosedTransferSnapshot, committed bool) error {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return err
	}
	if p == nil || p.owner == nil || !source.Standard {
		return errors.New("image successor lost source scope")
	}
	if err := desktopLinuxImagePair(source, p.snapshot); err != nil {
		return err
	}
	b := p.owner.baseline
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.released && (p.resolvedSource == nil || !reflect.DeepEqual(*p.resolvedSource, source) || p.resolvedCommitted != committed) {
		return errors.New("image successor resolution changed its original decision")
	}
	if !p.released && b.crossTransfer != p.id || b.removed {
		return errors.New("image successor changed pin")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, err := b.observe(ctx, false)
	if err != nil {
		return err
	}
	if err = desktopLinuxClosedTransferRead(ctx, source, committed); err != nil {
		return err
	}
	after, err := b.netlink.generation(ctx)
	if err != nil {
		return err
	}
	if before != after {
		return errors.New("image resolution changed native generation")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.released {
		return nil
	}
	b.crossTransfer = ""
	copy := source
	copy.Inventory = append([]byte(nil), source.Inventory...)
	copy.Endpoints = append([]netip.Addr(nil), source.Endpoints...)
	p.resolvedSource = &copy
	p.resolvedCommitted = committed
	p.released = true
	p.lease.close()
	return ctx.Err()
}
