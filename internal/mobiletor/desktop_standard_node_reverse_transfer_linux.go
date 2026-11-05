//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strings"
	"syscall"
)

// ClosedTransferSnapshot is comparison data only. Neither parsing it nor
// observing its table constructs a creator or authorizes deletion.
type DesktopLinuxClosedTransferSnapshot struct {
	Standard        bool                 `json:"standard"`
	NamespaceDevice uint64               `json:"namespace_device"`
	NamespaceInode  uint64               `json:"namespace_inode"`
	Capture         DesktopSocketCapture `json:"capture"`
	HomeLAN         bool                 `json:"home_lan"`
	Endpoints       []netip.Addr         `json:"endpoints,omitempty"`
	Inventory       json.RawMessage      `json:"inventory"`
}

func (s DesktopLinuxClosedTransferSnapshot) inventory() (*desktopLinuxNFT, error) {
	if !s.Capture.valid() || s.NamespaceInode == 0 || len(s.Inventory) == 0 || len(s.Inventory) > 24<<10 {
		return nil, errors.New("reverse transfer omitted its bounded original inventory")
	}
	var n desktopLinuxNFT
	d := json.NewDecoder(bytes.NewReader(s.Inventory))
	d.DisallowUnknownFields()
	if err := d.Decode(&n); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(n)
	if err != nil || !bytes.Equal(raw, s.Inventory) || n.Capture != s.Capture || n.TableHandle == 0 || n.TableHandle > 1<<53-1 || n.ChainHandle == 0 || n.ChainHandle > 1<<53-1 || len(n.Rules) != 0 || len(n.Sets) != 0 || n.UID != 0 || n.Prefix != "" {
		return nil, errors.New("reverse transfer changed its closed native inventory")
	}
	options := DesktopLinuxSocketOptions{}
	if s.HomeLAN {
		for _, v := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
			options.LANPrefixes = append(options.LANPrefixes, netip.MustParsePrefix(v))
		}
	}
	request := desktopLinuxNodeBaselineRequest(s.Capture, options)
	table := desktopLinuxNodeTable(s.Capture)
	if s.Standard {
		request, err = desktopLinuxStandardRequest(s.Capture, s.Endpoints, s.HomeLAN)
		table = desktopLinuxStandardTable(s.Capture)
	} else if len(s.Endpoints) != 0 {
		return nil, errors.New("closed Node transfer cannot widen endpoint permissions")
	}
	if err != nil || n.TableName != table {
		return nil, errors.Join(err, errors.New("reverse transfer substituted native table"))
	}
	expected := []any{}
	for _, row := range request {
		if add, ok := row["add"].(map[string]any); ok {
			if rule, ok := add["rule"].(map[string]any); ok {
				expected = append(expected, rule["expr"])
			}
		}
	}
	if len(n.Baseline) != len(expected) {
		return nil, errors.New("reverse transfer changed closed policy")
	}
	for handle, actual := range n.Baseline {
		if handle == 0 || handle > 1<<53-1 || handle == n.ChainHandle {
			return nil, errors.New("reverse transfer changed native rule handle")
		}
		found := -1
		for i, want := range expected {
			if reflect.DeepEqual(desktopLinuxSetNormalized(actual), desktopLinuxSetNormalized(want)) {
				found = i
				break
			}
		}
		if found < 0 {
			return nil, errors.New("reverse transfer widened closed policy")
		}
		expected = append(expected[:found], expected[found+1:]...)
	}
	return &n, nil
}
func (s DesktopLinuxClosedTransferSnapshot) Validate() error { _, err := s.inventory(); return err }
func (s DesktopLinuxClosedTransferSnapshot) namespace() error {
	info, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	v, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(v.Dev) != s.NamespaceDevice || v.Ino != s.NamespaceInode {
		return errors.New("reverse transfer changed native namespace")
	}
	return nil
}
func desktopLinuxClosedTransferRead(ctx context.Context, s DesktopLinuxClosedTransferSnapshot, absent bool) error {
	n, err := s.inventory()
	if err != nil {
		return err
	}
	if err = s.namespace(); err != nil {
		return err
	}
	if absent {
		raw, err := desktopLinuxNFTCommand(ctx, []string{"-j", "-n", "list", "tables"}, "")
		if err != nil {
			return err
		}
		rows, err := desktopLinuxNFTRows(raw)
		if err != nil {
			return err
		}
		return desktopLinuxTableListAbsent(rows, func(name string) bool { return name == n.TableName })
	}
	rows, err := desktopLinuxNFTReadTable(ctx, n.table())
	if err != nil {
		return err
	}
	closed := *n
	closed.Baseline = map[uint64]any{}
	for h, x := range n.Baseline {
		closed.Baseline[h] = desktopLinuxSetNormalized(x)
	}
	for i, row := range rows {
		rows[i] = desktopLinuxSetNormalized(row).(map[string]any)
	}
	return desktopLinuxProtectionInventoryRows(&closed, rows, false)
}

// This bounded observer is used only beside an authenticated original parent
// which retains the source pin. It cannot grant removal authority.
func ReadDesktopLinuxClosedTransferExclusive(ctx context.Context, s DesktopLinuxClosedTransferSnapshot) error {
	if ctx == nil || ctx.Err() != nil {
		return desktopLinuxReverseCaller(ctx)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	observer, err := desktopLinuxOpenBaselineNetlink()
	if err != nil {
		return err
	}
	defer observer.close()
	before, err := observer.generation(ctx)
	if err != nil {
		return err
	}
	if err = desktopLinuxClosedTransferRead(ctx, s, false); err != nil {
		return err
	}
	n, _ := s.inventory()
	raw, err := desktopLinuxNFTCommand(ctx, []string{"-j", "-n", "list", "tables"}, "")
	if err != nil {
		return err
	}
	rows, err := desktopLinuxNFTRows(raw)
	if err != nil {
		return err
	}
	if err = desktopLinuxTableListAbsent(rows, func(name string) bool {
		return name != n.TableName && (name == desktopLinuxNFTTable || strings.HasPrefix(name, desktopLinuxNodeTablePrefix) || strings.HasPrefix(name, desktopLinuxStandardTablePrefix))
	}); err != nil {
		return err
	}
	after, err := observer.generation(ctx)
	if err != nil {
		return err
	}
	if before != after {
		return errors.New("reverse source observation changed generation")
	}
	return ctx.Err()
}

type DesktopLinuxNodeStandardTransfer struct {
	source      *DesktopLinuxNodeBaseline
	id          string
	snapshot    DesktopLinuxClosedTransferSnapshot
	destination *DesktopLinuxClosedTransferSnapshot
	finished    bool
}
type DesktopLinuxStandardSuccessorPin struct {
	owner             *DesktopLinuxStandardProtection
	id                string
	snapshot          DesktopLinuxClosedTransferSnapshot
	released          bool
	resolvedSource    *DesktopLinuxClosedTransferSnapshot
	resolvedCommitted bool
}

func desktopLinuxClosedSnapshot(b *DesktopLinuxNodeBaseline, endpoints []netip.Addr) (DesktopLinuxClosedTransferSnapshot, error) {
	v, ok := b.namespaceInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return DesktopLinuxClosedTransferSnapshot{}, errors.New("reverse transfer lost namespace inode")
	}
	raw, err := json.Marshal(b.nft)
	if err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	s := DesktopLinuxClosedTransferSnapshot{Standard: b.standard, NamespaceDevice: uint64(v.Dev), NamespaceInode: v.Ino, Capture: b.nft.Capture, HomeLAN: b.homeLAN, Endpoints: append([]netip.Addr(nil), endpoints...), Inventory: raw}
	return s, s.Validate()
}
func (b *DesktopLinuxNodeBaseline) ReserveStandardTransfer(ctx context.Context, id string) (*DesktopLinuxNodeStandardTransfer, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return nil, err
	}
	if err := b.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { b.gate <- struct{}{} }()
	if !desktopSocketHex(id, 32) || b.standard || !b.complete || b.removed || b.successor != nil || b.crossTransfer != "" {
		return nil, errors.New("reverse source requires its unused original closed creator")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := b.observe(ctx, false); err != nil {
		return nil, err
	}
	s, err := desktopLinuxClosedSnapshot(b, nil)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.crossTransfer = id
	return &DesktopLinuxNodeStandardTransfer{source: b, id: id, snapshot: s}, nil
}
func (t *DesktopLinuxNodeStandardTransfer) Snapshot(ctx context.Context) (DesktopLinuxClosedTransferSnapshot, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	if t == nil || t.source == nil {
		return DesktopLinuxClosedTransferSnapshot{}, errors.New("reverse source lost original creator")
	}
	b := t.source
	if err := b.enter(ctx); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	defer func() { b.gate <- struct{}{} }()
	if t.finished || b.crossTransfer != t.id || b.removed {
		return DesktopLinuxClosedTransferSnapshot{}, errors.New("reverse source reservation ended")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := b.observe(ctx, false); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	s := t.snapshot
	s.Inventory = append([]byte(nil), s.Inventory...)
	return s, nil
}
func (p *DesktopLinuxStandardProtection) PinNodePredecessor(ctx context.Context, id string, endpoints []netip.Addr, lease *os.File) (*DesktopLinuxStandardSuccessorPin, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return nil, err
	}
	if !desktopSocketHex(id, 32) {
		return nil, errors.New("reverse successor has invalid original reservation")
	}
	if err := p.Current(ctx, lease); err != nil {
		return nil, err
	}
	b := p.baseline
	if err := b.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { b.gate <- struct{}{} }()
	if b.crossTransfer != "" || b.removed || b.successor != nil {
		return nil, errors.New("reverse successor already has an owner")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := b.observe(ctx, false); err != nil {
		return nil, err
	}
	s, err := desktopLinuxClosedSnapshot(b, endpoints)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.crossTransfer = id
	return &DesktopLinuxStandardSuccessorPin{owner: p, id: id, snapshot: s}, nil
}
func (p *DesktopLinuxStandardSuccessorPin) Snapshot(ctx context.Context) (DesktopLinuxClosedTransferSnapshot, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	if p == nil || p.owner == nil {
		return DesktopLinuxClosedTransferSnapshot{}, errors.New("reverse successor lost original pin")
	}
	b := p.owner.baseline
	if err := b.enter(ctx); err != nil {
		return DesktopLinuxClosedTransferSnapshot{}, err
	}
	defer func() { b.gate <- struct{}{} }()
	if p.released || b.crossTransfer != p.id || b.removed {
		return DesktopLinuxClosedTransferSnapshot{}, errors.New("reverse successor pin ended")
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
func (t *DesktopLinuxNodeStandardTransfer) Commit(ctx context.Context, next DesktopLinuxClosedTransferSnapshot) error {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return err
	}
	if t == nil || t.source == nil || !next.Standard {
		return errors.New("reverse transfer omitted standard successor")
	}
	if err := next.Validate(); err != nil {
		return err
	}
	b := t.source
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if t.finished || b.crossTransfer != t.id || b.standard || !b.complete || b.successor != nil {
		return errors.New("reverse transfer replaced original reservation")
	}
	if t.destination != nil && !reflect.DeepEqual(*t.destination, next) {
		return errors.New("reverse transfer redirected entered deletion")
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
			return errors.New("reverse transfer inventories changed generation")
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
func (t *DesktopLinuxNodeStandardTransfer) Result(ctx context.Context) (bool, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return false, err
	}
	if t == nil || t.source == nil {
		return false, errors.New("reverse transfer lost source")
	}
	b := t.source
	if err := b.enter(ctx); err != nil {
		return false, err
	}
	defer func() { b.gate <- struct{}{} }()
	if b.crossTransfer != t.id && !t.finished {
		return false, errors.New("reverse transfer changed reservation")
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
			return false, errors.New("reverse removal lost original successor")
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
		return false, errors.New("reverse result changed generation")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return b.removed, nil
}

func (t *DesktopLinuxNodeStandardTransfer) Finish(ctx context.Context) (bool, error) {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return false, err
	}
	if t == nil || t.source == nil {
		return false, errors.New("reverse transfer lost source")
	}
	b := t.source
	if err := b.enter(ctx); err != nil {
		return false, err
	}
	defer func() { b.gate <- struct{}{} }()
	if b.crossTransfer != t.id && !t.finished {
		return false, errors.New("reverse transfer changed reservation")
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
			return false, errors.New("reverse removal lost original successor")
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
		return false, errors.New("reverse result changed generation")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !t.finished {
		b.crossTransfer = ""
		t.finished = true
	}
	return b.removed, nil
}

// Resolve observes the exact source after the original controller reports its
// result. It never deletes the source or derives a creator from that report.
func (p *DesktopLinuxStandardSuccessorPin) Resolve(ctx context.Context, source DesktopLinuxClosedTransferSnapshot, committed bool) error {
	if err := desktopLinuxReverseCaller(ctx); err != nil {
		return err
	}
	if p == nil || p.owner == nil || source.Standard {
		return errors.New("reverse successor lost source scope")
	}
	b := p.owner.baseline
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if p.released && (p.resolvedSource == nil || !reflect.DeepEqual(*p.resolvedSource, source) || p.resolvedCommitted != committed) {
		return errors.New("reverse successor resolution changed its original decision")
	}
	if !p.released && b.crossTransfer != p.id || b.removed {
		return errors.New("reverse successor changed pin")
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
		return errors.New("reverse resolution changed native generation")
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
	return ctx.Err()
}

// Current compares the exact retained source while an independently owned
// successor may coexist. It grants no exception for any unrelated table and no
// authority to remove or reconstruct either creator.
func ReadDesktopLinuxClosedTransferCurrent(ctx context.Context, s DesktopLinuxClosedTransferSnapshot) error {
	if ctx == nil || ctx.Err() != nil {
		return desktopLinuxReverseCaller(ctx)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	observer, err := desktopLinuxOpenBaselineNetlink()
	if err != nil {
		return err
	}
	defer observer.close()
	before, err := observer.generation(ctx)
	if err != nil {
		return err
	}
	if err = desktopLinuxClosedTransferRead(ctx, s, false); err != nil {
		return err
	}
	after, err := observer.generation(ctx)
	if err != nil {
		return err
	}
	if before != after {
		return errors.New("reverse source observation changed generation")
	}
	return ctx.Err()
}

func desktopLinuxReverseCaller(ctx context.Context) error {
	if ctx == nil {
		return errors.New("reverse transfer omitted original context")
	}
	return ctx.Err()
}
