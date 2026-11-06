//go:build linux

package mobiletor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"router-vpn/internal/desktopnetwork"
)

// DesktopLinuxBootstrapDNSGroup owns one original baseline reservation and
// concurrently selected resolver sockets. Close joins every exchange and exact
// original mutation receipt. No validation callback runs under its mutex.
type DesktopLinuxBootstrapDNSGroup struct {
	mu                        sync.Mutex
	closeMu                   sync.Mutex
	owner                     *DesktopLinuxStandardProtection
	lease                     *os.File
	original                  context.Context
	ctx                       context.Context
	cancel                    context.CancelFunc
	deadline                  time.Time
	generation                uint32
	acknowledged              map[*desktopLinuxBootstrapGrant]bool
	members                   []*desktopLinuxStandardBootstrap
	wg                        sync.WaitGroup
	joined                    chan struct{}
	closing, closed, reserved bool
	blocked                   error
	active                    int
	initialDescriptors        int
	inventoryBytes            int
	admitted                  int
	dnssec                    *desktopLinuxBootstrapDNSSECBinding
}

const desktopLinuxBootstrapGroupActive = 257
const desktopLinuxBootstrapGroupTotal = 514

// Historical admission stays bounded even after exact retired members recycle.
const desktopLinuxBootstrapGroupAdmissions = 3 * desktopLinuxBootstrapGroupActive
const desktopLinuxBootstrapGroupGrantBytes = 4096
const desktopLinuxBootstrapGroupInventory = (2 << 20) - (64 << 10)

func (p *DesktopLinuxStandardProtection) BeginBootstrapDNSGroup(original context.Context, lease *os.File) (*DesktopLinuxBootstrapDNSGroup, error) {
	return p.beginBootstrapDNSGroup(original, lease, nil)
}
func (p *DesktopLinuxStandardProtection) beginBootstrapDNSGroup(original context.Context, lease *os.File, dnssec *desktopLinuxBootstrapDNSSECBinding) (*DesktopLinuxBootstrapDNSGroup, error) {
	if original == nil {
		return nil, errors.New("bootstrap group omitted original operation")
	}
	deadline, ok := original.Deadline()
	if !ok || original.Err() != nil {
		return nil, errors.New("bootstrap group requires original bounded operation")
	}
	if err := p.Current(original, lease); err != nil {
		return nil, err
	}
	b := p.baseline
	if err := b.enter(original); err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			b.gate <- struct{}{}
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if p.bootstrap != nil || b.crossTransfer != "" || b.successor != nil || b.removed {
		return nil, errors.New("bootstrap group original creator already reserved")
	}
	if err := desktopLinuxStandardLease(lease); err != nil {
		return nil, err
	}
	generation, err := b.observe(original, false)
	if err != nil {
		return nil, err
	}
	rows, err := desktopLinuxNFTReadTable(original, b.nft.table())
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rows)
	if err != nil || 2*len(raw)+4096 > desktopLinuxBootstrapGroupInventory-desktopLinuxBootstrapGroupActive*desktopLinuxBootstrapGroupGrantBytes {
		return nil, errors.New("bootstrap group baseline exceeds complete cohort inventory budget")
	}
	descriptors, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(original)
	g := &DesktopLinuxBootstrapDNSGroup{owner: p, lease: lease, original: original, ctx: ctx, cancel: cancel, deadline: deadline, generation: generation, acknowledged: map[*desktopLinuxBootstrapGrant]bool{}, reserved: true, inventoryBytes: 2*len(raw) + 4096, initialDescriptors: len(descriptors)}
	g.dnssec = dnssec
	p.bootstrap = &desktopLinuxStandardBootstrap{group: g}
	p.bootstrapGroup.Store(g)
	b.crossTransfer = "bootstrap"
	retained = true
	return g, nil
}

// Only an original committed mutation advances the expected kernel generation.
func (g *DesktopLinuxBootstrapDNSGroup) acknowledge(transaction *desktopLinuxBootstrapGrant) error {
	if transaction == nil || !transaction.sent || !transaction.owns(g.owner.baseline.netlink) || !transaction.complete() || transaction.rejected {
		return errors.New("bootstrap group lacks original acknowledged mutation")
	}
	if g.acknowledged[transaction] {
		return nil
	}
	if len(transaction.requests) != 4 && len(transaction.requests) != 5 {
		return errors.New("bootstrap group mutation shape changed")
	}
	fields, err := desktopLinuxBootstrapAttributeMap(transaction.requests[0][20:], 0)
	if err != nil || len(fields[1]) != 4 || binary.BigEndian.Uint32(fields[1]) != g.generation {
		return errors.New("bootstrap group mutation did not extend original generation")
	}
	g.generation++
	if g.generation == 0 {
		g.generation = 1
	}
	g.acknowledged[transaction] = true
	return nil
}

func (g *DesktopLinuxBootstrapDNSGroup) observe(ctx context.Context) (uint32, error) {
	b := g.owner.baseline
	if g.owner.bootstrap == nil || g.owner.bootstrap.group != g || b.crossTransfer != "bootstrap" {
		return 0, errors.New("bootstrap group lost original reservation")
	}
	if err := desktopLinuxStandardLease(g.lease); err != nil {
		return 0, err
	}
	if err := b.currentNamespace(ctx); err != nil {
		return 0, err
	}
	before, err := b.netlink.generation(ctx)
	if err != nil || before != g.generation {
		return 0, errors.Join(err, errors.New("bootstrap group encountered foreign generation"))
	}
	for _, t := range g.members {
		if t.grant != nil && t.grant.sent && !t.grant.complete() {
			return 0, errors.New("bootstrap group retains uncertain original creation")
		}
		if t.removal != nil && t.removal.sent && !t.removal.complete() {
			return 0, errors.New("bootstrap group retains uncertain original removal")
		}
		if t.handle != 0 && !t.retired {
			if err = t.observeNativeGrant(ctx, b); err != nil {
				return 0, err
			}
		}
	}
	rows, err := desktopLinuxNFTReadTable(ctx, b.nft.table())
	if err != nil {
		return 0, err
	}
	if err = g.inventory(b, rows); err != nil {
		return 0, err
	}
	after, err := b.netlink.generation(ctx)
	if err != nil || after != before {
		return 0, errors.Join(err, errors.New("bootstrap group changed during full readback"))
	}
	if err = b.currentNamespace(ctx); err != nil {
		return 0, err
	}
	return after, nil
}

func (g *DesktopLinuxBootstrapDNSGroup) capacity() error {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return err
	}
	descriptors, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	return g.capacityFor(len(descriptors), limit.Cur)
}
func (g *DesktopLinuxBootstrapDNSGroup) capacityFor(descriptors int, limit uint64) error {
	admissions := desktopLinuxBootstrapGroupAdmissions
	if g.dnssec != nil {
		admissions = g.dnssec.admissions
	}
	if g.admitted >= admissions || g.active >= desktopLinuxBootstrapGroupActive || len(g.members) >= desktopLinuxBootstrapGroupTotal || g.inventoryBytes+desktopLinuxBootstrapGroupGrantBytes > desktopLinuxBootstrapGroupInventory {
		return errors.New("bootstrap group exhausted bounded cohort inventory")
	}
	reserved := g.initialDescriptors + 2*(len(g.members)+1)
	if descriptors+2 > reserved {
		reserved = descriptors + 2
	}
	if uint64(reserved)+64 > limit {
		return errors.New("bootstrap group lacks original descriptor reserve")
	}
	return nil
}

func (g *DesktopLinuxBootstrapDNSGroup) Close(ctx context.Context) error {
	if g == nil || ctx == nil || g.owner == nil || g.owner.baseline == nil || g.ctx == nil || g.cancel == nil {
		return errors.New("bootstrap group cleanup omitted original owner")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("bootstrap group cleanup requires bounded recovery")
	}
	if err := desktopnetwork.LockContext(ctx, &g.closeMu); err != nil {
		return err
	}
	defer g.closeMu.Unlock()
	if err := desktopnetwork.LockContext(ctx, &g.mu); err != nil {
		return err
	}
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	if !g.closing {
		g.closing = true
		g.cancel()
		g.joined = make(chan struct{})
		go func() { g.wg.Wait(); close(g.joined) }()
	}
	joined := g.joined
	g.mu.Unlock()
	select {
	case <-joined:
	case <-ctx.Done():
		return ctx.Err()
	}
	b := g.owner.baseline
	if err := desktopnetwork.LockContext(ctx, &g.mu); err != nil {
		return err
	}
	defer g.mu.Unlock()
	if !g.reserved {
		if err := b.enter(ctx); err != nil {
			return err
		}
		g.reserved = true
	}
	defer func() { g.reserved = false; b.gate <- struct{}{} }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return g.cleanupLocked(ctx, g.lease)
}

// Called after every exchange joins, under original baseline gate and group
// mutex. Failure preserves all members and receipts for same-owner retry.
func (g *DesktopLinuxBootstrapDNSGroup) cleanupLocked(ctx context.Context, lease *os.File) error {
	if lease != g.lease || g.owner.bootstrap == nil || g.owner.bootstrap.group != g {
		return errors.New("bootstrap group cleanup replaced original capability")
	}
	if !g.closing {
		return errors.New("bootstrap group cleanup requires joined original IO")
	}
	select {
	case <-g.joined:
	default:
		return errors.New("bootstrap group IO has not joined")
	}
	b := g.owner.baseline
	if err := desktopLinuxStandardLease(lease); err != nil {
		return err
	}
	for _, t := range g.members {
		if t.grant != nil && t.grant.sent {
			if !t.grant.complete() {
				if err := b.netlink.bootstrapExchange(ctx, t.grant); err != nil && !t.grant.complete() {
					return err
				}
			}
			if !t.grant.rejected {
				if err := g.acknowledge(t.grant); err != nil {
					return err
				}
				t.handle = t.grant.ruleHandle
			}
		}
		if t.removal != nil && t.removal.sent {
			if !t.removal.complete() {
				if err := b.netlink.bootstrapExchange(ctx, t.removal); err != nil && !t.removal.complete() {
					return err
				}
			}
			if !t.removal.rejected {
				if err := g.acknowledge(t.removal); err != nil {
					return err
				}
				t.retired = true
			}
		}
	}
	if _, err := g.observe(ctx); err != nil {
		return err
	}
	for _, t := range g.members {
		if t.handle == 0 || t.retired {
			continue
		}
		generation, err := g.observe(ctx)
		if err != nil {
			return err
		}
		if t.removal == nil || t.removal.rejected {
			t.removal, err = b.netlink.newBootstrapRemoval(generation, t.grant)
			if err != nil {
				return err
			}
		}
		err = b.netlink.bootstrapExchange(ctx, t.removal)
		if !t.removal.complete() || t.removal.rejected {
			return errors.Join(err, errors.New("bootstrap group retains original uncommitted removal"))
		}
		if err = g.acknowledge(t.removal); err != nil {
			return err
		}
		t.retired = true
		if _, err = g.observe(ctx); err != nil {
			return err
		}
	}
	if _, err := g.observe(ctx); err != nil {
		return err
	}
	for _, t := range g.members {
		if err := t.closeSocket(); err != nil {
			return err
		}
	}
	g.owner.bootstrap = nil
	g.owner.bootstrapGroup.Store(nil)
	b.crossTransfer = ""
	g.closed = true
	return ctx.Err()
}

func (g *DesktopLinuxBootstrapDNSGroup) inventory(b *DesktopLinuxNodeBaseline, rows []map[string]any) error {
	var err error
	for _, t := range g.members {
		if t.handle == 0 {
			continue
		}
		rows, _, err = t.filterInventory(b, rows)
		if err != nil {
			return err
		}
	}
	baseline := *b.nft
	baseline.Baseline = map[uint64]any{}
	for handle, expression := range b.nft.Baseline {
		baseline.Baseline[handle] = desktopLinuxSetNormalized(expression)
	}
	if err = desktopLinuxProtectionInventoryRows(&baseline, rows, false); err != nil {
		return err
	}
	return nil
}
