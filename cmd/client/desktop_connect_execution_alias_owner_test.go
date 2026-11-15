//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"router-vpn/internal/desktopnetwork"
)

// Test-only ownership for the kernel addresses connecting the encrypted peer
// to the real relay's private TCP source check. No production route or source
// check is replaced. Native creation uses nonpersistent IP Helper entries.
type windowsCONNECTAliasIdentity struct {
	Index uint32
	LUID  uint64
}

type windowsCONNECTAliasRecord struct {
	Interface windowsCONNECTAliasIdentity
	Address   netip.Addr
	Bits      uint8
	Skip      bool
	Created   int64
}

type windowsCONNECTAliasKernel interface {
	Inventory(context.Context) (windowsCONNECTAliasIdentity, map[netip.Addr]windowsCONNECTAliasRecord, error)
	Create(context.Context, windowsCONNECTAliasIdentity, netip.Addr) (*windowsCONNECTAliasRecord, error)
	Delete(context.Context, windowsCONNECTAliasRecord) error
}

var windowsCONNECTAliasGate sync.Mutex

var windowsCONNECTAliasAddresses = [...]netip.Addr{netip.MustParseAddr("10.78.0.1"), netip.MustParseAddr("10.78.0.2")}

type windowsCONNECTAliasOwner struct {
	kernel   windowsCONNECTAliasKernel
	identity windowsCONNECTAliasIdentity
	added    []windowsCONNECTAliasRecord
	unlock   bool
	closed   bool
}

func windowsCONNECTOwnAliases(ctx context.Context, kernel windowsCONNECTAliasKernel) (*windowsCONNECTAliasOwner, error) {
	if ctx == nil || ctx.Err() != nil || kernel == nil {
		return nil, errors.New("CONNECT alias ownership requires its original caller and kernel")
	}
	if err := desktopnetwork.LockContext(ctx, &windowsCONNECTAliasGate); err != nil {
		return nil, err
	}
	owner := &windowsCONNECTAliasOwner{kernel: kernel, unlock: true}
	identity, present, err := kernel.Inventory(ctx)
	if err != nil || identity.Index == 0 || identity.LUID == 0 {
		owner.release()
		return nil, errors.Join(err, errors.New("CONNECT alias loopback identity unavailable"))
	}
	for _, address := range windowsCONNECTAliasAddresses {
		if _, exists := present[address]; exists {
			owner.release()
			return nil, errors.New("CONNECT alias collision precedes every mutation")
		}
	}
	owner.identity = identity
	for _, address := range windowsCONNECTAliasAddresses {
		// The native adapter returns a record whenever Create succeeded, even
		// if its subsequent readback fails. That partial owner must be retained.
		record, createErr := kernel.Create(ctx, identity, address)
		if record != nil {
			owner.added = append(owner.added, *record)
		}
		if createErr != nil {
			return owner, createErr
		}
		if record == nil || record.Interface != identity || record.Address != address || record.Bits != 32 || !record.Skip || record.Created <= 0 {
			return owner, errors.New("CONNECT alias creation lost its exact native record")
		}
		actual, current, err := kernel.Inventory(ctx)
		if err != nil || actual != identity || current[address] != *record {
			return owner, errors.Join(err, errors.New("CONNECT alias readback replaced its original entry"))
		}
	}
	return owner, nil
}

func (owner *windowsCONNECTAliasOwner) release() {
	if owner != nil && owner.unlock {
		owner.unlock = false
		windowsCONNECTAliasGate.Unlock()
	}
}

func (owner *windowsCONNECTAliasOwner) Close(ctx context.Context, join func(context.Context) error) error {
	if owner == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("CONNECT alias cleanup requires its original caller")
	}
	if owner.closed {
		return nil
	}
	if join == nil {
		return errors.New("CONNECT alias cleanup requires original native and relay joins")
	}
	if err := join(ctx); err != nil {
		return err
	}
	for len(owner.added) > 0 {
		record := owner.added[len(owner.added)-1]
		identity, present, err := owner.kernel.Inventory(ctx)
		if err != nil || identity != owner.identity {
			return errors.Join(err, errors.New("CONNECT alias cleanup replaced its loopback identity"))
		}
		current, exists := present[record.Address]
		if !exists {
			owner.added = owner.added[:len(owner.added)-1]
			continue
		}
		// Creation time distinguishes a same-address replacement on the same
		// interface. An unobserved partial Create never grants deletion rights.
		if record.Created <= 0 || current != record {
			return errors.New("CONNECT alias cleanup refused a replaced native entry")
		}
		if err := owner.kernel.Delete(ctx, record); err != nil {
			return err
		}
		identity, present, err = owner.kernel.Inventory(ctx)
		if err != nil || identity != owner.identity {
			return errors.Join(err, errors.New("CONNECT alias removal lost its original loopback"))
		}
		if _, exists := present[record.Address]; exists {
			return errors.New("CONNECT alias removal did not retire its original entry")
		}
		owner.added = owner.added[:len(owner.added)-1]
	}
	owner.closed = true
	owner.release()
	return nil
}
