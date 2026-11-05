//go:build linux

package main

import (
	"context"
	"errors"

	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/standardengine"
)

const linuxStandardMTURetestCapacity = mobilemtu.MaxCandidates + 2 // Winner and failure rollback.

// Admission requires room for the entire bounded optimizer before its first
// mutation. Retained native pages are never recycled or allowed to fill midway
// through a test that still owes the user an exact original-MTU rollback.
func (o *linuxStandardServiceMTUOwner) PrepareRetestContext(ctx context.Context) error {
	if o == nil || o.launch == nil {
		return errors.New("standard MTU Retest lost its original owner")
	}
	if err := mobilemtu.LockContext(ctx, &o.launch.mu); err != nil {
		return err
	}
	defer o.launch.mu.Unlock()
	before, err := o.currentLocked(ctx)
	if err != nil {
		return err
	}
	if o.pending != nil || o.sockets.Load() != 0 {
		return errors.New("standard MTU Retest still owns earlier work")
	}
	response, err := o.rpcLocked(ctx, "mtu-capture", &linuxStandardServiceMTURequest{})
	if err != nil {
		return err
	}
	n := o.launch.prepared.requestEpoch
	if response.CaptureSHA256 != standardengine.SHA256(n.startup.Capture) || response.Current != n.mtuBinding || response.Ready != n.mtuReceipt || response.Pending {
		return errors.New("standard MTU Retest capacity belongs to another original reader")
	}
	if err := validateLinuxStandardMTURetestCapacity(response.Remaining); err != nil {
		return err
	}
	after, err := o.currentLocked(ctx)
	if err != nil || before != after {
		return errors.Join(err, errors.New("standard MTU Retest admission changed its original path"))
	}
	return ctx.Err()
}

func validateLinuxStandardMTURetestCapacity(remaining int) error {
	if remaining < linuxStandardMTURetestCapacity || remaining > standardengine.OperationTransactions {
		return errors.New("this connection has reached its MTU test limit; reconnect before Retest, with the current MTU preserved")
	}
	return nil
}
