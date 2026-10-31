//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
)

// Created observes the original, independently verified exclusive creation
// before any guardian binds or admits traffic. The durable parent must record
// its prepare intent before construction and this receipt before allowing the
// child to create its source. An unknown creation cannot be repaired by a
// later matching readback or by decoding this comparison record.
func (b *DesktopLinuxNodeBaseline) Created(ctx context.Context) (DesktopLinuxNodeCreationRecord, error) {
	if err := b.enter(ctx); err != nil {
		return DesktopLinuxNodeCreationRecord{}, err
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.complete || b.prepared != nil {
		return DesktopLinuxNodeCreationRecord{}, errors.New("Linux Node creation receipt requires its original unbound creator")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := b.observe(ctx, false); err != nil {
		return DesktopLinuxNodeCreationRecord{}, err
	}
	encoded, err := json.Marshal(b.nft.Baseline)
	if err != nil {
		return DesktopLinuxNodeCreationRecord{}, err
	}
	record := DesktopLinuxNodeCreationRecord{Capture: b.nft.Capture, HomeLAN: b.homeLAN, TableName: b.nft.TableName,
		TableHandle: b.nft.TableHandle, ChainHandle: b.nft.ChainHandle, BaselineSHA256: desktopLinuxBaselineDigest(encoded)}
	if err := record.Validate(); err != nil || ctx.Err() != nil {
		return DesktopLinuxNodeCreationRecord{}, errors.Join(err, ctx.Err())
	}
	return record, nil
}
