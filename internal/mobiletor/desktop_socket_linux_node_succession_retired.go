//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"
)

// ObserveRetiredSuccession reads through two original retained creators after
// the candidate's source has joined. Supersede's ordinary retry requires that
// source to remain prepared; an interrupted parent acknowledgement can instead
// leave its already-committed candidate closed. Only the original committed
// deletion receipt and exact successor pointer can prove that transition.
//
// The returned bool reports an acknowledged original succession, never a new
// mutation. false with nil error proves both original closed tables still
// exist. An error proves neither outcome and leaves both owners retained.
// The caller separately owns authenticated source retirement, actual engine
// join and durable settlement; this method cannot infer any of them from nft.
func (b *DesktopLinuxNodeBaseline) ObserveRetiredSuccession(ctx context.Context, successor *DesktopLinuxNodeBaseline) (bool, error) {
	if b == nil || successor == nil || b == successor || b.nft == nil || successor.nft == nil ||
		b.nft.Capture.SessionID == successor.nft.Capture.SessionID {
		return false, errors.New("Linux retired succession requires two distinct original creators")
	}
	first, second := b, successor
	if first.nft.Capture.SessionID > second.nft.Capture.SessionID {
		first, second = second, first
	}
	if err := first.enter(ctx); err != nil {
		return false, err
	}
	defer func() { first.gate <- struct{}{} }()
	if err := second.enter(ctx); err != nil {
		return false, err
	}
	defer func() { second.gate <- struct{}{} }()
	if !b.complete || !successor.complete || b.prepared == nil || successor.prepared == nil ||
		successor.removed || successor.successor != nil ||
		b.removed && b.successor != successor || !b.removed && b.successor != nil ||
		b.namespaceInfo == nil || successor.namespaceInfo == nil || !os.SameFile(b.namespaceInfo, successor.namespaceInfo) {
		return false, errors.New("Linux retired succession lost its original receipt, candidate or prepared owners")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := b.currentNamespace(ctx); err != nil {
		return false, err
	}
	if err := successor.currentNamespace(ctx); err != nil {
		return false, err
	}
	before, err := b.netlink.generation(ctx)
	if err != nil {
		return false, err
	}
	if b.removed {
		rows, err := desktopLinuxNFTReadTable(ctx, b.nft.table())
		if err != nil || len(rows) != 0 {
			return false, errors.Join(err, errors.New("Linux retired succession's acknowledged predecessor is no longer absent"))
		}
	} else if err := b.read(ctx, false); err != nil {
		return false, err
	}
	if err := successor.read(ctx, false); err != nil {
		return false, err
	}
	after, err := b.netlink.generation(ctx)
	if err != nil || before != after || b.currentNamespace(ctx) != nil || successor.currentNamespace(ctx) != nil {
		return false, errors.Join(err, errors.New("Linux retired succession changed during its shared native snapshot"))
	}
	return b.removed, nil
}
