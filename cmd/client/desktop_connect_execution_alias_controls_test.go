//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Explicit kernel model for the original test-adapter ownership body. Native
// acceptance must separately execute the IP Helper implementation on Windows.
type windowsCONNECTAliasModel struct {
	identity                 windowsCONNECTAliasIdentity
	present                  map[netip.Addr]windowsCONNECTAliasRecord
	creates, removes         int
	createFault, removeFault int
	partial                  bool
}

type windowsCONNECTAliasWaiter struct {
	context.Context
	mu      sync.Mutex
	calls   int
	entered chan struct{}
}

func (ctx *windowsCONNECTAliasWaiter) Err() error {
	ctx.mu.Lock()
	ctx.calls++
	if ctx.calls == 2 {
		close(ctx.entered)
	}
	ctx.mu.Unlock()
	return ctx.Context.Err()
}

func newWindowsCONNECTAliasModel() *windowsCONNECTAliasModel {
	return &windowsCONNECTAliasModel{identity: windowsCONNECTAliasIdentity{7, 91}, present: make(map[netip.Addr]windowsCONNECTAliasRecord)}
}
func (k *windowsCONNECTAliasModel) Inventory(ctx context.Context) (windowsCONNECTAliasIdentity, map[netip.Addr]windowsCONNECTAliasRecord, error) {
	result := make(map[netip.Addr]windowsCONNECTAliasRecord)
	for key, value := range k.present {
		result[key] = value
	}
	return k.identity, result, ctx.Err()
}
func (k *windowsCONNECTAliasModel) Create(ctx context.Context, identity windowsCONNECTAliasIdentity, address netip.Addr) (*windowsCONNECTAliasRecord, error) {
	k.creates++
	if _, exists := k.present[address]; exists {
		return nil, errors.New("native collision")
	}
	if k.creates == k.createFault && !k.partial {
		return nil, errors.New("native create failed")
	}
	record := windowsCONNECTAliasRecord{identity, address, 32, true, int64(100 + k.creates)}
	k.present[address] = record
	if k.creates == k.createFault {
		return &record, errors.New("native post-create read failed")
	}
	return &record, ctx.Err()
}
func (k *windowsCONNECTAliasModel) Delete(ctx context.Context, record windowsCONNECTAliasRecord) error {
	k.removes++
	if k.removes == k.removeFault {
		return errors.New("native removal failed")
	}
	delete(k.present, record.Address)
	return ctx.Err()
}

func TestWindowsCONNECTAliasOwnerControls(t *testing.T) {
	ctx := context.Background()
	join := func(context.Context) error { return nil }
	own := func(t *testing.T, k *windowsCONNECTAliasModel) *windowsCONNECTAliasOwner {
		t.Helper()
		owner, err := windowsCONNECTOwnAliases(ctx, k)
		if err != nil || owner == nil {
			t.Fatal("original alias acquisition", err)
		}
		t.Cleanup(owner.release)
		return owner
	}
	t.Run("joined-idempotent", func(t *testing.T) {
		k := newWindowsCONNECTAliasModel()
		owner := own(t, k)
		joined := 0
		if err := owner.Close(ctx, func(context.Context) error {
			joined++
			if len(k.present) != 2 {
				t.Fatal("aliases retired before original join")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !owner.closed || owner.unlock || len(k.present) != 0 || k.removes != 2 || joined != 1 {
			t.Fatal("original aliases did not join and retire")
		}
		if owner.Close(ctx, func(context.Context) error { t.Fatal("closed alias owner rejoined"); return nil }) != nil || k.removes != 2 {
			t.Fatal("closed alias repeated mutation")
		}
	})
	t.Run("collision-before-mutation", func(t *testing.T) {
		k := newWindowsCONNECTAliasModel()
		address := windowsCONNECTAliasAddresses[1]
		k.present[address] = windowsCONNECTAliasRecord{Address: address}
		owner, err := windowsCONNECTOwnAliases(ctx, k)
		if owner != nil {
			defer owner.release()
		}
		if err == nil || owner != nil || k.creates != 0 || k.removes != 0 || len(k.present) != 1 {
			t.Fatal("existing second alias allowed an earlier mutation")
		}
	})
	for _, partial := range []bool{false, true} {
		name := "failed-create-retains-first"
		if partial {
			name = "partial-create-retains-second"
		}
		t.Run(name, func(t *testing.T) {
			k := newWindowsCONNECTAliasModel()
			k.createFault, k.partial = 2, partial
			owner, err := windowsCONNECTOwnAliases(ctx, k)
			if owner == nil || err == nil {
				t.Fatal("failed creation lost original owner")
			}
			defer owner.release()
			want := 1
			if partial {
				want = 2
			}
			if len(owner.added) != want || owner.Close(ctx, join) != nil || len(k.present) != 0 || k.removes != want {
				t.Fatal("partial native creation escaped original cleanup")
			}
		})
	}
	t.Run("failed-join-keeps-owner", func(t *testing.T) {
		k := newWindowsCONNECTAliasModel()
		owner := own(t, k)
		failure := errors.New("unjoined original peer")
		if err := owner.Close(ctx, func(context.Context) error { return failure }); !errors.Is(err, failure) || k.removes != 0 || len(k.present) != 2 || owner.closed || !owner.unlock {
			t.Fatal("failed native join retired original aliases")
		}
		if owner.Close(ctx, join) != nil {
			t.Fatal("original alias retry failed")
		}
	})
	t.Run("failed-delete-keeps-owner", func(t *testing.T) {
		k := newWindowsCONNECTAliasModel()
		owner := own(t, k)
		k.removeFault = 2
		if owner.Close(ctx, join) == nil || len(owner.added) != 1 || len(k.present) != 1 || owner.closed || !owner.unlock {
			t.Fatal("failed removal discarded original retry owner")
		}
		k.removeFault = 0
		if owner.Close(ctx, join) != nil || len(k.present) != 0 || k.removes != 3 {
			t.Fatal("original removal retry failed")
		}
	})
	for _, fault := range []string{"address-index", "address-luid", "mask", "skip", "recreated", "loopback-index", "loopback-luid", "unobserved-create"} {
		t.Run(fault, func(t *testing.T) {
			k := newWindowsCONNECTAliasModel()
			owner := own(t, k)
			address := windowsCONNECTAliasAddresses[1]
			original := k.present[address]
			changed := original
			switch fault {
			case "address-index":
				changed.Interface.Index++
			case "address-luid":
				changed.Interface.LUID++
			case "mask":
				changed.Bits = 24
			case "skip":
				changed.Skip = false
			case "recreated":
				changed.Created++
			case "loopback-index":
				k.identity.Index++
			case "loopback-luid":
				k.identity.LUID++
			case "unobserved-create":
				owner.added[1].Created = 0
			}
			k.present[address] = changed
			if owner.Close(ctx, join) == nil || k.removes != 0 || len(k.present) != 2 || owner.closed || !owner.unlock {
				t.Fatal("replaced native alias acquired deletion authority")
			}
			k.identity = original.Interface
			k.present[address] = original
			owner.added[1] = original
			if owner.Close(ctx, join) != nil {
				t.Fatal("original alias restoration could not retire")
			}
		})
	}
	t.Run("absent-original", func(t *testing.T) {
		k := newWindowsCONNECTAliasModel()
		owner := own(t, k)
		delete(k.present, windowsCONNECTAliasAddresses[1])
		if owner.Close(ctx, join) != nil || len(k.present) != 0 || k.removes != 1 {
			t.Fatal("absent alias triggered foreign mutation")
		}
	})
	t.Run("nil-join", func(t *testing.T) {
		k := newWindowsCONNECTAliasModel()
		owner := own(t, k)
		if owner.Close(ctx, nil) == nil || k.removes != 0 {
			t.Fatal("missing join retired original aliases")
		}
		if owner.Close(ctx, join) != nil {
			t.Fatal("original join retry failed")
		}
	})
	t.Run("cancelled-cleanup", func(t *testing.T) {
		k := newWindowsCONNECTAliasModel()
		owner := own(t, k)
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if owner.Close(cancelled, join) == nil || k.removes != 0 || owner.closed || !owner.unlock {
			t.Fatal("cancelled cleanup retired original aliases")
		}
		if owner.Close(ctx, join) != nil {
			t.Fatal("original caller retry failed")
		}
	})
	t.Run("cancelled-waiter", func(t *testing.T) {
		k := newWindowsCONNECTAliasModel()
		owner := own(t, k)
		base, cancel := context.WithCancel(ctx)
		defer cancel()
		waiting := &windowsCONNECTAliasWaiter{Context: base, entered: make(chan struct{})}
		done := make(chan error, 1)
		go func() {
			next, err := windowsCONNECTOwnAliases(waiting, k)
			if next != nil {
				next.release()
			}
			done <- err
		}()
		select {
		case <-waiting.entered:
		case <-time.After(time.Second):
			owner.release()
			<-done
			t.Fatal("original alias waiter never entered its context gate")
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) || k.creates != 2 || k.removes != 0 {
				t.Fatal("cancelled alias waiter mutated the original owner")
			}
		case <-time.After(time.Second):
			owner.release()
			<-done
			t.Fatal("cancelled alias waiter did not join behind original owner")
		}
		if owner.Close(ctx, join) != nil {
			t.Fatal("original owner could not retire after cancelled waiter")
		}
	})
}
