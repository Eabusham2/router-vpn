//go:build go1.25

package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

const pfSystemChildrenFixtureNamespace = "com.apple/000.router-vpn"
const pfSystemChildrenFixtureInventory = "000.router-vpn\n100.fixture\n250.ApplicationFirewall\n"

func TestDesktopPFReadbackSystemChildrenUseIdleSlotsWithoutExtendingReadback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		deadline, _ := ctx.Deadline()
		sibling := make(chan struct{})
		var siblingOnce sync.Once
		var active, maximum atomic.Int32
		var mu sync.Mutex
		seen := make(map[string]int)
		read := func(captured context.Context, kind, anchor string) error {
			if actual, ok := captured.Deadline(); !ok || actual != deadline {
				return errors.New("child read replaced its original deadline")
			}
			release, err := desktopPFEnterCommand(captured)
			if err != nil {
				return err
			}
			defer release()
			count := active.Add(1)
			defer active.Add(-1)
			for old := maximum.Load(); old < count; old = maximum.Load() {
				if maximum.CompareAndSwap(old, count) {
					break
				}
			}
			mu.Lock()
			seen[kind+" "+anchor]++
			mu.Unlock()
			if kind == "rules" && anchor == "com.apple/250.ApplicationFirewall" {
				siblingOnce.Do(func() { close(sibling) })
			}
			if kind == "rules" && anchor == "com.apple/100.fixture" {
				select {
				case <-sibling:
				case <-captured.Done():
					return errors.New("slow foreign child prevented an independent sibling from using idle command slots")
				}
			}
			return captured.Err()
		}
		err := desktopPFSystemChildReadback(ctx, pfSystemChildrenFixtureNamespace, []byte(pfSystemChildrenFixtureInventory),
			func(c context.Context, anchor string) (string, error) { return "", read(c, "rules", anchor) },
			func(c context.Context, anchor string) error { return read(c, "nat", anchor) })
		if err != nil || ctx.Err() != nil || active.Load() != 0 || maximum.Load() > 4 || len(seen) != 8 {
			t.Fatal("original bounded child inventory did not join all independent observations", err, seen, active.Load(), maximum.Load())
		}
		for _, root := range []string{"com.apple/100.fixture", "com.apple/250.ApplicationFirewall"} {
			for _, anchor := range []string{root, root + "/*"} {
				for _, kind := range []string{"rules", "nat"} {
					if seen[kind+" "+anchor] != 1 {
						t.Fatal("child read omitted, repeated or substituted an original query", kind, anchor, seen)
					}
				}
			}
		}
	})
}

func TestDesktopPFReadbackSystemChildrenJoinCancellationAndRejectLateSuccess(t *testing.T) {
	for _, mode := range []string{"cancel", "late-success", "sibling-failure"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				entered, cancelled, cleanup := make(chan struct{}), make(chan struct{}), make(chan struct{})
				defer func() {
					select {
					case <-cleanup:
					default:
						close(cleanup)
					}
				}()
				failure := errors.New("original sibling filter read failed")
				var joined atomic.Bool
				results := make(chan error, 1)
				go func() {
					results <- desktopPFSystemChildReadback(ctx, pfSystemChildrenFixtureNamespace, []byte(pfSystemChildrenFixtureInventory),
						func(captured context.Context, anchor string) (string, error) {
							release, err := desktopPFEnterCommand(captured)
							if err != nil {
								return "", err
							}
							defer release()
							if anchor == "com.apple/100.fixture" {
								close(entered)
								<-captured.Done()
								close(cancelled)
								<-cleanup
								joined.Store(true)
								if mode == "late-success" {
									return "", nil
								}
								return "", captured.Err()
							}
							if mode == "sibling-failure" && anchor == "com.apple/250.ApplicationFirewall" {
								<-entered
								return "", failure
							}
							return "", captured.Err()
						}, func(captured context.Context, _ string) error {
							release, err := desktopPFEnterCommand(captured)
							if err == nil {
								release()
							}
							return err
						})
				}()
				<-entered
				if mode != "sibling-failure" {
					cancel()
				}
				<-cancelled
				synctest.Wait()
				select {
				case err := <-results:
					t.Fatal("child readback returned before an admitted original reader joined", err)
				default:
				}
				close(cleanup)
				err := <-results
				want := error(context.Canceled)
				if mode == "sibling-failure" {
					want = failure
				}
				if !joined.Load() || !errors.Is(err, want) {
					t.Fatal("child readback published late success or lost its exact refusal", err)
				}
			})
		})
	}
}

func TestDesktopPFReadbackSystemChildrenKeepExactForeignInventoryAndRefusals(t *testing.T) {
	for _, fault := range []string{"earlier-direct", "earlier-recursive", "stateful-direct", "stateful-recursive", "translation-direct", "translation-recursive", "unknown", "duplicate", "escaping"} {
		t.Run(fault, func(t *testing.T) {
			inventory := pfSystemChildrenFixtureInventory
			root := "com.apple/100.fixture"
			if strings.HasPrefix(fault, "earlier-") {
				inventory = "000.before\n"
				root = "com.apple/000.before"
			}
			switch fault {
			case "unknown":
				inventory += "unowned*\n"
			case "duplicate":
				inventory += "com.apple/100.fixture\n"
			case "escaping":
				inventory += "../foreign\n"
			}
			if strings.HasSuffix(fault, "recursive") {
				root += "/*"
			}
			refusal := errors.New("original foreign translation refused")
			err := desktopPFSystemChildReadback(context.Background(), pfSystemChildrenFixtureNamespace, []byte(inventory),
				func(_ context.Context, anchor string) (string, error) {
					if anchor != root {
						return "", nil
					}
					if strings.HasPrefix(fault, "earlier-") {
						return "block out all", nil
					}
					if strings.HasPrefix(fault, "stateful-") {
						return "pass out all keep state", nil
					}
					return "", nil
				}, func(_ context.Context, anchor string) error {
					if strings.HasPrefix(fault, "translation-") && anchor == root {
						return refusal
					}
					return nil
				})
			if err == nil || strings.HasPrefix(fault, "translation-") && !errors.Is(err, refusal) {
				t.Fatal("parallel child inspection lost an original inventory/filter/translation rejection", fault, err)
			}
		})
	}
	t.Run("complete-larger-inventory", func(t *testing.T) {
		var inventory strings.Builder
		for index := range 33 {
			fmt.Fprintf(&inventory, "100.child%d\n", index)
		}
		var calls atomic.Int32
		err := desktopPFSystemChildReadback(context.Background(), pfSystemChildrenFixtureNamespace, []byte(inventory.String()),
			func(context.Context, string) (string, error) { calls.Add(1); return "block out all", nil },
			func(context.Context, string) error { calls.Add(1); return nil })
		if err != nil || calls.Load() != 4*33 {
			t.Fatal("bounded batches omitted a later original child", err, calls.Load())
		}
	})
}
