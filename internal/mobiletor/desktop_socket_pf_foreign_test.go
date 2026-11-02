//go:build go1.25

package mobiletor

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestDesktopPFReadbackNestedNativeCommandBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		deadline, _ := ctx.Deadline()
		started := time.Now()
		var active, peak, complete atomic.Int32
		command := func(captured context.Context) error {
			release, err := desktopPFEnterCommand(captured)
			if err != nil {
				return err
			}
			defer release()
			actual, _ := captured.Deadline()
			if actual != deadline {
				return errors.New("nested native command replaced its deadline")
			}
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			select {
			case <-time.After(30 * time.Millisecond):
				complete.Add(1)
				return nil
			case <-captured.Done():
				return captured.Err()
			}
		}
		var outer []func(context.Context) error
		for range 4 {
			outer = append(outer, func(captured context.Context) error {
				return desktopPFReadback(captured, command, command, command, command)
			})
		}
		err := desktopPFReadback(ctx, outer...)
		if err != nil || active.Load() != 0 || peak.Load() != 4 || complete.Load() != 16 || time.Since(started) != 120*time.Millisecond {
			t.Fatal("nested PF inspections lost the shared four-command limit, complete work or original deadline", err, active.Load(), peak.Load(), complete.Load(), time.Since(started))
		}
	})
}

func TestDesktopPFReadbackQueuedCommandCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := desktopPFWithCommandBudget(context.Background())
		var releases []func()
		for range 4 {
			release, err := desktopPFEnterCommand(ctx)
			if err != nil {
				t.Fatal(err)
			}
			releases = append(releases, release)
		}
		waiting, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		var launched atomic.Bool
		go func() {
			release, err := desktopPFEnterCommand(waiting)
			if err == nil {
				launched.Store(true)
				release()
			}
			done <- err
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) || launched.Load() {
			t.Fatal("cancelled queued PF command acquired native launch authority", err)
		}
		for _, release := range releases {
			release()
		}
		release, err := desktopPFEnterCommand(ctx)
		if err != nil {
			t.Fatal("cancelled queued command leaked its slot", err)
		}
		release()
	})
}

func TestDesktopPFReadbackCommandSlotJoinsCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		shared := desktopPFWithCommandBudget(context.Background())
		ctx, cancel := context.WithCancel(shared)
		cleanup := make(chan struct{})
		cleanupClosed := false
		defer func() {
			if !cleanupClosed {
				close(cleanup)
			}
		}()
		done := make(chan error, 1)
		var entered, joined atomic.Int32
		command := func(captured context.Context) error {
			release, err := desktopPFEnterCommand(captured)
			if err != nil {
				return err
			}
			defer release()
			entered.Add(1)
			<-captured.Done()
			<-cleanup
			joined.Add(1)
			return captured.Err()
		}
		go func() { done <- desktopPFReadback(ctx, command, command, command, command) }()
		synctest.Wait()
		if entered.Load() != 4 {
			t.Fatal("cleanup fixture did not enter all commands")
		}
		cancel()
		synctest.Wait()
		other, stop := context.WithCancel(shared)
		defer stop()
		admitted := make(chan struct{})
		otherDone := make(chan struct{})
		go func() {
			defer close(otherDone)
			release, err := desktopPFEnterCommand(other)
			if err == nil {
				close(admitted)
				release()
			}
		}()
		synctest.Wait()
		select {
		case <-admitted:
			t.Fatal("PF native command slot was released before cleanup joined")
		default:
		}
		select {
		case <-done:
			t.Fatal("PF readback returned before all native cleanup joined")
		default:
		}
		close(cleanup)
		cleanupClosed = true
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) || joined.Load() != 4 {
			t.Fatal("PF cleanup lost cancellation or complete joins", err, joined.Load())
		}
		<-otherDone
		select {
		case <-admitted:
		default:
			t.Fatal("joined PF commands did not release their native slots")
		}
	})
}

func TestDesktopPFReadbackForeignBranches(t *testing.T) {
	const root = "com.apple/zzz.foreign"
	for _, branch := range []string{root, root + "/*"} {
		for _, kind := range []string{"earlier", "stateful-in", "stateful-out", "unknown", "nat", "rdr", "binat", "read-error"} {
			t.Run(branch+"/"+kind, func(t *testing.T) {
				want := errors.New("captured foreign read failed")
				rules := func(_ context.Context, anchor string) (string, error) {
					if anchor != branch {
						return "", nil
					}
					switch kind {
					case "earlier":
						return "block out all", nil
					case "stateful-in":
						return "pass in all keep state", nil
					case "stateful-out":
						return "pass out all keep state", nil
					case "unknown":
						return "unexpected filter", nil
					case "read-error":
						return "", want
					}
					return "", nil
				}
				translations := func(_ context.Context, anchor string) error {
					if anchor == branch && (kind == "nat" || kind == "rdr" || kind == "binat") {
						return desktopPFNoTranslationText([]byte(kind + " on en0 from any to any -> 192.0.2.1"))
					}
					return desktopPFNoTranslationText([]byte("nat-anchor \"owned/*\" all\nrdr-anchor \"owned/*\" all\nbinat-anchor \"owned/*\" all\n}"))
				}
				err := desktopPFForeignBranches(context.Background(), root, kind == "earlier", rules, translations, nil)
				if err == nil || kind == "read-error" && !errors.Is(err, want) {
					t.Fatal("parallel foreign PF inspection accepted an original refusal", branch, kind, err)
				}
			})
		}
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		var calls [4]atomic.Int32
		started := time.Now()
		rules := func(_ context.Context, anchor string) (string, error) {
			index := 0
			if strings.HasSuffix(anchor, "/*") {
				index = 2
			}
			calls[index].Add(1)
			time.Sleep(30 * time.Millisecond)
			return "block out all\npass in all no state", nil
		}
		translations := func(_ context.Context, anchor string) error {
			index := 1
			if strings.HasSuffix(anchor, "/*") {
				index = 3
			}
			calls[index].Add(1)
			time.Sleep(30 * time.Millisecond)
			return nil
		}
		err := desktopPFForeignBranches(ctx, root, false, rules, translations, nil)
		if err != nil || time.Since(started) != 30*time.Millisecond {
			t.Fatal("foreign PF branch queries remained serial within the original deadline", err, time.Since(started))
		}
		for index := range calls {
			if calls[index].Load() != 1 {
				t.Fatal("foreign PF inspection omitted or repeated an original branch")
			}
		}
	})
}
