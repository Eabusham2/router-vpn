package mobiletor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestDesktopDarwinIdentityReadsShareOriginalBudgetAndJoin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type ownerKey struct{}
		owner := new(int)
		parent := context.WithValue(context.Background(), ownerKey{}, owner)
		ctx, cancel := context.WithTimeout(parent, 40*time.Millisecond)
		defer cancel()
		deadline, _ := ctx.Deadline()
		started := time.Now()
		var completed atomic.Int32
		query := func(captured context.Context) error {
			actual, ok := captured.Deadline()
			if !ok || actual != deadline || captured.Value(ownerKey{}) != owner {
				return errors.New("identity query replaced original operation")
			}
			release, err := desktopPFEnterCommand(captured)
			if err != nil {
				return err
			}
			defer release()
			select {
			case <-time.After(30 * time.Millisecond):
				completed.Add(1)
				return nil
			case <-captured.Done():
				return captured.Err()
			}
		}
		err := desktopDarwinIdentityReadback(ctx, query, query)
		if err != nil || completed.Load() != 2 || time.Since(started) != 30*time.Millisecond {
			t.Fatal("identity reads did not jointly finish within original budget", completed.Load(), time.Since(started), err)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		failure := errors.New("original directory owner changed")
		var active, finished atomic.Int32
		first := func(context.Context) error { time.Sleep(20 * time.Millisecond); return failure }
		second := func(captured context.Context) error {
			active.Add(1)
			defer active.Add(-1)
			<-captured.Done()
			time.Sleep(5 * time.Millisecond)
			finished.Add(1)
			return captured.Err()
		}
		err := desktopDarwinIdentityReadback(ctx, first, second)
		if !errors.Is(err, failure) || active.Load() != 0 || finished.Load() != 1 {
			t.Fatal("failed identity read escaped original joined sibling", active.Load(), finished.Load(), err)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	query := func(context.Context) error { called = true; return nil }
	if err := desktopDarwinIdentityReadback(ctx, query, query); !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled identity operation ran a directory query", called, err)
	}
}
