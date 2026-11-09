//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

type processObservationWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (ctx *processObservationWaitingContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

func TestWindowsControllerFoundationProcessObservationContext(t *testing.T) {
	original, err := OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := original.AliveContext(ctx); err != nil {
		t.Fatal("original native process not live", err)
	}
	original.mu.Lock()
	short, end := context.WithTimeout(ctx, 20*time.Millisecond)
	result := make(chan error, 1)
	go func() { result <- original.AliveContext(short) }()
	<-short.Done()
	var observed error
	select {
	case observed = <-result:
	case <-time.After(time.Second):
		original.mu.Unlock()
		observed = <-result
		t.Fatal("held original process mutex ignored observation deadline", observed)
	}
	original.mu.Unlock()
	end()
	if !errors.Is(observed, context.DeadlineExceeded) {
		t.Fatal("held native process observation lost original deadline", observed)
	}
	if err := original.AliveContext(ctx); err != nil {
		t.Fatal("observation expiry retired the retained process", err)
	}
	child := &GUIChild{process: original}
	if err := child.AliveContext(ctx); err != nil {
		t.Fatal("GUI observation bypassed original native process", err)
	}
	child.retiring.Store(true)
	if !errors.Is(child.AliveContext(ctx), ErrClosed) {
		t.Fatal("retiring child admitted strict observation")
	}
	identity, err := original.Identity()
	if err != nil {
		t.Fatal(err)
	}
	started, err := original.StartTimeUTCTicks()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"token", "creation"} {
		t.Run(kind, func(t *testing.T) {
			observe := func(caller context.Context) error {
				if kind == "token" {
					got, err := original.IdentityContext(caller)
					if err == nil && got != identity {
						return errors.New("contextual observation changed the retained native primary token")
					}
					return err
				}
				got, err := original.StartTimeUTCTicksContext(caller)
				if err == nil && got != started {
					return errors.New("contextual observation changed the retained native creation identity")
				}
				return err
			}
			if err := observe(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := observe(nil); err == nil {
				t.Fatal("native process identity query admitted a missing caller")
			}
			parent, stop := context.WithCancel(context.Background())
			defer stop()
			waiting := &processObservationWaitingContext{Context: parent, waiting: make(chan struct{})}
			original.mu.Lock()
			var released sync.Once
			unlock := func() { released.Do(original.mu.Unlock) }
			defer unlock()
			done := make(chan error, 1)
			go func() { done <- observe(waiting) }()
			select {
			case <-waiting.waiting:
			case <-time.After(time.Second):
				stop()
				unlock()
				<-done
				t.Fatal("native process identity query did not reach its original caller's held-lock admission")
			}
			stop()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("native process identity query lost original cancellation", err)
				}
			case <-time.After(time.Second):
				unlock()
				<-done
				t.Fatal("native process identity query waited for an ambient observer after cancellation")
			}
			unlock()
			if err := observe(context.Background()); err != nil {
				t.Fatal("cancelled process identity query retired the original handle or poisoned its retry", err)
			}
		})
	}
}
