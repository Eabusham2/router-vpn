//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

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
}
