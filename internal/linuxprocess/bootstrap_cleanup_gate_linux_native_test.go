//go:build linux && routervpn_controller_privileged

package linuxprocess

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLinuxProcessNamespaceBootstrapCleanupWitnessOriginalGate(t *testing.T) {
	original := observationContextBootstrap(t)
	w := original.parent
	<-w.gate
	held := true
	defer func() {
		if held {
			w.gate <- struct{}{}
		}
	}()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	call := &observationContextEntered{Context: parent, entered: make(chan struct{})}
	call.target.Store(1)
	done := make(chan error, 1)
	go func() { done <- w.Close(call) }()
	select {
	case <-call.entered:
	case <-time.After(time.Second):
		t.Fatal("original close did not reach witness gate")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		w.gate <- struct{}{}
		held = false
		<-done
		t.Fatal("original cleanup ignored its caller while gate was held")
	}
	if w.revoked || w.closed {
		t.Fatal("unadmitted close retired original witness")
	}
	w.gate <- struct{}{}
	held = false
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if e := w.Close(ctx); e != nil {
		t.Fatal("original close retry did not join", e)
	}
	if !w.closed {
		t.Fatal("original witness remained unjoined")
	}
}
