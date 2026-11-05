//go:build linux

package linuxprotection

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNodeControlOriginalContextGatePreservesAdmission(t *testing.T) {
	control := &NodeControl{gate: make(chan struct{}, 1), admitted: true}
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() { close(entered); result <- control.CurrentContext(caller) }()
	<-entered
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("strict control lost original cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("strict control ignored original caller while waiting for occupied gate")
	}
	if !control.admitted || control.uncertain != nil {
		t.Fatal("observer expiry consumed original admission", control.uncertain)
	}
}

func TestNodeControlOriginalContextKeepsRealFailure(t *testing.T) {
	control := &NodeControl{gate: make(chan struct{}, 1), admitted: true}
	control.gate <- struct{}{}
	failure := control.CurrentContext(context.Background())
	if failure == nil || control.uncertain == nil || failure != control.uncertain {
		t.Fatal("missing authenticated native owner was not latched", failure)
	}
	if control.CurrentContext(context.Background()) != failure {
		t.Fatal("later observation revived failed original owner")
	}
}
