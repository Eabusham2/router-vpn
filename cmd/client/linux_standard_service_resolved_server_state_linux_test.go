//go:build linux

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestResolvedServerStateCancelledAdmission(t *testing.T) {
	original, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	admission, cancel := context.WithCancel(original)
	helper := &linuxResolvedHelper{}
	helper.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := helper.serverStateScoped(admission, original, 0, "vpn.example"); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-original.Done():
		helper.mu.Unlock()
		t.Fatal("cancelled scope retained helper frame queue")
	}
	if helper.failure != nil || helper.sequence != 0 {
		t.Fatal("cancelled admission tainted original observer", helper.failure, helper.sequence)
	}
	helper.mu.Unlock()
}
