//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestResolvedHelperBoundedOriginalLaunch(t *testing.T) {
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	long, stop := context.WithTimeout(context.Background(), 3*time.Minute)
	defer stop()
	for name, ctx := range map[string]context.Context{"nil": nil, "unbounded": context.Background(), "cancelled": expired, "renewed": long} {
		t.Run(name, func(t *testing.T) {
			h, err := startLinuxResolvedHelper(ctx, t.TempDir(), strings.Repeat("a", 32), "vpn.example")
			if err == nil || h == nil || h.command != nil || h.pidfd != nil {
				t.Fatal("unbounded launch created a process", err)
			}
			cleanup, done := context.WithTimeout(context.Background(), time.Second)
			defer done()
			if err = h.Close(cleanup); err != nil {
				t.Fatal("partial descriptor owner could not retire", err)
			}
		})
	}
}
func TestResolvedHelperReadOnlyJoinedRetirement(t *testing.T) {
	t.Run("joined-error-is-not-observation-success", func(t *testing.T) {
		command := exec.Command("/bin/false")
		err := command.Run()
		if err == nil {
			t.Fatal("failed child unexpectedly succeeded")
		}
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		joined := make(chan struct{})
		close(joined)
		original, cancel := context.WithCancel(context.Background())
		cancel()
		h := &linuxResolvedHelper{original: original, joined: joined, waitErr: errors.New("original observation failed"), padding: reader, capture: writer, closedFiles: map[*os.File]bool{}}
		ctx, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		if err = h.current(ctx); err == nil {
			t.Fatal("joined failure became current authority")
		}
		if err = h.Close(ctx); err != nil || !h.closed || h.waitErr == nil {
			t.Fatal("read-only join did not retain failure diagnostic", err)
		}
		if _, err = reader.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("original descriptor survived joined retirement", err)
		}
	})
	t.Run("unjoined-owner-remains", func(t *testing.T) {
		h := &linuxResolvedHelper{joined: make(chan struct{}), closedFiles: map[*os.File]bool{}}
		ctx, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		if err := h.Close(ctx); err == nil || h.closed {
			t.Fatal("missing original pidfd joined a live child")
		}
	})
	t.Run("failed-native-close-remains", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		reader.Close()
		h := &linuxResolvedHelper{padding: reader, closedFiles: map[*os.File]bool{}}
		ctx, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		if err = h.Close(ctx); err == nil || h.closed {
			t.Fatal("failed original handle close was normalized")
		}
	})
}

func TestResolvedObservationTransactionLifetime(t *testing.T) {
	newOwner := func(request context.Context) *linuxResolvedHelper {
		deadline, _ := request.Deadline()
		h := &linuxResolvedHelper{request: request, cancellationJoined: make(chan struct{})}
		h.original, h.retainedCancel = context.WithDeadline(context.WithoutCancel(request), deadline)
		h.stopCancellation = context.AfterFunc(request, func() { h.retainedCancel(); close(h.cancellationJoined) })
		t.Cleanup(h.retainedCancel)
		return h
	}
	t.Run("successful-rpc-retirement-keeps-original-deadline", func(t *testing.T) {
		request, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		h := newOwner(request)
		if err := h.retainObservationLifetime(request); err != nil {
			t.Fatal(err)
		}
		before, _ := request.Deadline()
		after, _ := h.original.Deadline()
		cancel()
		if h.original.Err() != nil || !before.Equal(after) {
			t.Fatal("successful RPC lost or renewed transaction")
		}
		h.retainedCancel()
		if !errors.Is(h.original.Err(), context.Canceled) {
			t.Fatal("retired owner remained live")
		}
	})
	t.Run("cancelled-original-cannot-transfer", func(t *testing.T) {
		request, cancel := context.WithTimeout(context.Background(), time.Second)
		h := newOwner(request)
		cancel()
		<-h.cancellationJoined
		if h.retainObservationLifetime(request) == nil || h.original.Err() == nil {
			t.Fatal("cancelled original acquired replacement lifetime")
		}
	})
	t.Run("original-deadline-expires-after-rpc", func(t *testing.T) {
		request, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		h := newOwner(request)
		if err := h.retainObservationLifetime(request); err != nil {
			t.Fatal(err)
		}
		cancel()
		<-h.original.Done()
		if !errors.Is(h.original.Err(), context.DeadlineExceeded) {
			t.Fatal("original deadline renewed")
		}
	})
	t.Run("failed-helper-cannot-transfer", func(t *testing.T) {
		request, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		h := newOwner(request)
		h.failure = errors.New("original daemon changed")
		if h.retainCompleted(request) == nil || h.stopCancellation == nil {
			t.Fatal("changed daemon acquired retained authority")
		}
		cancel()
		<-h.cancellationJoined
	})
}
