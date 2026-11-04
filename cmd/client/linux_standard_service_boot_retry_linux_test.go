//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Only kernel policy is modeled. The original slot, saved-state transaction,
// watcher, deadlines, cancellation and notification socket are shipping code.
type linuxBootRetryModel struct {
	legacyExitKernelProtection
	failing, blocking atomic.Bool
	calls             atomic.Int32
	entered           chan context.Context
}

func (p *linuxBootRetryModel) Current(ctx context.Context, lease *os.File) error {
	p.calls.Add(1)
	select {
	case p.entered <- ctx:
	default:
	}
	if p.blocking.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	if p.failing.Load() {
		return errors.New("original boot acknowledgment is temporarily unavailable")
	}
	return p.legacyExitKernelProtection.Current(ctx, lease)
}

func linuxBootRetryFixture(t *testing.T) (*linuxStandardService, *legacyProtectionModel, *linuxBootRetryModel) {
	t.Helper()
	f := newLegacyExitFixture(t, "always")
	f.a.profiles.Profiles[0].Endpoint = "203.0.113.43"
	applyProfileDefaults(&f.a.profiles.Profiles[0])
	if err := f.a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	linuxStandardServicePreviousBootState(t, f.root, "control", "203.0.113.43")
	image, _ := os.Stat("/proc/self/exe")
	namespace, _ := os.Stat("/proc/thread-self/ns/net")
	s := newLinuxStandardService(f.root, image, namespace)
	model := newLegacyProtectionModel()
	wrapper := &linuxBootRetryModel{entered: make(chan context.Context, 32)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wanted := errors.New("first original creator acknowledgement interrupted")
	create := func(ctx context.Context, session, digest string, endpoints []netip.Addr, lan bool, lease *os.File) (legacyExitKernelProtection, error) {
		original, err := model.create(ctx, session, digest, endpoints, lan, lease)
		if err != nil {
			return original, err
		}
		wrapper.legacyExitKernelProtection = original
		return wrapper, wanted
	}
	s.bootFailure = s.reassertWithObservers(ctx, func() error { return nil }, func(context.Context) error { return nil }, create)
	if !errors.Is(s.bootFailure, wanted) || s.boot == nil || s.boot.kernel != wrapper || s.boot.persisted {
		t.Fatal("fixture did not retain original partial creator", s.bootFailure)
	}
	t.Cleanup(func() {
		wrapper.failing.Store(false)
		wrapper.blocking.Store(false)
		cleanup, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		<-s.gate
		defer func() { s.gate <- struct{}{} }()
		if err := s.repairBoot(cleanup); err != nil {
			t.Error("fixture original creator failed repair", err)
			return
		}
		lease, err := acquireLegacyExitMutationLease(cleanup, f.root)
		if err != nil {
			t.Error(err)
			return
		}
		defer lease.Close()
		if err = s.boot.release(cleanup, lease); err != nil {
			t.Error("fixture original creator failed release", err)
		}
	})
	return s, model, wrapper
}

func linuxBootWatch(t *testing.T, s *linuxStandardService) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	lifetime, cancel := context.WithCancel(context.Background())
	joined := make(chan struct{})
	go func() { defer close(joined); s.watch(lifetime) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("original boot watcher did not join cancellation")
		}
	})
	return cancel, joined
}

func TestLinuxStandardServiceBootWatcherRetriesOriginalCreatorWithoutClient(t *testing.T) {
	s, model, native := linuxBootRetryFixture(t)
	original := s.boot
	native.failing.Store(true)
	cancel, joined := linuxBootWatch(t, s)
	select {
	case <-native.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("degraded service watcher never retried its original boot creator without a client")
	}
	<-s.gate
	before := native.calls.Load()
	invalid := s.bootFailure == nil || s.boot != original || s.boot.persisted || !time.Now().Before(s.bootRetryAfter)
	s.retryBoot(context.Background())
	repeated := native.calls.Load() != before
	s.gate <- struct{}{}
	if invalid {
		t.Fatal("failed original boot retry discarded its creator or reported readiness")
	}
	if repeated {
		t.Fatal("boot retry bypassed its bounded retry cadence")
	}
	native.failing.Store(false)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("original boot creator never recovered through the retained watcher")
		case <-native.entered:
			<-s.gate
			recovered := s.bootFailure == nil
			invalid := recovered && (s.boot != original || !s.boot.persisted || !s.boot.detached)
			s.gate <- struct{}{}
			if invalid {
				t.Fatal("boot recovery reconstructed or discarded original authority")
			}
			if recovered {
				cancel()
				<-joined
				<-s.gate
				calls := native.calls.Load()
				s.retryBoot(context.Background())
				repeated := native.calls.Load() != calls
				s.gate <- struct{}{}
				if repeated {
					t.Fatal("successful readiness repeated a completed repair")
				}
				model.mu.Lock()
				defer model.mu.Unlock()
				if len(model.events) != 1 || len(model.tables) != 1 {
					t.Fatal("retry replaced the original native creator", model.events)
				}
				return
			}
		}
	}
}

func TestLinuxStandardServiceBootWatcherCancellationJoinsOriginalAttempt(t *testing.T) {
	s, _, native := linuxBootRetryFixture(t)
	original := s.boot
	native.blocking.Store(true)
	cancel, joined := linuxBootWatch(t, s)
	select {
	case attempt := <-native.entered:
		deadline, bounded := attempt.Deadline()
		if !bounded || time.Until(deadline) > 4*time.Second {
			t.Fatal("boot repair escaped its bounded original attempt")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retained boot watcher never entered original retry")
	}
	cancel()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("service lifetime cancellation did not join entered original boot repair")
	}
	<-s.gate
	defer func() { s.gate <- struct{}{} }()
	if !errors.Is(s.bootFailure, context.Canceled) || s.boot != original || original.closed || original.persisted {
		t.Fatal("cancelled boot repair discarded its creator or reported completion", s.bootFailure)
	}
}

func linuxBootNotificationPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	convert := func(number int) *net.UnixConn {
		file := os.NewFile(uintptr(number), "boot-notification-fixture")
		connection, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		channel, ok := connection.(*net.UnixConn)
		if !ok {
			_ = connection.Close()
			t.Fatal("notification fixture lost actual native datagram channel")
		}
		t.Cleanup(func() { _ = channel.Close() })
		return channel
	}
	return convert(fds[0]), convert(fds[1])
}

func TestLinuxStandardServiceBootNotificationUsesOriginalDeadline(t *testing.T) {
	sender, receiver := linuxBootNotificationPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	body := []byte("READY=1\nSTATUS=original retained owner")
	if err := linuxStandardServiceNotifyChannel(ctx, sender, body); err != nil {
		t.Fatal(err)
	}
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 4096)
	n, err := receiver.Read(got)
	if err != nil || string(got[:n]) != string(body) {
		t.Fatal("actual native notification was missing or changed", err)
	}
	cancel()
	if err = linuxStandardServiceNotifyChannel(ctx, sender, body); err == nil {
		t.Fatal("cancelled boot repair emitted readiness")
	}
	_ = receiver.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if n, err = receiver.Read(got); err == nil || n != 0 {
		t.Fatal("cancelled notification reached actual native channel")
	}
}

func TestLinuxStandardServiceBootNotificationCancellationJoinsBlockedWrite(t *testing.T) {
	sender, _ := linuxBootNotificationPair(t)
	// Fill the real datagram queue before asking production notification to
	// write. This proves cancellation of an entered native operation.
	_ = sender.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	body := []byte("READY=1")
	for {
		if _, err := sender.Write(body); err != nil {
			if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				t.Fatal("could not fill actual notification queue", err)
			}
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	joined := make(chan error, 1)
	go func() { joined <- linuxStandardServiceNotifyChannel(ctx, sender, []byte("READY=1")) }()
	// Wait for the actual write to enter the network poller. A scheduling
	// delay cannot impersonate cancellation of an already entered operation.
	entered := false
	admission := time.NewTimer(3 * time.Second)
	defer admission.Stop()
	for !entered {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		for _, goroutine := range bytes.Split(stack[:n], []byte("\n\n")) {
			if bytes.Contains(goroutine, []byte("linuxStandardServiceNotifyChannel")) && bytes.Contains(goroutine, []byte("internal/poll.runtime_pollWait")) {
				entered = true
				break
			}
		}
		if entered {
			break
		}
		select {
		case err := <-joined:
			t.Fatal("notification unexpectedly completed through a full native queue", err)
		case <-admission.C:
			t.Fatal("actual readiness write never entered its native poller")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-joined:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("readiness lost its original cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("readiness write escaped cancelled original repair budget")
	}
}
