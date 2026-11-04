//go:build linux && routervpn_controller_privileged

package linuxprocess

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These actual socket/process tests need root-owned captured descriptors, not
// namespace mutation. The installed native gate also requires every leaf inside
// its existing isolated namespace. The delay models original child cleanup;
// it does not claim to exercise native TUN or engine dependency retirement.
func retirementPair(t *testing.T) (*Channel, *Channel) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("retirement readiness requires actual root-owned channels")
	}
	first, file, err := ChannelPair()
	if first != nil {
		t.Cleanup(func() {
			if err := first.Close(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		if file != nil {
			file.Close()
		}
		t.Fatal(err)
	}
	second, err := CaptureChannel(file)
	if second != nil {
		t.Cleanup(func() {
			if err := second.Close(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}

type readinessContext struct {
	context.Context
	entered chan struct{}
}

func (c *readinessContext) Value(any) any { return nil }
func (c *readinessContext) AfterFunc(f func()) func() bool {
	close(c.entered)
	return context.AfterFunc(c.Context, f)
}

func TestLinuxProcessNamespaceRetirementReadinessWorker(t *testing.T) {
	if os.Getenv("ROUTERVPN_RETIREMENT_READINESS_CHILD") != "1" {
		return
	}
	channel, err := CaptureChannel(os.NewFile(3, "original-retirement-child"))
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	bootstrap, err := BindInheritedParent(ctx, channel, os.NewFile(4, "original-retirement-parent"), strings.Repeat("a", 64))
	if bootstrap != nil {
		defer bootstrap.Close(context.Background())
	}
	if err != nil {
		t.Fatal(err)
	}
	// The original five-second receive must not encompass this preceding phase.
	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	if err := bootstrap.Send(ctx, []byte("original-cleanup-complete")); err != nil {
		t.Fatal(err)
	}
	if body, err := bootstrap.Receive(ctx); err != nil || string(body) != "original-parent-received" {
		t.Fatal("original parent did not receive delayed child", err)
	}
}

func TestLinuxProcessNamespaceRetirementReadiness(t *testing.T) {
	for _, name := range []string{"delayed-original-child", "receive-still-five-seconds", "deadline", "cancelled", "local-close", "empty", "oversize", "foreign-sender", "unexpected-descriptor", "peer-eof", "original-replaced", "connection-replaced", "missing-deadline", "rights-unconsumed"} {
		t.Run(name, func(t *testing.T) {
			first, second := retirementPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
			defer cancel()
			if name == "delayed-original-child" {
				image, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				parent, err := CaptureSelf(ctx)
				if parent != nil {
					defer parent.Close(context.Background())
				}
				if err != nil {
					t.Fatal(err)
				}
				observed, err := parent.Current(ctx)
				if err != nil {
					t.Fatal(err)
				}
				directory, err := parent.DuplicateDirectory(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer directory.Close()
				child := exec.CommandContext(ctx, image, "-test.run=^TestLinuxProcessNamespaceRetirementReadinessWorker$", "-test.count=1", "-test.timeout=8s")
				child.Env = []string{"ROUTERVPN_RETIREMENT_READINESS_CHILD=1", "GORACE=atexit_sleep_ms=0"}
				child.ExtraFiles = []*os.File{second.file, directory}
				pidfd := -1
				child.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
				if err := child.Start(); err != nil {
					t.Fatal(err)
				}
				joined := make(chan error, 1)
				go func() { joined <- child.Wait() }()
				waited := false
				t.Cleanup(func() {
					if !waited {
						cancel()
						<-joined
					}
				})
				if pidfd < 0 {
					t.Fatal("original child has no creation pidfd")
				}
				original := os.NewFile(uintptr(pidfd), "original-readiness-child-pidfd")
				defer original.Close()
				if err := second.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := directory.Close(); err != nil {
					t.Fatal(err)
				}
				bootstrap, err := BindCreatedChild(ctx, first, parent, original, child.Process.Pid, observed.Image, strings.Repeat("a", 64))
				if bootstrap != nil {
					defer bootstrap.Close(context.Background())
				}
				if err != nil {
					t.Fatal("original child bootstrap failed", err)
				}
				start := time.Now()
				body, err := bootstrap.ReceiveAfterReady(ctx)
				if err != nil || string(body) != "original-cleanup-complete" || time.Since(start) < 5*time.Second {
					t.Fatal("original delayed child lost its exact authenticated frame", err)
				}
				if err := bootstrap.Send(ctx, []byte("original-parent-received")); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-joined:
					waited = true
					if err != nil {
						t.Fatal("original delayed child did not join", err)
					}
				case <-ctx.Done():
					t.Fatal("original delayed child exceeded existing deadline", ctx.Err())
				}
				return
			}
			if name == "missing-deadline" {
				if first.awaitMessage(context.Background()) == nil {
					t.Fatal("unbounded retirement phase admitted")
				}
				if _, err := first.currentIdentity(); err != nil {
					t.Fatal("refused unbounded caller changed untouched channel", err)
				}
				return
			}
			if name == "receive-still-five-seconds" || name == "deadline" {
				if name == "deadline" {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 60*time.Millisecond)
					defer stop()
				}
				start := time.Now()
				var err error
				if name == "deadline" {
					err = first.awaitMessage(ctx)
				} else {
					p, e := first.Receive(ctx, os.Getpid(), false)
					err = e
					if p != nil {
						p.Close()
					}
				}
				elapsed := time.Since(start)
				if err == nil || errors.Is(err, ErrPeerClosed) {
					t.Fatal("missing message became retirement authority", err)
				}
				if name == "deadline" && elapsed > time.Second {
					t.Fatal("caller deadline was extended", elapsed)
				}
				if name == "receive-still-five-seconds" && (elapsed < 5*time.Second || elapsed > 7*time.Second) {
					t.Fatal("ordinary exchange no longer has its original five-second bound", elapsed)
				}
				return
			}
			if name == "cancelled" || name == "local-close" {
				observed := &readinessContext{Context: ctx, entered: make(chan struct{})}
				done := make(chan error, 1)
				go func() { done <- first.awaitMessage(observed) }()
				select {
				case <-observed.entered:
				case <-ctx.Done():
					t.Fatal("readiness did not enter original bounded operation")
				}
				if name == "cancelled" {
					cancel()
				} else if err := first.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if err == nil || errors.Is(err, ErrPeerClosed) {
						t.Fatal("local interruption supplied peer authority", err)
					}
				case <-time.After(time.Second):
					t.Fatal("original readiness operation did not join")
				}
				if _, err := second.currentIdentity(); err != nil {
					t.Fatal("local cancellation retired the independent peer", err)
				}
				return
			}
			if name == "original-replaced" || name == "connection-replaced" {
				other, _ := retirementPair(t)
				if name == "original-replaced" {
					original := first.file
					first.file = other.file
					defer func() { first.file = original }()
				} else {
					original := first.conn
					first.conn = other.conn
					defer func() { first.conn = original }()
				}
				if first.awaitMessage(ctx) == nil {
					t.Fatal("foreign socket supplied original readiness")
				}
				if _, err := other.currentIdentity(); err != nil {
					t.Fatal("foreign socket was retired by refusal", err)
				}
				return
			}
			var source *os.File
			body := []byte("original-frame")
			expected := os.Getpid()
			wantFile := false
			switch name {
			case "peer-eof":
				if err := second.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "empty":
				body = nil
			case "oversize":
				body = []byte(strings.Repeat("x", MessageLimit+2))
			case "foreign-sender":
				expected++
			case "unexpected-descriptor", "rights-unconsumed":
				var err error
				source, err = os.Open("/proc/self")
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				wantFile = name == "rights-unconsumed"
			}
			if name != "peer-eof" {
				raw, err := second.conn.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var nativeErr error
				send := func(control []byte) {
					err = raw.Control(func(fd uintptr) { _, nativeErr = syscall.SendmsgN(int(fd), body, control, nil, 0) })
				}
				if source != nil {
					sourceRaw, e := source.SyscallConn()
					if e != nil {
						t.Fatal(e)
					}
					if e = sourceRaw.Control(func(fd uintptr) { send(syscall.UnixRights(int(fd))) }); e != nil {
						t.Fatal(e)
					}
				} else {
					send(nil)
				}
				if err != nil || nativeErr != nil {
					t.Fatal(err, nativeErr)
				}
			}
			start := time.Now()
			if err := first.awaitMessage(ctx); err != nil {
				t.Fatal("readiness must defer frame/EOF authentication to the original receiver", err)
			}
			packet, err := first.Receive(ctx, expected, wantFile)
			if packet != nil {
				defer packet.Close()
			}
			if name == "rights-unconsumed" {
				if err != nil || packet == nil || string(packet.Payload) != "original-frame" || len(packet.files) != 1 {
					t.Fatal("readiness consumed original payload or rights", err)
				}
			} else if err == nil || name != "peer-eof" && errors.Is(err, ErrPeerClosed) {
				t.Fatal("readiness bypassed original frame refusal", err)
			}
			if name == "peer-eof" && !errors.Is(err, ErrPeerClosed) {
				t.Fatal("unchanged receive lost strict EOF", err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("complete malformed frame escaped its bounded original receiver")
			}
			if source != nil {
				if packet == nil || len(packet.files) != 1 {
					t.Fatal("received rights were lost before retained cleanup")
				}
				received := packet.files[0]
				a, e1 := source.Stat()
				b, e2 := received.Stat()
				if e1 != nil || e2 != nil || !os.SameFile(a, b) {
					t.Fatal("retained descriptor no longer names original source", e1, e2)
				}
				if err := packet.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := received.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("received descriptor was not closed", err)
				}
				if _, err := source.Stat(); err != nil {
					t.Fatal("original unrelated source was closed", err)
				}
			}
		})
	}
}
