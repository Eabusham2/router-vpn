//go:build linux && routervpn_controller_privileged

package linuxprocess

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const observationContextCapture = "a4b91e29353401d1631a19ae763cb0768329b6a44f5c05719194c3698b4040ce"

func TestLinuxObservationContextChild(t *testing.T) {
	if os.Getenv("ROUTERVPN_OBSERVATION_CONTEXT_CHILD") != "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	channel, err := CaptureChannel(os.NewFile(3, "original-observation-channel"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := BindInheritedParent(ctx, channel, os.NewFile(4, "original-observation-parent"), observationContextCapture)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close(context.Background())
	if err := original.Send(ctx, []byte("ready")); err != nil {
		t.Fatal(err)
	}
	_, _ = original.Receive(ctx)
}

func observationContextBootstrap(t *testing.T) *Bootstrap {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	parent, err := CaptureSelf(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	record, err := parent.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := parent.DuplicateDirectory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	channel, endpoint, err := ChannelPair()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxObservationContextChild$", "-test.count=1")
	child.Env = append(os.Environ(), "ROUTERVPN_OBSERVATION_CONTEXT_CHILD=1", "GORACE=atexit_sleep_ms=0")
	child.ExtraFiles = []*os.File{endpoint, directory}
	child.Stdout = &output
	child.Stderr = &output
	pidfd := -1
	child.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	endpoint.Close()
	directory.Close()
	original, err := BindCreatedChild(ctx, channel, parent, os.NewFile(uintptr(pidfd), "original-observation-clone"), child.Process.Pid, record.Image, observationContextCapture)
	t.Cleanup(func() {
		cancel()
		_ = child.Wait()
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if original != nil {
			_ = original.Close(cleanup)
		} else {
			_ = channel.Close(cleanup)
		}
		_ = parent.Close(cleanup)
	})
	if err != nil {
		t.Fatal("original child authentication", err)
	}
	ready, err := original.Receive(ctx)
	if err != nil || string(ready) != "ready" {
		t.Fatal("original child readiness", err, string(ready))
	}
	return original
}

// Each Done call is the select admission of the original bootstrap, parent
// task, clone-created child, then child task. Signal only the selected nested
// admission; an earlier Err check must not make a held-task regression pass.
type observationContextEntered struct {
	context.Context
	once              sync.Once
	entered           chan struct{}
	admission, target atomic.Int32
}

func (c *observationContextEntered) Done() <-chan struct{} {
	if c.admission.Add(1) == c.target.Load() {
		c.once.Do(func() { close(c.entered) })
	}
	return c.Context.Done()
}

func TestLinuxObservationContextNestedOriginalGates(t *testing.T) {
	for _, boundary := range []string{"parent-task", "created-child", "child-task"} {
		t.Run(boundary, func(t *testing.T) {
			original := observationContextBootstrap(t)
			gate := original.parent.gate
			if boundary == "created-child" {
				gate = original.child.gate
			} else if boundary == "child-task" {
				gate = original.child.task.gate
			}
			<-gate
			held := true
			defer func() {
				if held {
					gate <- struct{}{}
				}
			}()
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &observationContextEntered{Context: parent, entered: make(chan struct{})}
			ctx.target.Store(map[string]int32{"parent-task": 2, "created-child": 3, "child-task": 4}[boundary])
			done := make(chan error, 1)
			go func() { _, _, err := original.ObservationsContext(ctx, observationContextCapture); done <- err }()
			select {
			case <-ctx.entered:
			case <-time.After(time.Second):
				t.Fatal("observation did not enter original caller")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("original observer error changed", err)
				}
			case <-time.After(time.Second):
				gate <- struct{}{}
				held = false
				<-done
				t.Fatal("original caller could not interrupt nested gate")
			}
			gate <- struct{}{}
			held = false
			if original.revoked || original.child.revoked || original.parent.revoked || original.child.task.revoked {
				t.Fatal("pure observer expiry revoked original authenticated participants")
			}
			retry, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if _, _, err := original.ObservationsContext(retry, observationContextCapture); err != nil {
				t.Fatal("original participant could not be reproved", err)
			}
		})
	}
}

type observationContextCancelAtTask struct {
	context.Context
	task   *Witness
	cancel context.CancelFunc
	once   sync.Once
}

func (c *observationContextCancelAtTask) Err() error {
	before := c.Context.Err()
	if len(c.task.gate) == 0 {
		c.once.Do(c.cancel)
	}
	return before
}

func TestLinuxObservationContextRejectsRealLossAndCapture(t *testing.T) {
	for _, mode := range []string{"native-loss", "native-loss-with-expiry"} {
		t.Run(mode, func(t *testing.T) {
			original := observationContextBootstrap(t)
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var ctx context.Context = parent
			if _, _, err := original.ObservationsContext(ctx, strings.Repeat("f", 64)); err == nil {
				t.Fatal("foreign capture gained original authority")
			}
			if original.revoked {
				t.Fatal("foreign caller revoked original participant")
			}
			if err := original.child.task.image.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "native-loss-with-expiry" {
				ctx = &observationContextCancelAtTask{Context: parent, task: original.child.task, cancel: cancel}
			}
			if _, _, err := original.ObservationsContext(ctx, observationContextCapture); err == nil || !original.revoked || !original.child.revoked {
				t.Fatal("actual original descriptor loss was not latched", err)
			}
			if mode == "native-loss-with-expiry" && parent.Err() == nil {
				t.Fatal("native loss did not race actual observer expiry")
			}
		})
	}
}
