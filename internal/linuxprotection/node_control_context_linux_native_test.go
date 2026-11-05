//go:build linux && routervpn_controller_privileged

package linuxprotection

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/linuxprocess"
)

func TestNodeObservationContextChild(t *testing.T) {
	capture := os.Getenv("ROUTERVPN_NODE_OBSERVATION_CAPTURE")
	if capture == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	channel, err := linuxprocess.CaptureChannel(os.NewFile(3, "original-node-observation-channel"))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := linuxprocess.BindInheritedParent(ctx, channel, os.NewFile(4, "original-node-observation-parent"), capture)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	if err := owner.Send(ctx, []byte("ready")); err != nil {
		t.Fatal(err)
	}
	_, _ = owner.Receive(ctx)
}

func nodeObservationControl(t *testing.T) (*NodeControl, *linuxprocess.Bootstrap) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	selection := NodeSelection{SessionID: strings.Repeat("a", 32), SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), Policy: "always"}
	capture, err := selection.CaptureSHA256()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := linuxprocess.CaptureSelf(ctx)
	if err != nil {
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
	channel, endpoint, err := linuxprocess.ChannelPair()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNodeObservationContextChild$", "-test.count=1")
	child.Env = append(os.Environ(), "ROUTERVPN_NODE_OBSERVATION_CAPTURE="+capture, "GORACE=atexit_sleep_ms=0")
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
	owner, err := linuxprocess.BindCreatedChild(ctx, channel, parent, os.NewFile(uintptr(pidfd), "original-node-observation-clone"), child.Process.Pid, record.Image, capture)
	t.Cleanup(func() {
		cancel()
		_ = child.Wait()
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if owner != nil {
			_ = owner.Close(cleanup)
		} else {
			_ = channel.Close(cleanup)
		}
		_ = parent.Close(cleanup)
	})
	if err != nil {
		t.Fatal("original authenticated child", err)
	}
	body, err := owner.Receive(ctx)
	if err != nil || string(body) != "ready" {
		t.Fatal("original ready exchange", err)
	}
	control, err := NewNodeParentControl(ctx, owner, selection)
	if err != nil {
		t.Fatal(err)
	}
	// Model only the previously completed firewall admission flag. The original
	// child, pidfd, task descriptors, capture and authenticated channel are real.
	// The existing guardian namespace suite also executes this strict reader
	// after actual ServePreparation/admission and before authenticated retirement.
	control.admitted = true
	return control, owner
}

type nodeObservationHeldContext struct {
	context.Context
	once             sync.Once
	entered, release chan struct{}
}

func (c *nodeObservationHeldContext) Err() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Context.Err()
}

func TestNodeControlContextWaitsForOriginalBootstrap(t *testing.T) {
	control, owner := nodeObservationControl(t)
	hold := &nodeObservationHeldContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
	held := make(chan error, 1)
	go func() { _, _, err := owner.ObservationsContext(hold, control.commandSHA256); held <- err }()
	<-hold.entered
	released := false
	defer func() {
		if !released {
			close(hold.release)
			<-held
		}
	}()
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- control.CurrentContext(caller) }()
	// Occupied control.gate proves the actual strict read entered its own
	// admission before cancellation while the original bootstrap remains held.
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	limit := time.NewTimer(time.Second)
	defer limit.Stop()
	for len(control.gate) != 0 {
		select {
		case <-tick.C:
		case <-limit.C:
			t.Fatal("strict observation did not enter original control")
		}
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("strict original observer changed error", err)
		}
	case <-time.After(time.Second):
		close(hold.release)
		released = true
		<-held
		<-result
		t.Fatal("strict read substituted independent observer lifetime")
	}
	if control.uncertain != nil {
		t.Fatal("pure strict expiry latched a protocol failure", control.uncertain)
	}
	close(hold.release)
	released = true
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	retry, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := control.CurrentContext(retry); err != nil {
		t.Fatal("original admitted participants could not be reproved", err)
	}
}
