//go:build windows && routervpn_controller_windows_native

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/windowscontroller"
)

const desktopNodeProcessNativeFixture = "ROUTERVPN_NODE_PROCESS_NATIVE_FIXTURE"

// Test-only executable body: no production launch can select this branch. It
// witnesses entry into the exact copied process after the shipping native
// creation/image/token/Job proof, without claiming to run a sing-box dataplane.
func init() {
	if os.Getenv(desktopNodeProcessNativeFixture) != "1" || len(os.Args) < 4 || os.Args[1] != "routervpn-node" {
		return
	}
	directory := os.Args[3]
	_, err := validateDesktopNodeProcessArguments(os.Args[1:], directory)
	if err == nil {
		current, currentErr := os.Getwd()
		actual, actualErr := os.Stat(current)
		expected, expectedErr := os.Stat(directory)
		if currentErr != nil || actualErr != nil || expectedErr != nil || !os.SameFile(actual, expected) {
			err = errors.New("native Node fixture entered another working directory")
		}
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(directory, "node-process-entered"), []byte(strconv.Itoa(os.Getpid())), 0600)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(23)
	}
	timer := time.NewTimer(40 * time.Second)
	<-timer.C
	os.Exit(24)
}

func desktopNodeProcessNativeImage(t *testing.T) (string, *windowscontroller.Image) {
	t.Helper()
	self, err := windowscontroller.PinCurrentImage()
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	directory := t.TempDir()
	path := filepath.Join(directory, "sing-box-routervpn.exe")
	source, err := os.Open(self.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	if err := errors.Join(copyErr, destination.Close()); err != nil {
		t.Fatal(err)
	}
	image, err := windowscontroller.PinImage(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = image.Close() })
	return directory, image
}

func TestWindowsOwnedNodeProcessActualRetirement(t *testing.T) {
	identity, err := windowscontroller.CurrentIdentity()
	if err != nil || !identity.Primary || !identity.Elevated || !identity.Administrator {
		t.Fatal("native Node process fixture requires its actual elevated primary token", err)
	}
	directory, image := desktopNodeProcessNativeImage(t)
	arguments := []string{"routervpn-node", "--runtime-dir", directory, "--session", strings.Repeat("a", 32),
		"--config-sha256", strings.Repeat("b", 64), "--physical-source-sha256", strings.Repeat("c", 64),
		"--physical-transfer-sha256", strings.Repeat("d", 64)}
	var retired atomic.Bool
	owner := newDesktopNodeProcessOwner(func() error {
		actual, err := windowscontroller.CurrentIdentity()
		if err != nil || actual != identity || retired.Load() {
			return errors.Join(err, errors.New("native fixture controller identity retired"))
		}
		return nil
	})
	owner.pins = append(owner.pins, image)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := owner.Close(ctx); err != nil {
			t.Error("native Node fixture did not join its retained child Job", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	environment := append(os.Environ(), desktopNodeProcessNativeFixture+"=1")
	if err := startDesktopCapturedNodeChild(ctx, owner, image, arguments, environment, directory); err != nil {
		t.Fatal(err)
	}
	if !owner.Started() || owner.Alive() != nil {
		t.Fatal("actual native child did not retain its direct launch owner")
	}
	for {
		body, err := os.ReadFile(filepath.Join(directory, "node-process-entered"))
		if err == nil {
			child := owner.child.(*windowscontroller.GUIChild)
			if string(body) != strconv.FormatUint(uint64(child.PID()), 10) {
				t.Fatal("native child entry came from another process")
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := owner.Alive(); err != nil {
			t.Fatal("retained native child exited before its actual entry witness", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual Node child did not enter its captured workspace")
		case <-time.After(10 * time.Millisecond):
		}
	}
	retired.Store(true)
	if owner.Alive() == nil {
		t.Fatal("retired controller still authorized the native child")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := owner.Close(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled native join falsely acknowledged retirement", err)
	}
	if err := os.Rename(directory, directory+".moved"); err == nil {
		_ = os.Rename(directory+".moved", directory)
		t.Fatal("pending native close released its captured image ancestry")
	}
	if err := owner.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if code, err := owner.Wait(ctx); err != nil || code != 1 {
		t.Fatal("joined native Job lost the actual process exit result", code, err)
	}
	if err := os.Rename(directory, directory+".moved"); err != nil {
		t.Fatal("joined native process retained its released package ancestry", err)
	}
	if err := os.Rename(directory+".moved", directory); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsOwnedNodeProcessRejectsMissingController(t *testing.T) {
	if windowsOwnedCapture.Load() != nil {
		t.Fatal("the rejection fixture unexpectedly inherited a controller capture")
	}
	directory, arguments := desktopNodeProcessArgumentsFixture(t)
	owner, err := startDesktopOwnedNodeProcess(context.Background(), arguments, os.Environ(), directory)
	if err == nil || owner != nil {
		t.Fatal("direct Node launch ran without an authenticated controller")
	}
	if _, err := os.Stat(filepath.Join(directory, "node-process-entered")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected direct Node launch entered an uncaptured executable")
	}
}
