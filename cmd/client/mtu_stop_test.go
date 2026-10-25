package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestMTUStopChildFixture(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_MTU_STOP_TEST_DIRECTORY")
	if directory == "" {
		return
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(directory, "stop.json"))
		var request desktopExternalStop
		if err == nil && decodeRelayControlJSON(raw, &request) == nil && request.Schema == 1 && request.SessionID == os.Getenv("ROUTERVPN_MTU_STOP_TEST_SESSION") && request.SourceSHA256 == os.Getenv("ROUTERVPN_MTU_STOP_TEST_CONFIG") {
			request.Closed = true
			data, _ := json.Marshal(request)
			if atomicWritePrivate(filepath.Join(directory, "stopped.json"), data) != nil {
				os.Exit(91)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Exit(92)
}

func mtuStopRunningNode(t *testing.T) (*app, *desktopNodeLaunch) {
	t.Helper()
	fixture := newDesktopNodeMTUFixture(t)
	launch := fixture.launch
	command := exec.Command(os.Args[0], "-test.run=^TestMTUStopChildFixture$")
	command.Env = append(os.Environ(), "ROUTERVPN_MTU_STOP_TEST_DIRECTORY="+launch.directory, "ROUTERVPN_MTU_STOP_TEST_SESSION="+launch.mtuSession, "ROUTERVPN_MTU_STOP_TEST_CONFIG="+launch.configSHA256)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	launch.command = command
	a := &app{cmd: command}
	desktopNodeOwners.Store(a, launch)
	t.Cleanup(func() {
		_ = command.Process.Kill()
		<-desktopNodeProcessDone(launch)
		desktopNodeOwners.Delete(a)
		mtuSuspensions.Delete(a)
	})
	return a, launch
}

func TestMTUExplicitStopCanRetireExactNativeOwnerAfterLeaseDrainFails(t *testing.T) {
	for _, kind := range []string{"router-node", "external"} {
		t.Run(kind, func(t *testing.T) {
			var a *app
			var launch *desktopNodeLaunch
			if kind == "router-node" {
				a, launch = mtuStopRunningNode(t)
			} else {
				a, launch = desktopExternalRunningFixture(t, "waiting")
				t.Cleanup(func() { mtuSuspensions.Delete(a) })
			}
			calls := 0
			release, command, err := a.holdMTUForStopWith(func(ctx context.Context) (func(), error) {
				calls++
				if calls == 1 {
					return nil, errors.New("unconfirmed MTU commit exceeded its revert deadline")
				}
				if _, err := readDesktopRuntimeFile(launch, "stopped.json", 4096); err != nil {
					t.Error("MTU teardown was retried before exact native cleanup acknowledgement", err)
				}
				return a.holdCapturedMTU(ctx)
			})
			if err != nil || release == nil || command != launch.command || calls != 2 {
				t.Fatal("explicit teardown could not discharge its exact native owner", err, calls)
			}
			release()
			if a.cmd != command {
				t.Fatal("MTU fallback cleared the runtime before ordinary teardown")
			}
		})
	}
}

func TestMTUExplicitStopNeverRetiresReplacementRuntime(t *testing.T) {
	a, launch := mtuStopRunningNode(t)
	replacement := &exec.Cmd{Path: "replacement"}
	release, _, err := a.holdMTUForStopWith(func(context.Context) (func(), error) {
		a.mu.Lock()
		a.cmd = replacement
		a.mu.Unlock()
		return nil, errors.New("old MTU drain failed")
	})
	if err == nil || release != nil {
		t.Fatal("old teardown followed a replacement runtime")
	}
	if _, err := launch.directoryRoot.Lstat("stop.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old failed hold sent a close command after runtime replacement", err)
	}
	if owner, _ := desktopNodeOwners.Load(a); owner != launch || a.cmd != replacement {
		t.Fatal("old fallback changed the replacement's ownership")
	}
}

func TestMTUSuccessfulHoldCannotBeReboundToReplacementStop(t *testing.T) {
	a, launch := mtuStopRunningNode(t)
	released := false
	release, command, err := a.holdMTUForStopWith(func(context.Context) (func(), error) {
		a.mu.Lock()
		a.cmd = &exec.Cmd{Path: "new-runtime"}
		a.mu.Unlock()
		return func() { released = true }, nil
	})
	if err == nil || release != nil || command != launch.command || !released {
		t.Fatal("successful old hold could be used to stop a replacement runtime")
	}
	if _, err := launch.directoryRoot.Lstat("stop.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replaced hold wrote a stop command", err)
	}
}
