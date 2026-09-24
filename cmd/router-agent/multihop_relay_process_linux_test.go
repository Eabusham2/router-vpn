//go:build linux

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRelayCrashProcessHelper(t *testing.T) {
	role := os.Getenv("ROUTER_VPN_RELAY_PROCESS_TEST")
	if role == "" {
		return
	}
	if role == "leaf" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	if role != "owner" {
		os.Exit(99)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayCrashProcessHelper$")
	cmd.Env = append(os.Environ(), "ROUTER_VPN_RELAY_PROCESS_TEST=leaf")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if configureRelayProcess(cmd) != nil {
		os.Exit(98)
	}
	p, err := startOwnedRelayProcess(cmd, os.Getenv("ROUTER_VPN_RELAY_TEST_DIR"))
	if err != nil {
		os.Exit(97)
	}
	fmt.Println(p.cmd.Process.Pid)
	_ = os.Stdout.Sync()
	time.Sleep(time.Minute)
	os.Exit(96)
}
func relayHelperCommand() *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayCrashProcessHelper$")
	cmd.Env = append(os.Environ(), "ROUTER_VPN_RELAY_PROCESS_TEST=leaf")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd
}
func TestRelayPinnedThreadNormalStopAndStartFailure(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "owned")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := relayHelperCommand()
	if err := configureRelayProcess(cmd); err != nil {
		t.Fatal(err)
	}
	p, err := startOwnedRelayProcess(cmd, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	if !p.Alive() {
		t.Fatal("new relay died before stop")
	}
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if p.Alive() {
		t.Fatal("relay survived confirmed stop")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("owned runtime directory survived stop")
	}
	if _, err := startOwnedRelayProcess(exec.Command(filepath.Join(root, "missing-engine")), dir); err == nil {
		t.Fatal("missing process adopted")
	}
}
func TestRelayKilledWhenAgentOwnerCrashes(t *testing.T) {
	owner := exec.Command(os.Args[0], "-test.run=^TestRelayCrashProcessHelper$")
	owner.Env = append(os.Environ(), "ROUTER_VPN_RELAY_PROCESS_TEST=owner", "ROUTER_VPN_RELAY_TEST_DIR="+t.TempDir())
	output, err := owner.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	owner.Stderr = io.Discard
	if err = owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Process.Kill(); _ = owner.Wait() }()
	ids := make(chan int, 1)
	go func() {
		line, _ := bufio.NewReader(output).ReadString('\n')
		pid, _ := strconv.Atoi(strings.TrimSpace(line))
		ids <- pid
	}()
	var pid int
	select {
	case pid = <-ids:
	case <-time.After(5 * time.Second):
		t.Fatal("relay owner did not report its child")
	}
	if pid <= 1 {
		t.Fatal("invalid owned process id")
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	if err = owner.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = owner.Wait()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		// A dead orphan may briefly remain a zombie until the environment's init
		// reaps it. It cannot run a listener and counts as terminated, not alive.
		if os.IsNotExist(err) || strings.Contains(string(raw), "State:\tZ") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("relay remained running after agent process death")
}
