//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestDNSSECOriginalChildHardJoin(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "natural"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			command := exec.Command("/bin/sh", "-c", "trap '' TERM; while :; do :; done")
			if mode == "natural" {
				command = exec.Command("/bin/sh", "-c", "exit 0")
			}
			pidfd := -1
			command.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			if pidfd < 0 {
				t.Fatal("original creation pidfd missing")
			}
			file := os.NewFile(uintptr(pidfd), "original-test-child")
			defer file.Close()
			h := &linuxResolvedHelper{pidfd: file, joined: make(chan struct{})}
			go func() { h.waitErr = command.Wait(); close(h.joined) }()
			c := &linuxDNSSECChild{base: h, original: ctx, watchDone: make(chan struct{})}
			go c.watchOriginal()
			if mode == "cancel" {
				cancel()
			}
			select {
			case <-h.joined:
			case <-time.After(3 * time.Second):
				t.Fatal("original noncooperative child not joined")
			}
			<-c.watchDone
			if c.watchErr != nil {
				t.Fatal(c.watchErr)
			}
			if mode == "natural" && h.waitErr != nil {
				t.Fatal(h.waitErr)
			}
			if mode != "natural" {
				status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatalf("child not killed by original pidfd: %v", command.ProcessState)
				}
			}
		})
	}
}
func TestDNSSECCloseRetainsActiveCallback(t *testing.T) {
	callback := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	c := &linuxDNSSECChild{base: &linuxResolvedHelper{closedFiles: make(map[*os.File]bool)}, original: ctx, cancel: cancel, callbackDone: callback}
	short, end := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer end()
	if err := c.Close(short); err == nil {
		t.Fatal("active physical callback abandoned")
	}
	if c.base.closed {
		t.Fatal("partial callback owner discarded")
	}
	close(callback)
	cleanup, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	if err := c.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	if !c.base.closed {
		t.Fatal("joined callback owner not retired")
	}
}
