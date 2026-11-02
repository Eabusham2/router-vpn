//go:build ignore

// Explicit test-only process boundary for the actual installcap receiver.
// This program is never included in a client package or normal Go build.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/installcap"
)

func run() (failure error) {
	if len(os.Args) != 7 || os.Args[1] != "--owned-installcap-fixture" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("receiver fixture requires its explicit owned root invocation")
	}
	info, err := os.Lstat(installcap.Root + "/fixture-installcap-authority")
	body, readErr := os.ReadFile(installcap.Root + "/fixture-installcap-authority")
	if err != nil || readErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		info.Sys().(*syscall.Stat_t).Uid != 0 || string(body) != "explicit disposable installer capability fixture\n" {
		return errors.New("receiver fixture has no exact private root marker")
	}
	descriptor, err := strconv.Atoi(os.Args[2])
	if err != nil {
		return err
	}
	issuer, err := strconv.Atoi(os.Args[4])
	if err != nil {
		return err
	}
	release, err := strconv.Atoi(os.Args[6])
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if os.Args[5] == "cancel-during-ack" {
		lifetime := os.NewFile(uintptr(release), "captured-cancellation-boundary")
		joined := make(chan struct{})
		go func() {
			var one [1]byte
			_, _ = lifetime.Read(one[:])
			cancel()
			close(joined)
		}()
		defer func() { lifetime.Close(); <-joined }()
	}
	if os.Args[5] == "canceled" {
		cancel()
	}
	// Use the same shared native ACL verifier as the installed PF utility.
	owner, err := installcap.Acquire(ctx, descriptor, os.Args[3], issuer, "plan", common.OwnedPathACL)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, owner.Close()) }()
	if len(owner.Files()) != 3 {
		return errors.New("receiver did not retain lock, lease and original channel")
	}
	if err := os.WriteFile(installcap.Root+"/fixture-native-adopted", []byte("exact native receiver admitted\n"), 0600); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, "native-adopted"); err != nil {
		return err
	}
	if os.Args[5] == "half-close" {
		if err := syscall.Shutdown(int(owner.Files()[2].Fd()), syscall.SHUT_WR); err != nil {
			return err
		}
	}
	if os.Args[5] == "hold" || os.Args[5] == "half-close" {
		lifetime := os.NewFile(uintptr(release), "captured-fixture-lifetime")
		defer lifetime.Close()
		var one [1]byte
		if n, err := lifetime.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
			return errors.New("receiver fixture lost its captured lifetime join")
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
