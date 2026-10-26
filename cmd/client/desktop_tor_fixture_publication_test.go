package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

// The child may fail while its parent is polling a drain receipt. Keep its
// actual publication error bounded and safe to read while exec is copying it.
type desktopTorFixtureOutput struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (output *desktopTorFixtureOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	const limit = 32 << 10
	remaining := limit - len(output.data)
	if len(data) > remaining {
		output.data = append(output.data, data[:remaining]...)
		output.truncated = true
	} else {
		output.data = append(output.data, data...)
	}
	return len(data), nil
}

func (output *desktopTorFixtureOutput) String() string {
	output.mu.Lock()
	defer output.mu.Unlock()
	result := string(output.data)
	if output.truncated {
		result += "\n[isolated fixture stderr truncated at 32 KiB]"
	}
	return result
}

func desktopTorFixturePauseIdentity(expected mobiletor.DesktopBridgeMetadata) string {
	return expected.SessionID + "\n" + expected.SourceSHA256 + "\n" + expected.ConfigSHA256 + "\n"
}

// This barrier is reached only between completed captured-root publications;
// every temporary write and replacement has completed before acknowledgement.
// The private acknowledgement lives outside the directory about to be renamed.
// The real child remains alive until its parent explicitly releases or kills it.
func desktopTorFixturePublicationBarrier(kind string, expected mobiletor.DesktopBridgeMetadata) {
	if kind != "proof-directory-retire" {
		return
	}
	control := os.Getenv("ROUTERVPN_TOR_TEST_RELEASE")
	request, err := os.ReadFile(control + ".pause")
	if os.IsNotExist(err) {
		return
	}
	identity := desktopTorFixturePauseIdentity(expected)
	if err != nil || string(request) != identity {
		fmt.Fprintf(os.Stderr, "isolated Tor fixture publication pause identity: %v\n", err)
		os.Exit(94)
	}
	if err := os.WriteFile(control+".paused", request, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "isolated Tor fixture publication pause acknowledgement: %v\n", err)
		os.Exit(95)
	}
	for {
		if resume, err := os.ReadFile(control + ".resume"); err == nil && string(resume) == identity {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func pauseDesktopTorFixturePublications(t *testing.T, ctx context.Context, launch *desktopNodeLaunch, control string) {
	t.Helper()
	identity := desktopTorFixturePauseIdentity(launch.tor.expected)
	if err := atomicWritePrivate(control+".pause", []byte(identity)); err != nil {
		t.Fatal(err)
	}
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if receipt, err := os.ReadFile(control + ".paused"); err == nil && string(receipt) == identity {
			if desktopNodeProcessExited(launch) {
				t.Fatal("publication barrier lost the live captured child")
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("captured child did not acknowledge publication quiescence", ctx.Err())
		case <-desktopNodeProcessDone(launch):
			t.Fatal("captured child exited before publication quiescence")
		case <-tick.C:
		}
	}
}
