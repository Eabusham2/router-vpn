package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDesktopExternalNativeMeasurementMailboxesRetireOnlyAfterExactStop(t *testing.T) {
	for _, kind := range []string{"dns-winner", "latency-winner"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopExternalRunningFixture(t, kind)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			if _, err := a.waitDesktopExternalProof(ctx, launch); err != nil {
				t.Fatal(err)
			}
			name := "latency-status.json"
			if kind == "dns-winner" {
				name = "dns-status.json"
			}
			if _, err := readDesktopRuntimeFile(launch, name, 64<<10); err != nil {
				t.Fatal("actual child did not publish its measurement mailbox", err)
			}
			if err := prepareDesktopExternalStop(a, launch.command); err != nil {
				t.Fatal(err)
			}
			select {
			case <-desktopExternalProcessDone(launch):
			case <-ctx.Done():
				t.Fatal("captured measurement child was not joined")
			}
			if !launch.external.stopAcknowledged {
				t.Fatal("measurement cleanup lost its native stop acknowledgment")
			}
			// Exact measurement names are owned; a similarly named unknown file
			// still prevents deletion of any part of the captured workspace.
			foreign := filepath.Join(launch.directory, name+".foreign")
			if err := os.WriteFile(foreign, []byte("preserve unrelated file"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := cleanupDesktopNodeLaunch(launch); err == nil {
				t.Fatal("unknown measurement-like file was accepted as owned")
			}
			if raw, err := os.ReadFile(foreign); err != nil || string(raw) != "preserve unrelated file" {
				t.Fatal("unknown file changed during rejected cleanup", err)
			}
			if _, err := readDesktopRuntimeFile(launch, name, 64<<10); err != nil {
				t.Fatal("rejected cleanup partially removed the native mailbox", err)
			}
			if err := os.Remove(foreign); err != nil {
				t.Fatal(err)
			}
			if err := cleanupDesktopNodeLaunch(launch); err != nil {
				t.Fatal("drained owned measurement workspace was retained", err)
			}
			if _, err := os.Lstat(launch.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("owned measurement workspace still exists", err)
			}
		})
	}
}
