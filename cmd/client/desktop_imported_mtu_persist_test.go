package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"router-vpn/internal/common"
)

// The first callback is the real private writer's initial admission. The next
// callback runs after its temporary file has been written, synced and closed,
// immediately before adoption. Cancel the same caller at that causal boundary.
type desktopImportedMTUFinalWriteContext struct {
	context.Context
	cancel context.CancelFunc
	checks atomic.Int32
}

func (c *desktopImportedMTUFinalWriteContext) Err() error {
	if c.checks.Add(1) == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestDesktopImportedMTUHistoricalWriteKeepsOriginalFinalCaller(t *testing.T) {
	for _, mode := range []string{"live", "cancelled-before-write", "cancelled-before-rename"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profiles.json")
			profiles := common.RouterProfileStore{SelectedID: "paired-final", Profiles: []common.RouterProfile{{ID: "paired-final", MTUPolicy: "auto", EffectiveMTU: 1420}}}
			if err := persistDesktopImportedMTUProfilesContext(context.Background(), path, profiles); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := os.Stat(path)
			if err != nil || !os.SameFile(identity, identity) {
				t.Fatal("original private file identity was not captured", err)
			}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := context.Context(parent)
			var final *desktopImportedMTUFinalWriteContext
			switch mode {
			case "cancelled-before-write":
				cancel()
			case "cancelled-before-rename":
				final = &desktopImportedMTUFinalWriteContext{Context: parent, cancel: cancel}
				ctx = final
			}
			profiles.Profiles[0].EffectiveMTU = 1380
			err = persistDesktopImportedMTUProfilesContext(ctx, path, profiles)
			after, readErr := os.ReadFile(path)
			current, statErr := os.Stat(path)
			if readErr != nil || statErr != nil {
				t.Fatal("private publication lost its original file", readErr, statErr)
			}
			if mode == "live" {
				if err != nil || bytes.Equal(before, after) || os.SameFile(identity, current) {
					t.Fatal("live original caller did not atomically publish its measured history", err)
				}
			} else if !errors.Is(err, context.Canceled) || !bytes.Equal(before, after) || !os.SameFile(identity, current) {
				t.Fatal("expired original caller adopted a late historical result", mode, err)
			}
			if final != nil && final.checks.Load() != 2 {
				t.Fatal("causal cancellation did not reach the actual final rename admission", final.checks.Load())
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 || entries[0].Name() != "profiles.json" {
				t.Fatal("joined private write retained an unowned temporary file", entries, err)
			}
		})
	}
}
