//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func expiredLegacyStopContext(t *testing.T, kind string) (context.Context, error) {
	t.Helper()
	if kind == "deadline" {
		ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
		t.Cleanup(cancel)
		return ctx, context.DeadlineExceeded
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, context.Canceled
}

func TestLegacyStandardMutationLeasePreservesExpiredAdmission(t *testing.T) {
	for _, kind := range []string{"cancelled", "deadline"} {
		for _, existing := range []bool{false, true} {
			name := "missing-root"
			if existing {
				name = "existing-root"
			}
			t.Run(kind+"/"+name, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "original")
				if existing {
					if err := os.Mkdir(root, 0700); err != nil {
						t.Fatal(err)
					}
				}
				ctx, want := expiredLegacyStopContext(t, kind)
				lease, err := acquireLegacyExitMutationLease(ctx, root)
				if lease != nil {
					lease.Close()
					t.Fatal("expired Stop acquired mutation authority")
				}
				if !errors.Is(err, want) {
					t.Fatal("expired admission lost original cancellation cause", err)
				}
				if _, err := os.Lstat(filepath.Join(root, "run")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("expired admission touched the mutation workspace", err)
				}
			})
		}
	}
}

func TestLegacyStandardProtectedExpiredStopRetainsRetryOwner(t *testing.T) {
	for _, kind := range []string{"cancelled", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			f := newLegacyExitFixture(t, "on-connect")
			m := newLegacyProtectionModel()
			owner, _ := startProtected(t, f, m)
			stop, err := captureLegacyStandardExitStop(f.a)
			if err != nil {
				t.Fatal(err)
			}
			ctx, want := expiredLegacyStopContext(t, kind)
			if err := stop.Retire(ctx, owner.command, true); !errors.Is(err, want) {
				t.Fatal("expired captured Stop lost original cancellation cause", err)
			}
			if owner.processRetired || owner.workspaceRetired || owner.protection.removed || len(m.events) != 1 {
				t.Fatal("expired Stop changed original child or protection")
			}
			if current, ok := legacyStandardExitOwners.Load(f.a); !ok || current != owner {
				t.Fatal("expired Stop discarded original retry owner")
			}
			if err := f.a.stopMode(); err != nil {
				t.Fatal("original owner could not complete a later explicit Stop", err)
			}
		})
	}
}
