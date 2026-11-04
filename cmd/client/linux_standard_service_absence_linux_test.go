//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxStandardServiceAbsentEndpointRequiresIndependentNativeObservation(t *testing.T) {
	for _, scenario := range []string{"full", "scoped-parent", "listener", "held-owner", "saved-state", "tun", "native", "lost-parent", "late-socket", "replaced-lock", "replaced-directory", "late-state", "foreign-namespace", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			root, err := os.MkdirTemp("/run", "routervpn-absence-test-")
			if err != nil {
				t.Fatal("privileged service absence fixture requires private runtime directory", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			directory := filepath.Join(root, "service")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			lease, err := acquireLegacyExitMutationLease(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			lease.Close()
			namespace, err := os.Stat("/proc/thread-self/ns/net")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			tun := func() error {
				calls++
				if scenario == "tun" {
					return errors.New("actual TUN observation failed")
				}
				return nil
			}
			var parent func(context.Context) error
			parentCalls := 0
			if scenario == "scoped-parent" || scenario == "lost-parent" {
				parent = func(context.Context) error {
					parentCalls++
					if scenario == "lost-parent" && parentCalls == 2 {
						return errors.New("original parent changed")
					}
					return nil
				}
			}
			nativeCalls := 0
			native := func(context.Context) error {
				nativeCalls++
				switch scenario {
				case "native":
					return errors.New("foreign native table remains")
				case "late-socket":
					return os.WriteFile(filepath.Join(directory, "control.sock"), []byte("foreign"), 0600)
				case "replaced-lock":
					if err := os.Rename(filepath.Join(directory, "owner.lock"), filepath.Join(directory, "old.lock")); err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(directory, "owner.lock"), nil, 0600)
				case "replaced-directory":
					if err := os.Rename(directory, directory+".old"); err != nil {
						return err
					}
					return os.Mkdir(directory, 0700)
				case "late-state":
					return os.WriteFile(filepath.Join(root, "run", "kill-switch.json"), []byte("{}"), 0600)
				}
				return nil
			}
			switch scenario {
			case "listener":
				if err := os.WriteFile(filepath.Join(directory, "control.sock"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "held-owner":
				owner, err := ownedDesktopLock(filepath.Join(directory, "owner.lock"), true)
				if err != nil {
					t.Fatal(err)
				}
				defer owner.Close()
			case "saved-state":
				if err := os.WriteFile(filepath.Join(root, "run", "kill-switch.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-namespace":
				namespace, err = os.Stat(root)
				if err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				cancel()
			}
			err = observeLinuxStandardServiceAbsence(ctx, root, directory, namespace, parent, tun, native)
			want := scenario == "full" || scenario == "scoped-parent"
			if (err == nil) != want {
				t.Fatal("service absence substituted endpoint or metadata for original native observation", scenario, err)
			}
			if want && nativeCalls != 1 {
				t.Fatal("successful absence omitted original native read")
			}
			if scenario == "full" && calls != 2 || scenario == "scoped-parent" && (calls != 0 || parentCalls != 2) {
				t.Fatal("scoped observation claimed TUN absence or lost actual parent continuity", calls, parentCalls)
			}
		})
	}
}
