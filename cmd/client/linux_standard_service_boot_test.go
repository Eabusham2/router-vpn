//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxStandardServiceBootKeepsOriginalPartialCreator(t *testing.T) {
	f := newLegacyExitFixture(t, "always")
	f.a.profiles.Profiles[0].Endpoint = "203.0.113.41"
	applyProfileDefaults(&f.a.profiles.Profiles[0])
	if err := f.a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	linuxStandardServicePreviousBootState(t, f.root, "control", "203.0.113.41")
	image, _ := os.Stat("/proc/self/exe")
	namespace, _ := os.Stat("/proc/thread-self/ns/net")
	s := newLinuxStandardService(f.root, image, namespace)
	m := newLegacyProtectionModel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wanted := errors.New("original acknowledgment readback interrupted")
	create := func(ctx context.Context, session, digest string, endpoints []netip.Addr, lan bool, lease *os.File) (legacyExitKernelProtection, error) {
		owner, err := m.create(ctx, session, digest, endpoints, lan, lease)
		if err != nil {
			return owner, err
		}
		return owner, wanted
	}
	err := s.reassertWithObservers(ctx, func() error { return nil }, func(context.Context) error { return nil }, create)
	if !errors.Is(err, wanted) || s.boot == nil || s.boot.kernel == nil || s.boot.persisted {
		t.Fatal("partial original boot creator was erased or treated as complete", err)
	}
	original := s.boot
	s.bootFailure = err
	if err = s.repairBoot(ctx); err != nil {
		t.Fatal("same original creator could not finish acknowledged readback", err)
	}
	if s.boot != original || !original.persisted || !original.detached || s.bootFailure != nil {
		t.Fatal("boot retry reconstructed authority instead of continuing original creator")
	}
	if actual, _ := legacyStandardProtectionOwners.Load(s.app); actual != original {
		t.Fatal("boot creator not available to actual engine succession")
	}
	if err = s.prepareIdleShutdownWithObservers(ctx, func() error { return nil }, func(context.Context) error { return nil }); err == nil {
		t.Fatal("partial-to-complete Always owner was discarded by idle upgrade")
	}
	lease, err := acquireLegacyExitMutationLease(ctx, f.root)
	if err != nil {
		t.Fatal(err)
	}
	if err = original.release(ctx, lease); err != nil {
		t.Fatal(err)
	}
	lease.Close()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) != 2 || len(m.tables) != 0 {
		t.Fatal("boot completion created or deleted different authority", m.events)
	}
}

func TestLinuxStandardServiceBootNeverAdoptsSavedOrExistingNativeOwner(t *testing.T) {
	for _, kind := range []string{"current-boot", "foreign-native", "corrupt-state"} {
		t.Run(kind, func(t *testing.T) {
			f := newLegacyExitFixture(t, "always")
			f.a.profiles.Profiles[0].Endpoint = "203.0.113.42"
			applyProfileDefaults(&f.a.profiles.Profiles[0])
			if err := f.a.persistProfilesLocked(); err != nil {
				t.Fatal(err)
			}
			linuxStandardServicePreviousBootState(t, f.root, "control", "203.0.113.42")
			image, _ := os.Stat("/proc/self/exe")
			namespace, _ := os.Stat("/proc/thread-self/ns/net")
			s := newLinuxStandardService(f.root, image, namespace)
			m := newLegacyProtectionModel()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			lease, err := acquireLegacyExitMutationLease(ctx, f.root)
			if err != nil {
				t.Fatal(err)
			}
			lease.Close()
			var original []byte
			if kind == "current-boot" {
				boot, err := readDesktopLinuxNodeBootID()
				if err != nil {
					t.Fatal(err)
				}
				original, _ = json.Marshal(legacyExitProtectionState{PolicyProfileID: "control", Owner: legacyExitProtectionMarker{Schema: 1, BootID: boot}})
			} else if kind == "corrupt-state" {
				original = []byte("{incomplete")
			}
			path := filepath.Join(f.root, "run", "kill-switch.json")
			if original != nil {
				if err = os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			absence := func(context.Context) error { return nil }
			if kind == "foreign-native" {
				absence = func(context.Context) error { return errors.New("existing unrelated native table") }
			}
			if err = s.reassertWithObservers(ctx, func() error { return nil }, absence, m.create); err == nil {
				t.Fatal("boot adopted unresolved native or saved authority")
			}
			if s.boot != nil || len(m.events) != 0 {
				t.Fatal("rejected boot mutated original native protection")
			}
			if original != nil {
				body, err := os.ReadFile(path)
				if err != nil || string(body) != string(original) {
					t.Fatal("boot changed unresolved saved owner", err)
				}
			}
		})
	}
}
