//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

func linuxStandardServicePreviousBootState(t *testing.T, root, profileID, endpoint string) []byte {
	t.Helper()
	baseline := json.RawMessage(`{"3":[],"4":[],"5":[],"6":[],"7":[]}`)
	digest := sha256.Sum256(baseline)
	state := legacyExitProtectionState{Policy: "always", ProfileID: profileID, PolicyProfileID: profileID, Endpoint: endpoint, EndpointIPs: []string{endpoint}, Platform: "linux", Enforced: true,
		Owner: legacyExitProtectionMarker{Schema: 1, BootID: "00000000-0000-0000-0000-000000000001", Receipt: mobiletor.DesktopLinuxStandardProtectionReceipt{
			NamespaceDevice: 1, NamespaceInode: 2, Baseline: baseline, CreationGeneration: 1, Session: strings.Repeat("1", 32), ConfigSHA256: strings.Repeat("2", 64),
			Table: "router_vpn_standard_" + strings.Repeat("1", 32), TableHandle: 1, ChainHandle: 2, BaselineSHA256: hex.EncodeToString(digest[:]),
		}}}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, "run"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "run", "kill-switch.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestLinuxStandardServiceLegacyBootFixture(t *testing.T) {
	switch os.Getenv("ROUTERVPN_LEGACY_BOOT_FIXTURE") {
	case "success":
		os.Exit(0)
	case "failure":
		os.Exit(42)
	case "wait":
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
}

func linuxLegacyBootTestCommand(mode string) *exec.Cmd {
	command := exec.Command(os.Args[0], "-test.run=^TestLinuxStandardServiceLegacyBootFixture$")
	command.Env = append(os.Environ(), "ROUTERVPN_LEGACY_BOOT_FIXTURE="+mode)
	return command
}

func TestLinuxStandardServiceBootDispatchRequiresExplicitStandardSelection(t *testing.T) {
	for _, kind := range []string{"unmarked-home-always", "legacy-state", "previous-standard", "current-standard", "corrupt-marker", "corrupt-receipt", "duplicate-marker"} {
		t.Run(kind, func(t *testing.T) {
			f := newLegacyExitFixture(t, "always")
			f.a.profiles.Profiles[0].Endpoint = "203.0.113.41"
			applyProfileDefaults(&f.a.profiles.Profiles[0])
			if err := f.a.persistProfilesLocked(); err != nil {
				t.Fatal(err)
			}
			image, _ := os.Stat("/proc/self/exe")
			namespace, _ := os.Stat("/proc/thread-self/ns/net")
			s := newLinuxStandardService(f.root, image, namespace)
			path := filepath.Join(f.root, "run", "kill-switch.json")
			if kind != "unmarked-home-always" {
				body := linuxStandardServicePreviousBootState(t, f.root, "control", "203.0.113.41")
				switch kind {
				case "legacy-state":
					body = []byte(`{"policy":"always","policy_profile_id":"control","profile_id":"control","endpoint":"203.0.113.41"}`)
				case "current-standard":
					boot, _ := readDesktopLinuxNodeBootID()
					body = []byte(strings.ReplaceAll(string(body), "00000000-0000-0000-0000-000000000001", boot))
				case "corrupt-marker":
					body = []byte(`{"policy":"always","linux_standard_owner":null}`)
				case "corrupt-receipt":
					body = []byte(strings.ReplaceAll(string(body), `"chain_handle":2`, `"chain_handle":3`))
				case "duplicate-marker":
					body = append([]byte(`{"linux_standard_owner":null,`), body[1:]...)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			m := newLegacyProtectionModel()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			legacyCalls := 0
			legacy := func(ctx context.Context) error {
				legacyCalls++
				if err := s.startLegacyBoot(ctx, linuxLegacyBootTestCommand("success")); err != nil {
					return err
				}
				return s.joinLegacyBoot(ctx)
			}
			err := s.reassertDispatch(ctx, func() error { return nil }, func(context.Context) error { return nil }, m.create, legacy)
			switch kind {
			case "unmarked-home-always", "legacy-state":
				if err != nil || legacyCalls != 1 || s.legacyBoot == nil || !s.legacyBoot.complete || s.boot != nil || len(m.events) != 0 {
					t.Fatal("unmarked legacy policy became guessed standard ownership", err)
				}
			case "previous-standard":
				if err != nil || legacyCalls != 0 || s.boot == nil || !s.boot.persisted {
					t.Fatal("explicit prior standard policy lost fresh original creator", err)
				}
				lease, e := acquireLegacyExitMutationLease(ctx, f.root)
				if e != nil {
					t.Fatal(e)
				}
				defer lease.Close()
				if e = s.boot.release(ctx, lease); e != nil {
					t.Fatal(e)
				}
			default:
				if err == nil || legacyCalls != 0 || s.boot != nil || len(m.events) != 0 {
					t.Fatal("invalid/current marker delegated or adopted original native authority", err)
				}
			}
		})
	}
}

func TestLinuxStandardServiceLegacyBootRetainsOriginalChildAcrossDeadline(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	image, _ := os.Stat("/proc/self/exe")
	namespace, _ := os.Stat("/proc/thread-self/ns/net")
	s := newLinuxStandardService(f.root, image, namespace)
	command := linuxLegacyBootTestCommand("wait")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err = s.startLegacyBoot(ctx, command); err != nil {
		t.Fatal(err)
	}
	original := s.legacyBoot
	if err = s.joinLegacyBoot(ctx); !errors.Is(err, context.DeadlineExceeded) || original.complete {
		t.Fatal("helper deadline fabricated child completion", err)
	}
	if retired, err := legacyExitPIDFDState(original.pidfd); err != nil || retired {
		t.Fatal("original helper was killed or replaced at budget expiry", err)
	}
	if err = s.prepareIdleShutdownWithObservers(context.Background(), func() error { return nil }, func(context.Context) error { return nil }); err == nil {
		t.Fatal("idle upgrade discarded original running helper")
	}
	if err = s.startLegacyBoot(context.Background(), linuxLegacyBootTestCommand("success")); err == nil {
		t.Fatal("retry replaced unjoined original helper")
	}
	_ = input.Close()
	retry, finish := context.WithTimeout(context.Background(), 5*time.Second)
	defer finish()
	if err = s.joinLegacyBoot(retry); err != nil || s.legacyBoot != original || !original.complete || !original.joined {
		t.Fatal("helper retry failed original wait/pidfd join", err)
	}
}

func TestLinuxStandardServiceLegacyBootFailureCannotReportReady(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	image, _ := os.Stat("/proc/self/exe")
	namespace, _ := os.Stat("/proc/thread-self/ns/net")
	s := newLinuxStandardService(f.root, image, namespace)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.startLegacyBoot(ctx, linuxLegacyBootTestCommand("failure")); err != nil {
		t.Fatal(err)
	}
	if err := s.joinLegacyBoot(ctx); err == nil || !s.legacyBoot.complete || !s.legacyBoot.joined {
		t.Fatal("legacy child failure was hidden before original join", err)
	}
	if err := s.notifyBoot(ctx, nil); err == nil {
		t.Fatal("failed actual legacy helper reported READY")
	}
	if s.boot != nil {
		t.Fatal("legacy failure invented retained standard authority")
	}
}

func TestLinuxStandardServiceLegacyBootRejectsReplacementChildDescriptor(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	image, _ := os.Stat("/proc/self/exe")
	namespace, _ := os.Stat("/proc/thread-self/ns/net")
	original := newLinuxStandardService(f.root, image, namespace)
	foreign := newLinuxStandardService(f.root, image, namespace)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, service := range []*linuxStandardService{original, foreign} {
		if err := service.startLegacyBoot(ctx, linuxLegacyBootTestCommand("success")); err != nil {
			t.Fatal(err)
		}
	}
	saved := original.legacyBoot.pidfd
	original.legacyBoot.pidfd = foreign.legacyBoot.pidfd
	if err := original.joinLegacyBoot(ctx); err == nil || original.legacyBoot.complete {
		t.Fatal("foreign retired descriptor authorized original helper completion")
	}
	original.legacyBoot.pidfd = saved
	for _, service := range []*linuxStandardService{original, foreign} {
		if err := service.joinLegacyBoot(ctx); err != nil {
			t.Fatal("original helper could not join after descriptor replacement was refused", err)
		}
	}
}
