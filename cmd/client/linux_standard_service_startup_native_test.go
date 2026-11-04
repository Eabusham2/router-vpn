//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/standardengine"
)

func init() {
	if os.Getenv("ROUTERVPN_STANDARD_STARTUP_CHILD") != "" && len(os.Args) == 4 && os.Args[1] == "routervpn-standard" {
		if err := linuxStandardStartupChildFixture(os.Getenv("ROUTERVPN_STANDARD_STARTUP_CHILD"), os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, "actual startup fixture:", err)
			os.Exit(83)
		}
		os.Exit(0)
	}
}

// Real sealed executable, original channel, task witnesses and clone pidfd.
// Only the child's native routing ledger and kernel observer are modeled here;
// the installed namespace case requires the actual generated engine/TUN.
func linuxStandardStartupChildFixture(scenario, expected string) error {
	raw, err := standardengine.ReadSealed(os.NewFile(9, "capture"), 2048)
	if err != nil {
		return err
	}
	capture, err := standardengine.DecodeCapture(raw, expected)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, capture.DeadlineNS))
	defer cancel()
	channel, err := linuxprocess.CaptureChannel(os.NewFile(7, "channel"))
	if err != nil {
		return err
	}
	imageFile := os.NewFile(3, "original-sealed-executable")
	defer imageFile.Close()
	if err := linuxprocess.SetCloseOnExec(imageFile); err != nil {
		return err
	}
	image, err := linuxprocess.CaptureSealedImage(imageFile)
	if err != nil {
		return err
	}
	peer, err := linuxprocess.BindInheritedSealedParent(ctx, channel, os.NewFile(8, "parent"), expected, image)
	if err != nil {
		return err
	}
	defer peer.Close(context.Background())
	config, err := standardengine.ReadSealed(os.NewFile(4, "config"), standardengine.MaxConfig)
	if err != nil || standardengine.SHA256(config) != capture.ConfigSHA256 {
		return errors.New("fixture lost original sealed config")
	}
	shape, err := standardengine.Config(config, capture.Mode)
	if err != nil {
		return err
	}
	if scenario == "cancelled" {
		if err := os.WriteFile("startup-bootstrap-entered", []byte("bound"), 0600); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
	receipt := desktopnetwork.DesktopNetworkReceipt{Schema: 1, TargetOS: "linux", Incarnation: strings.Repeat("f", 32), Name: shape.Name, Index: 91, MTU: shape.MTU, Addresses: []string{"172.29.0.1/30"}}
	if scenario == "wrong-mtu" {
		receipt.MTU++
	}
	ledger, err := desktopnetwork.CanonicalDesktopNetworkReceipt(receipt)
	if err != nil {
		return err
	}
	if scenario == "malformed-ledger" {
		ledger = "{}"
	}
	if scenario == "wrong-source" {
		expected = strings.Repeat("a", 64)
	}
	body, err := (standardengine.Ready{Schema: 1, CaptureSHA256: expected, NetworkReceipt: ledger}).Canonical()
	if err != nil {
		return err
	}
	if err := peer.Send(ctx, body); err != nil {
		return err
	}
	lifetime, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-lifetime.Done()
	return nil
}

type linuxStandardStartupObserverFixture struct {
	began, recorded, ended, closed bool
	failure, closeFailure          error
	invalidateAtRecord             bool
	receipt                        desktopnetwork.DesktopNetworkReceipt
}

func (n *linuxStandardStartupObserverFixture) CurrentContext(ctx context.Context) error {
	if n.failure != nil {
		return n.failure
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if n.closed {
		return errors.New("closed model observer")
	}
	return nil
}
func (n *linuxStandardStartupObserverFixture) Begin(ctx context.Context, old *desktopnetwork.DesktopNetworkReceipt) error {
	if err := n.CurrentContext(ctx); err != nil {
		return err
	}
	if n.began || old != nil {
		return errors.New("reused model startup")
	}
	n.began = true
	return nil
}
func (n *linuxStandardStartupObserverFixture) Record(r desktopnetwork.DesktopNetworkReceipt) error {
	if !n.began || r.Validate() != nil {
		return errors.New("unowned model ledger")
	}
	n.receipt = r
	n.recorded = true
	if n.invalidateAtRecord {
		n.failure = errors.New("original network invalidated during ledger adoption")
	}
	return nil
}
func (n *linuxStandardStartupObserverFixture) End(ctx context.Context, r *desktopnetwork.DesktopNetworkReceipt) error {
	if !n.began || !n.recorded || r == nil || n.receipt.Incarnation != r.Incarnation {
		return errors.New("model transition lost original ledger")
	}
	if err := n.CurrentContext(ctx); err != nil {
		return err
	}
	n.ended = true
	return nil
}
func (n *linuxStandardStartupObserverFixture) Close() error {
	if n.closeFailure != nil {
		return n.closeFailure
	}
	n.closed = true
	return nil
}

func linuxStandardStartupFixture(t *testing.T, scenario string) (*linuxStandardService, *legacyExitFixture, *linuxStandardStartupObserverFixture) {
	t.Helper()
	s, f, _ := linuxStandardServiceRuntimeFixture(t, "on-connect")
	observer := &linuxStandardStartupObserverFixture{invalidateAtRecord: scenario == "late-network"}
	prepare := s.prepare
	s.prepare = func(a *app, cmd *exec.Cmd, mode, base, id string) (legacyStandardExitLaunch, error) {
		result, err := prepare(a, cmd, mode, base, id)
		if err != nil {
			return result, err
		}
		o := result.(*linuxLegacyStandardExitOwner)
		executable, err := os.Open("/proc/self/exe")
		if err != nil {
			return result, err
		}
		defer executable.Close()
		image, err := sealLegacyExitFile("original-test-native-engine", executable, 512<<20)
		if err != nil {
			return result, err
		}
		_ = o.image.Close()
		o.image = image
		o.command.ExtraFiles[0] = image
		libraryPath := filepath.Join(f.root, "runtime", "native", "libcronet.so")
		if err := os.MkdirAll(filepath.Dir(libraryPath), 0700); err != nil {
			return result, err
		}
		if err := os.WriteFile(libraryPath, []byte("explicit model library bytes"), 0600); err != nil {
			return result, err
		}
		manifestPath := filepath.Join(filepath.Dir(libraryPath), "NATIVE-RUNTIME.json")
		if err := os.WriteFile(manifestPath, []byte("explicit model manifest"), 0600); err != nil {
			return result, err
		}
		library, err := os.Open(libraryPath)
		if err != nil {
			return result, err
		}
		manifest, err := os.Open(manifestPath)
		if err != nil {
			return result, err
		}
		libraryInfo, _ := library.Stat()
		manifestInfo, _ := manifest.Stat()
		sealed, err := sealLegacyExitFile("original-model-library", library, 128<<20)
		if err != nil {
			return result, err
		}
		raw, err := standardengine.ReadSealed(o.config, standardengine.MaxConfig)
		if err != nil {
			return result, err
		}
		shape, err := standardengine.Config(raw, mode)
		if err != nil {
			return result, err
		}
		imagePath := filepath.Join(filepath.Dir(libraryPath), "sing-box-routervpn")
		if err := os.WriteFile(imagePath, []byte("explicit original model image source"), 0500); err != nil {
			return result, err
		}
		imageSource, err := os.Open(imagePath)
		if err != nil {
			return result, err
		}
		imageInfo, err := imageSource.Stat()
		if err != nil {
			return result, err
		}
		lifetime, cancel := context.WithCancel(context.Background())
		o.native = &linuxStandardEngine{owner: o, imagePath: imagePath, imageSource: imageSource, imageInfo: imageInfo, manifestPath: manifestPath, manifest: manifest, manifestInfo: manifestInfo,
			librarySource: library, libraryInfo: libraryInfo, library: sealed, tracker: observer, lifetime: lifetime, cancel: cancel, shape: shape, closedFiles: make(map[*os.File]bool)}
		o.command.Stderr = os.Stderr
		o.command.Env = append(o.command.Env, "ROUTERVPN_STANDARD_STARTUP_CHILD="+scenario, "GORACE=atexit_sleep_ms=0")
		return o, nil
	}
	return s, f, observer
}

func TestLinuxStandardServiceStartupUsesOriginalChildLedger(t *testing.T) {
	for _, scenario := range []string{"complete", "wrong-source", "wrong-mtu", "malformed-ledger", "late-network", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			s, f, observer := linuxStandardStartupFixture(t, scenario)
			peer, _, _ := linuxStandardPeerFixture(t)
			request, directory := linuxStandardServiceRequestFixture(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			observed := make(chan bool, 1)
			if scenario == "cancelled" {
				go func() {
					ticker := time.NewTicker(5 * time.Millisecond)
					defer ticker.Stop()
					for {
						if _, err := os.Stat(filepath.Join(f.root, "startup-bootstrap-entered")); err == nil {
							observed <- true
							cancel()
							return
						}
						select {
						case <-ctx.Done():
							observed <- false
							return
						case <-ticker.C:
						}
					}
				}()
			}
			err := s.handle(ctx, peer, request, []*os.File{directory})
			if scenario == "cancelled" && !<-observed {
				t.Fatal("cancellation did not follow the actual child bootstrap")
			}
			if (err == nil) != (scenario == "complete") {
				t.Fatal("original startup verdict changed", err)
			}
			if s.session == nil || s.session.owner == nil || s.session.owner.command.Process == nil || s.session.owner.originalPIDFD == nil {
				t.Fatal("startup lost actual original engine")
			}
			owner := s.session.owner
			if scenario != "complete" && scenario != "cancelled" {
				witness := "standard startup ledger changed"
				if scenario == "wrong-source" {
					witness = "belongs to another source"
				}
				if scenario == "late-network" {
					witness = "invalidated during ledger adoption"
				}
				if !strings.Contains(err.Error(), witness) {
					t.Fatal("negative did not reach original ledger boundary", err)
				}
				if check := owner.native.bootstrap.CheckCapture(ctx, owner.native.captureSHA); check != nil {
					t.Fatal("negative did not authenticate original child before rejecting its ledger", check)
				}
				if check := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "current", false), nil); check == nil {
					t.Fatal("failed startup returned a successful current proof")
				}
			}
			if !observer.began || observer.ended != (scenario == "complete") || owner.native.ready != (scenario == "complete") {
				t.Fatal("startup bypassed original ledger transition", observer.began, observer.ended, owner.native.ready)
			}
			cleanup, stop := context.WithTimeout(context.Background(), 8*time.Second)
			defer stop()
			if err := s.retire(cleanup, false); err != nil {
				t.Fatal("original startup cleanup did not join", err)
			}
			if !observer.closed || !s.session.joined || !owner.protection.detached || owner.protection.removed {
				t.Fatal("failed startup discarded its original guard or observer")
			}
			assertLegacyOffJoined(t, owner)
			if err := s.handle(cleanup, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
				t.Fatal("explicit Stop lost original detached protection", err)
			}
		})
	}
}

// A failed post-prepare source check must retain the original partial native
// observer/files even when their first close cannot finish. No child is created.
func TestLinuxStandardServiceStartupRetainsRejectedPreparation(t *testing.T) {
	for _, scenario := range []string{"configuration", "network", "workspace-name", "workspace-descriptor", "preparation-error"} {
		t.Run(scenario, func(t *testing.T) {
			s, f, observer := linuxStandardStartupFixture(t, "complete")
			peer, _, _ := linuxStandardPeerFixture(t)
			request, directory := linuxStandardServiceRequestFixture(t, f)
			prepare := s.prepare
			var original *linuxLegacyStandardExitOwner
			var restore func()
			s.prepare = func(a *app, command *exec.Cmd, mode, base, id string) (legacyStandardExitLaunch, error) {
				prepared, err := prepare(a, command, mode, base, id)
				if err != nil {
					return prepared, err
				}
				original = prepared.(*linuxLegacyStandardExitOwner)
				switch scenario {
				case "configuration":
					original.digest = strings.Repeat("f", 64)
				case "network":
					original.dns.networkID = "changed-original-network"
				case "workspace-name":
					path := original.launch.directory
					if err := os.Rename(path, path+"-original"); err != nil {
						return original, err
					}
					if err := os.Mkdir(path, 0700); err != nil {
						return original, err
					}
					restore = func() {
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(path+"-original", path); err != nil {
							t.Fatal(err)
						}
					}
				case "workspace-descriptor":
					actual := original.directory
					foreign, err := os.Open(t.TempDir())
					if err != nil {
						return original, err
					}
					original.directory = foreign
					restore = func() { foreign.Close(); original.directory = actual }
				case "preparation-error":
					return original, errors.New("captured preparation failed")
				}
				return original, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			err := s.handle(ctx, peer, request, []*os.File{directory})
			if err == nil || original == nil || s.session == nil || s.session.owner != original || s.session.peer != peer || !s.session.cleanupPending || s.session.request != request {
				t.Fatal("rejected preparation lost its original retry owner", err)
			}
			if original.command.Process != nil || observer.closed || observer.began {
				t.Fatal("rejected preparation ran or discarded its original engine")
			}
			observer.closeFailure = errors.New("original reader join incomplete")
			if err := s.retire(ctx, false); err == nil || s.session.joined || s.session.owner != original || !s.session.cleanupPending || observer.closed {
				t.Fatal("failed original join erased retained partial owner", err)
			}
			if _, err := original.image.Stat(); err != nil {
				t.Fatal("failed native join closed original engine inputs", err)
			}
			cancelled, stop := context.WithCancel(ctx)
			stop()
			observer.closeFailure = nil
			if err := original.discardContext(cancelled); err == nil || observer.closed {
				t.Fatal("expired preparation extended cleanup budget", err)
			}
			if restore != nil {
				restore()
			}
			if err := s.retire(ctx, false); err != nil || !s.session.joined || s.session.cleanupPending || !observer.closed {
				t.Fatal("original partial owner did not complete retry", err)
			}
			if _, err := original.image.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("successful partial retirement left original image open", err)
			}
		})
	}
}

func TestLinuxStandardServiceStartupRequiresVerifiedRuntime(t *testing.T) {
	for _, scenario := range []string{"absent", "corrupt"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "bin"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "bin", "sing-box"), []byte("#!/bin/sh\nexit 0\n"), 0500); err != nil {
				t.Fatal(err)
			}
			if scenario == "corrupt" {
				if err := os.MkdirAll(filepath.Join(root, "runtime", "native"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "runtime", "native", "NATIVE-RUNTIME.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			owner := &linuxLegacyStandardExitOwner{protectionRoot: root}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			observer := &linuxStandardStartupObserverFixture{}
			if err := owner.prepareNativeEngineWithObserver(ctx, func(context.Context, context.Context) (linuxStandardStartupObserver, error) { return observer, nil }); err == nil || owner.native == nil || owner.native.imagePath != "" || owner.native.tracker != observer {
				t.Fatal("missing verified runtime fell back to unrelated installed stock image", err)
			}
			if err := owner.native.close(ctx); err != nil {
				t.Fatal("failed verified selection did not retain original partial owner", err)
			}
		})
	}
}

func TestLinuxStandardServiceStartupInstalledRequestHasNoStockChild(t *testing.T) {
	for _, scenario := range []string{"installed-request", "noninstalled-stock-required"} {
		t.Run(scenario, func(t *testing.T) {
			_, f, _ := linuxStandardServiceRuntimeFixture(t, "on-connect")
			command, err := nativeStandardExitCommand(f.a, f.a.profiles.Profiles[0], common.RouterProfile{}, f.exit, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(f.root, "bin", "sing-box")); err != nil {
				t.Fatal(err)
			}
			requestOnly := scenario == "installed-request"
			if requestOnly {
				f.a.localController = &linuxOwnedController{}
			}
			captured, err := prepareLegacyStandardExitOwnerWithRequestObserver(f.a, command, "standard-"+f.exit.Protocol, "external", "standard:"+f.exit.ID, func() error { return nil }, func() string { return "captured-test-network" }, false, requestOnly, func(context.Context, context.Context) (linuxStandardStartupObserver, error) {
				return &linuxStandardStartupObserverFixture{}, nil
			})
			if !requestOnly {
				if err == nil || !strings.Contains(err.Error(), "stock standard engine is unavailable") {
					t.Fatal("noninstalled stock path silently changed selection", err)
				}
				return
			}
			if err != nil || captured == nil {
				t.Fatal("installed request required an unrelated PATH executable", err)
			}
			owner := captured.(*linuxLegacyStandardExitOwner)
			defer owner.Discard()
			if owner.command != command || command.Process != nil || owner.image != nil || owner.sourceImage != nil || owner.native != nil || owner.requestEpoch == nil || !owner.requestEpoch.bound || owner.config == nil || owner.sourceConfig == nil || owner.directory == nil || owner.dns == nil {
				t.Fatal("controller source capture lost its exact request epoch or created an engine")
			}
			raw, err := standardengine.ReadSealed(owner.config, standardengine.MaxConfig)
			if err != nil || standardengine.SHA256(raw) != owner.digest || desktopExternalDirectoryCurrent(owner.launch) != nil {
				t.Fatal("installed request did not retain original sealed graph/workspace", err)
			}
		})
	}
}

func TestLinuxStandardServiceStartupPreparationFailureKeepsRetry(t *testing.T) {
	for _, scenario := range []string{"preparation-error", "remote-error", "replacement-workspace", "adopted-owner"} {
		t.Run(scenario, func(t *testing.T) {
			_, f, _ := linuxStandardServiceRuntimeFixture(t, "always")
			command, err := nativeStandardExitCommand(f.a, f.a.profiles.Profiles[0], common.RouterProfile{}, f.exit, true)
			if err != nil {
				t.Fatal(err)
			}
			f.a.localController = &linuxOwnedController{}
			prepared, err := prepareLegacyStandardExitOwnerWithRequestObserver(f.a, command, "standard-"+f.exit.Protocol, "external", "standard:"+f.exit.ID, func() error { return nil }, func() string { return "captured-test-network" }, false, true, func(context.Context, context.Context) (linuxStandardStartupObserver, error) {
				return &linuxStandardStartupObserverFixture{}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			owner := prepared.(*linuxLegacyStandardExitOwner)
			defer legacyStandardExitPreparations.Delete(owner)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			failure := errors.New("original preparation rejected")
			if scenario == "remote-error" {
				failure = nil
			} // Actual installed-root validation fails.
			retained, err := finishLegacyStandardExitPreparation(f.a, ctx, owner, failure)
			if err == nil || retained != owner {
				t.Fatal("failed preparation lost original capture", err)
			}
			if value, ok := legacyStandardExitPreparations.Load(owner); !ok || value != f.a {
				t.Fatal("route error has no cleanup retry owner")
			}
			if _, err := owner.config.Stat(); err != nil {
				t.Fatal("cancelled request acquired a fresh cleanup budget", err)
			}
			if owner.command.Process != nil || owner.registered || owner.native != nil {
				t.Fatal("request cleanup started/adopted an engine")
			}
			newer := &linuxStandardServiceLaunch{app: f.a, joined: true}
			linuxStandardServiceOwners.Store(f.a, newer)
			defer linuxStandardServiceOwners.CompareAndDelete(f.a, newer)
			if err := retireLegacyStandardPreparations(f.a, ctx); err == nil {
				t.Fatal("expired Stop retired original capture")
			}
			fresh, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if scenario == "replacement-workspace" {
				path := owner.launch.directory
				if err := os.Rename(path, path+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := retireLegacyStandardPreparations(f.a, fresh); err == nil {
					t.Fatal("retry erased replacement workspace")
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatal("replacement workspace was touched", err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path+"-original", path); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "adopted-owner" {
				owner.registered = true
				if err := retireLegacyStandardPreparations(f.a, fresh); err == nil {
					t.Fatal("pending registry retired an adopted runtime")
				}
				if _, err := owner.config.Stat(); err != nil {
					t.Fatal("adopted capture was closed", err)
				}
				owner.registered = false
			}
			observer := &linuxStandardStartupObserverFixture{closeFailure: errors.New("original preparation join pending")}
			owner.native = &linuxStandardEngine{owner: owner, tracker: observer, closedFiles: make(map[*os.File]bool)}
			if err := f.a.stopModeWithIntent(true); err == nil || !strings.Contains(err.Error(), "original preparation join pending") || observer.closed {
				t.Fatal("shipping Stop bypassed exact preparation retry", err)
			}
			observer.closeFailure = nil
			if err := retireLegacyStandardPreparations(f.a, fresh); err != nil {
				t.Fatal("original preparation did not complete retry", err)
			}
			if _, ok := legacyStandardExitPreparations.Load(owner); ok {
				t.Fatal("joined preparation remained pending")
			}
			if value, ok := linuxStandardServiceOwners.Load(f.a); !ok || value != newer {
				t.Fatal("old preparation cleanup replaced current runtime/protection owner")
			}
			if _, err := owner.config.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("original private config remained open", err)
			}
		})
	}
}

func TestLinuxStandardServiceStartupVerificationKeepsOriginalSources(t *testing.T) {
	for _, scenario := range []string{"unchanged", "catalog", "image", "library", "in-place", "foreign-result", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "runtime", "native")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			receipt := nativeReceiptFixture()
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string][]byte{"NATIVE-RUNTIME.json": raw, nativeBinaryName(): []byte("model image"), "libcronet.so": []byte("model library")} {
				if err := os.WriteFile(filepath.Join(directory, name), body, 0500); err != nil {
					t.Fatal(err)
				}
			}
			n := &linuxStandardEngine{owner: &linuxLegacyStandardExitOwner{protectionRoot: root}, closedFiles: make(map[*os.File]bool)}
			defer n.close(context.Background())
			if err := n.captureSources(); err != nil {
				t.Fatal(err)
			}
			original := n.manifest
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Full native provenance/version acceptance is exercised by the real bundle
			// gate. This explicit verifier seam mutates the actual captured filesystem.
			err = n.verifySources(ctx, func(context.Context, string) (string, error) {
				name := ""
				switch scenario {
				case "catalog":
					name = "NATIVE-RUNTIME.json"
				case "image":
					name = nativeBinaryName()
				case "library":
					name = "libcronet.so"
				}
				if name != "" {
					path := filepath.Join(directory, name)
					if err := os.Rename(path, path+"-original"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte("replacement"), 0500); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "in-place" {
					if err := os.Chmod(n.manifestPath, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(n.manifestPath, raw, 0500); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "foreign-result" {
					return filepath.Join(directory, "foreign"), nil
				}
				if scenario == "cancelled" {
					cancel()
				}
				return n.imagePath, nil
			})
			if scenario == "unchanged" && err != nil {
				t.Fatal(err)
			}
			if scenario != "unchanged" && err == nil {
				t.Fatal("verification rebased original catalog/payload capture")
			}
			if n.manifest != original {
				t.Fatal("verification replaced original retained descriptor")
			}
			if _, err := original.Stat(); err != nil {
				t.Fatal("failed verification lost cleanup capability", err)
			}
		})
	}
}
