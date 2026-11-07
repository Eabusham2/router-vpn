package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/nativeopenvpn"
)

// Use the same installed-image/remote-proof seam as the existing retained
// multihop lifecycle test. Capture, staging, child/Stop join, DNS configuration,
// runtime registries and restore selection are the real shipping paths.
func TestDesktopImportedDailyConnectRestoreAndOwnedTeardown(t *testing.T) {
	desktopImportedDailyConnectRestoreAndOwnedTeardown(t, "shadowsocks")
}

func TestDesktopImportedOpenVPNDailyConnectRestoreAndOwnedTeardown(t *testing.T) {
	desktopImportedDailyConnectRestoreAndOwnedTeardown(t, "openvpn")
}

func desktopImportedDailyConnectRestoreAndOwnedTeardown(t *testing.T, protocol string) {
	t.Helper()
	if physicalNetworkIdentity() == "" {
		if os.Getenv("ROUTERVPN_REQUIRE_IMPORTED_DESKTOP_LIFECYCLE") == "1" {
			t.Fatal("required imported desktop lifecycle cannot inventory a physical network")
		}
		t.Skip("imported desktop retained-process lifecycle requires permitted physical network inventory")
	}
	for _, fault := range []string{"success", "public-proof", "source-replaced"} {
		t.Run(fault, func(t *testing.T) {
			f := newNativeMultihopFailureFixture(t, "on-connect")
			if protocol == "openvpn" {
				// Retain a deterministic registered tracker, without starting an
				// unrelated background DNS request in this lifecycle fixture.
				sessionTrackers.Store(f.a, &sessionTracker{a: f.a, dnsProofLastAttempt: time.Now()})
			}
			var entry common.RouterProfile
			if protocol == "openvpn" {
				entry = desktopImportedOpenVPNProfileFixture(t, "tcp")
			} else {
				entry, _ = desktopExternalNativeFixture(t, protocol)
			}
			entry.ID = "entry"
			if protocol == "shadowsocks" {
				entry.External.Shadowsocks.Method = "2022-blake3-aes-256-gcm"
			}
			final := cloneRouterProfile(f.a.profiles.Profiles[2])
			final.DAITAEnabled = false
			final.KillSwitch, final.KillSwitchPolicy = true, "on-connect"
			final.MTUPolicy, final.ManualMTU = "manual", 1280
			final.MultihopEnabled, final.MultihopEntryID, final.MultihopExitID = true, entry.ID, final.ID
			final.MultihopEntryMode, final.MultihopExecution = "", "local"
			f.a.profiles.SelectedID, f.a.profiles.Profiles = final.ID, []common.RouterProfile{entry, final}
			if err := f.a.persistProfilesLocked(); err != nil {
				t.Fatal(err)
			}
			var captured multihopSelection
			originalCapture := f.driver.capture
			f.driver.capture = func(a *app, selection multihopSelection, modes []string) (multihopSelection, error) {
				var err error
				captured, err = originalCapture(a, selection, modes)
				return captured, err
			}
			f.proof = func(launch *desktopNodeLaunch) error {
				if !captured.Native.imported || f.a.state.Connected || f.a.state.RouterID != final.ID || f.a.state.Phase != "multihop:proving-exit" {
					t.Fatal("daily startup published before independent proofs")
				}
				actual, err := readDesktopRuntimeFile(launch, "sing-box.json", 4<<20)
				if err != nil || !bytes.Contains(actual, []byte(final.AdGuardIPv4)) || bytes.Contains(actual, []byte("entry-private")) {
					t.Fatal("staging changed final DNS or fabricated paired entry proof", err)
				}
				if fault == "public-proof" {
					return errors.New("imported entry public address differs")
				}
				if fault == "source-replaced" {
					f.a.mu.Lock()
					changed := f.a.profiles.Profiles[0].External
					switch protocol {
					case "wireguard":
						changed.WireGuard.PrivateKey = testWGKey('z')
					case "amneziawg":
						changed.AmneziaWG.PrivateKey = testWGKey('z')
					case "openvpn":
						changed.OpenVPN.Password += "replacement"
					default:
						changed.Shadowsocks.Password = testWGKey('z')
					}
					f.a.mu.Unlock()
					if f.a.nativeMultihopProofOwnerCurrent(captured, launch.command) {
						t.Fatal("same-ID imported replacement still owns proof")
					}
					return errors.New("source replaced before admission")
				}
				// Only the remote/native DNS exchange is modeled here. The public
				// adapter must consume the matching original private mailbox and
				// exact live TUN readback before Connected.
				readback := desktopNodeMTURecord{Schema: 1, Session: launch.mtuSession, Config: launch.configSHA256, Path: strings.Repeat("d", 64), Reader: 2, Interface: "router-vpn", Index: 7, MTU: 1280}
				if err := (&desktopNodeMTUFixture{launch: launch}).publish(readback, false); err != nil {
					t.Fatal(err)
				}
				if protocol == "openvpn" {
					// Keep the modeled mailbox peer alive through restoration too.
					// The separate production native gate observes a real TLS peer;
					// this fixture owns actual controller staging and child cleanup.
					peerContext, stop := context.WithCancel(context.Background())
					done := make(chan error, 1)
					state := nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{Remote: launch.importedOpenVPN.spec.Remote,
						Generation: 3, ConnectedAt: time.Now().UnixMilli()}, MTU: launch.importedOpenVPN.spec.Minimum}
					go func() {
						for {
							request, err := importedDesktopDNSReadRequest(peerContext, launch)
							if err != nil {
								if peerContext.Err() != nil {
									done <- nil
								} else {
									done <- err
								}
								return
							}
							var observed *nativeopenvpn.PacketObservation
							if request.Operation == "openvpn-observe" {
								observed = &state
							} else if request.Operation != "" {
								done <- errors.New("foreign native observation operation")
								return
							}
							if err := (&desktopNodeMTUFixture{launch: launch}).publish(readback, false); err != nil {
								done <- err
								return
							}
							if err := desktopImportedOpenVPNReply(launch, request, "passed", readback, observed); err != nil {
								done <- err
								return
							}
						}
					}()
					t.Cleanup(func() {
						stop()
						if err := <-done; err != nil && !desktopNodeProcessExited(launch) {
							t.Error(err)
						}
					})
					if err := f.a.observeImportedOpenVPN(context.Background(), captured, launch.command); err != nil {
						return err
					}
					_, err := f.a.proveImportedNativeDNS(context.Background(), captured, launch.command)
					return err
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				peer := make(chan error, 1)
				go func() {
					request, err := importedDesktopDNSReadRequest(ctx, launch)
					if err == nil {
						err = importedDesktopDNSReply(launch, request, "passed", readback)
					}
					peer <- err
				}()
				_, proofErr := f.a.proveImportedNativeDNS(ctx, captured, launch.command)
				return errors.Join(proofErr, <-peer)
			}
			q := multihopConnectRequest{EntryID: entry.ID, ExitID: final.ID, ExitMode: "shadowsocks", Execution: "local", Base: "wg"}
			body, _ := json.Marshal(q)
			r := httptest.NewRecorder()
			f.a.nativeMultihopConnectOwned(r, httptest.NewRequest(http.MethodPost, "/api/multihop/connect", bytes.NewReader(body)), f.driver)
			if len(f.launches) != 1 {
				t.Fatal("daily imported graph never reached actual retained staging", r.Code, r.Body.String())
			}
			launch := f.launches[0]
			if fault != "success" {
				if r.Code != http.StatusBadGateway || f.a.state.Connected {
					t.Fatal("failed original proof connected", r.Code, r.Body.String())
				}
				if _, found := desktopNodeOwners.Load(f.a); found {
					t.Fatal("failed runtime owner was not drained")
				}
				if _, found := getActiveMultihopGraph(f.a); found {
					t.Fatal("failed imported graph survived owned cleanup")
				}
				if _, err := os.Stat(launch.directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed private capture survived cleanup", err)
				}
				return
			}
			if r.Code != http.StatusOK || !f.a.state.Connected || f.a.state.RouterID != final.ID {
				t.Fatal("daily imported path not admitted", r.Code, r.Body.String())
			}
			if !reflect.DeepEqual(f.a.profiles.Profiles[0].External, entry.External) || f.a.profiles.Profiles[1].APIToken != final.APIToken {
				t.Fatal("entry/final credentials changed")
			}
			if protocol == "openvpn" {
				desktopImportedOpenVPNMeasurementLifecycle(t, f.a, captured, launch)
			}
			// A true retained readback authorizes restoration of the old graph.
			readback := desktopNodeMTURecord{Schema: 1, Session: launch.mtuSession, Config: launch.configSHA256, Path: strings.Repeat("d", 64), Reader: 2, Interface: "router-vpn", Index: 7, MTU: 1280}
			if err := (&desktopNodeMTUFixture{launch: launch}).publish(readback, false); err != nil {
				t.Fatal(err)
			}
			graph, _ := getActiveMultihopGraph(f.a)
			restored, err := captureNativeMultihopRestore(f.a, launch.command, graph, captured.Control, captured.Entry, captured.Exit)
			if err != nil || restored.Native != captured.Native || restored.restoreMTU != 1280 || restored.Entry.External == captured.Entry.External {
				t.Fatal("restore lost exact source or copied mutable credentials", err)
			}
			newLaunch, err := compileRetainedNativeMultihopLaunch(restored, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := desktopExternalDirectoryCurrent(launch); err != nil {
				t.Fatal("restore compilation removed original owner", err)
			}
			if r := externalFailureDisconnect(f.a); r.Code != http.StatusOK {
				t.Fatal(r.Code, r.Body.String())
			}
			if _, found := getActiveMultihopGraph(f.a); found {
				t.Fatal("Disconnect retained imported graph")
			}
			if _, err := os.Stat(filepath.Join(launch.directory, "sing-box.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("Disconnect retained private graph", err)
			}
			if err := stageOwnedNativeMultihopCommand(f.a, restored, newLaunch); err != nil {
				t.Fatal(err)
			}
			if newLaunch.directory == launch.directory || newLaunch.mtuSession == launch.mtuSession {
				t.Fatal("restore reused retired runtime identity")
			}
			if err := retireUnstartedNativeMultihop(newLaunch); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// These are the shipping Current-path and async-adoption adapters. The same
// modeled native peer above supplies their fresh observations; process/graph,
// source, original session and measurement locks remain real host ownership.
func desktopImportedOpenVPNMeasurementLifecycle(t *testing.T, a *app, selection multihopSelection, launch *desktopNodeLaunch) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, exists := sessionTrackers.Load(a)
	tracker, ok := raw.(*sessionTracker)
	if !exists || !ok {
		t.Fatal("connected path lost its registered tracker")
	}
	tracker.observe(tracker.capture())
	identity, path, err := captureSpeedLabIdentityContext(ctx, a)
	if err != nil || path.Topology != "multihop" || path.EntryMode != "openvpn" || identity.ImportedOpenVPN == nil {
		t.Fatal("Current path lost original connected OpenVPN observation", err)
	}
	if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
		t.Fatal(err)
	}
	_, session, err := measurementSessionContext(ctx, a, tracker)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	st := a.state
	a.mu.Unlock()
	measured, stop, valid, err := asyncMeasurementPathContext(ctx, a, selection.Exit, st, session, liveMeasurementProfileToken(selection.Exit))
	if err != nil {
		t.Fatal("async measurement omitted the original native observation", err)
	}
	defer stop()
	if err := valid(); err != nil {
		t.Fatal(err)
	}
	release, err := a.beginAsyncMeasurementAdoption(measured)
	if err != nil {
		t.Fatal("fresh original observation cannot reach measurement adoption", err)
	}
	release()
	// A cancellation is about this measurement. It must neither relatch the
	// original connected receipt nor stop the retained VPN process.
	stop()
	if launch.importedOpenVPN.retired.Load() || desktopNodeProcessExited(launch) {
		t.Fatal("measurement Stop retired healthy original VPN")
	}
	graph, _ := getActiveMultihopGraph(a)
	cancelled, abort := context.WithCancel(context.Background())
	abort()
	before := launch.importedDNSGeneration
	if _, err := captureNativeMultihopRestoreContext(cancelled, a, launch.command, graph, selection.Control, selection.Entry, selection.Exit); err == nil || launch.importedDNSGeneration != before {
		t.Fatal("cancelled restore queried or adopted OpenVPN")
	}
	// Losing the original TUN owner is terminal for every captured caller,
	// including a replacement that happens to carry the old command pointer.
	replacement := &desktopNodeLaunch{command: launch.command}
	if !desktopNodeOwners.CompareAndSwap(a, launch, replacement) {
		t.Fatal("test lost original TUN owner")
	}
	defer desktopNodeOwners.CompareAndSwap(a, replacement, launch)
	if err := validateSpeedLabIdentityContext(ctx, a, identity); err == nil {
		t.Fatal("Current measurement followed replacement owner")
	}
	if _, err := captureNativeMultihopRestoreContext(ctx, a, launch.command, graph, selection.Control, selection.Entry, selection.Exit); err == nil {
		t.Fatal("restore borrowed replacement TUN owner")
	}
	if err := a.observeImportedOpenVPN(ctx, selection, launch.command); err == nil {
		t.Fatal("public proof could borrow replacement owner")
	}
	if _, err := a.proveImportedNativeDNS(ctx, selection, launch.command); err == nil {
		t.Fatal("DNS borrowed replacement OpenVPN owner")
	}
	if current, present := desktopNodeOwners.Load(a); !present || current != replacement || desktopNodeProcessExited(launch) {
		t.Fatal("retired observation touched a replacement or stopped the original process")
	}
}
