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
)

// Use the same installed-image/remote-proof seam as the existing retained
// multihop lifecycle test. Capture, staging, child/Stop join, DNS configuration,
// runtime registries and restore selection are the real shipping paths.
func TestDesktopImportedDailyConnectRestoreAndOwnedTeardown(t *testing.T) {
	desktopImportedDailyConnectRestoreAndOwnedTeardown(t, "shadowsocks")
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
			entry, _ := desktopExternalNativeFixture(t, protocol)
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
