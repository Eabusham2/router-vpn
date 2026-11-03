//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
)

const macOSExternalNativeMarker = "fixture-external-host"

// This separate test-only role serves the actual application handlers inside
// the installed supervisor's authenticated original controller. The regular
// installer/controller fixture retains its existing no-PF-mutation lifecycle.
func macOSExternalNativeController(owned *ownedDesktopController) (bool, error) {
	raw, err := readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, macOSExternalNativeMarker), 128)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || string(raw) != "explicit disposable macOS external PF and TUN fixture\n" {
		return true, errors.Join(err, errors.New("native external fixture has no fixed disposable authority"))
	}
	a := &app{localController: owned, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{
		AutoTestSeconds: 10, Listen: linuxOwnedControllerAddress,
		ProfilesFile: filepath.Join(macOSOwnedControllerRoot, "routers.json"),
		ModesFile:    filepath.Join(macOSOwnedControllerRoot, "modes.json"),
		ScriptsDir:   filepath.Join(macOSOwnedControllerRoot, "modes"),
		StateFile:    filepath.Join(macOSOwnedControllerRoot, "state.json"),
	}}
	raw, err = readPrivateRegular(a.cfg.ProfilesFile, 64<<10)
	if err != nil || decodeRelayControlJSON(raw, &a.profiles) != nil || len(a.profiles.Profiles) != 1 || a.profiles.SelectedID != "installed-macos-external" || a.profiles.Profiles[0].ID != a.profiles.SelectedID {
		return true, errors.Join(err, errors.New("native external fixture lost its saved private profile"))
	}
	raw, err = readPrivateRegular(a.cfg.ModesFile, 256<<10)
	if err != nil || json.Unmarshal(raw, &a.modes) != nil || len(a.modes) != 20 {
		return true, errors.Join(err, errors.New("native external fixture lost its shipping mode catalog"))
	}
	captured, err := captureDesktopMacOSSession(context.Background(), a)
	if err != nil {
		return true, err
	}
	closing := newControllerShutdown(a, owned.ownerToken)
	listener, err := net.Listen("tcp4", linuxOwnedControllerAddress)
	if err != nil {
		return true, err
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if captured.Current(r.Context()) != nil {
			http.Error(w, "original controller unavailable", http.StatusConflict)
			return
		}
		a.mu.Lock()
		value := a.state
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(value)
	})
	mux.HandleFunc("/api/external-profile/connect", a.externalProfileConnect)
	mux.HandleFunc("/api/disconnect", a.disconnect)
	var observationMu sync.Mutex
	var original *desktopMacOSExternalHost
	mux.HandleFunc("/api/native-external-observation", func(w http.ResponseWriter, r *http.Request) {
		observationMu.Lock()
		defer observationMu.Unlock()
		if value, found := desktopExternalRetainedLaunches.Load(a); found {
			launch, ok := value.(*desktopNodeLaunch)
			if !ok || launch.external == nil {
				http.Error(w, "untyped native launch", http.StatusConflict)
				return
			}
			host, ok := launch.external.retained.(*desktopMacOSExternalHost)
			if !ok || host == nil || host.parent.parent != captured.parent || host.parent.session != captured.session || original != nil && original != host {
				http.Error(w, "replaced native host", http.StatusConflict)
				return
			}
			original = host
		}
		if original == nil {
			http.Error(w, "missing native host", http.StatusConflict)
			return
		}
		result, err := macOSExternalNativeObservation(r.Context(), original)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	return true, serveClientHTTP(closing, listener, mux, make(chan os.Signal))
}

type macOSExternalNativeResult struct {
	Session, Source, Config, Protocol                 string
	ProcessID                                         int
	Connected, Closed, NativeJoined, WorkspaceRetired bool
	Network                                           desktopnetwork.DesktopNetworkReceipt
	Baseline                                          *desktopMacOSExternalReceipt
	Proof                                             desktopExternalProof
}

func macOSExternalNativeObservation(ctx context.Context, h *desktopMacOSExternalHost) (macOSExternalNativeResult, error) {
	var result macOSExternalNativeResult
	if err := h.enter(ctx); err != nil {
		return result, err
	}
	defer func() { h.gate <- struct{}{} }()
	result.Session, result.Source, result.Config, result.Protocol = h.selection.Session, h.selection.Source, h.selection.Config, h.selection.Protocol
	result.Closed, result.NativeJoined, result.WorkspaceRetired = h.closed, h.nativeRetired, h.workspaceRetired
	if h.baseline != nil {
		value := *h.baseline
		result.Baseline = &value
	}
	if h.process == nil || h.process.command == nil || h.process.command.Process == nil {
		return result, errors.New("native observation lacks its created runtime")
	}
	result.ProcessID = h.process.command.Process.Pid
	if h.closed {
		if err := h.process.NativeCleanup(ctx); err != nil {
			return result, err
		}
		if _, err := os.Lstat(h.launch.directory); !errors.Is(err, os.ErrNotExist) {
			return result, errors.New("native retirement retained or replaced its private workspace")
		}
		return result, nil
	}
	if err := h.current(ctx, true); err != nil {
		return result, err
	}
	proof, err := h.parent.app.readDesktopExternalProofRecord(h.launch)
	if err != nil {
		return result, err
	}
	if err = h.proofCurrent(ctx, proof); err != nil {
		return result, err
	}
	result.Proof = proof
	result.Network, err = desktopnetwork.ParseDesktopNetworkReceipt(proof.NetworkReceipt)
	if err != nil {
		return result, err
	}
	h.parent.app.mu.Lock()
	result.Connected = h.parent.app.state.Connected
	h.parent.app.mu.Unlock()
	if !result.Connected || !h.activated || h.proof == nil || h.monitorDone == nil {
		return result, errors.New("native application published incomplete active ownership")
	}
	select {
	case <-h.monitorDone:
		return result, errors.New("native monitor already retired")
	default:
	}
	return result, nil
}

// Keep error details bounded to fixture observations, never imported keys.
func macOSExternalNativeHTTP(ctx context.Context, client *http.Client, method, path, body string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://"+linuxOwnedControllerAddress+path, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+testLocalControllerAccess)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	if len(raw) > 256<<10 {
		return 0, nil, errors.New("native external response exceeded its bounded receipt")
	}
	return response.StatusCode, raw, err
}

func TestMacOSRetainedExternalNativeSealedProtocols(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "http-connect", "https-connect", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) { macOSExternalNativeCase(t, protocol) })
	}
}

func macOSExternalNativeCase(t *testing.T, protocol string) {
	t.Helper()
	fixture := macOSControllerNativeInstall(t)
	macOSExternalNativeBundle(t)
	peer := macOSExternalNativePeerStart(t, protocol)
	macOSExternalNativeTrust(t, peer)
	macOSExternalNativeInstallProfile(t, peer)
	fixture.start()
	connection := fixture.connection(fixture.uid)
	if _, err := connection.Write(macOSControllerNativeFrame()); err != nil {
		t.Fatal(err)
	}
	started := macOSControllerNativeReceipt(t, connection, "started", 0)
	client := macOSControllerNativeHTTP(t)
	client.Timeout = 65 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	joined := false
	// This cleanup is registered last: native child/controller joins precede
	// GUI-peer cleanup, certificate removal, independent peer and install removal.
	t.Cleanup(func() {
		if !joined {
			cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
			defer stop()
			_, _, _ = macOSExternalNativeHTTP(cleanup, client, http.MethodPost, "/api/disconnect", "{}")
			if err := connection.CloseWrite(); err != nil {
				t.Error("native GUI lifetime did not half-close", err)
				return
			}
			receipt := macOSControllerNativeReceipt(t, connection, "stopped", started.ProcessID)
			if receipt.ExitCode != 0 {
				t.Error("native controller failed original cleanup", receipt.ExitCode)
			}
			joined = true
		}
	})
	macOSControllerNativeAwait(t, func() bool {
		probe, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		status, _, err := macOSExternalNativeHTTP(probe, client, http.MethodGet, "/api/status", "")
		return err == nil && status == http.StatusOK
	}, "actual external controller did not serve its authenticated original owner")
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/external-profile/connect", `{"profile_id":"installed-macos-external","direct":true,"execution":"local"}`)
	var connected struct {
		OK              bool   `json:"ok"`
		ProfileID       string `json:"profile_id"`
		ActualExitProof string `json:"actual_exit_proof"`
		Execution       string `json:"execution"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(raw, &connected) != nil || !connected.OK || connected.ProfileID != "installed-macos-external" || connected.ActualExitProof != "expected-public-ip-passed" || connected.Execution != "local" {
		t.Fatalf("actual sealed Darwin %s public Connect failed: status=%d error=%v response=%s", protocol, status, err, raw)
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var live macOSExternalNativeResult
	if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &live) != nil || !live.Connected || live.Closed || live.ProcessID <= 0 || live.ProcessID == started.ProcessID || live.Protocol != protocol ||
		!live.Proof.Healthy || !live.Proof.DNSProven || live.Proof.EntryProven || live.Network.TargetOS != "darwin" || !strings.HasPrefix(live.Network.Name, "utun") || live.Network.MTU != 1376 ||
		live.Baseline == nil || live.Baseline.Phase != "active" || !live.Baseline.Baseline.Present || live.Baseline.Capture.Session != live.Session {
		t.Fatalf("actual Darwin external ownership/readiness receipt failed: status=%d error=%v response=%s", status, err, raw)
	}
	observed := peer.stats(t)
	if observed.DNSQueries < 1 || observed.PublicAttempts < 1 || observed.PublicReplies < 1 || observed.Streams < 1 || observed.AuthFailures != 0 || protocol == "hysteria2" && (observed.PhysicalUDP < 1 || observed.Packets < 1) || protocol != "hysteria2" && observed.Connections < 1 {
		t.Fatal("independent peer did not observe the selected native transport, DNS and actual exit proof", observed)
	}
	// The HTTP Connect request has ended. Its original monitor and private
	// child must remain current, with a live native PF reference and TUN.
	time.Sleep(600 * time.Millisecond)
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retained macOSExternalNativeResult
	if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retained) != nil || retained.Session != live.Session || retained.ProcessID != live.ProcessID || !retained.Connected || retained.Baseline == nil || retained.Baseline.Token != live.Baseline.Token {
		t.Fatal("completed public request lost its original retained native owner", status, err, string(raw))
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/disconnect", "{}")
	if err != nil || status != http.StatusOK || strings.TrimSpace(string(raw)) != `{"ok":true}` {
		t.Fatal("actual Darwin public Disconnect failed", status, err, string(raw))
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || !retired.NativeJoined || !retired.WorkspaceRetired || retired.Session != live.Session || retired.ProcessID != live.ProcessID ||
		retired.Baseline == nil || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present || retired.Baseline.Token != live.Baseline.Token {
		t.Fatal("actual Darwin Disconnect did not join native cleanup and retire its exact PF reference", status, err, string(raw))
	}
	if link, err := net.InterfaceByIndex(int(live.Network.Index)); err == nil && link.Name == live.Network.Name {
		t.Fatal("actual native utun survived joined Disconnect")
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	receipt := macOSControllerNativeReceipt(t, connection, "stopped", started.ProcessID)
	joined = true
	if receipt.ExitCode != 0 {
		t.Fatal("original installed controller failed joined shutdown", receipt.ExitCode)
	}
	t.Logf("actual sealed Darwin ordinary host accepted %s: native child, selected DNS, exit proof, MTU1376, original PF retirement and controller join", protocol)
}
