package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This isolated child supplies explicit IPC fixture outcomes, never network
// evidence. In particular it can keep a healthy heartbeat while rejecting the
// fresh request, proving that the controller no longer accepts cached health.
func desktopPathChildFixture(kind, directory string, expected mobilemultihop.ExternalProofResult, write func(string, any)) func() {
	record := desktopPathRecord{desktopPathRequest: desktopPathRequest{Schema: 1, Session: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256}, Complete: true}
	write("path-status.json", record)
	ownedRequest := false
	read := func(name string, target any) bool {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		return err == nil && decodeRelayControlJSON(raw, target) == nil
	}
	return func() {
		var request desktopPathRequest
		if record.Complete && read("path-request.json", &request) && request.Schema == 1 && request.Session == expected.SessionID && request.SourceSHA256 == expected.SourceSHA256 && request.ConfigSHA256 == expected.ConfigSHA256 && request.Generation == record.Generation+1 {
			record = desktopPathRecord{desktopPathRequest: request}
			ownedRequest = true
		}
		if record.Generation == 0 {
			return
		}
		var cancel desktopPathRequest
		cancelled := kind != "path-ignore-cancel" && read("path-cancel.json", &cancel) && cancel == record.desktopPathRequest
		_, released := os.Stat(filepath.Join(directory, "path-release.fixture"))
		hold := kind == "path-ignore-cancel" || kind == "path-hold" || kind == "path-delayed" && released != nil
		if cancelled {
			record.Complete, record.Cancelled, record.Verified, record.CheckedAt = true, true, false, 0
		} else if !record.Complete && !hold {
			record.Complete, record.Verified, record.CheckedAt = true, true, time.Now().UnixMilli()
			if kind == "path-stale-time" {
				record.CheckedAt = time.Now().Add(-time.Minute).UnixMilli()
			}
			if kind == "path-fail" || kind == "path-fail-2" && record.Generation == 2 || kind == "mtu-path-fail-1" && record.Generation == 1 || kind == "mtu-path-fail-2" && record.Generation == 2 || kind == "mtu-path-fail-3" && record.Generation == 3 {
				record.Verified, record.CheckedAt = false, 0
			}
		}
		if record.Complete {
			if ownedRequest {
				_ = os.Remove(filepath.Join(directory, "path-request.json"))
				ownedRequest = false
			}
			if cancelled {
				_ = os.Remove(filepath.Join(directory, "path-cancel.json"))
			}
		}
		write("path-status.json", record)
	}
}

func desktopPathWait(t *testing.T, launch *desktopNodeLaunch, check func(desktopPathRecord) bool) desktopPathRecord {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		record, err := readDesktopPathRecord(launch)
		if err == nil && check(record) {
			return record
		}
		select {
		case <-deadline.C:
			t.Fatal("captured fresh-path record did not arrive", err, record)
		case <-tick.C:
		}
	}
}

func desktopPathController(t *testing.T, kind string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, launch := desktopExternalRunningFixture(t, kind)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := a.waitDesktopExternalProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	return a, launch
}

func TestDesktopExternalFreshPathUsesNewNonceAndRejectsHealthyStalePath(t *testing.T) {
	for _, kind := range []string{"proof", "path-fail", "path-stale-time"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopPathController(t, kind)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := a.verifyDesktopExternalCurrentPath(ctx, launch)
			if (err == nil) != (kind == "proof") {
				t.Fatal("fresh native outcome not required", err)
			}
			first := desktopPathWait(t, launch, func(r desktopPathRecord) bool { return r.Generation == 1 && r.Complete })
			if _, err := a.readDesktopExternalProof(launch); err != nil {
				t.Fatal("fixture did not retain the misleading healthy heartbeat", err)
			}
			if kind == "proof" {
				if err := a.verifyDesktopExternalCurrentPath(ctx, launch); err != nil {
					t.Fatal(err)
				}
				second := desktopPathWait(t, launch, func(r desktopPathRecord) bool { return r.Generation == 2 && r.Complete })
				if second.Request == first.Request || !second.Verified || second.CheckedAt < first.CheckedAt {
					t.Fatal("reused a prior path proof")
				}
			}
		})
	}
}

func TestDesktopExternalFreshPathDrainUsesOnlyCapturedDirectoryAndCloseAck(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	owner := &desktopExternalRuntime{session: strings.Repeat("a", 32), expected: mobilemultihop.ExternalProofResult{ExitID: "captured-native-exit", SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64)}}
	launch := &desktopNodeLaunch{external: owner}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = launch.directoryRoot.Close() })
	record := desktopPathRecord{desktopPathRequest: desktopPathRequest{Schema: 1, Session: owner.session, SourceSHA256: owner.expected.SourceSHA256, ConfigSHA256: owner.expected.ConfigSHA256, Generation: 1, Request: strings.Repeat("d", 32)}, Complete: true, Cancelled: true}
	raw, _ := json.Marshal(record)
	if err := os.WriteFile(filepath.Join(directory, "path-status.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if desktopPathNativeClosed(launch) {
		t.Fatal("missing native close acknowledgement was accepted")
	}
	original, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	retired := directory + "-retired"
	ackDirectory := retired
	renamed := true
	foreign := []byte(`{"replacement":"untouched"}`)
	if err := os.Rename(directory, retired); err != nil {
		if runtime.GOOS != "windows" || !errors.Is(err, syscall.Errno(5)) && !errors.Is(err, syscall.Errno(32)) {
			t.Fatal(err)
		}
		// An owned Windows directory can be non-renamable. Keep the live
		// handle and verify both its identity and the original drain/close
		// acknowledgements; do not skip or manufacture an unowned handle.
		renamed, ackDirectory = false, directory
		current, currentErr := os.Stat(directory)
		held, heldErr := launch.directoryRoot.Stat(".")
		if currentErr != nil || heldErr != nil || !os.SameFile(original, current) || !os.SameFile(original, held) {
			t.Fatal("denied rename changed captured directory ownership", currentErr, heldErr)
		}
		if _, err := os.Lstat(retired); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("denied rename created a retired directory", err)
		}
		if err := os.Mkdir(directory, 0700); !errors.Is(err, os.ErrExist) {
			t.Fatal("denied rename permitted a replacement directory", err)
		}
		if actual, err := readDesktopPathRecord(launch); err != nil || actual != record {
			t.Fatal("original captured reply was lost", err)
		}
	} else {
		t.Cleanup(func() { _ = os.RemoveAll(retired) })
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "path-status.json"), foreign, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readDesktopPathRecord(launch); err == nil {
			t.Fatal("renamed old result attested the replacement workspace")
		}
	}
	if drained, err := readDesktopPathDrainRecord(launch); err != nil || drained != record {
		t.Fatal("exact old worker drain was lost", err)
	}
	closed := desktopExternalStop{Schema: 1, SessionID: strings.Repeat("f", 32), SourceSHA256: owner.expected.SourceSHA256, Closed: true}
	raw, _ = json.Marshal(closed)
	if err := os.WriteFile(filepath.Join(ackDirectory, "stopped.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if desktopPathNativeClosed(launch) {
		t.Fatal("foreign close acknowledgement was accepted")
	}
	closed.SessionID = owner.session
	raw, _ = json.Marshal(closed)
	if err := os.WriteFile(filepath.Join(ackDirectory, "stopped.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if !desktopPathNativeClosed(launch) {
		t.Fatal("captured native close did not establish worker drain")
	}
	if renamed {
		if actual, _ := os.ReadFile(filepath.Join(directory, "path-status.json")); string(actual) != string(foreign) {
			t.Fatal("cleanup acknowledgement changed replacement workspace")
		}
	} else {
		current, currentErr := os.Stat(directory)
		held, heldErr := launch.directoryRoot.Stat(".")
		if currentErr != nil || heldErr != nil || !os.SameFile(original, current) || !os.SameFile(original, held) {
			t.Fatal("drain acknowledgement lost captured directory ownership", currentErr, heldErr)
		}
		if actual, err := readDesktopPathDrainRecord(launch); err != nil || actual != record {
			t.Fatal("close acknowledgement changed original captured reply", err)
		}
	}
}

func TestDesktopExternalFreshPathCancellationDrainsWithoutStoppingHealthyVPN(t *testing.T) {
	a, launch := desktopPathController(t, "path-hold")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.verifyDesktopExternalCurrentPath(ctx, launch) }()
	desktopPathWait(t, launch, func(r desktopPathRecord) bool { return r.Generation == 1 && !r.Complete })
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("canceled check reported success", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not drain its captured request")
	}
	record := desktopPathWait(t, launch, func(r desktopPathRecord) bool { return r.Generation == 1 && r.Complete })
	if !record.Cancelled || record.Verified || desktopExternalProcessExited(launch) {
		t.Fatal("measurement cancellation retained a usable proof or stopped the healthy connection")
	}
	if _, err := a.readDesktopExternalProof(launch); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopExternalFreshPathUnresponsiveCancellationRetiresOnlyCapturedProcess(t *testing.T) {
	a, launch := desktopPathController(t, "path-ignore-cancel")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.verifyDesktopExternalCurrentPath(ctx, launch) }()
	desktopPathWait(t, launch, func(r desktopPathRecord) bool { return r.Generation == 1 && !r.Complete })
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !desktopExternalProcessExited(launch) || !launch.external.stopAcknowledged {
			t.Fatal("undrained check returned without retiring its captured native owner", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("captured unresponsive process was not retired")
	}
}

func TestDesktopExternalFreshPathLateReplyCannotAttestReplacement(t *testing.T) {
	a, launch := desktopPathController(t, "path-delayed")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.verifyDesktopExternalCurrentPath(ctx, launch) }()
	desktopPathWait(t, launch, func(r desktopPathRecord) bool { return r.Generation == 1 && !r.Complete })
	replacement := exec.Command("replacement-not-started")
	a.mu.Lock()
	a.cmd = replacement
	a.mu.Unlock()
	if err := os.WriteFile(filepath.Join(launch.directory, "path-release.fixture"), []byte("release captured worker"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("late old-native reply attested a replacement")
		}
	case <-ctx.Done():
		t.Fatal("old worker was not drained")
	}
	a.mu.Lock()
	current := a.cmd
	a.mu.Unlock()
	if current != replacement || desktopExternalProcessExited(launch) {
		t.Fatal("late measurement changed or stopped another connection owner")
	}
}

func TestDesktopExternalFreshPathRecordRejectsIdentityReplayAndMalformedEvidence(t *testing.T) {
	a, launch := desktopPathController(t, "proof")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.verifyDesktopExternalCurrentPath(ctx, launch); err != nil {
		t.Fatal(err)
	}
	valid := desktopPathWait(t, launch, func(r desktopPathRecord) bool { return r.Generation == 1 && r.Verified })
	for _, change := range []string{"session", "source", "config", "request", "unfinished", "cancelled", "zero-time", "duplicate", "unknown"} {
		t.Run(change, func(t *testing.T) {
			record := valid
			switch change {
			case "session":
				record.Session = strings.Repeat("b", 32)
			case "source":
				record.SourceSHA256 = strings.Repeat("b", 64)
			case "config":
				record.ConfigSHA256 = strings.Repeat("b", 64)
			case "request":
				record.Request = ""
			case "unfinished":
				record.Complete = false
			case "cancelled":
				record.Cancelled = true
			case "zero-time":
				record.CheckedAt = 0
			}
			raw, _ := json.Marshal(record)
			if change == "duplicate" {
				raw = append([]byte(`{"schema":1,`), raw[1:]...)
			}
			if change == "unknown" {
				raw = append([]byte(`{"unowned":true,`), raw[1:]...)
			}
			if _, err := decodeDesktopPathRecord(launch, raw); err == nil {
				t.Fatal("invalid fresh-path evidence accepted")
			}
		})
	}
	launch.external.pathGeneration++
	if err := a.verifyDesktopExternalCurrentPath(ctx, launch); err == nil {
		t.Fatal("older generation replay accepted as a fresh idle owner")
	}
}

func TestDesktopExternalMTURequiresFreshPathAtSaveCommitAndAdoption(t *testing.T) {
	for _, kind := range []string{"mtu-path-fail-1", "mtu-path-fail-2", "mtu-path-fail-3"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopMTUControllerFixture(t, kind)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := a.runDesktopExternalMTU(ctx, launch, true); err == nil {
				t.Fatal("cached heartbeat adopted a changed native path")
			}
			record := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Complete && r.Status.Restored })
			if record.Status.EffectiveMTU != 1280 || record.Status.Measured {
				t.Fatal("failed fresh path check retained the provisional native MTU")
			}
			a.mu.Lock()
			profile := common.CloneRouterProfile(a.profiles.Profiles[0])
			a.mu.Unlock()
			if profile.EffectiveMTU != 1350 || profile.EffectiveMTUSource != "historical-fixture" {
				t.Fatal("failed fresh path check retained the provisional durable MTU")
			}
		})
	}
}

func TestSpeedLabExternalRequiresFreshBoundaryAfterIdlePhase(t *testing.T) {
	a, launch := desktopPathController(t, "path-fail-2")
	profile := common.CloneRouterProfile(launch.external.profile)
	a.mu.Lock()
	a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	a.state = state{Connected: true, Phase: "connected", Mode: "external-node", RuntimeMode: "external-hysteria2", RouterID: profile.ID}
	a.mu.Unlock()
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "fresh-path-speed-lab", Connected: true, Phase: "connected", PathProof: "passed", RouterID: profile.ID}})
	t.Cleanup(func() { sessionTrackers.Delete(a) })
	var requests atomic.Int32
	var transfers atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Query().Get("bytes") != "1" {
			transfers.Add(1)
		}
		_, _ = w.Write([]byte{1})
	}))
	defer server.Close()
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "speed.cloudflare.com:443" {
			return nil, errors.New("unexpected measurement target")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = previous; transport.CloseIdleConnections() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", nil).WithContext(ctx)
	_, measured, _, err := a.speedLabCurrent(request, speedLabDuration{Mode: "auto"}, time.Second, time.Second)
	if err == nil || measured.Download.Bytes != 0 || measured.Upload.Bytes != 0 || requests.Load() != 10 || transfers.Load() != 0 {
		t.Fatal("failed fresh post-idle check did not stop later transfer phases", err, requests.Load())
	}
	if _, err := a.readDesktopExternalProof(launch); err != nil {
		t.Fatal("fixture lost its cached heartbeat instead of exercising fresh proof", err)
	}
}
