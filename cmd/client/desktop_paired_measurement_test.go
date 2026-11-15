package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This is the explicit native-host boundary for the common application tests.
// It cannot prove PF, utun binding or actual selected-DNS execution. The actual
// Darwin parent/child native gate separately exercises those capabilities.
type pairedMeasurementFixtureHost struct {
	desktopMacOSPairedNodeRuntime
	identity desktopMacOSPairedNodeMeasurementIdentity
	ready    mobilemultihop.DesktopNodeReadyRecord
	epoch    atomic.Uint64
	failed   atomic.Bool
	reads    atomic.Int32
	requests atomic.Int32
	closes   atomic.Int32
	handler  func(*http.Request) (*http.Response, error)
}

type pairedMeasurementFixtureCapture struct {
	host  *pairedMeasurementFixtureHost
	epoch uint64
	id    desktopMacOSPairedNodeMeasurementIdentity
}

type pairedMeasurementFixtureTransport func(*http.Request) (*http.Response, error)

func (f pairedMeasurementFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
func (h *pairedMeasurementFixtureHost) CaptureMeasurement(ctx context.Context) (desktopMacOSPairedNodeMeasurement, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &pairedMeasurementFixtureCapture{host: h, epoch: h.epoch.Load(), id: h.identity}, nil
}
func (h *pairedMeasurementFixtureHost) Ready(ctx context.Context) (mobilemultihop.DesktopNodeReadyRecord, error) {
	if h.failed.Load() || ctx.Err() != nil {
		return mobilemultihop.DesktopNodeReadyRecord{}, errors.New("fixture native readiness failed")
	}
	return h.ready, nil
}
func (h *pairedMeasurementFixtureHost) Close(context.Context) error {
	h.closes.Add(1)
	return errors.New("measurement must never close the retained VPN")
}
func (m *pairedMeasurementFixtureCapture) Identity() desktopMacOSPairedNodeMeasurementIdentity {
	return m.id
}
func (m *pairedMeasurementFixtureCapture) MatchesOriginal() bool {
	return !m.host.failed.Load() && m.epoch == m.host.epoch.Load()
}
func (m *pairedMeasurementFixtureCapture) Current(ctx context.Context) error {
	m.host.reads.Add(1)
	if ctx.Err() != nil || !m.MatchesOriginal() {
		return errors.New("fixture original native reader/PF failed")
	}
	return nil
}
func (m *pairedMeasurementFixtureCapture) HTTPClient(ctx context.Context, timeout time.Duration) (*http.Client, error) {
	if err := m.Current(ctx); err != nil {
		return nil, err
	}
	return &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("fixture refuses redirect")
	}, Transport: pairedMeasurementFixtureTransport(func(r *http.Request) (*http.Response, error) {
		if err := m.Current(r.Context()); err != nil {
			return nil, err
		}
		m.host.requests.Add(1)
		return m.host.handler(r)
	})}, nil
}

func pairedMeasurementFixture(t *testing.T) (*app, common.RouterProfile, connectionSession, *pairedMeasurementFixtureHost) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	p := common.RouterProfile{ID: "paired", Name: "Paired Router", NodeKind: "router-vpn", RouterAPI: "http://10.77.0.1:8787", APIToken: "private-fixture-token",
		DNSMode: "home", AdGuardIPv4: "10.77.0.1", IPv6Mode: "on", KillSwitchPolicy: "off", MTUPolicy: "auto", StartLayer: "off"}
	p.NodeProofID = writeTestWGIdentity(t, root, p.ID)
	command := &exec.Cmd{}
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")}, cmd: command,
		profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: p.ID, Profiles: []common.RouterProfile{p}},
		state:    state{Connected: true, Phase: "connected", Mode: "wg", LogicalMode: "wg", RuntimeMode: "wg", Base: "wg", RouterID: p.ID}}
	session := connectionSession{ID: "paired-test-session", RouterID: p.ID, Connected: true, Phase: "connected", PathProof: "passed", ActualMode: "wg", ActualBase: "wg"}
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &session})
	launch := &desktopNodeLaunch{command: command, profileID: p.ID, policyProfileID: p.ID, mode: "wg", mtuSession: strings.Repeat("a", 32), configSHA256: strings.Repeat("b", 64)}
	h := &pairedMeasurementFixtureHost{}
	launch.pairedNode = h
	h.identity = desktopMacOSPairedNodeMeasurementIdentity{launch: launch, host: h, command: command, profileID: p.ID, mode: "wg", nodeID: p.NodeProofID,
		session: launch.mtuSession, source: strings.Repeat("c", 64), config: launch.configSHA256, network: "original-network", profileToken: desktopOwnedNodeProfileToken(p)}
	h.ready = mobilemultihop.DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: h.identity.session, SourceSHA256: h.identity.source, ConfigSHA256: h.identity.config,
		DNSMilliseconds: 2.75, InterfaceName: "utun17", InterfaceIndex: 17, MTU: 1400, ProvedAt: time.Now().UnixMilli()}
	h.handler = func(r *http.Request) (*http.Response, error) {
		body := "203.0.113.27"
		switch r.URL.Path {
		case "/health":
			body = fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":%q}`, p.NodeProofID, desktopNodeProofKind)
		case "/api/dns/benchmark":
			if r.Header.Get("Authorization") != "Bearer "+p.APIToken {
				return nil, errors.New("private benchmark changed the original token")
			}
			body = `{"winner":{"address":"9.9.9.9","name":"measured","latency_ms":2.5},"results":[]}`
		case "/api/benchmark/download":
			body = strings.Repeat("x", 1<<20)
		case "/api/benchmark/upload":
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				return nil, err
			}
			body = fmt.Sprintf(`{"bytes":%d,"server_receive_ms":1}`, n)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}
	desktopNodeOwners.Store(a, launch)
	t.Cleanup(func() { desktopNodeOwners.Delete(a); sessionTrackers.Delete(a); homeExitProofs.Delete(a) })
	return a, p, session, h
}

func refuseAmbientPairedMeasurementHTTP(t *testing.T) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	previous := http.DefaultTransport
	http.DefaultTransport = &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("ordinary route is not the captured native tunnel")
	}}
	t.Cleanup(func() { http.DefaultTransport = previous })
	return &calls
}

func TestDesktopPairedMeasurementCaptureRejectsMissingAndForeignOwners(t *testing.T) {
	for _, change := range []string{"none", "registry", "host", "command", "configuration", "node", "profile", "source", "mixed-purpose", "native-readback", "cancel"} {
		t.Run(change, func(t *testing.T) {
			a, p, _, h := pairedMeasurementFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if change == "registry" || change == "host" {
				// This capture-only refusal identifies a required Darwin path.
				// Public handler tests do not impersonate a native controller on
				// the host OS; their explicit boundary is the measurement host.
				a.localController = &ownedDesktopController{nodeParent: &desktopMacOSParent{}}
			}
			switch change {
			case "registry":
				desktopNodeOwners.Delete(a)
			case "host":
				h.identity.launch.pairedNode = nil
			case "command":
				a.cmd = &exec.Cmd{}
			case "configuration":
				h.identity.launch.configSHA256 = strings.Repeat("d", 64)
			case "node":
				h.identity.nodeID = strings.Repeat("d", 64)
			case "profile":
				a.profiles.Profiles[0].APIToken = "rotated-private-token"
			case "source":
				h.identity.source = "missing-source"
			case "mixed-purpose":
				h.identity.launch.external = &desktopExternalRuntime{}
			case "native-readback":
				h.failed.Store(true)
			case "cancel":
				cancel()
			}
			b, err := captureDesktopPairedMeasurement(ctx, a, p, a.state)
			if change == "none" {
				if err != nil || b == nil {
					t.Fatal("valid original native capture was refused", err)
				}
			} else if err == nil {
				t.Fatal("invalid original path fell back or was accepted", change, b)
			}
			if h.requests.Load() != 0 || h.closes.Load() != 0 {
				t.Fatal("capture started HTTP or changed VPN lifetime")
			}
		})
	}
}

func TestDesktopPairedMeasurementPublicHandlersUseCapturedTransport(t *testing.T) {
	for _, endpoint := range []string{"public-ip", "home-exit", "dns-retest", "latency", "throughput"} {
		t.Run(endpoint, func(t *testing.T) {
			a, p, _, h := pairedMeasurementFixture(t)
			ambient := refuseAmbientPairedMeasurementHTTP(t)
			if endpoint == "throughput" {
				ctx, stop, _, err := connectionTelemetryPathContext(context.Background(), a, p, a.state, "paired-test-session")
				if err != nil {
					t.Fatal(err)
				}
				defer stop()
				value, err := measureRoutedProfileSpeedContext(ctx, p, 1<<20)
				if err != nil || value.Bytes != 1<<20 || value.DownloadMbps <= 0 || value.UploadMbps <= 0 {
					t.Fatal("captured throughput failed", value, err)
				}
			} else {
				handler, method := a.publicIP, http.MethodGet
				switch endpoint {
				case "home-exit":
					handler, method = a.proveHomeExit, http.MethodPost
				case "dns-retest":
					handler, method = a.retestDNS, http.MethodPost
				case "latency":
					handler, method = a.connectionLiveLatency, http.MethodGet
				}
				w := httptest.NewRecorder()
				handler(w, httptest.NewRequest(method, "/measurement", nil))
				if w.Code != http.StatusOK {
					t.Fatalf("captured %s returned %d: %s", endpoint, w.Code, w.Body.String())
				}
			}
			if ambient.Load() != 0 || h.requests.Load() == 0 || h.reads.Load() == 0 || h.closes.Load() != 0 {
				t.Fatal("measurement bypassed native capture or changed VPN", ambient.Load(), h.requests.Load(), h.reads.Load(), h.closes.Load())
			}
		})
	}
}

func TestDesktopPairedMeasurementLateSuccessCannotPersistAfterEpochChange(t *testing.T) {
	for _, endpoint := range []string{"public-ip", "home-exit", "dns-retest", "latency"} {
		t.Run(endpoint, func(t *testing.T) {
			a, _, _, h := pairedMeasurementFixture(t)
			ambient := refuseAmbientPairedMeasurementHTTP(t)
			if err := a.persistProfiles(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			original := h.handler
			h.handler = func(r *http.Request) (*http.Response, error) {
				response, err := original(r)
				h.epoch.Add(1) // An MTU/native-reader transition before adoption.
				return response, err
			}
			handler, method := a.publicIP, http.MethodGet
			switch endpoint {
			case "home-exit":
				handler, method = a.proveHomeExit, http.MethodPost
			case "dns-retest":
				handler, method = a.retestDNS, http.MethodPost
			case "latency":
				handler, method = a.connectionLiveLatency, http.MethodGet
			}
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest(method, "/measurement", nil))
			if w.Code == http.StatusOK {
				t.Fatal("successful late response survived original native epoch change", endpoint, w.Body.String())
			}
			after, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil || string(before) != string(after) {
				t.Fatal("stale native result changed durable profile", err)
			}
			if _, found := homeExitProofs.Load(a); found {
				t.Fatal("stale native result entered Home cache")
			}
			if ambient.Load() != 0 || h.closes.Load() != 0 || !a.state.Connected {
				t.Fatal("measurement used fallback or disconnected replacement")
			}
		})
	}
}

func TestDesktopPairedMeasurementSelectedDNSCannotUseOrdinaryLookup(t *testing.T) {
	for _, change := range []string{"none", "readback", "receipt", "source-policy"} {
		t.Run(change, func(t *testing.T) {
			a, p, _, h := pairedMeasurementFixture(t)
			observed := sessionTrackerFor(a).capture()
			if change == "readback" {
				h.failed.Store(true)
			}
			if change == "receipt" {
				h.ready.SourceSHA256 = strings.Repeat("f", 64)
			}
			if change == "source-policy" {
				a.profiles.Profiles[0].DNSHost = "8.8.8.8"
			}
			var lookups atomic.Int32
			proof := proveSelectedDNSWithLookup(context.Background(), a, observed, "wg", func(context.Context, string) ([]string, error) {
				lookups.Add(1)
				return []string{"203.0.113.17"}, nil
			})
			if (proof.Status == "passed") != (change == "none") || lookups.Load() != 0 {
				t.Fatal("selected DNS bypassed original native proof", change, proof, lookups.Load())
			}
			if change == "none" && (proof.LatencyMs != 2.75 || proof.Host != p.AdGuardIPv4 || !strings.Contains(proof.Reason, "before connection")) {
				t.Fatal("startup DNS proof was mislabeled or retargeted", proof)
			}
		})
	}
}

func TestDesktopPairedMeasurementLockedAdoptionRetainsOriginalEpoch(t *testing.T) {
	a, p, session, h := pairedMeasurementFixture(t)
	ctx, stop, _, err := asyncMeasurementPathContext(context.Background(), a, p, a.state, session, asyncMeasurementProfileToken(p))
	if err != nil {
		t.Fatal(err)
	}
	binding := ctx.Value(asyncMeasurementBindingKey{}).(*asyncMeasurementAdoption)
	stop() // Keep the exact captured binding; test final adoption without observer scheduling.
	ctx = context.WithValue(context.Background(), asyncMeasurementBindingKey{}, binding)
	release, err := a.beginAsyncMeasurementAdoption(ctx)
	if err != nil {
		t.Fatal("original native adoption failed", err)
	}
	release()
	h.epoch.Add(1)
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	a.mu.Lock()
	err = binding.validateLocked(tracker.session)
	a.mu.Unlock()
	tracker.mu.Unlock()
	if err == nil {
		t.Fatal("locked adoption accepted a retired native reader")
	}
	if !a.operationMu.TryLock() {
		t.Fatal("adoption leaked operation ownership")
	}
	a.operationMu.Unlock()
	if h.closes.Load() != 0 {
		t.Fatal("result refusal stopped the VPN")
	}
}
