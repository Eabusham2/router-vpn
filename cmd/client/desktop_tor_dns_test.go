package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/mobiletor"
)

// The child exchanges isolated typed IPC records. It does not claim public
// DNS timings; native Box/service fixtures execute the actual query path.
func desktopTorDNSChildFixture(kind, directory string, expected mobiletor.DesktopBridgeMetadata, write func(string, any)) func() {
	if !strings.HasPrefix(kind, "tor-dns-") && kind != "tor-mtu-dns-complete" {
		return func() {}
	}
	record := desktopDNSNativeRecord{desktopDNSNativeRequest: desktopDNSNativeRequest{Schema: 1, Session: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256},
		Status: dnsmeasure.Status{Schema: 1, NodeID: expected.NodeID, SessionID: expected.SessionID, Stage: "idle", Complete: true, Drained: true, Results: []dnsmeasure.Result{}}}
	write("dns-status.json", record)
	read := func(name string, value any) bool {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		return err == nil && decodeRelayControlJSON(raw, value) == nil
	}
	retire := func() {
		_ = os.Remove(filepath.Join(directory, "dns-request.json"))
		_ = os.Remove(filepath.Join(directory, "dns-cancel.json"))
	}
	return func() {
		var request desktopDNSNativeRequest
		if record.Status.Complete && record.Status.Drained && read("dns-request.json", &request) && request.Schema == 1 && request.Session == expected.SessionID && request.SourceSHA256 == expected.SourceSHA256 && request.ConfigSHA256 == expected.ConfigSHA256 && request.Generation == record.Generation+1 {
			record = desktopDNSNativeRecord{desktopDNSNativeRequest: request, Status: dnsmeasure.Status{Schema: 1, NodeID: expected.NodeID, SessionID: expected.SessionID, Request: request.Request, PublicTransport: request.Transport, Stage: "measuring", Results: []dnsmeasure.Result{}}}
		}
		if record.Generation == 0 {
			return
		}
		var cancel desktopDNSNativeRequest
		if read("dns-cancel.json", &cancel) && cancel == record.desktopDNSNativeRequest {
			record.Status.Stage, record.Status.Failure, record.Status.Complete, record.Status.Results = "cancelled", "isolated Tor DNS cancellation", true, []dnsmeasure.Result{}
			_, released := os.Stat(filepath.Join(directory, "dns-drain-release.fixture"))
			record.Status.Drained = kind != "tor-dns-cancel-delay" && kind != "tor-dns-read-fail" || released == nil
			if record.Status.Drained {
				retire()
			}
		} else if !record.Status.Complete && kind != "tor-dns-hold" && kind != "tor-dns-cancel-delay" && kind != "tor-dns-read-fail" {
			selected := dnsmeasure.Endpoint{ID: "selected", Name: "Selected DNS", Kind: "selected", Address: expected.DNS.Address, Port: expected.DNS.Port, Transport: expected.DNS.Transport,
				ServerName: expected.DNS.ServerName, Path: expected.DNS.Path, Route: expected.FinalTag, RouteLabel: "Selected DNS via captured Tor exit"}
			for i, endpoint := range append([]dnsmeasure.Endpoint{selected}, dnsmeasure.PublicEndpoints(record.Transport, "Current Tor connection")...) {
				median := float64(i + 1)
				row := dnsmeasure.Result{Endpoint: endpoint, Samples: 3, Ready: true, Median: &median}
				if strings.Contains(endpoint.ID, "6") {
					row.Samples, row.Failed, row.Ready, row.Median, row.Failure = 0, 3, false, nil, "isolated unavailable IPv6 answer"
				}
				record.Status.Results = append(record.Status.Results, row)
			}
			switch kind {
			case "tor-dns-wrong-transport":
				record.Status.Results[1].Transport = "udp"
			case "tor-dns-wrong-selected":
				record.Status.Results[0].Address = "1.1.1.1"
			case "tor-dns-wrong-route":
				record.Status.Results[0].RouteLabel = "Selected DNS via ordinary network"
			}
			record.Status.Stage, record.Status.Complete, record.Status.Drained = "complete", true, true
			retire()
		}
		published := record
		if kind == "tor-dns-read-fail" && !record.Status.Drained {
			published.Session = "replacement-native-session"
		}
		write("dns-status.json", published)
	}
}

func desktopTorDNSControllerFixture(t *testing.T, kind string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, launch, _ := desktopTorRunningFixture(t, kind)
	a.cfg.ProfilesFile = filepath.Join(t.TempDir(), "profiles.json")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	a.state.Connected, a.state.Phase = true, "connected"
	t.Cleanup(func() {
		// Release only this fixture's controlled late worker before joining it.
		_ = os.WriteFile(filepath.Join(launch.directory, "dns-drain-release.fixture"), []byte("release isolated worker"), 0600)
		invalidateDesktopDNSResults(a)
		if a.dnsMeasurements != nil && a.dnsMeasurements.current != nil {
			select {
			case <-a.dnsMeasurements.current.done:
			case <-time.After(5 * time.Second):
				t.Error("isolated Tor DNS operation did not drain")
			}
		}
		mtuSuspensions.Delete(a)
	})
	return a, launch
}

func TestDesktopTorDNSUsesCapturedMailboxAndExplicitMeasuredDraft(t *testing.T) {
	for _, transport := range []string{"tcp", "tls", "https"} {
		t.Run(transport, func(t *testing.T) {
			a, launch := desktopTorDNSControllerFixture(t, "tor-dns-complete")
			before := cloneRouterProfileStore(a.profiles)
			operation, request := desktopDNSStartForTest(t, a, transport)
			view := desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			if view.Status.Stage != "complete" || len(view.Status.Results) != 13 || launch.external != nil {
				t.Fatal("Tor result did not retain its distinct native owner", view.Status)
			}
			selected := view.Status.Results[0]
			if selected.Kind != "selected" || selected.Address != launch.tor.expected.DNS.Address || selected.Port != launch.tor.expected.DNS.Port || selected.Transport != launch.tor.expected.DNS.Transport || selected.Route != launch.tor.expected.FinalTag || selected.RouteLabel != "Selected DNS via captured Tor exit" {
				t.Fatal("Tor selected DNS policy or route changed", selected)
			}
			if !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("DNS measurements silently changed the saved resolver")
			}
			request.Transport, request.ResultID = "", "fastest"
			chosen := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/select", request)
			var response struct {
				Draft dnsPolicyRequest `json:"draft"`
			}
			if chosen.Code != http.StatusOK || json.Unmarshal(chosen.Body.Bytes(), &response) != nil || response.Draft.Protocol != transport || response.Draft.MeasurementID != request.Request {
				t.Fatal("typed Tor DNS draft lost its measured transport", chosen.Code, chosen.Body.String())
			}
			if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/policy", response.Draft); w.Code != http.StatusConflict {
				t.Fatal("measured Tor DNS applied while the captured connection was active", w.Code)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
				t.Fatal(err)
			}
			if err := stopDesktopTorRuntime(a, launch, launch.command); err != nil {
				t.Fatal(err)
			}
			a.mu.Lock()
			a.cmd, a.state.Connected, a.state.Phase = nil, false, "off"
			a.mu.Unlock()
			desktopNodeOwners.Delete(a)
			if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/policy", response.Draft); w.Code != http.StatusOK {
				t.Fatal("explicit disconnect lost the still-current typed draft", w.Code, w.Body.String())
			}
			if a.profiles.Profiles[0].DNSProtocol != transport || a.profiles.Profiles[0].External.TorBridge.Bridges[0] != before.Profiles[0].External.TorBridge.Bridges[0] {
				t.Fatal("saving Tor DNS substituted protocol or bridge credentials")
			}
		})
	}
}

func TestDesktopTorDNSRetestAfterMeasuredMTURetainsTheSameNativeOwner(t *testing.T) {
	// Both services exchange explicit synthetic IPC data with the same real
	// child. This tests controller ownership, not live Tor DNS or throughput.
	a, launch := desktopTorMTUControllerFixture(t, "tor-mtu-dns-complete")
	t.Cleanup(func() { invalidateDesktopDNSResults(a) })
	before := desktopTorSavedMTU(t, a)
	if before.EffectiveMTU != 1350 || asyncMeasurementProfileToken(before) == launch.tor.profileToken {
		t.Fatal("fixture did not capture distinct historical MTU metadata")
	}
	initial := desktopDNSCaptureForTest(t, a)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	measured, err := a.runDesktopExternalMTU(ctx, launch, true)
	if err != nil || !measured.Status.Measured || measured.Status.EffectiveMTU != 1380 || measured.MTUReadback == nil {
		t.Fatal("real Tor child did not commit its synthetic MTU transfer result", err, measured)
	}
	after := desktopTorSavedMTU(t, a)
	if after.EffectiveMTU != 1380 || desktopTorSourceIdentityToken(after) != launch.tor.profileToken {
		t.Fatal("MTU persistence replaced the captured Tor policy identity")
	}
	owner := desktopMeasurementMTUSession(launch)
	owner.mu.Lock()
	satisfied := owner.automatic
	owner.mu.Unlock()
	if !satisfied {
		t.Fatal("successful Retest left Auto pending for the same captured native reader")
	}
	operation, request := desktopDNSStartForTest(t, a, "https")
	view := desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
	<-operation.done
	if view.Status.Stage != "complete" || len(view.Status.Results) != 13 || view.SessionID != initial.SessionID ||
		view.SessionID != launch.tor.expected.SessionID || view.Status.Request != request.Request || launch.external != nil || a.cmd != launch.command {
		t.Fatal("DNS Retest after MTU did not retain the exact Tor child", view.Status)
	}
	proof, err := a.readDesktopTorProof(launch)
	if err != nil || proof.MTUReadback == nil || *proof.MTUReadback != *measured.MTUReadback || proof.EffectiveMTU != 1380 {
		t.Fatalf("DNS Retest replaced the committed Tor reader: err=%v committed=%+v current=%+v mtu=%d", err, measured.MTUReadback, proof.MTUReadback, proof.EffectiveMTU)
	}
	if !reflect.DeepEqual(after, desktopTorSavedMTU(t, a)) {
		t.Fatal("DNS Retest changed saved credentials, resolver or MTU metadata")
	}
	request.Transport, request.ResultID = "", "fastest"
	if response := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/select", request); response.Code != http.StatusOK {
		t.Fatal("current measured DNS draft was rejected after MTU persistence", response.Code, response.Body.String())
	}
}

func TestDesktopTorDNSCancellationRetainsNativeOwnerAndHoldUntilDrain(t *testing.T) {
	for _, kind := range []string{"tor-dns-cancel-delay", "tor-dns-read-fail"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopTorDNSControllerFixture(t, kind)
			operation, request := desktopDNSStartForTest(t, a, "https")
			deadline := time.Now().Add(5 * time.Second)
			for {
				record, err := readDesktopDNSRecord(launch)
				if err == nil && record.Generation > 0 || kind == "tor-dns-read-fail" && err != nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("isolated native DNS request did not arrive")
				}
				time.Sleep(5 * time.Millisecond)
			}
			request.Transport = ""
			if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/cancel", request); w.Code != http.StatusAccepted {
				t.Fatal("Tor DNS cancel was not admitted", w.Code)
			}
			desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Stage == "draining" })
			if launch.tor.dnsMu.TryLock() {
				launch.tor.dnsMu.Unlock()
				t.Fatal("Tor DNS released native command ownership before worker drain")
			}
			if !mtuSuspended(a) || a.cmd != launch.command || !a.state.Connected {
				t.Fatal("Tor DNS cancellation released its measurement hold or stopped the VPN")
			}
			select {
			case <-operation.done:
				t.Fatal("cancel acknowledgement replaced actual worker drain")
			default:
			}
			if err := os.WriteFile(filepath.Join(launch.directory, "dns-drain-release.fixture"), []byte("release"), 0600); err != nil {
				t.Fatal(err)
			}
			view := desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			if view.Status.Stage != "cancelled" || len(view.Status.Results) != 0 || a.cmd != launch.command {
				t.Fatal("cancelled Tor DNS retained results or changed the VPN", view.Status)
			}
		})
	}
}

func TestDesktopTorDNSRejectsResolverTransportRouteAndReplacementOwners(t *testing.T) {
	for _, kind := range []string{"tor-dns-wrong-transport", "tor-dns-wrong-selected", "tor-dns-wrong-route"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := desktopTorDNSControllerFixture(t, kind)
			operation, _ := desktopDNSStartForTest(t, a, "tls")
			view := desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			if view.Status.Stage != "invalidated" || len(view.Status.Results) != 0 {
				t.Fatal("substituted Tor DNS sample acquired a score", kind, view.Status)
			}
		})
	}
	for _, changed := range []string{"profile", "dns-policy", "network", "command", "native-owner", "session", "request", "profile-id", "profile-token", "expired"} {
		t.Run(changed, func(t *testing.T) {
			a, launch := desktopTorDNSControllerFixture(t, "tor-dns-complete")
			operation, request := desktopDNSStartForTest(t, a, "https")
			desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			request.Transport, request.ResultID = "", "fastest"
			switch changed {
			case "profile":
				a.profiles.Profiles[0].External.TorBridge.Bridges[0] = torImportSnowflakeBridge
			case "dns-policy":
				a.profiles.Profiles[0].DNSPort++
			case "network":
				launch.tor.networkIdentity = func() string { return "replacement" }
			case "command":
				a.cmd = exec.Command("replacement")
			case "native-owner":
				desktopNodeOwners.Store(a, &desktopNodeLaunch{})
			case "session":
				request.SessionID = strings.Repeat("f", 32)
			case "request":
				request.Request = strings.Repeat("f", 32)
			case "profile-id":
				request.ProfileID += "-replacement"
			case "profile-token":
				request.ProfileToken = strings.Repeat("f", 64)
			case "expired":
				operation.completedAt = time.Now().Add(-3 * time.Minute)
			}
			if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/select", request); w.Code != http.StatusConflict {
				t.Fatal("stale Tor measurement selected a resolver", changed, w.Code)
			}
		})
	}
}

func TestDesktopTorDNSCleanupRequiresBothReceiptAndRealProcessJoin(t *testing.T) {
	a, launch, release := desktopTorRunningFixture(t, "receipt-before-exit")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	short, shortCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer shortCancel()
	if err := requestDesktopTorStop(short, a, launch, launch.command); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("early receipt became process drain", err)
	}
	if desktopDNSNativeClosed(launch) {
		t.Fatal("DNS measurement retired a still-live native process")
	}
	if err := os.WriteFile(release, []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil || !desktopDNSNativeClosed(launch) {
		t.Fatal("actual joined native owner lost its DNS cleanup receipt", err)
	}
}
