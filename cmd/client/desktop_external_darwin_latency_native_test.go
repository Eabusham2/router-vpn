//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type macOSExternalLatencyReceipt struct {
	DNS, TLS, Requests, Responses, Cancelled, Active uint32
	MTUDownload                                      uint32 `json:"mtu_download"`
	MTUUpload                                        uint32 `json:"mtu_upload"`
	MTUActive                                        uint32 `json:"mtu_active"`
	MTUCancelled                                     uint32 `json:"mtu_cancelled"`
}

func (p *macOSExternalNativePeer) latencyControl(t *testing.T, command string) macOSExternalPeerReply {
	t.Helper()
	if command != "hold-latency" && command != "release-latency" && command != "hold-mtu" && command != "release-mtu" {
		t.Fatal("unowned latency reference command")
	}
	if _, err := p.input.Write([]byte(command + "\n")); err != nil {
		t.Fatal(err)
	}
	return p.read(t)
}
func macOSExternalNativeLatency(t *testing.T, ctx context.Context, client *http.Client, peer *macOSExternalNativePeer, live macOSExternalNativeResult) {
	t.Helper()
	const endpoint = "/api/speed-lab/external-latency"
	read := func(path string) desktopLatencyView {
		t.Helper()
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, path, "")
		var value desktopLatencyView
		if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &value) != nil || value.ProfileID != "installed-macos-external" || value.SessionID != live.Session || value.SourceSHA256 != live.Source || value.ConfigSHA256 != live.Config || value.ProfileToken == "" {
			t.Fatal("native latency lost original profile/session/source", status, err, string(raw))
		}
		return value
	}
	initial := read(endpoint)
	post := func(request desktopLatencyRequest, path string, want int) {
		t.Helper()
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, path, string(body))
		if err != nil || status != want {
			t.Fatal("native latency public operation failed", path, status, err, string(raw))
		}
	}
	request := desktopLatencyRequest{ProfileID: initial.ProfileID, ProfileToken: initial.ProfileToken, SessionID: initial.SessionID, Request: strings.Repeat("5", 32)}
	before := peer.latencyControl(t, "hold-latency")
	if before.Latency == nil || before.Latency.Active != 0 {
		t.Fatal("native benchmark has no idle captured reference")
	}
	post(request, endpoint, http.StatusAccepted)
	deadline := time.Now().Add(15 * time.Second)
	for {
		value := peer.stats(t)
		if value.Latency != nil && value.Latency.Requests == before.Latency.Requests+1 && value.Latency.Active == 1 && value.Latency.Responses == before.Latency.Responses {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native Cancel never reached the held actual HTTPS responder", value)
		}
		time.Sleep(10 * time.Millisecond)
	}
	foreign := request
	foreign.SessionID = strings.Repeat("e", 32)
	post(foreign, endpoint+"/cancel", http.StatusConflict)
	post(request, endpoint+"/cancel", http.StatusAccepted)
	deadline = time.Now().Add(15 * time.Second)
	for {
		value := read(endpoint + "?request_id=" + request.Request)
		if value.Status.Complete && value.Status.Drained {
			if value.Status.Stage != "cancelled" || len(value.Status.Results) != 0 || value.MeasuredAt != 0 {
				t.Fatal("native Cancel published partial or stale score", value)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native Cancel did not join exact workers", value)
		}
		time.Sleep(10 * time.Millisecond)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		value := peer.stats(t)
		if value.Latency != nil && value.Latency.Active == 0 && value.Latency.Cancelled == before.Latency.Cancelled+1 && value.Latency.Responses == before.Latency.Responses {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native Cancel did not close its actual held TLS response", value)
		}
		time.Sleep(10 * time.Millisecond)
	}
	before = peer.latencyControl(t, "release-latency")
	post(request, endpoint, http.StatusConflict)
	request.Request = strings.Repeat("6", 32)
	post(request, endpoint, http.StatusAccepted)
	deadline = time.Now().Add(100 * time.Second)
	var completed desktopLatencyView
	for {
		completed = read(endpoint + "?request_id=" + request.Request)
		if completed.Status.Complete && completed.Status.Drained {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native50 Retest did not finish its actual path", completed)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if completed.Status.Stage != "complete" || completed.Status.Failure != "" || len(completed.Status.Results) != 1 || !completed.Status.Results[0].Ready || completed.Status.Results[0].Benchmark == nil || completed.MeasuredAt <= 0 {
		t.Fatal("native50 Retest did not publish one complete current score", completed)
	}
	benchmark := completed.Status.Results[0].Benchmark
	if benchmark.Attempts != 50 || benchmark.Failed != 0 || benchmark.Distribution == nil || benchmark.Distribution.Samples != 50 || benchmark.TrimmedMean <= 0 || benchmark.Endpoint != "https://speed.cloudflare.com/__down?bytes=1" {
		t.Fatal("native50 result lost its exact response metric", benchmark)
	}
	after := peer.stats(t)
	if after.Latency == nil || after.Latency.Requests-before.Latency.Requests != 50 || after.Latency.TLS-before.Latency.TLS != 50 || after.Latency.Responses-before.Latency.Responses != 50 || after.Latency.DNS < 1 || after.Latency.Active != 0 || after.Latency.Cancelled != before.Latency.Cancelled || after.AuthFailures != 0 {
		t.Fatal("native50 bypassed actual selected DNS/TLS/response or worker drain", before, after)
	}
	post(request, endpoint, http.StatusConflict)
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retained macOSExternalNativeResult
	if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retained) != nil || !retained.Connected || retained.ProcessID != live.ProcessID || retained.Session != live.Session || retained.Source != live.Source || retained.Config != live.Config || retained.Baseline == nil || retained.Baseline.Token != live.Baseline.Token || retained.Network.Name != live.Network.Name || retained.Network.Index != live.Network.Index || retained.Network.MTU != live.Network.MTU {
		t.Fatal("native Retest/Cancel replaced its original child/PF/TUN owner", status, err, string(raw))
	}
	t.Logf("actual sealed Darwin latency accepted %s: held TLS Cancel joined, foreign cancellation and replay refused, Retest50 actual responses, original session child PF and MTU retained", peer.name)
}
