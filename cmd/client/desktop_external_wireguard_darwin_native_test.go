//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobiletor"
)

func macOSExternalNativeWireGuardRefused(t *testing.T, ctx context.Context, client *http.Client, peer *macOSExternalNativePeer, status int, raw []byte, failure error, controllerPID int, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if failure != nil || status != http.StatusConflict && status != http.StatusBadGateway {
		t.Fatal("WireGuard negative did not complete actual native refusal", status, failure, string(raw))
	}
	observed := peer.stats(t)
	if observed.PhysicalUDP < 1 {
		t.Fatal("WireGuard negative did not reach its independent encrypted peer", observed)
	}
	switch peer.fault {
	case "wrong-client-key", "wrong-psk":
		if observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 || observed.Streams != 0 || observed.Packets != 0 {
			t.Fatal("unauthenticated WireGuard peer reached inner proof", observed)
		}
	case "wrong-dns":
		if observed.DNSQueries < 1 || observed.Packets < 1 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("WireGuard DNS negative missed selected DNS or reached exit", observed)
		}
	case "wrong-trust":
		if observed.DNSQueries < 1 || observed.Streams < 1 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("WireGuard TLS negative failed before TLS or admitted untrusted proof", observed)
		}
	case "wrong-exit":
		if observed.DNSQueries < 1 || observed.PublicAttempts < 1 || observed.PublicReplies < 1 {
			t.Fatal("WireGuard exit mismatch did not reach actual public proof", observed)
		}
	default:
		t.Fatal("unknown WireGuard refusal")
	}
	status, raw, failure = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if failure != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || retired.Connected || !retired.NativeJoined || !retired.WorkspaceRetired || retired.ProcessID <= 0 || retired.ProcessID == controllerPID || retired.Baseline == nil || retired.Baseline.Capture.Session != retired.Session || retired.Baseline.Capture.Source != retired.Source || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present || retired.Protocol != "wireguard" || retired.PhysicalNetwork != "udp" || retired.PhysicalAddress != peer.address.String() {
		t.Fatal("WireGuard refusal lost exact joined native source/child/PF owner", status, failure, string(raw))
	}
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, before)
}

// Inspect retained Always without changing its baseline or inventing absence.
// The native read-only operation independently validates the empty descendant
// namespace and exact canonical deny policy after the original guardian joins.
func macOSExternalNativeAlwaysKernel(t *testing.T, parent context.Context, receipt *desktopMacOSExternalReceipt, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if receipt == nil || receipt.Capture.Policy != "always" || receipt.Phase != "retired" || !receipt.Baseline.Present {
		t.Fatal("Always lost its original retired deny receipt")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	request, err := mobiletor.EncodeDesktopDarwinPFReferenceRequest(mobiletor.DesktopDarwinPFReferenceRequest{Schema: 1, Token: receipt.Token})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mobiletor.RunDesktopDarwinPFReference(ctx, request)
	var reference mobiletor.DesktopDarwinPFReferenceResult
	if err != nil || decodeRelayControlJSON(raw, &reference) != nil || reference.Token != receipt.Token || !reference.Present {
		t.Fatal("Always lost its original live PF reference", err, string(raw))
	}
	proof := mobiletor.DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: receipt.Baseline.Rules}
	request, err = mobiletor.EncodeDesktopDarwinPFBaselineRequest(mobiletor.DesktopDarwinPFBaselineRequest{Schema: 1, Action: "replace", HomeLANAccess: receipt.Capture.HomeLAN, Expected: []mobiletor.DesktopDarwinPFBaselineProof{proof}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = mobiletor.RunDesktopDarwinPFBaseline(ctx, request, false)
	var baseline mobiletor.DesktopDarwinPFBaselineResult
	if err != nil || decodeRelayControlJSON(raw, &baseline) != nil || baseline.Applied || baseline.Previous != proof || baseline.Target != proof {
		t.Fatal("Always retained a live generation, grant or another baseline", err, string(raw))
	}
	// A differing target runs the native descendant retirement inspection even
	// though apply=false makes this an observation, never a PF mutation.
	request, err = mobiletor.EncodeDesktopDarwinPFBaselineRequest(mobiletor.DesktopDarwinPFBaselineRequest{Schema: 1, Action: "clear", Expected: []mobiletor.DesktopDarwinPFBaselineProof{proof}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = mobiletor.RunDesktopDarwinPFBaseline(ctx, request, false)
	baseline = mobiletor.DesktopDarwinPFBaselineResult{}
	if err != nil || decodeRelayControlJSON(raw, &baseline) != nil || baseline.Applied || baseline.Previous != proof || baseline.Target != (mobiletor.DesktopDarwinPFBaselineProof{}) {
		t.Fatal("Always retained a descendant anchor, grant or translation", err, string(raw))
	}
	raw, err = os.ReadFile(filepath.Join(macOSOwnedControllerRoot, "run", "kill-switch.json"))
	var journal struct {
		Capture desktopMacOSExternalSelection `json:"native_external_capture"`
		Token   string                        `json:"pf_token"`
		Policy  string                        `json:"policy"`
	}
	if err != nil || json.Unmarshal(raw, &journal) != nil || journal.Capture != receipt.Capture || journal.Token != receipt.Token || journal.Policy != "always" {
		t.Fatal("Always durable journal changed original owner", err)
	}
	if after := macOSExternalNativeTunnels(t); !maps.Equal(before, after) {
		t.Fatal("Always retained a new utun after joined cleanup", before, after)
	}
}

// Explicit disposable-runner cleanup occurs only after the real controller
// reports joined. Before mutation, revalidate the exact retained journal/token;
// afterward independently require original reference and namespace absence.
func macOSExternalNativeReleaseAlways(t *testing.T, parent context.Context, receipt *desktopMacOSExternalReceipt, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	macOSExternalNativeAlwaysKernel(t, parent, receipt, before)
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	python, _, err := macOSPythonTrustRoot(os.Getenv("ROUTERVPN_MACOS_FIXTURE_PYTHON"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, python, "-BEsS", filepath.Join(macOSOwnedControllerRoot, "modes", "kill-switch-platform.py"), "force-off")
	command.Dir, command.Env = macOSOwnedControllerRoot, macOSOwnedEnvironment()
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatal("explicit original Always fixture cleanup failed", err, string(raw))
	}
	macOSExternalNativeRetiredKernel(t, ctx, receipt.Token, before)
}

func macOSExternalNativeAwaitAutomaticMTU(t *testing.T, ctx context.Context, client *http.Client, peer *macOSExternalNativePeer) {
	t.Helper()
	deadline := time.Now().Add(130 * time.Second)
	for {
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/mtu/status", "")
		var value struct {
			Status mobilemtu.Status `json:"status"`
		}
		if err == nil && status == http.StatusOK && json.Unmarshal(raw, &value) == nil && value.Status.Complete && !value.Status.Running {
			macOSExternalNativeMTUResult(t, value.Status, peer.stats(t))
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("WireGuard automatic native MTU did not finish", status, err, string(raw))
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func macOSExternalNativeMTUResult(t *testing.T, status mobilemtu.Status, peer macOSExternalPeerReply) {
	t.Helper()
	if !status.Measured || !status.Complete || status.Running || status.Source != "measured-public-system-tun-transfer" || status.PathKey == "" || status.EffectiveMTU < 1280 || status.EffectiveMTU > 1420 || peer.Latency == nil || peer.Latency.MTUDownload < 256<<10 || peer.Latency.MTUUpload < 256<<10 {
		t.Fatal("WireGuard MTU omitted actual selected-path payload or committed provenance", status, peer.Latency)
	}
	changed := false
	for _, candidate := range status.Candidates {
		if candidate.Working && candidate.MTU != 1280 && candidate.Download != nil && candidate.Upload != nil && candidate.Download.Bytes > 0 && candidate.Upload.Bytes > 0 {
			changed = true
		}
	}
	if !changed {
		t.Fatal("WireGuard MTU never measured an actual changed utun candidate", status)
	}
}
func macOSExternalNativeWireGuardMTU(t *testing.T, parent context.Context, client *http.Client, peer *macOSExternalNativePeer, live macOSExternalNativeResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 150*time.Second)
	defer cancel()
	// Retest response is synchronous. Use a private copy with the shipping
	// optimizer's bounded operation plus rollback allowance, not a global timeout.
	bounded := *client
	bounded.Timeout = 140 * time.Second
	type reply struct {
		code int
		body []byte
		err  error
	}
	request := mtuViewRequest{Request: strings.Repeat("7", 32), Session: live.Session, Profile: "installed-macos-external"}
	encode := func(value mtuViewRequest) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	before := peer.latencyControl(t, "hold-mtu")
	done := make(chan reply, 1)
	go func() {
		code, body, err := macOSExternalNativeHTTP(ctx, &bounded, http.MethodPost, "/api/mtu/retest", encode(request))
		done <- reply{code, body, err}
	}()
	joined := false
	defer func() {
		if !joined {
			cancel()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Error("original MTU HTTP worker did not join")
			}
		}
	}()
	deadline := time.Now().Add(25 * time.Second)
	for {
		observed := peer.stats(t)
		if observed.Latency != nil && observed.Latency.MTUActive == 1 && observed.Latency.MTUDownload == before.Latency.MTUDownload {
			break
		}
		select {
		case ended := <-done:
			joined = true
			t.Fatal("MTU Retest ended before its real held payload", ended.code, ended.err, string(ended.body))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("MTU Cancel did not reach its held actual TLS payload", observed)
		}
		time.Sleep(20 * time.Millisecond)
	}
	foreign := request
	foreign.Session = strings.Repeat("e", 32)
	code, body, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/cancel", encode(foreign))
	if err != nil || code != http.StatusConflict {
		t.Fatal("foreign MTU cancellation reached original owner", code, err, string(body))
	}
	code, body, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/cancel", encode(request))
	if err != nil || code != http.StatusOK {
		t.Fatal("original MTU cancel refused", code, err, string(body))
	}
	select {
	case ended := <-done:
		joined = true
		if ended.err != nil || ended.code != http.StatusConflict {
			t.Fatal("cancelled MTU request published success or missed joined rollback", ended.code, ended.err, string(ended.body))
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	code, body, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/mtu/status?request_id="+request.Request+"&session_id="+request.Session, "")
	var cancelled struct {
		Status mobilemtu.Status `json:"status"`
	}
	if err != nil || code != http.StatusOK || json.Unmarshal(body, &cancelled) != nil || !cancelled.Status.Complete || cancelled.Status.Running || !cancelled.Status.Restored || cancelled.Status.Measured || cancelled.Status.EffectiveMTU != int(live.Network.MTU) {
		t.Fatal("MTU Cancel lost original restored interface", code, err, string(body))
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		observed := peer.stats(t)
		if observed.Latency != nil && observed.Latency.MTUActive == 0 && observed.Latency.MTUCancelled == before.Latency.MTUCancelled+1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("MTU Cancel did not close actual held TLS payload", observed)
		}
		time.Sleep(10 * time.Millisecond)
	}
	peer.latencyControl(t, "release-mtu")
	request.Request = strings.Repeat("8", 32)
	code, body, err = macOSExternalNativeHTTP(ctx, &bounded, http.MethodPost, "/api/mtu/retest", encode(request))
	var result struct {
		OK     bool             `json:"ok"`
		Result mobilemtu.Status `json:"result"`
	}
	if err != nil || code != http.StatusOK || json.Unmarshal(body, &result) != nil || !result.OK {
		t.Fatal("WireGuard native MTU Retest failed", code, err, string(body))
	}
	macOSExternalNativeMTUResult(t, result.Result, peer.stats(t))
	code, body, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var current macOSExternalNativeResult
	if err != nil || code != http.StatusOK || decodeRelayControlJSON(body, &current) != nil || current.Session != live.Session || current.ProcessID != live.ProcessID || current.Source != live.Source || current.Config != live.Config || current.Baseline == nil || current.Baseline.Token != live.Baseline.Token || int(current.Network.MTU) != result.Result.EffectiveMTU {
		t.Fatal("MTU changed original runtime/source/PF identity or omitted native readback", code, err, string(body))
	}
	t.Log("actual sealed Darwin WireGuard MTU accepted: automatic changed utun, transferred bytes, original Cancel rollback joined, Retest committed and original runtime PF retained")
}
