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

func macOSPairedNodeNativeAwaitAuto(t *testing.T, ctx context.Context, client *http.Client, peer *macOSPairedNodePeer) {
	t.Helper()
	deadline := time.Now().Add(130 * time.Second)
	for {
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/mtu/status", "")
		var value macOSNodeChainMTUView
		if err != nil || status != http.StatusOK && status != http.StatusConflict || status == http.StatusOK && json.Unmarshal(raw, &value) != nil {
			t.Fatal("actual automatic MTU status lost its bounded public response", status, err, string(raw))
		}
		// A reader replacement can own the native observation gate longer than
		// the status request's four-second proof budget. Only a later complete
		// successful response can satisfy Auto; a conflict is never a result.
		if status == http.StatusOK && value.Status.Complete && !value.Status.Running {
			if !value.Status.Measured || value.Status.Failure != "" || value.Status.Source != "auto-throughput" || value.Status.EffectiveMTU < 1280 {
				t.Fatal("actual ordered automatic MTU did not adopt a measured winner", value)
			}
			stats := peer.observe(t, "stats")
			if stats.Benchmark == nil || stats.Benchmark.Replies == 0 || stats.Benchmark.SentBytes == 0 || stats.Benchmark.ReceivedBytes == 0 || stats.Benchmark.MaximumPayload < 1252 {
				t.Fatal("automatic MTU lacked real final-only UDP benchmark bytes", stats)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("actual ordered automatic MTU exceeded unchanged measurement budget", status, string(raw), value)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func macOSPairedNodeNativeMTU(t *testing.T, ctx context.Context, client *http.Client, peer *macOSPairedNodePeer, original macOSPairedNodeNativeResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	if original.Ready == nil || original.MTU.Reader <= 1 || original.MTU.Generation == 0 || original.EffectiveSource != "auto-throughput" || original.EffectiveMTU != original.MTU.MTU {
		t.Fatal("Auto did not adopt actual ordered reader succession", original)
	}
	before := peer.observe(t, "hold-benchmark")
	if before.Benchmark == nil || !before.Benchmark.Held {
		t.Fatal("actual independent benchmark hold was not admitted")
	}
	request := strings.Repeat("a", 32)
	makeBody := func(session, id string) string {
		raw, _ := json.Marshal(mtuViewRequest{Request: id, Session: session, Profile: original.Profile})
		return string(raw)
	}
	type completion struct {
		status int
		raw    []byte
		err    error
	}
	done := make(chan completion, 1)
	joined := false
	go func() {
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/retest", makeBody(original.ViewSession, request))
		done <- completion{status, raw, err}
	}()
	defer func() {
		if joined {
			return
		}
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("original ordered MTU HTTP worker did not join after fixture cancellation")
		}
	}()
	deadline := time.Now().Add(25 * time.Second)
	for {
		select {
		case result := <-done:
			joined = true
			t.Fatal("held actual optimizer completed before captured Cancel", result.status, result.err, string(result.raw))
		default:
		}
		stats := peer.observe(t, "stats")
		if stats.Benchmark.HeldPackets > before.Benchmark.HeldPackets {
			view := macOSNodeChainNativeMTUStatus(t, ctx, client, "")
			if view.Status.Running && view.Status.Request == request {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("actual Retest did not reach held final-only benchmark and original Running receipt", stats)
		}
		time.Sleep(25 * time.Millisecond)
	}
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/cancel", makeBody(original.ViewSession+"-foreign", request))
	if err != nil || status != http.StatusConflict {
		t.Fatal("foreign ordered MTU Cancel acquired original operation", status, err, string(raw))
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/cancel", makeBody(original.ViewSession, request))
	if err != nil || status != http.StatusOK {
		t.Fatal("original ordered MTU Cancel failed", status, err, string(raw))
	}
	select {
	case result := <-done:
		joined = true
		if result.err != nil || result.status != http.StatusRequestTimeout {
			t.Fatal("canceled actual optimizer did not join its rollback", result.status, result.err, string(result.raw))
		}
	case <-time.After(25 * time.Second):
		t.Fatal("canceled actual optimizer retained an unjoined worker")
	}
	view := macOSNodeChainNativeMTUStatus(t, ctx, client, request)
	if view.Status.Running || !view.Status.Complete || view.Status.Measured || !view.Status.Restored || view.Status.EffectiveMTU != original.MTU.MTU {
		t.Fatal("public cancellation omitted exact MTU restoration", view)
	}
	restored := macOSPairedNodeNativeRead(t, ctx, client)
	if restored.MTUActive || !restored.Connected || restored.Session != original.Session || restored.ProcessID != original.ProcessID || restored.Transfer != original.Transfer || restored.MTU.MTU != original.MTU.MTU || restored.MTU.Reader <= original.MTU.Reader || restored.EffectiveMTU != original.EffectiveMTU || restored.Baseline.Token != original.Baseline.Token {
		t.Fatal("public Cancel lost original native owner or restored reader", restored)
	}
	peer.observe(t, "release-benchmark")
	before = peer.observe(t, "stats")
	request = strings.Repeat("b", 32)
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/retest", makeBody(original.ViewSession, request))
	var result struct {
		OK     bool   `json:"ok"`
		MTU    int    `json:"effective_mtu"`
		Source string `json:"effective_mtu_source"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(raw, &result) != nil || !result.OK || result.MTU < 1280 || result.Source != "auto-throughput" {
		t.Fatal("actual ordered Retest did not adopt fresh final-path winner", status, err, string(raw))
	}
	view = macOSNodeChainNativeMTUStatus(t, ctx, client, request)
	adopted := macOSPairedNodeNativeRead(t, ctx, client)
	after := peer.observe(t, "stats")
	if view.Status.Running || !view.Status.Complete || !view.Status.Measured || view.Status.Request != request || view.Status.EffectiveMTU != result.MTU ||
		adopted.MTUActive || !adopted.Connected || adopted.Session != original.Session || adopted.ProcessID != original.ProcessID || adopted.Transfer != original.Transfer || adopted.MTU.Reader <= restored.MTU.Reader || adopted.MTU.MTU != result.MTU || adopted.EffectiveMTU != result.MTU || adopted.Baseline.Token != original.Baseline.Token ||
		after.Benchmark.Replies <= before.Benchmark.Replies || after.Benchmark.SentBytes <= before.Benchmark.SentBytes || after.Benchmark.ReceivedBytes <= before.Benchmark.ReceivedBytes {
		t.Fatal("fresh Retest omitted actual transfer and original reader adoption", view, adopted, after)
	}
	encryptedDatagrams := after.RawUDP > before.RawUDP
	if peer.mode == "naive-h2" {
		// H2 carries application datagrams in authenticated UoT-v2 streams;
		// its physical lower must remain TCP even during the real MTU test.
		encryptedDatagrams = after.RawUDP == 0 && before.RawUDP == 0 && after.ProtocolRawUDP == 0 && after.ProtocolRawTCP > 0 && after.ProtocolTLSHTTP > 0 && after.ProtocolUDP > before.ProtocolUDP
	}
	if pairedREALITYMode(peer.mode) {
		encryptedDatagrams = after.RawUDP == 0 && before.RawUDP == 0 && after.ProtocolRawUDP == 0 && after.ProtocolRawTCP > 0 && after.ProtocolUDP > before.ProtocolUDP
	}
	if !encryptedDatagrams || after.DirectQueries != before.DirectQueries {
		t.Fatal("paired MTU bypassed original encrypted UDP", before, after)
	}

	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/retest", makeBody(original.ViewSession, request))
	if err != nil || status != http.StatusConflict {
		t.Fatal("completed ordered MTU request was replayed", status, err, string(raw))
	}
	t.Log("actual paired Darwin MTU: Auto and Retest transferred original encrypted UDP, held Cancel joined exact rollback, original process PF and reader succession retained")
}
