package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"router-vpn/internal/common"
)

const multihopEntryProofProxy = "http://127.0.0.1:1098"

func newMultihopLaneHTTPClient(proxyRaw string, timeout time.Duration) (*http.Client, func(), error) {
	proxyURL, err := url.Parse(strings.TrimSpace(proxyRaw))
	if err != nil || proxyURL.Scheme != "http" || proxyURL.Hostname() != "127.0.0.1" || (proxyURL.Port() != "1098" && proxyURL.Port() != "1099") {
		return nil, nil, errors.New("multihop hop telemetry requires a reserved local proof proxy")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = false
	client := &http.Client{Transport: transport, Timeout: timeout}
	return client, transport.CloseIdleConnections, nil
}

func multihopLaneProofURL(p common.RouterProfile) (string, error) {
	target := strings.TrimSpace(p.PathProbeURL)
	if target == "" && strings.TrimSpace(p.RouterAPI) != "" {
		target = strings.TrimRight(strings.TrimSpace(p.RouterAPI), "/") + "/health"
	}
	if target == "" || !trustedPathProbeURL(target) {
		return "", errors.New("multihop hop has no trusted private node-proof URL")
	}
	return target, nil
}

func proveMultihopLaneNode(p common.RouterProfile, proxyRaw string) error {
	if strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") || p.External != nil {
		return errors.New("exact Router VPN hop proof is unavailable for an external-only node")
	}
	target, err := multihopLaneProofURL(p)
	if err != nil {
		return err
	}
	client, closeIdle, err := newMultihopLaneHTTPClient(proxyRaw, 2500*time.Millisecond)
	if err != nil {
		return err
	}
	defer closeIdle()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	if strings.TrimSpace(p.APIToken) != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIToken)
	}
	req.Header.Set("Cache-Control", "no-store")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("multihop hop node proof failed: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
	_ = resp.Body.Close()
	if readErr != nil {
		return readErr
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("multihop hop node proof returned HTTP %d", resp.StatusCode)
	}
	if len(body) > 4096 {
		return errors.New("multihop hop node proof response is oversized")
	}
	if err := validateSelectedNodeProof(p, body); err != nil {
		return fmt.Errorf("multihop hop lane reached the wrong Router VPN node: %w", err)
	}
	return nil
}

func measureRoutedProfileLatencyViaProxy(p common.RouterProfile, samples int, proxyRaw string) (connectionLatencyResult, error) {
	if samples <= 0 {
		samples = 4
	}
	if samples > 10 {
		samples = 10
	}
	target, err := multihopLaneProofURL(p)
	if err != nil {
		return connectionLatencyResult{}, err
	}
	client, closeIdle, err := newMultihopLaneHTTPClient(proxyRaw, 2500*time.Millisecond)
	if err != nil {
		return connectionLatencyResult{}, err
	}
	defer closeIdle()
	values := make([]float64, 0, samples)
	failed := 0
	for i := 0; i < samples; i++ {
		req, reqErr := http.NewRequest(http.MethodGet, target, nil)
		if reqErr != nil {
			return connectionLatencyResult{}, reqErr
		}
		if strings.TrimSpace(p.APIToken) != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIToken)
		}
		req.Header.Set("Cache-Control", "no-store")
		started := time.Now()
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			failed++
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode/100 != 2 || len(body) > 4096 || validateSelectedNodeProof(p, body) != nil {
			failed++
			continue
		}
		values = append(values, float64(time.Since(started).Microseconds())/1000.0)
		if i+1 < samples {
			time.Sleep(35 * time.Millisecond)
		}
	}
	if len(values) == 0 {
		return connectionLatencyResult{}, errors.New("exact multihop hop lane did not return a valid node-identity RTT sample")
	}
	sort.Float64s(values)
	return connectionLatencyResult{
		Connected: true, Mode: "multihop", RouterID: p.ID, Name: p.Name,
		Samples: len(values), Failed: failed, MinMs: round3(values[0]),
		MedianMs: round3(percentile(values, .50)), AverageMs: round3(average(values)),
		P90Ms: round3(percentile(values, .90)), MaxMs: round3(values[len(values)-1]),
		MeasuredAt: time.Now().UTC(),
		Proof: "exact Router VPN node-identity HTTP RTT through reserved local multihop hop lane " + proxyRaw,
	}, nil
}

func measureRoutedProfileSpeedViaProxy(p common.RouterProfile, bytesCount int64, proxyRaw string) (routedSpeedResult, error) {
	if err := proveMultihopLaneNode(p, proxyRaw); err != nil {
		return routedSpeedResult{}, err
	}
	bytesCount = clampSpeedBytes(bytesCount)
	if strings.TrimSpace(p.RouterAPI) == "" || strings.TrimSpace(p.APIToken) == "" {
		return routedSpeedResult{}, errors.New("node has no private benchmark API/token")
	}
	client, closeIdle, err := newMultihopLaneHTTPClient(proxyRaw, 30*time.Second)
	if err != nil {
		return routedSpeedResult{}, err
	}
	defer closeIdle()
	base := strings.TrimRight(p.RouterAPI, "/")

	downloadURL := base + "/api/benchmark/download?bytes=" + strconv.FormatInt(bytesCount, 10)
	downloadReq, err := privateBenchmarkRequest(http.MethodGet, downloadURL, p.APIToken, nil)
	if err != nil {
		return routedSpeedResult{}, err
	}
	downloadReq.Header.Set("Accept-Encoding", "identity")
	downloadStarted := time.Now()
	downloadResp, err := client.Do(downloadReq)
	if err != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane download benchmark failed: %w", err)
	}
	downloaded, copyErr := io.Copy(io.Discard, io.LimitReader(downloadResp.Body, bytesCount+1))
	_ = downloadResp.Body.Close()
	if copyErr != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane download benchmark read failed: %w", copyErr)
	}
	if downloadResp.StatusCode/100 != 2 {
		return routedSpeedResult{}, fmt.Errorf("hop-lane download benchmark returned HTTP %d", downloadResp.StatusCode)
	}
	if downloaded != bytesCount {
		return routedSpeedResult{}, fmt.Errorf("hop-lane download benchmark returned %d bytes; expected %d", downloaded, bytesCount)
	}
	downloadElapsed := time.Since(downloadStarted)

	payload := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		return routedSpeedResult{}, fmt.Errorf("prepare hop-lane upload benchmark: %w", err)
	}
	uploadURL := base + "/api/benchmark/upload"
	uploadReq, err := privateBenchmarkRequest(http.MethodPost, uploadURL, p.APIToken, bytes.NewReader(payload))
	if err != nil {
		return routedSpeedResult{}, err
	}
	uploadReq.ContentLength = bytesCount
	uploadStarted := time.Now()
	uploadResp, err := client.Do(uploadReq)
	if err != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane upload benchmark failed: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(uploadResp.Body, 64<<10))
	_ = uploadResp.Body.Close()
	if readErr != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane upload benchmark response failed: %w", readErr)
	}
	if uploadResp.StatusCode/100 != 2 {
		return routedSpeedResult{}, fmt.Errorf("hop-lane upload benchmark returned HTTP %d", uploadResp.StatusCode)
	}
	uploadElapsed := time.Since(uploadStarted)
	var ack struct {
		Bytes           int64   `json:"bytes"`
		ServerReceiveMs float64 `json:"server_receive_ms"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane upload benchmark proof is invalid: %w", err)
	}
	if ack.Bytes != bytesCount {
		return routedSpeedResult{}, fmt.Errorf("hop-lane upload benchmark acknowledged %d bytes; expected %d", ack.Bytes, bytesCount)
	}
	// Re-prove the same node after the load; token-authenticated byte transfer
	// alone is not enough to label a hop when private addresses overlap.
	if err := proveMultihopLaneNode(p, proxyRaw); err != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane identity changed after throughput benchmark: %w", err)
	}

	mbits := float64(bytesCount*8) / 1_000_000.0
	return routedSpeedResult{
		RouterID: p.ID, Name: p.Name, Bytes: bytesCount,
		DownloadMbps: round3(mbits / downloadElapsed.Seconds()), UploadMbps: round3(mbits / uploadElapsed.Seconds()),
		DownloadMs: round3(float64(downloadElapsed.Microseconds()) / 1000.0), UploadMs: round3(float64(uploadElapsed.Microseconds()) / 1000.0),
		ServerReceiveMs: round3(ack.ServerReceiveMs), MeasuredAt: time.Now().UTC(),
		Proof: "independent authenticated transfer through reserved local multihop hop lane " + proxyRaw + "; node identity proved before and after load",
	}, nil
}
