package main

import (
	"bytes"
	"context"
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
	if err != nil || proxyURL.Scheme != "http" || proxyURL.Hostname() != "127.0.0.1" || (proxyURL.Port() != "1098" && proxyURL.Port() != "1099") || proxyURL.User != nil || proxyURL.Path != "" || proxyURL.RawQuery != "" || proxyURL.Fragment != "" || proxyURL.ForceQuery {
		return nil, nil, errors.New("multihop hop telemetry requires a reserved local proof proxy")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = false
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("multihop proof/benchmark redirect refused")
		},
	}
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
	return proveMultihopLaneNodeContext(context.Background(), p, proxyRaw)
}

func proveMultihopLaneNodeContext(ctx context.Context, p common.RouterProfile, proxyRaw string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
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
	return measureRoutedProfileLatencyViaProxyContext(context.Background(), p, samples, proxyRaw)
}

func measureRoutedProfileLatencyViaProxyContext(ctx context.Context, p common.RouterProfile, samples int, proxyRaw string) (connectionLatencyResult, error) {
	return measureRoutedProfileLatencyViaProxyWithClock(ctx, p, samples, proxyRaw, startClientMeasurementInterval)
}

func measureRoutedProfileLatencyViaProxyWithClock(ctx context.Context, p common.RouterProfile, samples int, proxyRaw string, startClock clientMeasurementClock) (connectionLatencyResult, error) {
	if err := ctx.Err(); err != nil {
		return connectionLatencyResult{}, err
	}
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
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if reqErr != nil {
			return connectionLatencyResult{}, reqErr
		}
		if strings.TrimSpace(p.APIToken) != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIToken)
		}
		req.Header.Set("Cache-Control", "no-store")
		interval, clockErr := startClock()
		if clockErr != nil {
			return connectionLatencyResult{}, clockErr
		}
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			if err := ctx.Err(); err != nil {
				return connectionLatencyResult{}, err
			}
			failed++
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode/100 != 2 || len(body) > 4096 {
			failed++
			continue
		}
		// Do not retain earlier samples after a lane answers as another node.
		// A wrong identity is not ordinary packet loss within one proved path.
		if err := validateSelectedNodeProof(p, body); err != nil {
			return connectionLatencyResult{}, fmt.Errorf("multihop hop lane reached the wrong Router VPN node: %w", err)
		}
		elapsed, clockErr := clientMeasurementMilliseconds(ctx, interval)
		if clockErr != nil {
			// A faulty interval invalidates this observation, including earlier
			// samples. It is not packet loss within one measured clock domain.
			return connectionLatencyResult{}, clockErr
		}
		values = append(values, elapsed)
		if i+1 < samples {
			select {
			case <-ctx.Done():
				return connectionLatencyResult{}, ctx.Err()
			case <-time.After(35 * time.Millisecond):
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return connectionLatencyResult{}, err
	}
	if len(values) == 0 {
		return connectionLatencyResult{}, errors.New("exact multihop hop lane did not return a valid node-identity RTT sample")
	}
	sort.Float64s(values)
	return connectionLatencyResult{
		Connected: true, Mode: "multihop", RouterID: p.ID, Name: p.Name,
		Samples: len(values), Failed: failed, MinMs: roundMeasuredMilliseconds(values[0]),
		MedianMs: roundMeasuredMilliseconds(percentile(values, .50)), AverageMs: roundMeasuredMilliseconds(averageMeasuredMilliseconds(values)),
		P90Ms: roundMeasuredMilliseconds(percentile(values, .90)), MaxMs: roundMeasuredMilliseconds(values[len(values)-1]),
		MeasuredAt: time.Now().UTC(),
		Proof:      "exact Router VPN node-identity HTTP RTT through reserved local multihop hop lane " + proxyRaw,
	}, nil
}

func measureRoutedProfileSpeedViaProxy(p common.RouterProfile, bytesCount int64, proxyRaw string) (routedSpeedResult, error) {
	return measureRoutedProfileSpeedViaProxyContext(context.Background(), p, bytesCount, proxyRaw)
}

func measureRoutedProfileSpeedViaProxyContext(ctx context.Context, p common.RouterProfile, bytesCount int64, proxyRaw string) (routedSpeedResult, error) {
	return measureRoutedProfileSpeedViaProxyWithClock(ctx, p, bytesCount, proxyRaw, startClientMeasurementInterval)
}

func measureRoutedProfileSpeedViaProxyWithClock(ctx context.Context, p common.RouterProfile, bytesCount int64, proxyRaw string, startClock clientMeasurementClock) (routedSpeedResult, error) {
	if err := context.Cause(ctx); err != nil {
		return routedSpeedResult{}, err
	}
	if err := proveMultihopLaneNodeContext(ctx, p, proxyRaw); err != nil {
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
	downloadReq = downloadReq.WithContext(ctx)
	downloadReq.Header.Set("Accept-Encoding", "identity")
	downloadInterval, err := startClock()
	if err != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane download benchmark clock start failed: %w", errors.Join(err, context.Cause(ctx)))
	}
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
	downloadMs, err := clientMeasurementMilliseconds(ctx, downloadInterval)
	if err != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane download benchmark clock failed: %w", err)
	}
	downloadMbps, err := privateBenchmarkMbps(bytesCount, downloadMs)
	if err != nil {
		return routedSpeedResult{}, err
	}

	payload := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		return routedSpeedResult{}, fmt.Errorf("prepare hop-lane upload benchmark: %w", err)
	}
	uploadURL := base + "/api/benchmark/upload"
	uploadReq, err := privateBenchmarkRequest(http.MethodPost, uploadURL, p.APIToken, bytes.NewReader(payload))
	if err != nil {
		return routedSpeedResult{}, err
	}
	uploadReq = uploadReq.WithContext(ctx)
	uploadReq.ContentLength = bytesCount
	uploadInterval, err := startClock()
	if err != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane upload benchmark clock start failed: %w", errors.Join(err, context.Cause(ctx)))
	}
	uploadResp, err := client.Do(uploadReq)
	if err != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane upload benchmark failed: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(uploadResp.Body, (64<<10)+1))
	_ = uploadResp.Body.Close()
	if readErr != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane upload benchmark response failed: %w", readErr)
	}
	if uploadResp.StatusCode/100 != 2 {
		return routedSpeedResult{}, fmt.Errorf("hop-lane upload benchmark returned HTTP %d", uploadResp.StatusCode)
	}
	if len(body) > 64<<10 {
		return routedSpeedResult{}, errors.New("hop-lane upload benchmark response is oversized")
	}
	uploadMs, err := clientMeasurementMilliseconds(ctx, uploadInterval)
	if err != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane upload benchmark clock failed: %w", err)
	}
	uploadMbps, err := privateBenchmarkMbps(bytesCount, uploadMs)
	if err != nil {
		return routedSpeedResult{}, err
	}
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
	if err := proveMultihopLaneNodeContext(ctx, p, proxyRaw); err != nil {
		return routedSpeedResult{}, fmt.Errorf("hop-lane identity changed after throughput benchmark: %w", err)
	}

	if err := context.Cause(ctx); err != nil {
		return routedSpeedResult{}, err
	}
	return routedSpeedResult{
		RouterID: p.ID, Name: p.Name, Bytes: bytesCount,
		DownloadMbps: downloadMbps, UploadMbps: uploadMbps,
		DownloadMs: roundMeasuredMilliseconds(downloadMs), UploadMs: roundMeasuredMilliseconds(uploadMs),
		ServerReceiveMs: round3(ack.ServerReceiveMs), MeasuredAt: time.Now().UTC(),
		Proof: "independent authenticated transfer through reserved local multihop hop lane " + proxyRaw + "; node identity proved before and after load",
	}, nil
}
