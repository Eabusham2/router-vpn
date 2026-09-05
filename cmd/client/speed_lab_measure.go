package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	speedLabDownloadURL = "https://speed.cloudflare.com/__down"
	speedLabUploadURL   = "https://speed.cloudflare.com/__up"
	speedLabAutoMin     = 4 * time.Second
	speedLabAutoMax     = 12 * time.Second
)

type speedLabDuration struct {
	Mode       string  `json:"mode"`
	MinSeconds float64 `json:"min_seconds"`
	MaxSeconds float64 `json:"max_seconds"`
}

type speedLabLatencyStats struct {
	Samples   int     `json:"samples"`
	Failed    int     `json:"failed"`
	MinMs     float64 `json:"min_ms"`
	MedianMs  float64 `json:"median_ms"`
	AverageMs float64 `json:"average_ms"`
	P90Ms     float64 `json:"p90_ms"`
	MaxMs     float64 `json:"max_ms"`
	JitterMs  float64 `json:"jitter_ms"`
}

type speedLabDirectionResult struct {
	Direction      string               `json:"direction"`
	Mbps           float64              `json:"mbps"`
	Bytes          int64                `json:"bytes"`
	Seconds        float64              `json:"seconds"`
	Rounds         int                  `json:"rounds"`
	LoadedLatency  speedLabLatencyStats `json:"loaded_latency"`
	BufferbloatMs  float64              `json:"bufferbloat_ms"`
	StoppedStable  bool                 `json:"stopped_stable"`
	ProviderDetail string               `json:"provider_detail"`
}

type speedLabMeasurement struct {
	Provider string                  `json:"provider"`
	Duration speedLabDuration        `json:"duration"`
	Idle     speedLabLatencyStats    `json:"idle_latency"`
	Download speedLabDirectionResult `json:"download"`
	Upload   speedLabDirectionResult `json:"upload"`
	Started  time.Time               `json:"started_at"`
	Finished time.Time               `json:"finished_at"`
}

type speedLabPatternReader struct {
	pattern []byte
	offset  int
}

type speedLabParallelResult struct {
	bytes int64
	err   error
}

func (r *speedLabPatternReader) Read(p []byte) (int, error) {
	if len(r.pattern) == 0 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = r.pattern[r.offset]
		r.offset++
		if r.offset == len(r.pattern) {
			r.offset = 0
		}
	}
	return len(p), nil
}

func normalizeSpeedLabDuration(mode string, minSeconds, maxSeconds float64) (speedLabDuration, time.Duration, time.Duration, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "auto" || mode == "default" {
		return speedLabDuration{Mode: "auto", MinSeconds: speedLabAutoMin.Seconds(), MaxSeconds: speedLabAutoMax.Seconds()}, speedLabAutoMin, speedLabAutoMax, nil
	}
	if mode != "custom" {
		return speedLabDuration{}, 0, 0, errors.New("speed-test duration mode must be auto or custom")
	}
	if math.IsNaN(minSeconds) || math.IsNaN(maxSeconds) || math.IsInf(minSeconds, 0) || math.IsInf(maxSeconds, 0) {
		return speedLabDuration{}, 0, 0, errors.New("custom speed-test duration must be finite")
	}
	if minSeconds < 1 || minSeconds > 60 || maxSeconds < 1 || maxSeconds > 60 || maxSeconds < minSeconds {
		return speedLabDuration{}, 0, 0, errors.New("custom speed-test time must satisfy 1s <= min <= max <= 60s")
	}
	minDuration := time.Duration(minSeconds * float64(time.Second))
	maxDuration := time.Duration(maxSeconds * float64(time.Second))
	return speedLabDuration{Mode: "custom", MinSeconds: round3(minSeconds), MaxSeconds: round3(maxSeconds)}, minDuration, maxDuration, nil
}

func newSpeedLabHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.MaxIdleConns = 32
	transport.MaxIdleConnsPerHost = 8
	transport.MaxConnsPerHost = 8
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("speed-test provider redirect refused")
		},
	}
}

func speedLabProbeOnce(ctx context.Context, client *http.Client) (float64, error) {
	url := speedLabDownloadURL + "?bytes=1&r=" + strconv.FormatInt(time.Now().UnixNano(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", "RouterVPN-SpeedLab/1")
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("latency probe returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2))
	if err != nil {
		return 0, err
	}
	if len(body) != 1 {
		return 0, fmt.Errorf("latency probe returned %d bytes; expected 1", len(body))
	}
	return float64(time.Since(started).Microseconds()) / 1000.0, nil
}

func computeSpeedLabLatencyStats(values []float64, failed int) (speedLabLatencyStats, error) {
	if len(values) == 0 {
		return speedLabLatencyStats{}, errors.New("no latency probes succeeded")
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mean := average(sorted)
	variance := 0.0
	for _, value := range sorted {
		delta := value - mean
		variance += delta * delta
	}
	variance /= float64(len(sorted))
	return speedLabLatencyStats{
		Samples: len(sorted), Failed: failed,
		MinMs: round3(sorted[0]), MedianMs: round3(percentile(sorted, 0.50)),
		AverageMs: round3(mean), P90Ms: round3(percentile(sorted, 0.90)), MaxMs: round3(sorted[len(sorted)-1]),
		JitterMs: round3(math.Sqrt(variance)),
	}, nil
}

func measureSpeedLabIdleLatency(ctx context.Context) (speedLabLatencyStats, error) {
	client := newSpeedLabHTTPClient(3 * time.Second)
	if transport, ok := client.Transport.(*http.Transport); ok {
		defer transport.CloseIdleConnections()
	}
	values := make([]float64, 0, 10)
	failed := 0
	for i := 0; i < 10; i++ {
		value, err := speedLabProbeOnce(ctx, client)
		if err != nil {
			failed++
		} else {
			values = append(values, value)
		}
		if i != 9 {
			select {
			case <-ctx.Done():
				return speedLabLatencyStats{}, ctx.Err()
			case <-time.After(60 * time.Millisecond):
			}
		}
	}
	if len(values) < 3 {
		return speedLabLatencyStats{}, errors.New("too few successful idle latency samples")
	}
	return computeSpeedLabLatencyStats(values, failed)
}

func speedLabLoadedLatencySampler(ctx context.Context) <-chan speedLabLatencyStats {
	result := make(chan speedLabLatencyStats, 1)
	go func() {
		defer close(result)
		client := newSpeedLabHTTPClient(2500 * time.Millisecond)
		if transport, ok := client.Transport.(*http.Transport); ok {
			defer transport.CloseIdleConnections()
		}
		values := make([]float64, 0, 64)
		failed := 0
		for {
			select {
			case <-ctx.Done():
				stats, _ := computeSpeedLabLatencyStats(values, failed)
				result <- stats
				return
			default:
			}
			value, err := speedLabProbeOnce(ctx, client)
			if err != nil {
				failed++
			} else {
				values = append(values, value)
			}
			select {
			case <-ctx.Done():
				stats, _ := computeSpeedLabLatencyStats(values, failed)
				result <- stats
				return
			case <-time.After(110 * time.Millisecond):
			}
		}
	}()
	return result
}

func speedLabStable(rates []float64) bool {
	if len(rates) < 3 {
		return false
	}
	last := rates[len(rates)-3:]
	minRate, maxRate, total := last[0], last[0], 0.0
	for _, rate := range last {
		if rate < minRate {
			minRate = rate
		}
		if rate > maxRate {
			maxRate = rate
		}
		total += rate
	}
	mean := total / float64(len(last))
	return mean > 0 && (maxRate-minRate)/mean <= 0.04
}

func speedLabRoundBytes(previousMbps float64) int64 {
	if previousMbps <= 0 {
		return 8 << 20
	}
	// Aim for roughly 700 ms of aggregate payload. Fast links can use up to
	// 64 MiB per round so a gigabit-class path is not dominated by setup time.
	value := int64(previousMbps * 1_000_000 / 8 * 0.70)
	if value < 1<<20 {
		value = 1 << 20
	}
	if value > 64<<20 {
		value = 64 << 20
	}
	return value
}

func speedLabStreamCount(previousMbps float64) int {
	switch {
	case previousMbps >= 250:
		return 4
	case previousMbps >= 80:
		return 2
	default:
		return 1
	}
}

func speedLabDownloadRound(ctx context.Context, client *http.Client, bytesCount int64) (int64, time.Duration, error) {
	url := speedLabDownloadURL + "?bytes=" + strconv.FormatInt(bytesCount, 10) + "&r=" + strconv.FormatInt(time.Now().UnixNano(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", "RouterVPN-SpeedLab/1")
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, 0, fmt.Errorf("download load returned HTTP %d", resp.StatusCode)
	}
	read, err := io.Copy(io.Discard, io.LimitReader(resp.Body, bytesCount+1))
	elapsed := time.Since(started)
	if err != nil {
		return read, elapsed, err
	}
	if read != bytesCount {
		return read, elapsed, fmt.Errorf("download load returned %d bytes; expected %d", read, bytesCount)
	}
	return read, elapsed, nil
}

func speedLabUploadRound(ctx context.Context, client *http.Client, bytesCount int64, pattern []byte) (int64, time.Duration, error) {
	reader := io.LimitReader(&speedLabPatternReader{pattern: pattern}, bytesCount)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, speedLabUploadURL, reader)
	if err != nil {
		return 0, 0, err
	}
	req.ContentLength = bytesCount
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", "RouterVPN-SpeedLab/1")
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	elapsed := time.Since(started)
	if resp.StatusCode/100 != 2 {
		return 0, elapsed, fmt.Errorf("upload load returned HTTP %d", resp.StatusCode)
	}
	return bytesCount, elapsed, nil
}

func speedLabParallelRound(ctx context.Context, direction string, client *http.Client, bytesCount int64, streams int, pattern []byte) (int64, time.Duration, error) {
	if streams < 1 {
		streams = 1
	}
	if streams > 4 {
		streams = 4
	}
	if bytesCount < int64(streams) {
		bytesCount = int64(streams)
	}
	roundCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan speedLabParallelResult, streams)
	base := bytesCount / int64(streams)
	remainder := bytesCount % int64(streams)
	started := time.Now()
	for i := 0; i < streams; i++ {
		part := base
		if int64(i) < remainder {
			part++
		}
		go func(size int64) {
			var done int64
			var err error
			if direction == "download" {
				done, _, err = speedLabDownloadRound(roundCtx, client, size)
			} else {
				done, _, err = speedLabUploadRound(roundCtx, client, size, pattern)
			}
			if err != nil {
				cancel()
			}
			results <- speedLabParallelResult{bytes: done, err: err}
		}(part)
	}
	total := int64(0)
	var firstErr error
	for i := 0; i < streams; i++ {
		result := <-results
		total += result.bytes
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
	}
	elapsed := time.Since(started)
	if firstErr != nil {
		return total, elapsed, firstErr
	}
	if total != bytesCount {
		return total, elapsed, fmt.Errorf("parallel %s load transferred %d bytes; expected %d", direction, total, bytesCount)
	}
	return total, elapsed, nil
}

func measureSpeedLabDirection(ctx context.Context, direction string, minDuration, maxDuration time.Duration, idleMedian float64) (speedLabDirectionResult, error) {
	if direction != "download" && direction != "upload" {
		return speedLabDirectionResult{}, errors.New("speed-test direction must be download or upload")
	}
	if minDuration <= 0 || maxDuration < minDuration {
		return speedLabDirectionResult{}, errors.New("invalid speed-test duration bounds")
	}

	directionCtx, cancelDirection := context.WithTimeout(ctx, maxDuration+8*time.Second)
	defer cancelDirection()
	loadedCtx, cancelLoaded := context.WithCancel(directionCtx)
	loadedDone := speedLabLoadedLatencySampler(loadedCtx)

	client := newSpeedLabHTTPClient(maxDuration + 8*time.Second)
	if transport, ok := client.Transport.(*http.Transport); ok {
		defer transport.CloseIdleConnections()
	}
	pattern := make([]byte, 64<<10)
	if _, err := rand.Read(pattern); err != nil {
		cancelLoaded()
		<-loadedDone
		return speedLabDirectionResult{}, fmt.Errorf("prepare upload pattern: %w", err)
	}

	started := time.Now()
	totalBytes := int64(0)
	totalWall := time.Duration(0)
	rates := make([]float64, 0, 16)
	stoppedStable := false
	maxStreamsUsed := 1
	for {
		elapsed := time.Since(started)
		if elapsed >= maxDuration {
			break
		}
		previous := 0.0
		if len(rates) > 0 {
			previous = rates[len(rates)-1]
		}
		bytesCount := speedLabRoundBytes(previous)
		streams := speedLabStreamCount(previous)
		if streams > maxStreamsUsed {
			maxStreamsUsed = streams
		}
		bytesDone, roundElapsed, err := speedLabParallelRound(directionCtx, direction, client, bytesCount, streams, pattern)
		if err != nil {
			cancelLoaded()
			<-loadedDone
			return speedLabDirectionResult{}, err
		}
		if roundElapsed <= 0 || bytesDone <= 0 {
			cancelLoaded()
			<-loadedDone
			return speedLabDirectionResult{}, errors.New("speed-test load produced no measurable transfer")
		}
		totalBytes += bytesDone
		totalWall += roundElapsed
		rates = append(rates, float64(bytesDone*8)/1_000_000/roundElapsed.Seconds())
		if time.Since(started) >= minDuration && speedLabStable(rates) {
			stoppedStable = true
			break
		}
	}
	cancelLoaded()
	loaded := <-loadedDone
	if totalBytes == 0 || totalWall <= 0 {
		return speedLabDirectionResult{}, errors.New("speed-test completed without transferred bytes")
	}
	if loaded.Samples < 2 {
		return speedLabDirectionResult{}, errors.New("too few loaded-latency samples completed")
	}
	seconds := totalWall.Seconds()
	mbps := float64(totalBytes*8) / 1_000_000 / seconds
	return speedLabDirectionResult{
		Direction: direction, Mbps: round3(mbps), Bytes: totalBytes, Seconds: round3(time.Since(started).Seconds()), Rounds: len(rates),
		LoadedLatency: loaded, BufferbloatMs: round3(math.Max(0, loaded.MedianMs-idleMedian)), StoppedStable: stoppedStable,
		ProviderDetail: fmt.Sprintf("HTTPS transfer against Cloudflare's fixed speed test edge using adaptive 1-%d concurrent streams while independent 1-byte probes measure loaded latency", maxStreamsUsed),
	}, nil
}

func measureSpeedLab(ctx context.Context, duration speedLabDuration, minDuration, maxDuration time.Duration, validate func() error) (speedLabMeasurement, error) {
	started := time.Now().UTC()
	idle, err := measureSpeedLabIdleLatency(ctx)
	if err != nil {
		return speedLabMeasurement{}, err
	}
	if validate != nil {
		if err := validate(); err != nil {
			return speedLabMeasurement{}, err
		}
	}
	download, err := measureSpeedLabDirection(ctx, "download", minDuration, maxDuration, idle.MedianMs)
	if err != nil {
		return speedLabMeasurement{}, err
	}
	if validate != nil {
		if err := validate(); err != nil {
			return speedLabMeasurement{}, err
		}
	}
	upload, err := measureSpeedLabDirection(ctx, "upload", minDuration, maxDuration, idle.MedianMs)
	if err != nil {
		return speedLabMeasurement{}, err
	}
	if validate != nil {
		if err := validate(); err != nil {
			return speedLabMeasurement{}, err
		}
	}
	return speedLabMeasurement{
		Provider: "Cloudflare Speed Test edge (built-in Router VPN Speed Lab)",
		Duration: duration, Idle: idle, Download: download, Upload: upload,
		Started: started, Finished: time.Now().UTC(),
	}, nil
}
