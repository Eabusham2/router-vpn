package hopmeasure

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// These are the same fixed HTTPS payload endpoints used by native Speed Lab.
// Only the captured native engine can resolve/dial the provider. A public
// benchmark is an explicitly labelled routed path, never a private node API.
const PublicHost = "speed.cloudflare.com"
const PublicAddress = PublicHost + ":443"

func (s *Service) provePublic(parent context.Context, h Hop) (float64, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	_, elapsed, err := s.publicRequest(ctx, h, 1, false, nil)
	if err != nil {
		return 0, err
	}
	return elapsed * 1000, nil
}

func (s *Service) transferPublic(parent context.Context, h Hop, size int, upload bool, idle *Latency) (*Transfer, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	activity := newTransferActivity()
	defer activity.finish()
	monitor, stop := context.WithCancel(ctx)
	defer stop()
	sampling := make(chan loadedSampling, 1)
	go func() {
		sampling <- sampleUnderLoad(monitor, activity, func(ctx context.Context) (float64, error) { return s.provePublic(ctx, h) })
	}()
	n, elapsed, err := s.publicRequest(ctx, h, size, upload, activity)
	activity.finish()
	stop()
	samples := <-sampling
	if err != nil || elapsed <= 0 || n != int64(size) {
		return nil, errors.New("incomplete routed public transfer")
	}
	if err = s.valid(ctx); err != nil {
		return nil, err
	}
	result := &Transfer{Bytes: n, Seconds: elapsed, Mbps: float64(n) * 8 / elapsed / 1e6}
	if len(samples.values) > 0 && !samples.failed {
		result.Loaded = distribution(samples.values)
		delta := result.Loaded.Average - idle.Average
		result.Bufferbloat = &delta
	} else {
		result.LoadedReason = "Transfer finished before a complete loaded sample, or loaded probe failed"
	}
	return result, nil
}

// Synchronous HTTP retains late native dials and closes, including cancellation.
// It creates no ambient proxy/resolver/redirect or detached transport worker.
// Timing begins at the HTTPS request after native DNS/TCP/TLS preparation, so
// an entry-path response does not include resolving the provider over the exit.
func (s *Service) publicRequest(ctx context.Context, h Hop, size int, upload bool, activity *transferActivity) (n int64, elapsed float64, failure error) {
	if size < 1 || size > MaxBytes || s.valid(ctx) != nil {
		return 0, 0, errors.New("invalid public measurement owner or size")
	}
	conn, err := s.engine.Dial(ctx, h.Tag, PublicAddress)
	if err != nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return 0, 0, errors.New("captured public measurement dial failed")
	}
	var once sync.Once
	var closeErr error
	closed := make(chan struct{})
	closeOwned := func() { once.Do(func() { closeErr = conn.Close(); close(closed) }) }
	stop := context.AfterFunc(ctx, closeOwned)
	defer func() {
		if !stop() {
			<-closed
		}
		closeOwned()
		if s.valid(ctx) != nil || closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && !errors.Is(closeErr, io.ErrClosedPipe) {
			n = 0
			elapsed = 0
			failure = errors.New("public measurement canceled or close did not finish cleanly")
		}
	}()
	deadline, ok := ctx.Deadline()
	if !ok || s.valid(ctx) != nil || conn.SetDeadline(deadline) != nil {
		return 0, 0, errors.New("public measurement requires a working deadline")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: PublicHost}
	if s.publicTLS != nil {
		config = s.publicTLS.Clone()
		config.ServerName = PublicHost
	}
	secure := tls.Client(conn, config)
	if secure.HandshakeContext(ctx) != nil || s.valid(ctx) != nil {
		return 0, 0, errors.New("public measurement TLS identity failed")
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return 0, 0, errors.New("public measurement nonce unavailable")
	}
	path := "/__down?bytes=" + strconv.Itoa(size) + "&routervpn=" + hex.EncodeToString(nonce[:])
	method := http.MethodGet
	var body io.Reader
	if upload {
		method = http.MethodPost
		path = "/__up?routervpn=" + hex.EncodeToString(nonce[:])
		body = io.LimitReader(rand.Reader, int64(size))
		if activity != nil {
			body = &activityReader{Reader: body, activity: activity}
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://"+PublicHost+path, body)
	if err != nil {
		return 0, 0, errors.New("public measurement request invalid")
	}
	request.Close = true
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-store, no-transform")
	request.Header.Set("User-Agent", "RouterVPN-SpeedLab/1")
	if upload {
		request.ContentLength = int64(size)
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	start := time.Now()
	if request.Write(secure) != nil {
		return 0, 0, errors.New("public payload write failed")
	}
	if upload && activity != nil {
		activity.finish()
	}
	// Bound raw headers, chunk framing and payload. Individual payload/ack
	// limits below are tighter; net/http never reads an unbounded header line.
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(secure, int64(size)*2+32*1024)), request)
	if err != nil {
		return 0, 0, errors.New("public measurement response invalid")
	}
	defer func() { closeOwned(); _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 || response.StatusCode == 206 ||
		response.Header.Get("Content-Range") != "" ||
		response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return 0, 0, errors.New("public measurement refused redirect, partial or compressed payload")
	}
	if upload {
		ack, e := io.ReadAll(io.LimitReader(response.Body, 8193))
		if e != nil || len(ack) > 8192 {
			return 0, 0, errors.New("public upload acknowledgement invalid")
		}
		// A successful TLS response follows a completely written request body.
		// This reports locally transferred bytes; it is not a private byte receipt.
		n = int64(size)
	} else {
		if response.ContentLength >= 0 && response.ContentLength != int64(size) {
			return 0, 0, errors.New("public download length differs")
		}
		reader := io.Reader(response.Body)
		if activity != nil {
			reader = &activityReader{Reader: reader, activity: activity, remaining: int64(size), finishOnBytes: true}
		}
		n, err = io.Copy(io.Discard, io.LimitReader(reader, int64(size)+1))
		if err != nil || n != int64(size) {
			return 0, 0, errors.New("public download payload differs")
		}
	}
	elapsed = time.Since(start).Seconds()
	if elapsed <= 0 || s.valid(ctx) != nil {
		return 0, 0, errors.New("public measurement owner changed")
	}
	return n, elapsed, nil
}
