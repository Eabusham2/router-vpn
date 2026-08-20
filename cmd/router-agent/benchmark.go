package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	benchmarkDefaultBytes int64 = 8 << 20
	benchmarkMaxBytes     int64 = 16 << 20
	benchmarkChunkBytes         = 64 << 10
)

func registerBenchmarkRoutes(h *http.ServeMux, s *server) {
	h.HandleFunc("/api/benchmark/download", s.benchmarkDownload)
	h.HandleFunc("/api/benchmark/upload", s.benchmarkUpload)
	registerClientForwardingMasterRoute(h, s)
}

func benchmarkRequestedBytes(r *http.Request) (int64, error) {
	value := benchmarkDefaultBytes
	if raw := r.URL.Query().Get("bytes"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil { return 0, errors.New("bytes must be an integer") }
		value = n
	}
	if value < 64<<10 || value > benchmarkMaxBytes {
		return 0, errors.New("benchmark bytes must be between 65536 and 16777216")
	}
	return value, nil
}

func (s *server) benchmarkDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	peer, err := s.authorized(r)
	if err != nil { http.Error(w, err.Error(), http.StatusForbidden); return }
	size, err := benchmarkRequestedBytes(r)
	if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }

	w.Header().Set("content-type", "application/octet-stream")
	w.Header().Set("cache-control", "no-store, no-transform")
	w.Header().Set("content-encoding", "identity")
	w.Header().Set("x-routervpn-benchmark", "download-v1")
	w.Header().Set("x-routervpn-benchmark-bytes", strconv.FormatInt(size, 10))
	w.Header().Set("x-routervpn-peer", peer.String())
	w.Header().Set("content-length", strconv.FormatInt(size, 10))

	buf := make([]byte, benchmarkChunkBytes)
	remaining := size
	for remaining > 0 {
		n := int64(len(buf)); if n > remaining { n = remaining }
		if _, err := rand.Read(buf[:n]); err != nil { return }
		if _, err := w.Write(buf[:n]); err != nil { return }
		remaining -= n
	}
}

func (s *server) benchmarkUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	peer, err := s.authorized(r)
	if err != nil { http.Error(w, err.Error(), http.StatusForbidden); return }
	if r.ContentLength > benchmarkMaxBytes {
		http.Error(w, "benchmark upload exceeds 16777216 bytes", http.StatusRequestEntityTooLarge)
		return
	}

	started := time.Now()
	limited := http.MaxBytesReader(w, r.Body, benchmarkMaxBytes)
	n, err := io.Copy(io.Discard, limited)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) { http.Error(w, "benchmark upload exceeds 16777216 bytes", http.StatusRequestEntityTooLarge); return }
		http.Error(w, "benchmark upload read failed", http.StatusBadRequest)
		return
	}
	if n < 64<<10 { http.Error(w, "benchmark upload must contain at least 65536 bytes", http.StatusBadRequest); return }
	elapsed := time.Since(started)

	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true,
		"direction": "upload",
		"bytes": n,
		"server_receive_ms": float64(elapsed.Microseconds()) / 1000.0,
		"peer": peer.String(),
		"proof": "authenticated tunnel-peer private throughput sink",
	})
}
