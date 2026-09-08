package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"router-vpn/internal/common"
)

const dnsBenchmarkWorkers = 4
const dnsBenchmarkTimeout = 40 * time.Second
const dnsBenchmarkProbeTimeout = 1250 * time.Millisecond

type dnsCandidate struct {
	Name    string
	Address string
}

type dnsProbeFunc func(context.Context, string, uint16) (time.Duration, error)

func dnsProbeContext(ctx context.Context, address string, qtype uint16) (time.Duration, error) {
	return common.ProbeDNSUDP(ctx, net.JoinHostPort(address, "53"), qtype, dnsBenchmarkProbeTimeout)
}

// Bound the entire request, not just each socket. Four workers keep the fixed
// catalog within the native clients' 45-second HTTP budget even when upstreams
// time out. Workers are joined before returning, including on cancellation.
func measureDNSCandidates(ctx context.Context, candidates []dnsCandidate, probe dnsProbeFunc) ([]common.DNSBenchmarkResult, error) {
	if ctx == nil || probe == nil || len(candidates) == 0 || len(candidates) > 128 {
		return nil, errors.New("DNS benchmark requires a bounded candidate catalog and probe")
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	results := make([]common.DNSBenchmarkResult, len(candidates))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for i := 0; i < min(dnsBenchmarkWorkers, len(candidates)); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				candidate := candidates[index]
				values := make([]float64, 0, 5)
				for _, qtype := range []uint16{1, 28, 1, 28, 1} {
					if ctx.Err() != nil {
						return
					}
					elapsed, err := probe(ctx, candidate.Address, qtype)
					if ctx.Err() != nil {
						return
					}
					if err == nil && elapsed > 0 {
						values = append(values, float64(elapsed)/float64(time.Millisecond))
					}
				}
				result := common.DNSBenchmarkResult{Name: candidate.Name, Address: candidate.Address, Family: "ipv4", Working: len(values) > 0}
				if ip := net.ParseIP(candidate.Address); ip != nil && ip.To4() == nil {
					result.Family = "ipv6"
				}
				if len(values) > 0 {
					sort.Float64s(values)
					median := values[len(values)/2]
					if len(values)%2 == 0 {
						median = (values[len(values)/2-1] + median) / 2
					}
					result.LatencyMs = mathRound3(median)
				}
				results[index] = result
			}
		}()
	}
feed:
	for index := range candidates {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	workers.Wait()
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	return results, nil
}

func measuredDNSWinner(results []common.DNSBenchmarkResult) common.DNSBenchmarkResult {
	var winner common.DNSBenchmarkResult
	for _, result := range results {
		if result.Working && (!winner.Working || result.LatencyMs < winner.LatencyMs) {
			winner = result
		}
	}
	// No response means no measured winner. Never manufacture a fallback IP
	// that a native client could persist as a measured Fastest result.
	return winner
}

func (s *server) serveDNSBenchmark(w http.ResponseWriter, r *http.Request, candidates []dnsCandidate, probe dnsProbeFunc) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if _, err := s.authorized(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if r.Context().Err() != nil {
		http.Error(w, "DNS benchmark was cancelled", http.StatusRequestTimeout)
		return
	}
	if !s.dnsMu.TryLock() {
		http.Error(w, "another DNS benchmark is already running", http.StatusConflict)
		return
	}
	defer s.dnsMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), dnsBenchmarkTimeout)
	defer cancel()
	results, err := measureDNSCandidates(ctx, candidates, probe)
	if err != nil {
		status := http.StatusBadGateway
		if r.Context().Err() != nil {
			status = http.StatusRequestTimeout
		} else if ctx.Err() != nil {
			status = http.StatusGatewayTimeout
		}
		http.Error(w, "DNS benchmark did not complete: "+err.Error(), status)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"policy": "fastest-public", "winner": measuredDNSWinner(results), "results": results,
		"tested_from": "home-vpn-node",
		"test": "five real DNS A/AAAA UDP queries; exact transaction/question and complete framing required; median of responsive samples shown; NXDOMAIN/NODATA prove responsiveness, not a usable address or client DNS enforcement",
	})
}
