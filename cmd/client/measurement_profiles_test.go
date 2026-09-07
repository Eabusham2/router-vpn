package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestMeasurementObserversTrackBothHopProfiles(t *testing.T) {
	for _, observer := range []string{"async", "connection", "routed"} {
		for _, hop := range []int{0, 1} {
			for _, change := range []string{"credential", "policy", "removed"} {
				t.Run(observer+"/"+[]string{"entry", "exit"}[hop]+"/"+change, func(t *testing.T) {
					a, p, session := asyncPathFixture(t, "http://10.77.0.1:8787")
					var ctx context.Context
					var stop func()
					var validate func() error
					var err error
					switch observer {
					case "async":
						ctx, stop, validate, err = asyncMeasurementPathContext(context.Background(), a, p, a.state, session, asyncMeasurementProfileToken(p))
					case "connection":
						ctx, stop, validate, err = connectionTelemetryPathContext(context.Background(), a, p, a.state, session.ID)
					case "routed":
						graph, _ := getActiveMultihopGraph(a)
						ctx, stop, validate, err = routedSpeedPathContext(context.Background(), a, a.state, graph, session.ID, p)
					}
					if err != nil {
						t.Fatal(err)
					}
					defer stop()
					a.mu.Lock()
					switch change {
					case "credential":
						a.profiles.Profiles[hop].APIToken = "rotated-private-credential"
					case "policy":
						a.profiles.Profiles[hop].IPv6Mode = "off"
					case "removed":
						a.profiles.Profiles = append(a.profiles.Profiles[:hop], a.profiles.Profiles[hop+1:]...)
					}
					a.mu.Unlock()
					if err := validate(); err == nil || strings.Contains(err.Error(), "rotated-private-credential") {
						t.Fatalf("stale profile accepted or secret exposed: %v", err)
					}
					select {
					case <-ctx.Done():
						if context.Cause(ctx) == nil {
							t.Fatal("missing path-change cause")
						}
					case <-time.After(time.Second):
						t.Fatal("stale path observer did not cancel network work")
					}
					if !a.state.Connected {
						t.Fatal("measurement cleanup disconnected VPN")
					}
				})
			}
		}
	}
}

func TestMeasurementProfileCaptureRejectsStaleOrForeignSnapshots(t *testing.T) {
	a, p, session := asyncPathFixture(t, "http://10.77.0.1:8787")
	graph, _ := getActiveMultihopGraph(a)
	foreign := p
	foreign.ID = "unrelated"
	if _, err := captureMeasurementProfiles(a, a.state, graph, foreign); err == nil {
		t.Fatal("foreign node accepted into proof ownership")
	}
	entry := a.profiles.Profiles[0]
	a.profiles.Profiles[0].APIToken = "replacement"
	_, stop, _, err := connectionTelemetryPathContext(context.Background(), a, p, a.state, session.ID, entry)
	if stop != nil {
		stop()
	}
	if err == nil {
		t.Fatal("captured stale entry accepted before its first RTT request")
	}
	if err := validateMeasurementProfiles(a, nil); err == nil {
		t.Fatal("missing captured profiles accepted")
	}
}

func TestMeasurementProfileCaptureIgnoresSelectionAndResults(t *testing.T) {
	a, p, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	graph, _ := getActiveMultihopGraph(a)
	tokens, err := captureMeasurementProfiles(a, a.state, graph, p)
	if err != nil {
		t.Fatal(err)
	}
	a.profiles.SelectedID = "exit"
	for i := range a.profiles.Profiles {
		x := &a.profiles.Profiles[i]
		x.Name = "display-only rename"
		x.PublicIP = "203.0.113.20"
		x.LatencyMedianMs = 12
		x.FastestDNSHost = "1.1.1.1"
		x.DNSResults = []common.DNSBenchmarkResult{{Address: "1.1.1.1", LatencyMs: 1}}
	}
	if err := validateMeasurementProfiles(a, tokens); err != nil {
		t.Fatalf("unrelated telemetry made active path stale: %v", err)
	}
}
