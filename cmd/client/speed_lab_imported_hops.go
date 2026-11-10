package main

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"time"

	"router-vpn/internal/common"
)

type speedLabImportedHopRuntime struct {
	client func(string, time.Duration) (*http.Client, func(), error)
	prove  func(context.Context, common.RouterProfile, string) error
}

// Imported nodes do not own a Router API or benchmark token. Measure actual
// public HTTPS transfers through the reserved entry lane, with its original
// public exit proof before/after. These values describe the entry-routed path
// to the public benchmark endpoint, never ICMP RTT or a private node benchmark.
func measureSpeedLabImportedEntryHop(ctx context.Context, profile common.RouterProfile, validate func(context.Context) error) (speedLabHopMeasurement, error) {
	return measureSpeedLabImportedEntryHopWithRuntime(ctx, profile, validate, speedLabImportedHopRuntime{})
}

func measureSpeedLabImportedEntryHopWithRuntime(ctx context.Context, profile common.RouterProfile, validate func(context.Context) error, driver speedLabImportedHopRuntime) (speedLabHopMeasurement, error) {
	if ctx == nil || validate == nil || profile.NodeKind != "external" || profile.External == nil || !desktopImportedEntryProtocol(profile.External.Protocol) {
		return speedLabHopMeasurement{}, errors.New("imported hop measurement requires the original captured entry and owner")
	}
	if driver.client == nil {
		driver.client = newMultihopLaneHTTPClient
	}
	if driver.prove == nil {
		driver.prove = proveNativeMultihopLaneContext
	}
	current := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return validate(ctx)
	}
	proof := func() error {
		if err := current(); err != nil {
			return err
		}
		if err := driver.prove(ctx, profile, multihopEntryProofProxy); err != nil {
			return err
		}
		return current()
	}
	if err := proof(); err != nil {
		return speedLabHopMeasurement{}, err
	}
	client, closeIdle, err := driver.client(multihopEntryProofProxy, 30*time.Second)
	if err != nil {
		return speedLabHopMeasurement{}, err
	}
	defer closeIdle()
	hop := speedLabHopMeasurement{Role: "entry", RouterID: profile.ID, Name: profile.Name,
		LatencyLabel: "Entry-routed HTTP response", SpeedLabel: "Entry-routed HTTPS transfer"}
	values, failed := make([]float64, 0, 4), 0
	for i := 0; i < 4; i++ {
		if err := current(); err != nil {
			return speedLabHopMeasurement{}, err
		}
		value, probeErr := speedLabProbeOnce(ctx, client)
		if err := current(); err != nil {
			return speedLabHopMeasurement{}, err
		}
		if probeErr != nil {
			failed++
		} else {
			values = append(values, value)
		}
	}
	stats, latencyErr := computeSpeedLabLatencyStats(values, failed)
	if latencyErr != nil {
		hop.LatencyError = latencyErr.Error()
	} else {
		hop.Latency = &connectionLatencyResult{Connected: true, Mode: "multihop", RouterID: profile.ID, Name: profile.Name,
			Samples: stats.Samples, Failed: stats.Failed, MinMs: stats.MinMs, MedianMs: stats.MedianMs, AverageMs: stats.AverageMs,
			P90Ms: stats.P90Ms, MaxMs: stats.MaxMs, MeasuredAt: time.Now().UTC(),
			Proof: "HTTPS response time from the public Speed Lab endpoint through the original imported entry lane; not a private node or ICMP measurement"}
	}
	if err := proof(); err != nil {
		return speedLabHopMeasurement{}, err
	}
	const bytesCount int64 = 8 << 20
	pattern := make([]byte, 64<<10)
	if _, err := rand.Read(pattern); err != nil {
		return speedLabHopMeasurement{}, err
	}
	downBytes, downTime, downErr := speedLabDownloadRound(ctx, client, bytesCount)
	if err := current(); err != nil {
		return speedLabHopMeasurement{}, err
	}
	upBytes, upTime, upErr := speedLabUploadRound(ctx, client, bytesCount, pattern)
	if err := proof(); err != nil {
		return speedLabHopMeasurement{}, err
	}
	if downErr != nil || upErr != nil {
		hop.SpeedError = errors.Join(downErr, upErr).Error()
	} else if downBytes != bytesCount || upBytes != bytesCount || downTime <= 0 || upTime <= 0 {
		hop.SpeedError = "imported entry transfer did not retain exact byte counts and elapsed time"
	} else {
		hop.Speed = &routedSpeedResult{RouterID: profile.ID, Name: profile.Name, Bytes: bytesCount,
			DownloadMbps: round3(float64(downBytes) * 8 / 1_000_000 / downTime.Seconds()),
			UploadMbps:   round3(float64(upBytes) * 8 / 1_000_000 / upTime.Seconds()),
			DownloadMs:   roundMeasuredMilliseconds(float64(downTime) / float64(time.Millisecond)), UploadMs: roundMeasuredMilliseconds(float64(upTime) / float64(time.Millisecond)),
			MeasuredAt: time.Now().UTC(),
			Proof:      "independent byte-counted HTTPS transfer through the original imported entry lane to the public Speed Lab endpoint; public exit identity proved before and after load"}
	}
	if hop.Latency == nil && hop.Speed == nil {
		return speedLabHopMeasurement{}, errors.New("imported entry lane returned no valid response-time or transfer measurement")
	}
	return hop, nil
}
