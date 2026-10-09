package hopmeasure

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func awaitSampling(t *testing.T, ch <-chan loadedSampling) loadedSampling {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("sampler did not cancel/drain")
	}
	return loadedSampling{}
}
func TestLoadedSamplingRequiresPayloadAndNeverIncludesLateProbe(t *testing.T) {
	for _, end := range []string{"no-payload", "payload-ended", "cancelled", "probe-failed"} {
		t.Run(end, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := newTransferActivity()
			var calls atomic.Int64
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan loadedSampling, 1)
			go func() {
				done <- sampleUnderLoad(ctx, a, func(context.Context) (float64, error) {
					calls.Add(1)
					close(entered)
					<-release
					if end == "probe-failed" {
						return 0, errors.New("actual route failed")
					}
					return 17.5, nil
				})
			}()
			if end == "no-payload" {
				// A sample arriving during connection/header setup is not a loaded sample.
				select {
				case <-entered:
					t.Fatal("probe began before payload")
				case <-time.After(75 * time.Millisecond):
				}
				a.finish()
				got := awaitSampling(t, done)
				if calls.Load() != 0 || len(got.values) != 0 || got.failed {
					t.Fatal("idle time counted as throughput load")
				}
				return
			}
			a.begin()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("sampler did not probe active transfer")
			}
			switch end {
			case "payload-ended":
				a.finish()
			case "cancelled":
				cancel()
			}
			close(release)
			got := awaitSampling(t, done)
			if len(got.values) != 0 {
				t.Fatal("completed, cancelled or failed probe produced a value")
			}
			if (end == "probe-failed") != got.failed {
				t.Fatal("failed active probe confused with completed transfer")
			}
		})
	}
}
func TestPayloadWindowDoesNotInventBytesOrWaitForUploadAcknowledgement(t *testing.T) {
	download := newTransferActivity()
	r := &activityReader{Reader: strings.NewReader("payload"), activity: download, remaining: 7, finishOnBytes: true}
	b := make([]byte, 3)
	if n, e := r.Read(b); n != 3 || e != nil || string(b) != "pay" || !download.running() {
		t.Fatal("first real payload was not retained")
	}
	if n, e := io.Copy(io.Discard, r); n != 4 || e != nil || download.running() {
		t.Fatal("last byte did not close load window")
	}
	upload := newTransferActivity()
	w := &activityReader{Reader: strings.NewReader("upload"), activity: upload}
	if _, e := io.Copy(io.Discard, w); e != nil || !upload.running() {
		t.Fatal("upload must remain active until socket write completes")
	}
	// This event is invoked by httptrace.WroteRequest in requestWithActivity.
	upload.finish()
	if upload.running() {
		t.Fatal("waiting for acknowledgement must not count as payload load")
	}
	upload.begin()
	upload.finish()
	if upload.running() {
		t.Fatal("completed load window reopened")
	}
	empty := newTransferActivity()
	_, _ = (&activityReader{Reader: strings.NewReader(""), activity: empty, finishOnBytes: true}).Read(b)
	if empty.running() {
		t.Fatal("empty response invented an active payload")
	}
}
func TestLoadedSamplingCollectsActualValueOnlyWithinActiveWindow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newTransferActivity()
	a.begin()
	var calls atomic.Int64
	done := make(chan loadedSampling, 1)
	go func() {
		done <- sampleUnderLoad(ctx, a, func(context.Context) (float64, error) {
			if calls.Add(1) == 2 {
				a.finish()
			}
			return 9.25, nil
		})
	}()
	got := awaitSampling(t, done)
	if len(got.values) != 1 || got.values[0] != 9.25 || got.failed {
		t.Fatal("did not retain exactly the first completed active-window sample", got)
	}
}
