package hopmeasure

import (
	"context"
	"io"
	"sync"
	"time"
)

// A loaded sample must start and finish during payload I/O. Connection setup,
// delayed headers and waiting for an upload acknowledgement are not load.
// Fast transfers truthfully retain the existing missing-sample explanation.
type transferActivity struct {
	started, ended     chan struct{}
	beginOnce, endOnce sync.Once
}

func newTransferActivity() *transferActivity {
	return &transferActivity{started: make(chan struct{}), ended: make(chan struct{})}
}
func (a *transferActivity) begin()  { a.beginOnce.Do(func() { close(a.started) }) }
func (a *transferActivity) finish() { a.endOnce.Do(func() { close(a.ended) }) }
func (a *transferActivity) running() bool {
	select {
	case <-a.ended:
		return false
	default:
	}
	select {
	case <-a.started:
		return true
	default:
		return false
	}
}

type activityReader struct {
	io.Reader
	activity      *transferActivity
	remaining     int64
	finishOnBytes bool
}

func (r *activityReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	if n > 0 {
		r.activity.begin()
	}
	if r.finishOnBytes {
		r.remaining -= int64(n)
		if r.remaining <= 0 || e != nil {
			r.activity.finish()
		}
	}
	return n, e
}

type loadedSampling struct {
	values []float64
	failed bool
}

func sampleUnderLoad(ctx context.Context, a *transferActivity, probe func(context.Context) (float64, error)) loadedSampling {
	r := loadedSampling{}
	select {
	case <-ctx.Done():
		return r
	case <-a.ended:
		return r
	case <-a.started:
	}
	for i := 0; i < 24; i++ {
		timer := time.NewTimer(60 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return r
		case <-a.ended:
			timer.Stop()
			return r
		case <-timer.C:
		}
		if !a.running() {
			return r
		}
		value, e := probe(ctx)
		if e != nil {
			if ctx.Err() == nil && a.running() {
				r.failed = true
			}
			return r
		}
		if ctx.Err() != nil || !a.running() {
			return r
		}
		r.values = append(r.values, value)
	}
	return r
}
