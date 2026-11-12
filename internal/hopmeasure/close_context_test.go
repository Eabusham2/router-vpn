package hopmeasure

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMeasurementCloseContextBoundsMutexAdmission(t *testing.T) {
	service, _ := observedService(t)
	service.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	err := service.CloseContext(ctx)
	cancel()
	closed := service.closed
	service.mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) || closed {
		t.Fatal("close lost original admission deadline or mutated after timeout", err, closed)
	}
	if err := service.CloseContext(nil); err == nil {
		t.Fatal("nil caller admitted")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := service.CloseContext(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled caller admitted", err)
	}
	service.mu.Lock()
	closed = service.closed
	service.mu.Unlock()
	if closed {
		t.Fatal("invalid caller retired untouched service")
	}
	if err := service.CloseContext(context.Background()); err != nil {
		t.Fatal("original retry failed", err)
	}
}

func TestMeasurementCloseContextRetainsAdmissionAndWorkerUntilDrain(t *testing.T) {
	for _, phase := range []string{"admission", "worker"} {
		t.Run(phase, func(t *testing.T) {
			service, engine := observedService(t)
			entered, finish := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(finish) }) }
			defer unblock()
			var releases atomic.Int32
			engine.setBegin(func(ctx context.Context) (func(), error) {
				if phase == "admission" {
					close(entered)
					<-ctx.Done()
				}
				return func() {
					if phase == "admission" {
						<-finish
					}
					releases.Add(1)
				}, nil
			})
			started := make(chan error, 1)
			go func() {
				started <- service.startContext(context.Background(), strings.Repeat("e", 32), func(ctx context.Context) { close(entered); <-ctx.Done(); <-finish })
			}()
			receiveMeasurement(t, entered)
			if phase == "worker" {
				if err := receiveMeasurement(t, started); err != nil {
					t.Fatal(err)
				}
			}
			service.mu.Lock()
			original := service.done
			if phase == "admission" {
				original = service.pending.done
			}
			service.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
			err := service.CloseContext(ctx)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) || releases.Load() != 0 {
				t.Fatal("unfinished cleanup was acknowledged or released", err, releases.Load())
			}
			select {
			case <-original:
				t.Fatal("original drain channel closed before actual cleanup")
			default:
			}
			service.mu.Lock()
			retained := service.done
			if phase == "admission" && service.pending != nil {
				retained = service.pending.done
			}
			closed := service.closed
			service.mu.Unlock()
			if !closed || retained != original {
				t.Fatal("deadline discarded original cleanup authority")
			}
			if err := service.Start(strings.Repeat("f", 32), 65536); err == nil {
				t.Fatal("replacement admitted during pending close")
			}
			unblock()
			if phase == "admission" {
				if err := receiveMeasurement(t, started); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
			retry, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := service.CloseContext(retry); err != nil || releases.Load() != 1 {
				t.Fatal("original retry did not join exact scope", err, releases.Load())
			}
			if err := service.Close(); err != nil {
				t.Fatal("compatibility close lost completed original", err)
			}
		})
	}
}
