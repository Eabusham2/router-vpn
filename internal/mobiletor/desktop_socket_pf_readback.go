package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Failure observations contain only bounded numeric progress. They retain the
// original error through Unwrap and never become native authorization or a
// cached result. Zero-state checks were never received by a worker; state 1
// was cancelled before entry; state 2 is running; state 3 returned.
type desktopPFCheckTiming struct {
	state      uint8
	queue, run time.Duration
}

type desktopPFReadbackFailure struct {
	cause   error
	elapsed time.Duration
	checks  []desktopPFCheckTiming
}

func (e *desktopPFReadbackFailure) Unwrap() error { return e.cause }
func (e *desktopPFReadbackFailure) Error() string {
	var out strings.Builder
	fmt.Fprintf(&out, "Darwin PF readback elapsed_us=%d checks=%d", e.elapsed.Microseconds(), len(e.checks))
	for index, check := range e.checks {
		fmt.Fprintf(&out, " [check=%d state=%d queue_us=%d run_us=%d]", index, check.state, check.queue.Microseconds(), check.run.Microseconds())
	}
	fmt.Fprintf(&out, ": %v", e.cause)
	return out.String()
}

// The caller's existing context starts before grant's native socket/interface
// checks. Record its remaining budget at PF entry, without replacing it or
// creating a new deadline. Phases: 0=validation, 1=pre, 2=load, 3=post, 4=freshness.
type desktopPFGrantProgress struct {
	started   time.Time
	deadline  bool
	remaining time.Duration
	phase     uint8
	durations [3]time.Duration
}

func desktopPFStartGrant(ctx context.Context) desktopPFGrantProgress {
	progress := desktopPFGrantProgress{started: time.Now()}
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			progress.deadline = true
			progress.remaining = deadline.Sub(progress.started)
		}
	}
	return progress
}

func (p *desktopPFGrantProgress) run(phase uint8, operation func() error) error {
	p.phase = phase
	started := time.Now()
	defer func() { p.durations[phase-1] = time.Since(started) }()
	return operation()
}

type desktopPFGrantFailure struct {
	cause    error
	progress desktopPFGrantProgress
	elapsed  time.Duration
}

func (p *desktopPFGrantProgress) failure(cause error) error {
	if cause == nil {
		return nil
	}
	return &desktopPFGrantFailure{cause: cause, progress: *p, elapsed: time.Since(p.started)}
}
func (e *desktopPFGrantFailure) Unwrap() error { return e.cause }
func (e *desktopPFGrantFailure) Error() string {
	p := e.progress
	return fmt.Sprintf("Darwin PF grant phase=%d deadline=%t entry_remaining_us=%d elapsed_us=%d pre_us=%d load_us=%d post_us=%d: %v",
		p.phase, p.deadline, p.remaining.Microseconds(), e.elapsed.Microseconds(), p.durations[0].Microseconds(), p.durations[1].Microseconds(), p.durations[2].Microseconds(), e.cause)
}

type desktopPFChildrenProgress struct {
	listed                                                   bool
	children, child, verified, command, attempted, completed int
}

type desktopPFChildrenFailure struct {
	cause    error
	progress desktopPFChildrenProgress
}

func (p *desktopPFChildrenProgress) failure(cause error) error {
	if cause == nil {
		return nil
	}
	return &desktopPFChildrenFailure{cause: cause, progress: *p}
}
func (e *desktopPFChildrenFailure) Unwrap() error { return e.cause }
func (e *desktopPFChildrenFailure) Error() string {
	p := e.progress
	return fmt.Sprintf("Darwin PF system-child progress listed=%t children=%d child=%d verified=%d command=%d attempted=%d completed=%d: %v",
		p.listed, p.children, p.child, p.verified, p.command, p.attempted, p.completed, e.cause)
}

// The six global inspections and four captured-owner inspections share one
// bounded group. Nesting a global group or serializing the owner inspections
// would either exceed that worker bound or spend the original proof deadline
// on avoidable subprocess startup. Every check must complete and join before
// this invocation can authorize its caller; no proof is retained here.
func desktopPFCompleteReadback(ctx context.Context, global [6]func(context.Context) error,
	physical, baseline, pointer, generation func(context.Context) error) error {
	checks := append(global[:], physical, baseline, pointer, generation)
	return desktopPFReadback(ctx, checks...)
}

// Each check is read-only and captures the same native proof deadline. A fixed
// worker bound avoids paying every subprocess startup serially while retaining
// every validation. No readback survives this invocation or authorizes a write.
// Returning waits for every admitted check, including cancellation cleanup.
func desktopPFReadback(ctx context.Context, checks ...func(context.Context) error) (failure error) {
	if ctx == nil || len(checks) == 0 || len(checks) > 32 {
		return errors.New("Darwin PF readback requires a bounded captured inspection")
	}
	for _, check := range checks {
		if check == nil {
			return errors.New("Darwin PF readback has an absent inspection")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	started := time.Now()
	timings := make([]desktopPFCheckTiming, len(checks))
	var timingMu sync.Mutex
	observe := func(index int, timing desktopPFCheckTiming) {
		timingMu.Lock()
		timings[index] = timing
		timingMu.Unlock()
	}
	defer func() {
		if failure != nil {
			timingMu.Lock()
			captured := append([]desktopPFCheckTiming(nil), timings...)
			timingMu.Unlock()
			failure = &desktopPFReadbackFailure{cause: failure, elapsed: time.Since(started), checks: captured}
		}
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make([]error, len(checks))
	next := make(chan int)
	var joined sync.WaitGroup
	for range min(4, len(checks)) {
		joined.Add(1)
		go func() {
			// Preserve the pinned WaitGroup.Go ordering on the module's Go 1.24:
			// a fatal worker panic must not unblock a successful readback.
			defer func() {
				if failure := recover(); failure != nil {
					panic(failure)
				}
				joined.Done()
			}()
			for index := range next {
				entered := time.Now()
				timing := desktopPFCheckTiming{state: 1, queue: entered.Sub(started)}
				if err := ctx.Err(); err != nil {
					observe(index, timing)
					results[index] = err
					continue
				}
				timing.state = 2
				observe(index, timing)
				err := checks[index](ctx)
				timing.state, timing.run = 3, time.Since(entered)
				observe(index, timing)
				if err == nil {
					err = ctx.Err()
				}
				results[index] = err
				if err != nil {
					cancel()
				}
			}
		}()
	}
schedule:
	for index := range checks {
		select {
		case next <- index:
		case <-ctx.Done():
			break schedule
		}
	}
	close(next)
	joined.Wait()
	return errors.Join(ctx.Err(), errors.Join(results...))
}
