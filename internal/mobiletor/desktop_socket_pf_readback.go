package mobiletor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type desktopPFCommandBudgetKey struct{}

// Nested read-only groups share this invocation's original four native
// command slots. A parent inspection does not occupy a slot while waiting for
// its children; only an admitted command holds one, through its actual join.
func desktopPFWithCommandBudget(ctx context.Context) context.Context {
	if ctx.Value(desktopPFCommandBudgetKey{}) == nil {
		return context.WithValue(ctx, desktopPFCommandBudgetKey{}, make(chan struct{}, 4))
	}
	return ctx
}

func desktopPFEnterCommand(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	budget, _ := ctx.Value(desktopPFCommandBudgetKey{}).(chan struct{})
	if budget == nil {
		return func() {}, nil
	}
	select {
	case budget <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-budget
			return nil, err
		}
		return func() { <-budget }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

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
// bounded group. Independent queries within an inspection may form a nested
// group, sharing the same four native-command slots. Every check must complete
// and join before this invocation can authorize its caller; no proof is
// retained here.
func desktopPFCompleteReadback(ctx context.Context, global [6]func(context.Context) error,
	physical, baseline, pointer, generation func(context.Context) error) error {
	checks := append(global[:], physical, baseline, pointer, generation)
	return desktopPFReadback(ctx, checks...)
}

// The dry-run parser consumes captured rule text independently of the live
// anchor read. Neither changes the rules. Both share the enclosing command
// budget and must join before this generation can authorize a change.
func desktopPFVerifyGeneration(ctx context.Context, read, canonical func(context.Context) (string, error)) error {
	var actual, expected string
	err := desktopPFReadback(ctx, func(captured context.Context) error {
		var err error
		actual, err = read(captured)
		return err
	}, func(captured context.Context) error {
		var err error
		expected, err = canonical(captured)
		return err
	})
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("Darwin physical permits differ from their complete captured tuples")
	}
	return ctx.Err()
}

// A heartbeat proves both the complete firewall and its original disabled
// account. These independent reads share the same captured deadline and four
// native-command slots, including nested PF checks. Serial account inspection
// must not start a fresh two-second budget after the PF inspection has spent
// the caller's entire two-second response lifetime. Both reads must join.
func desktopPFProbeReadback(ctx context.Context, firewall, account func(context.Context) error) error {
	return desktopPFReadback(ctx, firewall, account)
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
	ctx = desktopPFWithCommandBudget(ctx)
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

// Diagnostic only: compare already captured rule text after exact readback has
// refused it. Quoted labels/paths are represented by length and digest, never
// copied to the error. Each structural excerpt is bounded independently.
func desktopPFRuleDifference(expected, actual string) error {
	if expected == actual {
		return nil
	}
	expectedLines, actualLines := strings.Split(expected, "\n"), strings.Split(actual, "\n")
	line := 0
	for line < len(expectedLines) && line < len(actualLines) && expectedLines[line] == actualLines[line] {
		line++
	}
	structural := func(lines []string) string {
		if line >= len(lines) {
			return "<absent>"
		}
		source := lines[line]
		var out strings.Builder
		for len(source) != 0 && out.Len() < 240 {
			if source[0] == '"' {
				// A backslash quotes the next byte, including another backslash.
				// Never treat an escaped quote as the end of a captured label.
				end := 1
				for end < len(source) && source[end] != '"' {
					if source[end] == '\\' {
						end++
					}
					end++
				}
				if end >= len(source) {
					out.WriteString("<unclosed-quoted>")
					break
				}
				value := source[1:end]
				digest := sha256.Sum256([]byte(value))
				fmt.Fprintf(&out, "<quoted:%d:%x>", len(value), digest[:4])
				source = source[end+1:]
			} else {
				out.WriteByte(source[0])
				source = source[1:]
			}
		}
		result := out.String()
		if len(result) > 240 {
			result = result[:240]
		}
		if source != "" {
			result += "<truncated>"
		}
		return result
	}
	return fmt.Errorf("Darwin PF rule difference expected_bytes=%d actual_bytes=%d first_line=%d expected=%q actual=%q", len(expected), len(actual), line+1, structural(expectedLines), structural(actualLines))
}
