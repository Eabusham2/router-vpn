package mobiletor

import (
	"context"
	"errors"
	"sync"
)

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
func desktopPFReadback(ctx context.Context, checks ...func(context.Context) error) error {
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
				if err := ctx.Err(); err != nil {
					results[index] = err
					continue
				}
				err := checks[index](ctx)
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
