//go:build linux

package standardengine

import (
	"context"
	"errors"
	"time"
)

// RetireOriginal serializes cleanup of the already captured native owner. A
// failed attempt remains in this exact child and waits for a fresh request on
// its inherited object. It never creates a replacement owner or extends an
// issued request deadline. The caller must keep its original signal handler
// installed until this function returns.
func RetireOriginal(file *CleanupFile, expected string, deadline time.Time, startupFailed bool, retire func(context.Context) (string, error)) error {
	if file == nil || retire == nil || deadline.IsZero() || !digest(expected, 32) {
		return errors.New("original cleanup has no captured owner or budget")
	}
	attempt := CleanupRequest{Schema: 1, CaptureSHA256: expected, DeadlineNS: deadline.UnixNano()}
	var sequence uint64
	first := true
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := file.Current(); err != nil {
			return err
		}
		request, err := file.ReadRequest(expected)
		fresh := err == nil && request.Sequence > sequence
		if fresh {
			sequence, attempt = request.Sequence, request
		}
		if !first && !fresh {
			<-tick.C
			continue
		}
		first = false
		bound := time.Unix(0, attempt.DeadlineNS)
		limit := 15 * time.Second
		if attempt.Sequence == 0 {
			limit = 4 * time.Second
		}
		if time.Until(bound) > limit {
			return errors.New("original cleanup request exceeds its native bound")
		}
		began := time.Now()
		ctx, cancel := context.WithDeadline(context.Background(), bound)
		var ledger string
		failure := ctx.Err()
		if failure == nil {
			ledger, failure = retire(ctx)
			failure = errors.Join(failure, ctx.Err())
		}
		cancel()
		result := CleanupResult{Schema: 1, CaptureSHA256: expected, Sequence: attempt.Sequence,
			DeadlineNS: attempt.DeadlineNS, StartedNS: began.UnixNano(), Authority: "request", StartupFailed: startupFailed, Complete: failure == nil, Ledger: ledger}
		if attempt.Sequence == 0 {
			result.Authority = "signal"
			if startupFailed {
				result.Authority = "startup"
			}
		}
		if failure != nil {
			result.Error = "original native cleanup remains pending"
		}
		if err := file.WriteResult(result); err != nil {
			return err
		}
		if result.Complete {
			return nil
		}
	}
}
