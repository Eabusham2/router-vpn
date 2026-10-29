package mobiletor

import (
	"context"
	"errors"
	"time"
)

// Libinfo caches keyed UID results until Directory Services publishes its
// invalidation notification. Deletion does not itself prove that the system
// namespace has retired the identity. Keep checking the independent readback
// within the caller's existing deletion deadline; never flush a global cache
// or turn an unknown/occupied lookup into a successful retirement.
func desktopDarwinWaitForUIDAbsence(ctx context.Context, uid uint32, inspect func(uint32) (bool, error)) error {
	if ctx == nil || inspect == nil || uid < 0x40000000 || uid >= 0x80000000 {
		return errors.New("Darwin physical identity retirement has no valid captured lookup")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, errors.New("Darwin physical identity retirement has no independent absent readback"))
		}
		absent, err := inspect(uid)
		if err != nil {
			return errors.Join(err, errors.New("Darwin physical identity retirement native lookup failed"))
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(err, errors.New("Darwin physical identity retirement readback completed after its deadline"))
		}
		if absent {
			return nil
		}
		select {
		case <-ctx.Done():
		case <-tick.C:
		}
	}
}
