package mobiletor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
)

// Every direct child is captured from this invocation's real kernel inventory.
// Independent children share the original deadline and four command slots;
// a slow reader in one child must not leave those slots idle for every sibling.
// No inventory, filter or translation result survives the joined invocation.
func desktopPFSystemChildReadback(ctx context.Context, namespace string, inventory []byte,
	rules func(context.Context, string) (string, error), translation func(context.Context, string) error) error {
	if ctx == nil || rules == nil || translation == nil || !desktopPFInventoryPath(namespace) ||
		!strings.HasPrefix(namespace, "com.apple/") || strings.Count(namespace, "/") != 1 {
		return errors.New("Darwin PF child readback has no captured namespace or readers")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	children, err := desktopPFInventoryChildren("com.apple", inventory)
	if err != nil {
		return err
	}
	var foreign []string
	for _, child := range children {
		if child != namespace {
			foreign = append(foreign, child)
		}
	}
	ctx = desktopPFWithCommandBudget(ctx)
	var verified atomic.Int32
	checks := make([]func(context.Context) error, len(foreign))
	for index, child := range foreign {
		checks[index] = func(captured context.Context) error {
			progress := desktopPFChildrenProgress{listed: true, children: len(foreign), child: index + 1, attempted: 1, completed: 1}
			var progressMu sync.Mutex
			observe := func(command int, completed bool) {
				progressMu.Lock()
				defer progressMu.Unlock()
				if completed {
					progress.completed++
				} else {
					progress.command = command
					progress.attempted++
				}
			}
			// A preceding nonempty filter, any stateful/unknown filter, or any
			// translation still refuses the complete original path. Both direct
			// and recursive reads join before this child's verdict is retained.
			err := desktopPFForeignBranches(captured, child, child < namespace, rules, translation, observe)
			if err == nil {
				verified.Add(1)
			}
			progress.verified = int(verified.Load())
			return progress.failure(err)
		}
	}
	// Keep the existing per-readback worker bound for larger inventories too.
	// A new batch retains the same caller deadline and native command budget.
	for start := 0; start < len(checks); start += 32 {
		if err := desktopPFReadback(ctx, checks[start:min(start+32, len(checks))]...); err != nil {
			return err
		}
	}
	return ctx.Err()
}
