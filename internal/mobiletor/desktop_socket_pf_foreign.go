package mobiletor

import (
	"context"
	"errors"
	"strings"
)

func desktopDarwinPFStatelessFilters(rules string) error {
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "}" || strings.HasPrefix(line, "anchor ") || strings.HasPrefix(line, "block ") {
			continue
		}
		if !strings.HasPrefix(line, "pass ") || !strings.Contains(line, " no state") || strings.Contains(line, " keep state") || strings.Contains(line, " modulate state") || strings.Contains(line, " synproxy state") {
			return errors.New("Darwin protected physical path intersects a foreign stateful or unknown filter")
		}
	}
	return nil
}

func desktopPFNoTranslationText(raw []byte) error {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "}" || strings.HasPrefix(line, "nat-anchor ") || strings.HasPrefix(line, "rdr-anchor ") || strings.HasPrefix(line, "binat-anchor ") {
			continue
		}
		return errors.New("Darwin physical protection intersects an active foreign translation rule")
	}
	return nil
}

// Direct and recursive filters and translations are independent observations.
// Retain every original refusal, caller deadline and entered-command join while
// allowing idle slots in the invocation's existing four-command budget to run
// these queries. No result is cached or used to modify a foreign owner.
func desktopPFForeignBranches(ctx context.Context, root string, earlier bool,
	rules func(context.Context, string) (string, error), translation func(context.Context, string) error,
	observe func(int, bool)) error {
	if !desktopPFInventoryPath(root) || rules == nil || translation == nil {
		return errors.New("Darwin PF foreign inspection has no captured reader or anchor")
	}
	var checks []func(context.Context) error
	for branch, anchor := range []string{root, root + "/*"} {
		checks = append(checks, func(captured context.Context) error {
			if observe != nil {
				observe(2+2*branch, false)
			}
			actual, err := rules(captured, anchor)
			if err == nil && observe != nil {
				observe(2+2*branch, true)
			}
			if err != nil || earlier && actual != "" {
				return errors.Join(err, errors.New("Darwin PF dispatch has an unreadable or earlier nonempty filter owner"))
			}
			return desktopDarwinPFStatelessFilters(actual)
		}, func(captured context.Context) error {
			if observe != nil {
				observe(3+2*branch, false)
			}
			err := translation(captured, anchor)
			if err == nil && observe != nil {
				observe(3+2*branch, true)
			}
			return err
		})
	}
	return desktopPFReadback(ctx, checks...)
}
