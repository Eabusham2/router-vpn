package mobiletor

import (
	"context"
	"errors"
)

// DesktopWindowsProtectionCommit describes one exact native write transaction.
// These copied comparison values confer no mutation or recovery authority. The
// native owner supplies them only after proving its old state and complete
// candidate under the same BFE write lock that will perform the commit.
type DesktopWindowsProtectionCommit struct {
	Action    string
	Previous  *DesktopWindowsProtectionTarget
	Candidate *DesktopWindowsProtectionTarget
}

func (change DesktopWindowsProtectionCommit) Validate() error {
	if change.Previous != nil {
		if err := change.Previous.Validate(); err != nil {
			return err
		}
	}
	if change.Candidate != nil {
		if err := change.Candidate.Validate(); err != nil {
			return err
		}
	}
	switch change.Action {
	case "successor":
		if change.Candidate == nil || change.Previous != nil && change.Previous.Capture == change.Candidate.Capture {
			return errors.New("Windows commit lost its distinct captured successor")
		}
	case "release", "off":
		if change.Previous == nil || change.Candidate != nil || change.Action == "release" && change.Previous.Policy != "on-connect" {
			return errors.New("Windows retirement commit lost its exact authorized target")
		}
	default:
		return errors.New("Windows protection commit has an unknown operation")
	}
	return nil
}

// DesktopWindowsProtectionCommitBarrier must acknowledge the exact durable
// intent before returning nil. It runs while the BFE write transaction is held:
// it must not re-enter BFE through another engine or call this owner's Close.
// A failed native commit may retry this same change; the callback must preserve
// its original operation/record identity rather than create a different intent.
// Success alone does not prove a kernel commit; joined native readback does.
type DesktopWindowsProtectionCommitBarrier func(context.Context, DesktopWindowsProtectionCommit) error

func cloneDesktopWindowsProtectionCommit(change DesktopWindowsProtectionCommit) DesktopWindowsProtectionCommit {
	if change.Previous != nil {
		previous := *change.Previous
		change.Previous = &previous
	}
	if change.Candidate != nil {
		candidate := *change.Candidate
		change.Candidate = &candidate
	}
	return change
}

func desktopWindowsCompleteProtectionCommit(ctx context.Context, barrier DesktopWindowsProtectionCommitBarrier, change DesktopWindowsProtectionCommit) error {
	if ctx == nil || ctx.Err() != nil || barrier == nil {
		return errors.New("Windows protection commit has no live durable barrier")
	}
	if err := change.Validate(); err != nil {
		return err
	}
	// Do not expose the native owner's retained expectation to caller mutation.
	err := barrier(ctx, cloneDesktopWindowsProtectionCommit(change))
	return errors.Join(err, ctx.Err())
}
