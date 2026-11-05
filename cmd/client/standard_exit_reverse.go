package main

import "os/exec"

// A captured predecessor is a live capability retained before the old engine
// joins. It cannot be recovered from the protection journal or saved profile.
type standardReversePreparation interface {
	PrepareCommand() (*exec.Cmd, error)
	DiscardPlanning() error
	Bind(legacyStandardExitLaunch) error
}
