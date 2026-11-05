package main

// A captured predecessor is a live capability retained before the old engine
// joins. It cannot be recovered from the protection journal or saved profile.
type standardReversePreparation interface {
	Bind(legacyStandardExitLaunch) error
}
