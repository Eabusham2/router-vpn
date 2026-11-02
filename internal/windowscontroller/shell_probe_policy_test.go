package windowscontroller

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

// This is fixture evidence only, never a process-launch capability. Native
// success still requires the separate retained child, image, token and thread
// proofs. Only the one fully observed no-creation failure is classifiable here.
type fixtureShellProbeObservation struct {
	calls                         int
	succeeded                     bool
	rawError                      error
	instance, rawProcess          uint64
	returnedProcess               bool
	callbackCount                 int32
	callbackBefore, callbackAfter uint32
	callbackResult                uint32
	callbackDenied                bool
	callerCancelled               bool
	imageBefore, imageAfter       bool
	proofError, closeError        error
	launchError                   error
}

// errors.Is alone would accept a joined file-not-found and cleanup/ownership
// error. The native wrapper may add context or a single-child errors.Join;
// every leaf must remain the one exact native failure, within a fixed bound.
func fixtureShellOnlyFileNotFound(err error) bool {
	for depth := 0; depth < 8 && err != nil; depth++ {
		if errno, ok := err.(syscall.Errno); ok {
			return errno == 2 // ERROR_FILE_NOT_FOUND / SE_ERR_FNF.
		}
		switch wrapped := err.(type) {
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			if len(children) != 1 {
				return false
			}
			err = children[0]
		case interface{ Unwrap() error }:
			err = wrapped.Unwrap()
		default:
			return false
		}
	}
	return false
}

func fixtureGlobalRootUnavailable(observed fixtureShellProbeObservation) bool {
	errno, nativeError := observed.rawError.(syscall.Errno)
	return observed.calls == 1 && !observed.succeeded && nativeError && errno == 2 && observed.instance == 2 &&
		observed.rawProcess == 0 && !observed.returnedProcess && observed.callbackCount == 0 &&
		observed.callbackBefore == 0 && observed.callbackAfter == 0 && observed.callbackResult == 0x8000ffff &&
		!observed.callbackDenied && !observed.callerCancelled && observed.imageBefore && observed.imageAfter &&
		observed.proofError == nil && observed.closeError == nil && fixtureShellOnlyFileNotFound(observed.launchError)
}

func fixtureGlobalRootUnavailableObservation() fixtureShellProbeObservation {
	return fixtureShellProbeObservation{
		calls: 1, rawError: syscall.Errno(2), instance: 2, callbackResult: 0x8000ffff,
		imageBefore: true, imageAfter: true,
		launchError: errors.Join(fmt.Errorf("native administrator launch: %w", syscall.Errno(2))),
	}
}

func TestFixtureGlobalRootUnavailableRequiresExactNoCreation(t *testing.T) {
	for _, scenario := range []struct {
		name string
		edit func(*fixtureShellProbeObservation)
	}{
		{"exact-unavailable", func(*fixtureShellProbeObservation) {}},
		{"no-native-call", func(o *fixtureShellProbeObservation) { o.calls = 0 }},
		{"repeated-native-call", func(o *fixtureShellProbeObservation) { o.calls = 2 }},
		{"native-success", func(o *fixtureShellProbeObservation) { o.succeeded = true }},
		{"missing-native-error", func(o *fixtureShellProbeObservation) { o.rawError = nil }},
		{"different-native-error", func(o *fixtureShellProbeObservation) { o.rawError = syscall.Errno(3) }},
		{"wrapped-raw-error", func(o *fixtureShellProbeObservation) { o.rawError = fmt.Errorf("wrapped: %w", syscall.Errno(2)) }},
		{"joined-raw-error", func(o *fixtureShellProbeObservation) {
			o.rawError = errors.Join(syscall.Errno(2), errors.New("close failed"))
		}},
		{"zero-instance", func(o *fixtureShellProbeObservation) { o.instance = 0 }},
		{"different-instance", func(o *fixtureShellProbeObservation) { o.instance = 3 }},
		{"successful-instance", func(o *fixtureShellProbeObservation) { o.instance = 33 }},
		{"raw-child", func(o *fixtureShellProbeObservation) { o.rawProcess = 1 }},
		{"invalid-raw-child", func(o *fixtureShellProbeObservation) { o.rawProcess = ^uint64(0) }},
		{"returned-owner", func(o *fixtureShellProbeObservation) { o.returnedProcess = true }},
		{"creation-callback", func(o *fixtureShellProbeObservation) { o.callbackCount = 1 }},
		{"invalid-callback-count", func(o *fixtureShellProbeObservation) { o.callbackCount = -1 }},
		{"callback-before", func(o *fixtureShellProbeObservation) { o.callbackBefore = 4 }},
		{"callback-after", func(o *fixtureShellProbeObservation) { o.callbackAfter = 4 }},
		{"callback-success", func(o *fixtureShellProbeObservation) { o.callbackResult = 0 }},
		{"callback-denied", func(o *fixtureShellProbeObservation) { o.callbackDenied = true }},
		{"cancelled-caller", func(o *fixtureShellProbeObservation) { o.callerCancelled = true }},
		{"missing-before-proof", func(o *fixtureShellProbeObservation) { o.imageBefore = false }},
		{"missing-after-proof", func(o *fixtureShellProbeObservation) { o.imageAfter = false }},
		{"independent-proof-failure", func(o *fixtureShellProbeObservation) { o.proofError = errors.New("image changed") }},
		{"independent-close-failure", func(o *fixtureShellProbeObservation) { o.closeError = errors.New("close failed") }},
		{"missing-launch-error", func(o *fixtureShellProbeObservation) { o.launchError = nil }},
		{"different-launch-error", func(o *fixtureShellProbeObservation) { o.launchError = syscall.Errno(5) }},
		{"launch-error-text", func(o *fixtureShellProbeObservation) {
			o.launchError = errors.New("The system cannot find the file specified.")
		}},
		{"mixed-launch-error", func(o *fixtureShellProbeObservation) {
			o.launchError = errors.Join(o.launchError, errors.New("invalid process handle"))
		}},
		{"duplicated-launch-error", func(o *fixtureShellProbeObservation) { o.launchError = errors.Join(o.launchError, syscall.Errno(2)) }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			observed := fixtureGlobalRootUnavailableObservation()
			scenario.edit(&observed)
			if got, want := fixtureGlobalRootUnavailable(observed), scenario.name == "exact-unavailable"; got != want {
				t.Fatalf("GLOBALROOT capability classification accepted a mixed or unproved observation: got=%t want=%t", got, want)
			}
		})
	}
}

type fixtureShellErrorCycle struct{}

func (fixtureShellErrorCycle) Error() string   { return "cyclic fixture error" }
func (e fixtureShellErrorCycle) Unwrap() error { return e }

func TestFixtureGlobalRootErrorChainIsBounded(t *testing.T) {
	var deep error = syscall.Errno(2)
	for index := 0; index < 9; index++ {
		deep = fmt.Errorf("level %d: %w", index, deep)
	}
	for _, scenario := range []struct {
		name string
		err  error
		want bool
	}{
		{"exact", syscall.Errno(2), true},
		{"native-wrapper", fmt.Errorf("administrator launch: %w", syscall.Errno(2)), true},
		{"single-join", errors.Join(fmt.Errorf("native: %w", syscall.Errno(2))), true},
		{"mixed", errors.Join(syscall.Errno(2), errors.New("close failed")), false},
		{"deep", deep, false},
		{"cycle", fixtureShellErrorCycle{}, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if got := fixtureShellOnlyFileNotFound(scenario.err); got != scenario.want {
				t.Fatalf("GLOBALROOT error chain escaped its exact single-leaf bound: got=%t want=%t", got, scenario.want)
			}
		})
	}
}
