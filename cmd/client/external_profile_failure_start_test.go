//go:build go1.25

package main

import (
	"context"
	"errors"
	"net/http"
	"os/exec"
	"testing"
	"testing/synctest"
)

func TestExternalStartFailurePreservesReplacementHistory(t *testing.T) {
	for _, replacementKind := range []string{"command", "operation", "tracker", "retained-owner", "legacy-owner"} {
		t.Run(replacementKind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopWindowsExternalFixture(t, "always")
				a := f.base.a
				originalTracker := sessionTrackerFor(a)
				var originalOperation context.Context
				replacement := exec.Command("replacement-before-start-return")
				foreignLaunch := &desktopNodeLaunch{command: replacement}
				f.onAdmit = func(*desktopWindowsExternalChild) error {
					a.mu.Lock()
					originalOperation = a.connectionContext
					switch replacementKind {
					case "command":
						a.cmd = replacement
					case "operation":
						a.connectionContext = context.Background()
					case "tracker":
						sessionTrackers.Store(a, &sessionTracker{a: a})
					case "retained-owner":
						desktopExternalRetainedLaunches.Store(a, foreignLaunch)
					case "legacy-owner":
						desktopNodeOwners.Store(a, foreignLaunch)
					}
					a.mu.Unlock()
					if replacementKind == "command" || replacementKind == "tracker" {
						sessionTrackerFor(a).declareRequest("wg", "wireguard")
					}
					return errors.New("original child admission failed")
				}
				t.Cleanup(func() {
					if len(f.children) > 0 {
						a.mu.Lock()
						a.cmd = f.children[0].launch.command
						a.state.RouterID = f.children[0].launch.profileID
						a.connectionContext = originalOperation
						a.mu.Unlock()
						desktopExternalRetainedLaunches.Store(a, f.children[0].launch)
						desktopNodeOwners.Delete(a)
						sessionTrackers.Store(a, originalTracker)
					}
				})
				response := externalFailureConnect(t, f)
				history := sessionTrackerFor(a).snapshot(0)
				if response.Code == http.StatusOK || len(f.children) != 1 {
					t.Fatal("Start failure was not reached", response.Code, response.Body.String())
				}
				if replacementKind == "command" && a.cmd != replacement {
					t.Fatal("failed Start adopted replacement command")
				}
				if history.Error != nil || history.EndedAt != nil {
					t.Fatal("failed Start or deferred cleanup adopted replacement history", response.Code, response.Body.String(), history)
				}
				if (replacementKind == "command" || replacementKind == "tracker") && history.RequestedMode != "wg" {
					t.Fatal("failed Start replaced the requested replacement mode", history)
				}
			})
		})
	}
}

func TestExternalStartFailureStillRecordsOriginalHistory(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopWindowsExternalFixture(t, policy)
				f.onAdmit = func(*desktopWindowsExternalChild) error {
					return errors.New("original child admission failed")
				}
				response := externalFailureConnect(t, f)
				history := sessionTrackerFor(f.base.a).snapshot(0)
				if response.Code != http.StatusInternalServerError || history.RequestedMode != "external-node" ||
					history.Error == nil || history.Error.Message != "original child admission failed" || history.Phase != "failed" || history.EndedAt == nil {
					t.Fatal("original owned Start error was hidden", response.Code, response.Body.String(), history)
				}
			})
		})
	}
}
