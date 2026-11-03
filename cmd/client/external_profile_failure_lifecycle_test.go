//go:build go1.25

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"

	"router-vpn/internal/mobiletor"
)

func externalFailureConnect(t *testing.T, f *desktopWindowsExternalFixture) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(externalProfileConnectRequest{ProfileID: f.profiles["http-connect"].ID})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	f.base.a.externalProfileConnect(response, httptest.NewRequest(http.MethodPost, "/api/external-profile/connect", bytes.NewReader(body)))
	return response
}

func externalFailureDisconnect(a *app) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	a.disconnect(response, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil))
	return response
}

// Observe the real legacy release dispatch after a proved-empty native slot is
// removed. This helper does not model or establish native protection absence.
func externalFailureReleaseHelper(t *testing.T, a *app, status int) string {
	t.Helper()
	directory := a.cfg.ScriptsDir
	name, body := "kill-switch-platform.py", fmt.Sprintf("import pathlib,sys\nassert sys.argv[1:] == ['release']\nwith (pathlib.Path(__file__).parent / 'release-observed.txt').open('a') as f: f.write('release\\n')\nsys.exit(%d)\n", status)
	if runtime.GOOS == "windows" {
		directory = filepath.Join(filepath.Dir(directory), "client")
		name = "windows-kill-switch.ps1"
		body = fmt.Sprintf("param([string]$Action,[string]$Root)\nif ($Action -ne 'release') { exit 99 }\nAdd-Content -LiteralPath (Join-Path $PSScriptRoot 'release-observed.txt') -Value 'release'\nexit %d\n", status)
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "release-observed.txt")
}

// Reopening a completely released On-connect journal remains a native boundary
// in this model. The public handler and real recovery/slot machinery execute;
// no test directly inserts an application slot or a running owner.
func externalFailureReopenBackend(t *testing.T, f *desktopWindowsExternalFixture) {
	t.Helper()
	a := f.base.a
	backend := a.nodeProtection.backend
	empty := f.store.head
	prior := a.nodeConnectionHost.capture
	a.nodeConnectionHost.capture = func(a *app) (desktopOwnedNodePreparation, error) {
		capture, err := prior(a)
		capture.protectionBackend = func() (desktopNodeProtectionBackend, error) {
			backend.bootstrap = func(ctx context.Context, profiles string) (desktopNodeRecoveryBackend, error) {
				if ctx.Err() != nil || profiles != a.cfg.ProfilesFile || f.base.kernel.target != nil || f.store.head.Committed.Target != nil || f.store.head.Committed.Engine != nil {
					return desktopNodeRecoveryBackend{}, errors.New("reopen changed original empty controller")
				}
				return desktopNodeRecoveryBackend{controller: empty.Controller, current: capture.current,
					open: func(context.Context) (desktopNodeProtectionJournal, error) {
						return &desktopInitialJournalStore{absent: true}, nil
					},
					create: func(context.Context) (desktopNodeProtectionJournal, error) {
						f.store = &desktopNodeJournalFixtureStore{head: empty}
						return f.store, nil
					},
					begin: func(context.Context, desktopNodeProtectionJournal) (desktopNodeJournalRecovery, error) {
						return nil, errors.New("empty same-controller journal cannot recover another owner")
					},
				}, nil
			}
			return backend, nil
		}
		return capture, err
	}
}

func TestExternalFailedConnectLeavesJoinedIdentity(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		for _, next := range []string{"disconnect", "connect"} {
			t.Run(policy+"/"+next, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newDesktopWindowsExternalFixture(t, policy)
					externalFailureReopenBackend(t, f)
					f.proofFault = func(p *desktopExternalProof) { p.DNSProven = false }
					failed := externalFailureConnect(t, f)
					a := f.base.a
					if failed.Code != http.StatusBadGateway || len(f.children) != 1 || a.cmd != nil || a.state.Connected {
						t.Fatal("failed proof did not join its actual child", failed.Code, failed.Body.String())
					}
					if _, exists := desktopExternalRetainedLaunches.Load(a); exists {
						t.Fatal("failed child still has registry authority")
					}
					if a.state.Mode != "off" || a.state.LogicalMode != "" || a.state.RuntimeMode != "" || a.state.Base != "" || a.state.Phase != "failed" || a.state.LastError == "" {
						t.Fatal("failed request resurrected a retired runtime or lost diagnostics", a.state)
					}
					history := sessionTrackerFor(a).snapshot(0)
					if history.RequestedMode != "external-node" || history.RequestedBase != "auto" || history.Phase != "failed" || history.Error == nil || history.EndedAt == nil {
						t.Fatal("joined teardown erased requested failure history", history)
					}
					if (f.base.kernel.target != nil) != (policy == "always") || f.base.kernel.locked {
						t.Fatal("failed proof changed original policy outcome")
					}
					if next == "disconnect" {
						release := externalFailureReleaseHelper(t, a, 0)
						response := externalFailureDisconnect(a)
						if response.Code != http.StatusOK || a.state.Mode != "off" || a.state.Phase != "off" || a.state.LastError != "" {
							t.Fatal("Disconnect after joined failure failed", response.Code, response.Body.String())
						}
						if policy == "on-connect" {
							if body, err := os.ReadFile(release); err != nil || strings.Count(string(body), "release") != 1 {
								t.Fatal("explicit Disconnect skipped ordinary protection release", err, string(body))
							}
						}
						if (f.base.kernel.target != nil) != (policy == "always") || f.base.kernel.locked {
							t.Fatal("Disconnect changed retained Always policy")
						}
					} else {
						f.proofFault = nil
						launch := f.connect(t, "http-connect")
						if len(f.children) != 2 || launch == f.children[0].launch || !a.state.Connected {
							t.Fatal("new Connect reused the failed original child")
						}
					}
				})
			})
		}
	}
}

func TestExternalFailedConnectProtectionReleaseStillFailsClosed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopWindowsExternalFixture(t, "on-connect")
		f.proofFault = func(p *desktopExternalProof) { p.DNSProven = false }
		if response := externalFailureConnect(t, f); response.Code != http.StatusBadGateway {
			t.Fatal(response.Code, response.Body.String())
		}
		path := externalFailureReleaseHelper(t, f.base.a, 17)
		failed := externalFailureDisconnect(f.base.a)
		if failed.Code != http.StatusInternalServerError || strings.Contains(failed.Body.String(), "unknown mode") || f.base.a.state.Phase != "failed" {
			t.Fatal("nil command bypassed actual protection-release failure", failed.Code, failed.Body.String())
		}
		externalFailureReleaseHelper(t, f.base.a, 0)
		if retry := externalFailureDisconnect(f.base.a); retry.Code != http.StatusOK {
			t.Fatal("explicit release retry failed", retry.Code, retry.Body.String())
		}
		if body, err := os.ReadFile(path); err != nil || strings.Count(string(body), "release") != 2 {
			t.Fatal("release did not execute on both attempts", err, string(body))
		}
	})
}

func TestExternalFailedConnectCleanupRetainsExactRetry(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopWindowsExternalFixture(t, policy)
				f.proofFault = func(p *desktopExternalProof) { p.DNSProven = false }
				f.onAdmit = func(child *desktopWindowsExternalChild) error {
					child.mu.Lock()
					child.closeErr = errors.New("original child has not joined")
					child.mu.Unlock()
					return nil
				}
				failed := externalFailureConnect(t, f)
				if failed.Code != http.StatusInternalServerError || len(f.children) != 1 {
					t.Fatal("cleanup failure not reached", failed.Code, failed.Body.String())
				}
				a, child := f.base.a, f.children[0]
				launch := child.launch
				if owner, exists := desktopExternalRetainedLaunches.Load(a); !exists || owner != launch || a.cmd != launch.command || a.state.Mode != "external-node" || a.state.RuntimeMode != "external-http-connect" || a.state.Phase != "failed" || !strings.Contains(a.state.LastError, "runtime cleanup failed") {
					t.Fatal("partial cleanup lost original retry identity", a.state)
				}
				child.mu.Lock()
				child.closeErr = nil
				child.mu.Unlock()
				retry := externalFailureDisconnect(a)
				if retry.Code != http.StatusOK || a.cmd != nil || a.state.Mode != "off" || (f.base.kernel.target != nil) != (policy == "always") {
					t.Fatal("same original cleanup retry failed", retry.Code, retry.Body.String())
				}
			})
		})
	}
}

func TestExternalFailedConnectDoesNotAdoptReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopWindowsExternalFixture(t, "always")
		replacement := exec.Command("replacement-owner")
		f.onAdmit = func(*desktopWindowsExternalChild) error {
			f.base.a.mu.Lock()
			f.base.a.cmd = replacement
			f.base.a.state.Mode = "replacement-mode"
			f.base.a.state.RouterID = "replacement"
			f.base.a.mu.Unlock()
			return errors.New("replaced before proof")
		}
		response := externalFailureConnect(t, f)
		if response.Code == http.StatusOK || f.base.a.cmd != replacement || f.base.a.state.Mode != "replacement-mode" || f.base.a.state.RouterID != "replacement" {
			t.Fatal("old failed request changed replacement", response.Code, response.Body.String())
		}
		// Fixture cleanup alone restores the named original child to join its owner.
		f.base.a.mu.Lock()
		f.base.a.cmd = f.children[0].launch.command
		f.base.a.state.RouterID = f.children[0].launch.profileID
		f.base.a.mu.Unlock()
	})
}

type externalFailureReleaseFunc func(context.Context) error

func (f externalFailureReleaseFunc) Close(ctx context.Context) error { return f(ctx) }

func TestExternalFailedConnectDoesNotAdoptCleanupReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopWindowsExternalFixture(t, "on-connect")
		a := f.base.a
		f.proofFault = func(p *desktopExternalProof) { p.DNSProven = false }
		replacement := exec.Command("replacement-during-cleanup")
		original := a.nodeProtection.backend.releaseWithBarrier
		replaced := false
		a.nodeProtection.backend.releaseWithBarrier = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget, barrier mobiletor.DesktopWindowsProtectionCommitBarrier) (desktopNodeProtectionRelease, error) {
			owner, err := original(ctx, target, barrier)
			if err != nil {
				return owner, err
			}
			return externalFailureReleaseFunc(func(ctx context.Context) error {
				if err := owner.Close(ctx); err != nil {
					return err
				}
				if !replaced {
					replaced = true
					a.mu.Lock()
					a.cmd = replacement
					a.state.Mode = "replacement-mode"
					a.state.LogicalMode = "replacement-mode"
					a.state.RuntimeMode = "replacement-runtime"
					a.state.RouterID = "replacement"
					a.state.Phase = "replacement-proving"
					a.state.LastError = "replacement-owned-detail"
					a.mu.Unlock()
					sessionTrackerFor(a).declareRequest("wg", "wireguard")
				}
				return nil
			}), nil
		}
		response := externalFailureConnect(t, f)
		history := sessionTrackerFor(a).snapshot(0)
		if !replaced || response.Code != http.StatusConflict || a.cmd != replacement || a.state.Mode != "replacement-mode" || a.state.RuntimeMode != "replacement-runtime" || a.state.RouterID != "replacement" || a.state.Phase != "replacement-proving" || a.state.LastError != "replacement-owned-detail" || history.RequestedMode != "wg" || history.Error != nil || history.EndedAt != nil {
			t.Fatal("cleanup completion adopted replacement state or history", response.Code, response.Body.String(), a.state, history)
		}
		// Only test cleanup restores the original named child, never the handler.
		a.mu.Lock()
		a.cmd = f.children[0].launch.command
		a.state.RouterID = f.children[0].launch.profileID
		a.mu.Unlock()
	})
}
