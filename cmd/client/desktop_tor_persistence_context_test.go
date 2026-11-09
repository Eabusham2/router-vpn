package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestDesktopTorChoiceCallerKeepsBothOriginalLifetimes(t *testing.T) {
	for _, boundary := range []string{"operation", "intent", "short-operation", "short-intent", "no-intent"} {
		t.Run(boundary, func(t *testing.T) {
			operationLimit, intentLimit := time.Second, time.Second
			if boundary == "short-operation" {
				operationLimit = 20 * time.Millisecond
			}
			if boundary == "short-intent" {
				intentLimit = 20 * time.Millisecond
			}
			operation, cancelOperation := context.WithTimeout(context.Background(), operationLimit)
			defer cancelOperation()
			intent, cancelIntent := context.WithTimeout(context.WithValue(context.Background(), desktopTorComparisonCallerKey{}, "original-choice"), intentLimit)
			defer cancelIntent()
			if boundary == "no-intent" {
				intent = nil
			}
			ctx, finish, err := desktopTorChoiceCaller(operation, intent)
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			deadline, ok := ctx.Deadline()
			operationDeadline, _ := operation.Deadline()
			if !ok || deadline.After(operationDeadline) {
				t.Fatal("choice renewed its original connection deadline")
			}
			if intent != nil {
				intentDeadline, _ := intent.Deadline()
				if deadline.After(intentDeadline) || ctx.Value(desktopTorComparisonCallerKey{}) != "original-choice" {
					t.Fatal("choice detached its original intent")
				}
			}
			switch boundary {
			case "operation":
				cancelOperation()
			case "intent":
				cancelIntent()
			case "no-intent":
				finish()
				if operation.Err() != nil || ctx != operation {
					t.Fatal("finishing this admission cancelled its original connection")
				}
				return
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("choice reader survived cancellation of its original owner")
			}
		})
	}
}

type desktopTorChoiceCallerFixture struct {
	a         *app
	launch    *desktopNodeLaunch
	selection *desktopTorSelection
	request   externalProfileConnectRequest
	operation context.Context
	cancel    context.CancelFunc
	ip        string
}

// Retain the actual private files and joined child of the native proof fixture.
// Its network identity and public-exit receipt are controlled fixture evidence;
// this exercises durable host admission, not physical Tor circuit acceptance.
func newDesktopTorChoiceCallerFixture(t *testing.T) desktopTorChoiceCallerFixture {
	t.Helper()
	a, launch, _ := desktopTorRunningFixture(t, "proof")
	parent, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	proof, err := a.waitDesktopTorProof(parent, launch)
	if err != nil {
		t.Fatal(err)
	}
	operation, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a.connectionContext = operation
	a.cfg.ProfilesFile = filepath.Join(t.TempDir(), "profiles.json")
	a.cfg.StateFile = filepath.Join(t.TempDir(), "startup.json")
	a.state.LogicalMode, a.state.Base = "external-node", "tor"
	profile := cloneRouterProfile(a.profiles.Profiles[0])
	policy := cloneRouterProfile(profile)
	policy.MultihopEnabled, policy.MultihopExecution = false, "local"
	policy.MultihopEntryID, policy.MultihopExitID, policy.MultihopEntryMode = "", "", ""
	selection := &desktopTorSelection{profile: profile, policy: policy, preference: "local", profileToken: desktopTorSourceIdentityToken(profile)}
	direct := true
	request := externalProfileConnectRequest{ProfileID: profile.ID, Execution: "local", Direct: &direct}
	if err := a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	return desktopTorChoiceCallerFixture{a, launch, selection, request, operation, cancel, proof.Proof.IP}
}

func (f desktopTorChoiceCallerFixture) commit() (*desktopTorChoiceAdoption, error) {
	return f.a.commitDesktopTorChoice(f.selection, f.launch, f.request, nil, f.operation, f.selection.profile.ID, f.ip)
}

func TestDesktopTorChoiceSaveAndAdoptKeepHeldOwnerDeadline(t *testing.T) {
	for _, phase := range []string{"save", "adopt"} {
		for _, boundary := range []string{"app", "proof", "native"} {
			t.Run(phase+"/"+boundary, func(t *testing.T) {
				f := newDesktopTorChoiceCallerFixture(t)
				var saved *desktopTorChoiceAdoption
				if phase == "adopt" {
					var err error
					saved, err = f.commit()
					if err != nil {
						t.Fatal("original private choice did not commit", err)
					}
				}
				before, err := os.ReadFile(f.a.cfg.ProfilesFile)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				f.selection.adoption = ctx
				if saved != nil {
					saved.intent = ctx
				}
				var mutex *sync.Mutex
				switch boundary {
				case "app":
					mutex = &f.a.mu
				case "proof":
					mutex = &f.launch.tor.proofMu
				case "native":
					mutex = &f.launch.tor.mu
				}
				release := measurementHeldLock(mutex)
				defer release()
				done := make(chan error, 1)
				go func() {
					if saved == nil {
						_, err := f.commit()
						done <- err
					} else {
						_, err := saved.adopt(f.a)
						done <- err
					}
				}()
				if err := measurementContextResult(t, done, release); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("durable choice waited beyond its original caller", err)
				}
				release()
				after, err := os.ReadFile(f.a.cfg.ProfilesFile)
				if err != nil || !bytes.Equal(before, after) || f.a.state.Connected || desktopNodeProcessExited(f.launch) {
					t.Fatal("expired admission changed disk, reported Connected, or discarded its native owner", err)
				}
				if _, err := os.Stat(f.a.cfg.StateFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("expired adoption wrote Startup Last", err)
				}
			})
		}
	}
}

func TestDesktopTorChoiceRecordedCancelIntentPrecedesContextDelivery(t *testing.T) {
	for _, phase := range []string{"save", "adopt"} {
		t.Run(phase, func(t *testing.T) {
			f := newDesktopTorChoiceCallerFixture(t)
			var saved *desktopTorChoiceAdoption
			if phase == "adopt" {
				var err error
				saved, err = f.commit()
				if err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(f.a.cfg.ProfilesFile)
			entered, deliver, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
			f.a.mu.Lock()
			f.a.connectionCancel = func() {
				close(entered)
				<-deliver
				f.cancel()
			}
			f.a.mu.Unlock()
			go func() { defer close(joined); f.a.cancelConnectionOperation() }()
			defer func() {
				close(deliver)
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("original Disconnect did not join after cancellation delivery")
				}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("real Disconnect did not record its intent before cancellation delivery")
			}
			// Keep the real cancel callback paused after Disconnect records its
			// intent under app.mu, exposing the precise final-adoption interval.
			var err error
			if saved == nil {
				_, err = f.commit()
			} else {
				_, err = saved.adopt(f.a)
			}
			after, readErr := os.ReadFile(f.a.cfg.ProfilesFile)
			if err == nil || f.operation.Err() != nil || readErr != nil || !bytes.Equal(before, after) || f.a.state.Connected {
				t.Fatal("recorded original cancellation lost the interval before context delivery", err, readErr)
			}
		})
	}
}

func TestDesktopTorChoiceProfilesKeepFinalRenameAdmission(t *testing.T) {
	for _, boundary := range []string{"live", "cancelled-before-work", "cancelled-before-rename"} {
		t.Run(boundary, func(t *testing.T) {
			a := &app{profiles: common.RouterProfileStore{SelectedID: "tor", Profiles: []common.RouterProfile{{ID: "tor"}}}}
			a.cfg.ProfilesFile = filepath.Join(t.TempDir(), "profiles.json")
			if err := a.persistDesktopTorChoiceProfilesContext(context.Background(), func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(a.cfg.ProfilesFile)
			identity, err := os.Stat(a.cfg.ProfilesFile)
			if err != nil || !os.SameFile(identity, identity) {
				t.Fatal("original file identity was not captured", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if boundary == "cancelled-before-work" {
				cancel()
			}
			a.profiles.Profiles[0].UseCount++
			checks := 0
			current := func() error {
				checks++
				if boundary == "cancelled-before-rename" && checks == 3 {
					temporary, err := filepath.Glob(filepath.Join(filepath.Dir(a.cfg.ProfilesFile), ".profiles.json.tmp-*"))
					if err != nil || len(temporary) != 1 {
						t.Fatal("causal cancellation missed the actual prepared private file", err)
					}
					cancel()
				}
				return ctx.Err()
			}
			err = a.persistDesktopTorChoiceProfilesContext(ctx, current)
			after, readErr := os.ReadFile(a.cfg.ProfilesFile)
			published, statErr := os.Stat(a.cfg.ProfilesFile)
			if readErr != nil || statErr != nil {
				t.Fatal(readErr, statErr)
			}
			if boundary == "live" {
				if err != nil || bytes.Equal(before, after) || os.SameFile(identity, published) {
					t.Fatal("live caller could not publish its choice", err)
				}
			} else if !errors.Is(err, context.Canceled) || !bytes.Equal(before, after) || !os.SameFile(identity, published) {
				t.Fatal("cancelled final admission replaced the original file", err)
			}
			if boundary == "cancelled-before-rename" && checks != 3 {
				t.Fatal("final rename callback was not executed", checks)
			}
			entries, err := os.ReadDir(filepath.Dir(a.cfg.ProfilesFile))
			if err != nil || len(entries) != 1 || entries[0].Name() != "profiles.json" {
				t.Fatal("joined write retained a private temporary file", err)
			}
		})
	}
}

func TestDesktopTorChoiceStartupKeepsFinalCallerAndSavedChoice(t *testing.T) {
	for _, boundary := range []string{"live", "cancelled-before-rename"} {
		t.Run(boundary, func(t *testing.T) {
			f := newDesktopTorChoiceCallerFixture(t)
			saved, err := f.commit()
			if err != nil {
				t.Fatal("original private choice did not commit", err)
			}
			if err := f.a.saveStartupSelection(saved.startup); err != nil {
				t.Fatal(err)
			}
			profileBytes, _ := os.ReadFile(f.a.cfg.ProfilesFile)
			before, _ := os.ReadFile(f.a.cfg.StateFile)
			identity, err := os.Stat(f.a.cfg.StateFile)
			if err != nil || !os.SameFile(identity, identity) {
				t.Fatal("original Startup Last identity was not captured", err)
			}
			saved.startup.UpdatedAt = saved.startup.UpdatedAt.Add(time.Second)
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), desktopTorComparisonCallerKey{}, "original-startup"))
			defer cancel()
			original := f.launch.tor.networkIdentityContext
			defer func() { f.launch.tor.networkIdentityContext = original }()
			checks := 0
			f.launch.tor.networkIdentityContext = func(call context.Context) (string, error) {
				checks++
				if call != ctx {
					return "", errors.New("Startup Last changed its original observer caller")
				}
				if boundary == "cancelled-before-rename" && checks == 3 {
					temporary, err := filepath.Glob(filepath.Join(filepath.Dir(f.a.cfg.StateFile), ".startup.json.tmp-*"))
					if err != nil || len(temporary) != 1 {
						t.Fatal("startup cancellation missed its prepared temporary file", err)
					}
					cancel()
				}
				return f.launch.tor.network, call.Err()
			}
			f.a.mu.Lock()
			err = f.a.saveDesktopTorChoiceStartupContext(ctx, saved)
			f.a.mu.Unlock()
			f.launch.tor.networkIdentityContext = original
			after, _ := os.ReadFile(f.a.cfg.StateFile)
			published, statErr := os.Stat(f.a.cfg.StateFile)
			if statErr != nil || checks != 3 {
				t.Fatal("Startup Last missed its original final observer", checks, statErr)
			}
			if boundary == "live" {
				if err != nil || bytes.Equal(before, after) || os.SameFile(identity, published) {
					t.Fatal("live original Startup Last was not saved", err)
				}
				if _, err := saved.adopt(f.a); err != nil || !f.a.state.Connected {
					t.Fatal("live original saved choice could not adopt fresh native proof", err)
				}
			} else if !errors.Is(err, context.Canceled) || !bytes.Equal(before, after) || !os.SameFile(identity, published) || f.a.state.Connected {
				t.Fatal("cancelled Startup Last admission replaced durable state or reported Connected", err)
			}
			currentProfiles, _ := os.ReadFile(f.a.cfg.ProfilesFile)
			if !bytes.Equal(profileBytes, currentProfiles) || f.launch.tor.committedChoice.Load() != saved.choice {
				t.Fatal("later Startup Last admission claimed to roll back the saved choice")
			}
			entries, err := os.ReadDir(filepath.Dir(f.a.cfg.StateFile))
			if err != nil || len(entries) != 1 || entries[0].Name() != "startup.json" {
				t.Fatal("joined Startup Last write retained an unowned temporary file", err)
			}
		})
	}
}
