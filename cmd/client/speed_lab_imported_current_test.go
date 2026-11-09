package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/routechoice"
)

// Only physical-network observation and the already-running native child are
// modeled. The source compiler, original profile ownership, private DNS mailbox,
// and live MTU readback execute unchanged.
// Installed native traffic and physical transitions retain their separate gates.
func speedLabCurrentImportedSessionFixture(t *testing.T) (*desktopExecutionSession, *desktopNodeMTUFixture) {
	t.Helper()
	root, initial := desktopImportedFixture(t, "shadowsocks", "reality-vision")
	initial.Exit.MultihopExecution = "auto"
	initial.Control = cloneRouterProfile(initial.Exit)
	selection, err := captureNativeMultihopSelection(context.Background(), root, initial, []string{initial.ExitMode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", root)
	manifest := filepath.Join(root, "runtime", "native", "NATIVE-RUNTIME.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	launch, err := compileRetainedNativeMultihopLaunch(selection, nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(launch.config)
	launch.configSHA256, launch.mtuSession = hex.EncodeToString(digest[:]), strings.Repeat("4", 32)
	launch.command = &exec.Cmd{}
	if err := writeDesktopRuntimeFile(launch, "sing-box.json", launch.config, false); err != nil {
		t.Fatal(err)
	}
	a := &app{cmd: launch.command, cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "profiles.json")},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileSchemaVersion, SelectedID: selection.Control.ID, Profiles: []common.RouterProfile{cloneRouterProfile(selection.Entry), cloneRouterProfile(selection.Exit)}},
		state:    state{Connected: true, Phase: "connected", Mode: "multihop", LogicalMode: "multihop", RuntimeMode: selection.ExitMode, Base: "native", RouterID: selection.Exit.ID}}
	desktopNodeOwners.Store(a, launch)
	setActiveMultihopGraph(a, selection)
	graph, _ := getActiveMultihopGraph(a)
	const network = "modeled-original-physical-network"
	native := &nativeMultihopRuntime{launch: launch, selection: selection, graph: graph, network: network,
		networkIdentityContext: func(ctx context.Context) (string, error) { return network, ctx.Err() }}
	nativeMultihopOwners.Store(a, native)
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "original-imported-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: selection.Exit.ID}})
	f := &desktopNodeMTUFixture{launch: launch, base: desktopNodeMTURecord{Schema: 1, Session: launch.mtuSession, Config: launch.configSHA256, Path: strings.Repeat("d", 64), Reader: 3, Interface: "router-vpn", Index: 7, MTU: 1280}}
	if err := f.publish(f.base, false); err != nil {
		t.Fatal(err)
	}
	session := &desktopExecutionSession{driver: &desktopExecutionDriver{a: a, selection: selection, network: network}, selection: selection, command: launch.command, native: launch, generation: "original-current-imported",
		candidate: routechoice.Candidate{Execution: routechoice.Local, Transport: selection.ExitMode, EntryID: selection.Entry.ID, ExitID: selection.Exit.ID}}
	t.Cleanup(func() {
		sessionTrackers.Delete(a)
		nativeMultihopOwners.Delete(a)
		desktopNodeOwners.Delete(a)
		activeMultihopGraphs.Delete(a)
		_ = launch.directoryRoot.Close()
	})
	return session, f
}

func TestSpeedLabImportedCurrentRejectsReplacedOwnerBeforeObservation(t *testing.T) {
	for _, change := range []string{"missing", "same-command-same-graph", "missing-capture"} {
		t.Run(change, func(t *testing.T) {
			command := &exec.Cmd{}
			graph := activeMultihopGraph{EntryID: "imported", ExitID: "final", EntryMode: "shadowsocks", ExitMode: "reality-vision", ImportedEntry: true, SourceSHA: strings.Repeat("a", 64), Execution: "local"}
			original := &nativeMultihopRuntime{launch: &desktopNodeLaunch{command: command}, graph: graph, network: "original-network"}
			a := &app{cmd: command}
			identity := speedLabPathIdentity{Graph: graph, GraphOK: true, Command: command, Imported: original}
			switch change {
			case "same-command-same-graph":
				replacement := *original
				nativeMultihopOwners.Store(a, &replacement)
			case "missing-capture":
				nativeMultihopOwners.Store(a, original)
				identity.Imported = nil
			}
			t.Cleanup(func() { nativeMultihopOwners.Delete(a) })
			// This refusal must happen before any tracker, OS network inventory
			// or native mailbox observation can borrow a replacement's authority.
			err := validateSpeedLabIdentityContext(context.Background(), a, identity)
			if err == nil || !strings.Contains(err.Error(), "imported runtime owner changed") || a.cmd != command {
				t.Fatal("retired imported owner reached another observer or replaced the runtime", err)
			}
		})
	}
}

func TestSpeedLabImportedCurrentVerificationKeepsCallerAtHeldLocks(t *testing.T) {
	for _, held := range []string{"tracker", "app"} {
		t.Run(held, func(t *testing.T) {
			command := &exec.Cmd{}
			profile := common.RouterProfile{ID: "final", NodeKind: "router-vpn"}
			a := &app{cmd: command, profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}},
				state: state{Connected: true, Phase: "connected", Mode: "multihop", RouterID: profile.ID}}
			tracker := &sessionTracker{a: a, session: &connectionSession{ID: "original-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: profile.ID}}
			graph := activeMultihopGraph{EntryID: "imported", ExitID: profile.ID, ImportedEntry: true}
			owner := &nativeMultihopRuntime{launch: &desktopNodeLaunch{command: command}, graph: graph}
			identity := speedLabPathIdentity{Tracker: tracker, SessionID: tracker.session.ID, RouterID: profile.ID, Command: command, GraphOK: true, Graph: graph, Imported: owner}
			sessionTrackers.Store(a, tracker)
			nativeMultihopOwners.Store(a, owner)
			t.Cleanup(func() { sessionTrackers.Delete(a); nativeMultihopOwners.Delete(a) })
			locked := &tracker.mu
			if held == "app" {
				locked = &a.mu
			}
			locked.Lock()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- verifySpeedLabPath(ctx, a, identity) }()
			select {
			case err := <-done:
				locked.Unlock()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("Speed Lab verification lost its original caller deadline", err)
				}
			case <-time.After(time.Second):
				locked.Unlock()
				<-done
				t.Fatal("Speed Lab verification retained a background observation after its caller expired")
			}
		})
	}
}

func TestSpeedLabImportedCurrentReprovesNativeSelectedDNS(t *testing.T) {
	for _, fault := range []string{"success", "dns-failed", "native-owner"} {
		t.Run(fault, func(t *testing.T) {
			s, f := speedLabCurrentImportedSessionFixture(t)
			a := s.driver.a
			identity, _, err := captureSpeedLabIdentityContext(context.Background(), a)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			rounds := 1
			if fault == "success" {
				rounds = 2
			}
			for round := 0; round < rounds; round++ {
				done := make(chan error, 1)
				go func() {
					request, err := importedDesktopDNSReadRequest(ctx, f.launch)
					if err == nil {
						status := "passed"
						if fault == "dns-failed" {
							status = "failed"
						}
						if fault == "native-owner" {
							replacement := *identity.Imported
							nativeMultihopOwners.Store(a, &replacement)
						}
						err = f.publish(f.base, false)
						if err == nil {
							err = importedDesktopDNSReply(f.launch, request, status, f.base)
						}
					}
					done <- err
				}()
				err := verifySpeedLabPath(ctx, a, identity)
				if peerErr := <-done; peerErr != nil {
					t.Fatal("measurement phase omitted its native selected-DNS exchange", peerErr)
				}
				if (fault == "success") != (err == nil) {
					t.Fatal("measurement accepted failed DNS or a replacement runtime", fault, err)
				}
			}
			if fault == "success" && f.launch.importedDNSGeneration != 2 {
				t.Fatal("another measurement phase borrowed a cached DNS receipt")
			}
		})
	}
}

func TestSpeedLabImportedCurrentCancelledDNSJoinsOriginalMailbox(t *testing.T) {
	s, f := speedLabCurrentImportedSessionFixture(t)
	a := s.driver.a
	identity, _, err := captureSpeedLabIdentityContext(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- verifySpeedLabPath(ctx, a, identity) }()
	bound, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	request, err := importedDesktopDNSReadRequest(bound, f.launch)
	if err != nil {
		t.Fatal("measurement did not reach original DNS mailbox", err)
	}
	cancel()
	for {
		_, err := readDesktopRuntimeFile(f.launch, "node-dns-cancel.json", 4096)
		if err == nil {
			break
		}
		select {
		case <-bound.Done():
			t.Fatal("measurement cancellation did not reach original native query")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case err := <-done:
		t.Fatal("cancelled DNS query returned before the owned native request drained", err)
	default:
	}
	if err := importedDesktopDNSReply(f.launch, request, "cancelled", f.base); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled measurement lost its original caller", err)
		}
	case <-bound.Done():
		t.Fatal("measurement failed to join its native cancellation acknowledgment")
	}
	if _, err := readDesktopRuntimeFile(f.launch, "node-dns-cancel.json", 4096); !errors.Is(err, os.ErrNotExist) || a.cmd != identity.Command || f.launch.importedDNSGeneration != 1 {
		t.Fatal("old cancellation leaked into a replacement operation", err)
	}
}

func TestSpeedLabImportedCurrentNetworkObserverCannotDisappearOrChange(t *testing.T) {
	for _, fault := range []string{"missing", "network", "deadline"} {
		t.Run(fault, func(t *testing.T) {
			s, _ := speedLabCurrentImportedSessionFixture(t)
			a := s.driver.a
			identity, _, err := captureSpeedLabIdentityContext(context.Background(), a)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "missing":
				identity.Imported.networkIdentityContext = nil
			case "network":
				identity.Imported.networkIdentityContext = func(ctx context.Context) (string, error) { return "changed-network", ctx.Err() }
			case "deadline":
				identity.Imported.networkIdentityContext = func(ctx context.Context) (string, error) { <-ctx.Done(); return "", ctx.Err() }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			if err := validateSpeedLabIdentityContext(ctx, a, identity); err == nil || fault == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("captured physical observer lost its original source or caller", err)
			}
		})
	}
}
func TestSpeedLabImportedCurrentIdentityAndRestoreRetainOriginalOwner(t *testing.T) {
	s, f := speedLabCurrentImportedSessionFixture(t)
	a := s.driver.a
	a.state.Connected, a.state.Phase = true, "connected"
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "original-imported-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: s.selection.Exit.ID}})
	identity, _, err := captureSpeedLabIdentityContext(context.Background(), a)
	if err != nil || identity.Imported == nil || identity.Imported.selection.Native != s.selection.Native {
		t.Fatal("current imported path did not capture its retained owner", err)
	}
	snapshot := speedLabTemporarySnapshot{Profiles: cloneRouterProfileStore(a.profiles), State: a.state, Runtime: a.cmd}
	plan, err := a.speedLabCaptureRestorePlanContext(context.Background(), snapshot)
	if err != nil || plan.multihop == nil || plan.multihop.Native != s.selection.Native || plan.multihop.restoreMTU != f.base.MTU || plan.request.Execution != "local" || !reflect.DeepEqual(plan.multihop.Entry, s.selection.Entry) || !reflect.DeepEqual(plan.multihop.Exit, s.selection.Exit) {
		t.Fatal("restoration lost original imported source, live MTU or proved Local execution", err)
	}
	replacement := *identity.Imported
	nativeMultihopOwners.Store(a, &replacement)
	if err := validateSpeedLabIdentityContext(context.Background(), a, identity); err == nil {
		t.Fatal("same-command same-graph replacement inherited the captured Speed Lab identity")
	}
}
