package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func expectedSpeedLabFixture(t *testing.T, topology string) (*app, speedLabRequest) {
	t.Helper()
	a := setupProfileTestApp(t)
	q := speedLabRequest{Scope: "temporary", Topology: topology, ExpectedSelectedNodeID: "home", ExpectedProfileTokens: map[string]string{}}
	ids := []string{"home"}
	switch topology {
	case "router":
		q.NodeID = "exit"
		ids = append(ids, q.NodeID)
	case "multihop":
		q.EntryID, q.ExitID, q.ExitMode = "entry", "exit", "naive-h3"
		ids = append(ids, q.EntryID, q.ExitID)
	case "external":
		q.NodeID, q.EntryID = "external", "entry"
		ids = append(ids, q.NodeID, q.EntryID)
	case "current":
		q.Scope, q.Topology = "current", ""
	}
	for _, id := range ids {
		profile, _ := a.profileByIDLocked(id)
		q.ExpectedProfileTokens[id] = publicProfileToken(profile)
	}
	return a, q
}

func TestSpeedLabExpectedProfilesCoverExactGraphAndIgnoreMeasurements(t *testing.T) {
	for _, topology := range []string{"router", "multihop", "external", "system-direct", "current"} {
		t.Run(topology, func(t *testing.T) {
			a, q := expectedSpeedLabFixture(t, topology)
			if err := a.validateSpeedLabExpectedProfiles(q, nil); err != nil {
				t.Fatal("valid captured graph rejected", err)
			}
			for i := range a.profiles.Profiles {
				a.profiles.Profiles[i].Name = "Display update"
				a.profiles.Profiles[i].LatencyMedianMs = 3.5
				a.profiles.Profiles[i].EffectiveMTU = 1390
			}
			if err := a.validateSpeedLabExpectedProfiles(q, nil); err != nil {
				t.Fatal("telemetry retired a requested path", err)
			}
			for id, token := range q.ExpectedProfileTokens {
				delete(q.ExpectedProfileTokens, id)
				if a.validateSpeedLabExpectedProfiles(q, nil) == nil {
					t.Fatal("incomplete graph revisions accepted", id)
				}
				q.ExpectedProfileTokens[id] = token
			}
		})
	}
	// Existing callers and a first-use system-direct test remain valid. Once a
	// caller supplies one half of the capture, missing revisions cannot bypass it.
	a := &app{}
	if a.validateSpeedLabExpectedProfiles(speedLabRequest{}, nil) != nil || a.validateSpeedLabExpectedProfiles(speedLabRequest{ExpectedProfileTokens: map[string]string{}}, nil) != nil {
		t.Fatal("legacy or no-node system-direct request changed")
	}
	if a.validateSpeedLabExpectedProfiles(speedLabRequest{ExpectedSelectedNodeID: "missing"}, nil) == nil {
		t.Fatal("selected identity without a revision map was accepted")
	}
}

func TestSpeedLabExpectedProfileRejectionPrecedesSnapshotAndSuspension(t *testing.T) {
	for _, scope := range []string{"current", "temporary"} {
		for _, fault := range []string{"selected", "credential", "node-proof", "policy", "missing", "malformed", "missing-selected-token", "unlinked-extra"} {
			t.Run(scope+"/"+fault, func(t *testing.T) {
				a, q := expectedSpeedLabFixture(t, "multihop")
				q.Scope = scope
				a.cmd = &exec.Cmd{}
				a.state = state{Connected: true, Phase: "connected", Mode: "wg", RuntimeMode: "wg", Base: "wg", RouterID: "home"}
				switch fault {
				case "selected":
					a.profiles.SelectedID = "exit"
				case "credential":
					a.profiles.Profiles[1].APIToken = "relinked-private-key"
				case "node-proof":
					a.profiles.Profiles[1].NodeProofID = strings.Repeat("f", 64)
				case "policy":
					a.profiles.Profiles[1].IPv6Mode = "off"
				case "missing":
					a.profiles.Profiles = append(a.profiles.Profiles[:1], a.profiles.Profiles[2:]...)
				case "malformed":
					q.ExpectedProfileTokens["entry"] = "not-a-revision"
				case "missing-selected-token":
					delete(q.ExpectedProfileTokens, "home")
				case "unlinked-extra":
					q.ExpectedProfileTokens["removed"] = strings.Repeat("a", 64)
				}
				before, previous, command := cloneRouterProfileStore(a.profiles), a.state, a.cmd
				raw, _ := json.Marshal(q)
				response := httptest.NewRecorder()
				a.speedLabRun(response, httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", strings.NewReader(string(raw))))
				if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), errSpeedLabSelectionChanged.Error()) || a.state != previous || a.cmd != command || !reflect.DeepEqual(a.profiles, before) {
					t.Fatal("stale HTTP request touched or replaced the active path", response.Code, response.Body.String())
				}
				// Call the owned transaction entry as well: an early HTTP check
				// alone cannot close a relink race before suspension.
				if _, _, finish, err := a.beginSpeedLabTemporaryOperationExpected(&q); !errors.Is(err, errSpeedLabSelectionChanged) || finish != nil {
					t.Fatal("transaction did not recheck revisions before taking a restore snapshot", err)
				}
				if _, err := os.Stat(filepath.Join(os.Getenv("HOMEVPN_ROOT"), "run")); !os.IsNotExist(err) {
					t.Fatal("rejected path performed private runtime preflight", err)
				}
				if !a.operationMu.TryLock() {
					t.Fatal("rejected capture retained the mutation lock")
				}
				a.operationMu.Unlock()
				if _, exists := speedLabRunOwners.Load(a); exists {
					t.Fatal("rejected HTTP capture retained the measurement owner")
				}
				if _, exists := speedLabTemporaryOwners.Load(a); exists || a.connectionContext != nil {
					t.Fatal("rejected capture installed a temporary owner")
				}
			})
		}
	}
}

func TestSpeedLabExpectedCurrentCaptureBindsRuntimeAndReleasesMutationLock(t *testing.T) {
	a, q := expectedSpeedLabFixture(t, "current")
	a.cmd = &exec.Cmd{}
	a.state = state{Connected: true, Phase: "connected", Mode: "wg", RuntimeMode: "wg", Base: "wg", RouterID: "exit"}
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "expected-live-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: "exit"}}
	sessionTrackers.Store(a, tracker)
	t.Cleanup(func() { sessionTrackers.Delete(a) })
	if _, _, err := a.captureExpectedSpeedLabIdentity(q); !errors.Is(err, errSpeedLabSelectionChanged) {
		t.Fatal("selected-node revision substituted for the different active path", err)
	}
	profile, _ := a.profileByIDLocked("exit")
	q.ExpectedProfileTokens["exit"] = publicProfileToken(profile)
	identity, path, err := a.captureExpectedSpeedLabIdentity(q)
	if err != nil || path.NodeID != "exit" || identity.RouterID != "exit" {
		t.Fatal("current capture lost its actual runtime", err)
	}
	if !a.operationMu.TryLock() {
		t.Fatal("current measurement would block Disconnect")
	}
	a.operationMu.Unlock()
	a.profiles.Profiles[2].APIToken = "rotated-after-current-capture"
	if validateSpeedLabIdentity(a, identity) == nil {
		t.Fatal("post-capture relink survived the actual live-path observer")
	}
}
