package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestDesktopExternalComparisonBenchmarkAllowsOnlyArithmeticRounding(t *testing.T) {
	b := cloneDesktopComparisonBenchmark(desktopLatencyStatusFixture("rounding", "exit").Results[0].Benchmark)
	d := b.Distribution
	// These are the native service's IEEE-754 results for 50 equal 1.1 ms
	// samples (and the middle 40 samples). The statistics are still a complete,
	// valid benchmark even though summation rounds the means above the maximum.
	d.Min, d.Median, d.P90, d.Max, d.Jitter = 1.1, 1.1, 1.1, 1.1, 0
	d.Average, b.TrimmedMean = 1.1000000000000008, 1.1000000000000008
	if !validDesktopComparisonBenchmark(b) {
		t.Fatal("native arithmetic roundoff rejected a complete benchmark")
	}
	for _, field := range []string{"average", "trimmed", "jitter", "negative", "infinite", "nan", "partial", "order", "overflow"} {
		t.Run(field, func(t *testing.T) {
			bad := cloneDesktopComparisonBenchmark(b)
			switch field {
			case "average":
				bad.Distribution.Average += 1e-8
			case "trimmed":
				bad.TrimmedMean -= 1e-8
			case "jitter":
				bad.Distribution.Jitter = 1e-8
			case "negative":
				bad.Distribution.Jitter = -math.SmallestNonzeroFloat64
			case "infinite":
				bad.Distribution.Max = math.Inf(1)
			case "nan":
				bad.TrimmedMean = math.NaN()
			case "partial":
				bad.Distribution.Samples = 49
			case "order":
				bad.Distribution.P90 = math.Nextafter(bad.Distribution.Median, 0)
			case "overflow":
				bad.Distribution.Min, bad.Distribution.Median, bad.Distribution.P90 = 1, 1, 1
				bad.Distribution.Max = math.MaxFloat64
				bad.Distribution.Average = math.Inf(1)
			}
			if validDesktopComparisonBenchmark(bad) {
				t.Fatal("roundoff allowance admitted invalid measurement")
			}
		})
	}
	d.Min, d.Median, d.P90, d.Max, d.Average, b.TrimmedMean = 1, 1.5, 2, 2, 1.5, 1.5
	d.Jitter = math.Nextafter(1, 2)
	if !validDesktopComparisonBenchmark(b) {
		t.Fatal("a single rounded ulp in accumulated jitter was rejected")
	}
}

// This file runs the actual batch/Speed Lab/sidecar/native-mailbox composition.
// Only host TUN launches and native event receipts are explicit fixture seams;
// the child statistics are synthetic IPC values, not OS/network acceptance.
type desktopComparisonNetworkFixture struct {
	mu                       sync.Mutex
	open, closed             bool
	invalid                  error
	closeError               error
	closeCalls               int
	starts, ends, transients int
	check                    func() error
	record                   func(context.Context, *desktopNodeLaunch) error
}

func (*desktopComparisonNetworkFixture) Identity() string { return strings.Repeat("a", 64) }
func (n *desktopComparisonNetworkFixture) Current() error {
	n.mu.Lock()
	bad, open, closed, check := n.invalid, n.open, n.closed, n.check
	n.mu.Unlock()
	if bad != nil {
		return bad
	}
	if open || closed {
		return errors.New("fixture network is not in a settled cohort")
	}
	if check != nil {
		return check()
	}
	return nil
}
func (n *desktopComparisonNetworkFixture) BeforeTransition(ctx context.Context, _ speedLabPathIdentity) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.open || n.closed {
		return errors.New("duplicate fixture transition")
	}
	n.open = true
	n.starts++
	return n.invalid
}
func (n *desktopComparisonNetworkFixture) AfterTransition(ctx context.Context, _ speedLabPathIdentity) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.open || n.closed {
		return errors.New("fixture transition was not owned")
	}
	n.open = false
	n.ends++
	return n.invalid
}
func (n *desktopComparisonNetworkFixture) RecordTransient(ctx context.Context, launch *desktopNodeLaunch) error {
	n.mu.Lock()
	record := n.record
	n.mu.Unlock()
	if record != nil {
		if err := record(ctx, launch); err != nil {
			return err
		}
	}
	n.mu.Lock()
	n.transients++
	n.mu.Unlock()
	return nil
}
func (n *desktopComparisonNetworkFixture) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closeCalls++
	if n.closeError != nil {
		return n.closeError
	}
	n.closed = true
	return nil
}

func TestDesktopExternalComparisonHistoryRejectsIdenticalReplacementBeforeFirstWriteCheck(t *testing.T) {
	f := newDesktopComparisonFixture(t, false)
	path := desktopComparisonHistoryPath(f.a)
	original := []byte("{\"schema\":1,\"rows\":[]}\n")
	if err := atomicWritePrivate(path, original); err != nil {
		t.Fatal(err)
	}
	before, err := desktopComparisonCaptureFileInfo(path)
	if err != nil {
		t.Fatal(err)
	}
	row := desktopExternalComparisonRow{ID: "a-fast", Name: "Saved fastest", Protocol: "hysteria2", Status: "complete", SourceToken: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), NetworkSHA256: strings.Repeat("d", 64), Execution: "local", MeasuredAt: time.Now().UnixMilli(), Benchmark: desktopLatencyStatusFixture("request", "a-fast").Results[0].Benchmark}
	checks := 0
	var replacement os.FileInfo
	receipt, err := saveDesktopExternalComparisonHistory(f.a, []desktopExternalComparisonRow{row}, func() error {
		checks++
		if checks == 2 {
			if err := atomicWritePrivate(path, original); err != nil {
				return err
			}
			if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
				return err
			}
			var err error
			replacement, err = desktopComparisonCaptureFileInfo(path)
			return err
		}
		return nil
	})
	if err == nil || receipt != nil || checks != 2 || replacement == nil || os.SameFile(before, replacement) {
		t.Fatal("same-content foreign history writer was accepted", err, checks)
	}
	fresh, statErr := desktopComparisonCaptureFileInfo(path)
	raw, readErr := readPrivateRegular(path, 2<<20)
	if statErr != nil || readErr != nil || !os.SameFile(replacement, fresh) || !bytes.Equal(raw, original) {
		t.Fatal("refused history save overwrote the replacement", statErr, readErr)
	}
	clear(raw)
}

func TestDesktopExternalComparisonPostRenameHistoryInvalidationRetiresOnlyOwnImage(t *testing.T) {
	for _, kind := range []string{"initially-absent", "original-history", "replacement-history"} {
		t.Run(kind, func(t *testing.T) {
			f := newDesktopComparisonFixture(t, true)
			path := desktopComparisonHistoryPath(f.a)
			var before os.FileInfo
			original := []byte("{\"schema\":1,\"rows\":[]}\n")
			if kind != "initially-absent" {
				if err := atomicWritePrivate(path, original); err != nil {
					t.Fatal(err)
				}
				before, _ = os.Lstat(path)
			}
			changed := false
			foreign := []byte("{\"schema\":1, \"rows\": []}\n")
			f.network.check = func() error {
				info, err := os.Lstat(path)
				if !changed && err == nil && (before == nil || !os.SameFile(before, info)) {
					changed = true
					if kind == "replacement-history" {
						if err := atomicWritePrivate(path, foreign); err != nil {
							return err
						}
					}
					f.network.mu.Lock()
					f.network.invalid = errors.New("fixture latched physical network event after history rename")
					f.network.mu.Unlock()
					return errors.New("cohort invalidated after history rename")
				}
				return nil
			}
			op, ctx := f.operation(false)
			if err := f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime()); err == nil || !changed {
				t.Fatal("post-rename event accepted", err)
			}
			actual, err := os.ReadFile(path)
			wanted := original
			if kind == "replacement-history" {
				wanted = foreign
			}
			if err != nil || !bytes.Equal(actual, wanted) {
				t.Fatal("provisional history was retained or replacement overwritten", err, string(actual))
			}
			if op.snapshot().Committed || !f.a.state.Connected || f.a.state.RouterID != "z-original" {
				t.Fatal("history failure changed original connection")
			}
		})
	}
}

func TestDesktopExternalComparisonLatchedNetworkChangeStillRestoresAndNeverScores(t *testing.T) {
	f := newDesktopComparisonFixture(t, true)
	op, ctx := f.operation(false)
	changed := false
	f.network.check = func() error {
		if !changed && op.snapshot().Stage == "measuring" {
			changed = true
			f.network.mu.Lock()
			f.network.invalid = errors.New("away-and-back physical event fixture")
			f.network.mu.Unlock()
			return errors.New("captured network event")
		}
		return nil
	}
	if err := f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime()); err == nil || !changed {
		t.Fatal("changed network acquired a score", err)
	}
	if !f.a.state.Connected || f.a.state.RouterID != "z-original" || !op.snapshot().Restored {
		t.Fatal("latched comparison witness blocked original restoration")
	}
	if !f.network.closed || f.network.ends != 2 || f.restorations != 1 {
		t.Fatal("network change skipped exact transition cleanup", f.network, f.restorations)
	}
	for _, row := range op.snapshot().Rows {
		if row.Benchmark != nil {
			t.Fatal("invalid cohort retained a score")
		}
	}
}

func TestDesktopExternalComparisonLateObserverEventInvalidatesScoresWithoutUndoingAdoption(t *testing.T) {
	f := newDesktopComparisonFixture(t, true)
	f.network.closeError = errors.New("fixture physical event delivered during native observer join")
	op, ctx := f.operation(true)
	f.a.desktopExternalComparisonFor().current = op
	err := f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime())
	op.finish(ctx, err)
	close(op.done)
	view := op.snapshot()
	if err == nil || !view.Committed || view.Stage != "connected-with-warning" || view.WinnerID != "a-fast" || view.Warning == "" || view.Failure != "" || view.Drained {
		t.Fatal("late observer event concealed durable adoption or cleanup", err, view)
	}
	if !f.a.state.Connected || f.a.state.RouterID != "a-fast" || f.a.profiles.SelectedID != "a-fast" || f.restorations != 4 {
		t.Fatal("late validation failure tore down or restored over the committed winner")
	}
	for _, row := range view.Rows {
		if row.Benchmark != nil || row.Status != "invalid" || row.Failure == "" {
			t.Fatal("invalidated committed comparison retained a score", row)
		}
	}
	history, historyErr := readDesktopExternalComparisonHistory(f.a)
	if historyErr != nil || len(history.Rows) != 0 {
		t.Fatal("late observer event retained provisional history", historyErr, history)
	}
	var saved common.RouterProfileStore
	raw, readErr := readPrivateRegular(f.a.cfg.ProfilesFile, maxPrivateStoreBytes)
	if readErr != nil || json.Unmarshal(raw, &saved) != nil || saved.SelectedID != "a-fast" || saved.Profiles[0].UseCount != 8 {
		t.Fatal("history rollback changed durable selection or final usage", readErr)
	}
	clear(raw)
	winner := f.a.cmd
	f.network.mu.Lock()
	f.network.closeError = nil
	f.network.mu.Unlock()
	request, _ := json.Marshal(op.request)
	w := httptest.NewRecorder()
	f.a.cancelDesktopExternalComparison(w, httptest.NewRequest(http.MethodPost, "/api/speed-lab/external-comparison/cancel", bytes.NewReader(request)))
	if w.Code != http.StatusAccepted || desktopComparisonPending(op) || !op.snapshot().Drained || f.a.cmd != winner || !f.a.state.Connected || f.a.profiles.Profiles[0].UseCount != 8 {
		t.Fatal("cleanup retry changed final adoption or repeated usage", w.Code, op.snapshot())
	}
}

func TestDesktopExternalComparisonFailedObserverCloseIsRetainedAndRetried(t *testing.T) {
	f := newDesktopComparisonFixture(t, false)
	f.network.closeError = errors.New("fixture unregister acknowledgment unresolved")
	op, ctx := f.operation(false)
	op.warn("Earlier private-history warning must remain visible.")
	f.a.desktopExternalComparisonFor().current = op
	if err := f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime()); err == nil {
		t.Fatal("unjoined observer reported success")
	}
	close(op.done)
	if !desktopComparisonPending(op) || op.snapshot().Drained || f.network.closed || f.network.closeCalls != 1 {
		t.Fatal("observer capability was discarded", op.snapshot())
	}
	f.network.mu.Lock()
	f.network.closeError = nil
	f.network.mu.Unlock()
	request, _ := json.Marshal(op.request)
	w := httptest.NewRecorder()
	f.a.cancelDesktopExternalComparison(w, httptest.NewRequest(http.MethodPost, "/api/speed-lab/external-comparison/cancel", bytes.NewReader(request)))
	if w.Code != http.StatusAccepted || desktopComparisonPending(op) || !op.snapshot().Drained || !f.network.closed || f.network.closeCalls != 2 {
		t.Fatal("exact observer cleanup was not retried", w.Code, op.snapshot())
	}
	warning := op.snapshot().Warning
	if !strings.Contains(warning, "Earlier private-history warning must remain visible.") || strings.Contains(warning, "Retry Cancel") || !strings.Contains(warning, "cleanup is complete") {
		t.Fatal("cleanup retry erased an earlier warning or retained a stale pending claim", warning)
	}
}

type desktopComparisonFixture struct {
	t                                         *testing.T
	a                                         *app
	root                                      string
	network                                   *desktopComparisonNetworkFixture
	mu                                        sync.Mutex
	last                                      *desktopNodeLaunch
	starts, stops, preparations, restorations int
	kinds                                     map[string]string
	beforePrepare                             func(speedLabRequest) error
	beforeRestart                             func(speedLabRestorePlan) error
}

func newDesktopComparisonFixture(t *testing.T, connected bool) *desktopComparisonFixture {
	t.Helper()
	// macOS exposes its system temporary root through /var -> /private/var.
	// Resolve only our newly created fixture root; production private paths
	// must continue to reject symlink components and replacements.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", root)
	base, _ := desktopExternalNativeFixture(t, "hysteria2")
	profiles := []common.RouterProfile{}
	for _, id := range []string{"a-fast", "b-second", "z-original"} {
		p := cloneRouterProfile(base)
		p.ID, p.Name = id, "Saved "+id
		p.MTUPolicy, p.ManualMTU, p.EffectiveMTU = "manual", 1280, 9000
		p.UseCount, p.LastUsedAt = 7, "2026-10-01T00:00:00Z"
		profiles = append(profiles, p)
	}
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "profiles.json"), StateFile: filepath.Join(root, "startup.json"), ScriptsDir: filepath.Join(root, "modes")},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion, SelectedID: "z-original", Profiles: profiles}, state: state{Mode: "off", Phase: "off", RouterID: "z-original"}}
	if err := a.speedLabWriteStore(a.profiles); err != nil {
		t.Fatal(err)
	}
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{Phase: "off", RouterID: "z-original"}})
	f := &desktopComparisonFixture{t: t, a: a, root: root, network: &desktopComparisonNetworkFixture{}, kinds: map[string]string{}}
	t.Cleanup(func() {
		a.mu.Lock()
		a.closing = true
		a.mu.Unlock()
		sessionTrackers.Delete(a)
		desktopNodeOwners.Delete(a)
		speedLabTemporaryOwners.Delete(a)
	})
	if connected {
		p := profiles[2]
		exit, err := standardExitFromExternalProfile(p)
		if err != nil {
			t.Fatal(err)
		}
		launch, err := compileDesktopExternalCaptured(context.Background(), p, common.RouterProfile{}, exit, true, "", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.startLaunch(launch, p.ID); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *desktopComparisonFixture) startLaunch(launch *desktopNodeLaunch, id string) error {
	if launch == nil {
		return errors.New("fixture has no compiled native source")
	}
	kind := f.kinds[id]
	if kind == "" {
		kind = "latency-winner"
	}
	other, launch := desktopExternalRunCompiledFixture(f.t, kind, f.root, launch)
	desktopNodeOwners.Delete(other)
	launch.external.network = physicalNetworkIdentity()
	launch.external.networkIdentity = physicalNetworkIdentity
	if launch.external.network == "" {
		return errors.New("fixture cannot read actual physical interface inventory")
	}
	a := f.a
	a.mu.Lock()
	if a.cmd != nil {
		a.mu.Unlock()
		return errors.New("fixture start cannot replace a runtime")
	}
	a.cmd = launch.command
	a.profiles.SelectedID = id
	a.state = state{Connected: true, Phase: "connected", Mode: "external-node", LogicalMode: "external-node", RuntimeMode: "external-hysteria2", Base: "external", RouterID: id}
	a.mu.Unlock()
	desktopNodeOwners.Store(a, launch)
	if err := a.speedLabOwnRuntime(launch.command); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := a.waitDesktopExternalProof(ctx, launch); err != nil {
		return err
	}
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	tracker.session = &connectionSession{ID: "batch-fixture-" + launch.external.session, Connected: true, Phase: "connected", PathProof: "passed", RouterID: id, ActualMode: "external-hysteria2", ActualBase: "external"}
	tracker.mu.Unlock()
	a.mu.Lock()
	captureDesktopMTUBaselineLocked(a, launch)
	a.mu.Unlock()
	f.mu.Lock()
	f.last = launch
	f.starts++
	f.mu.Unlock()
	return nil
}

func (f *desktopComparisonFixture) stop(hold bool) error {
	a := f.a
	if raw, exists := speedLabTemporaryOwners.Load(a); exists {
		if err := a.speedLabCheckOwner(raw.(*speedLabTemporaryOwner)); err != nil {
			return err
		}
	}
	a.mu.Lock()
	command := a.cmd
	a.mu.Unlock()
	if command != nil {
		raw, exists := desktopNodeOwners.Load(a)
		launch, ok := raw.(*desktopNodeLaunch)
		if !exists || !ok || launch.command != command {
			return errors.New("fixture cannot stop a foreign command")
		}
		if err := prepareDesktopExternalStop(a, command); err != nil {
			return err
		}
		select {
		case <-desktopExternalProcessDone(launch):
		case <-time.After(4 * time.Second):
			return errors.New("fixture child did not join")
		}
		// This explicit test control is outside the production mailbox list.
		// Only the fixture removes its own exact bytes after its child joins.
		release := filepath.Join(launch.directory, "latency-drain-release.fixture")
		if raw, err := os.ReadFile(release); err == nil && string(raw) == "release explicit fixture worker" {
			if err := os.Remove(release); err != nil {
				return err
			}
		}
		if err := cleanupDesktopNodeLaunch(launch); err != nil {
			return err
		}
		desktopNodeOwners.CompareAndDelete(a, launch)
		f.mu.Lock()
		f.stops++
		f.mu.Unlock()
	}
	a.mu.Lock()
	a.cmd = nil
	a.state.Connected, a.state.Mode, a.state.Phase = false, "off", "off"
	if raw, exists := speedLabTemporaryOwners.Load(a); exists {
		raw.(*speedLabTemporaryOwner).runtime = nil
	}
	a.mu.Unlock()
	return nil
}

func (f *desktopComparisonFixture) runtime() desktopExternalComparisonRuntime {
	return desktopExternalComparisonRuntime{
		prepare: func(q speedLabRequest) (*speedLabExternalPreparation, error) {
			f.preparations++
			if f.beforePrepare != nil {
				if err := f.beforePrepare(q); err != nil {
					return nil, err
				}
			}
			p, err := f.a.previewSpeedLabTemporaryProfile(q.NodeID, q)
			if err != nil {
				return nil, err
			}
			exit, err := standardExitFromExternalProfile(p)
			if err != nil {
				return nil, err
			}
			launch, err := compileDesktopExternalCaptured(context.Background(), p, common.RouterProfile{}, exit, true, "", nil, nil, nil)
			if err != nil {
				return nil, err
			}
			return &speedLabExternalPreparation{profile: p, policy: p, direct: true, native: launch}, nil
		},
		start: func(q speedLabRequest) (speedLabPath, error) {
			if q.preparedExternal == nil {
				return speedLabPath{}, errors.New("fixture lost its preflight")
			}
			launch := q.preparedExternal.native
			q.preparedExternal.native = nil // the started child now owns this private capture
			return speedLabPath{}, f.startLaunch(launch, q.NodeID)
		},
		stop: f.stop,
		restart: func(plan speedLabRestorePlan) error {
			f.restorations++
			if f.beforeRestart != nil {
				if err := f.beforeRestart(plan); err != nil {
					return err
				}
			}
			if plan.external == nil || plan.request.Execution != "local" || plan.external.execution != "local" {
				return errors.New("fixture restart repeated a strategy or lost its retained leaf")
			}
			exit, err := standardExitFromExternalProfile(plan.external.profile)
			if err != nil {
				return err
			}
			launch, err := compileSpeedLabExternalRestore(plan.external, exit)
			if err != nil {
				return err
			}
			if err = f.startLaunch(launch, plan.profile.ID); err != nil {
				return err
			}
			if err = f.a.restoreDesktopCapturedMTU(f.a.connectionOperationContextOrBackground(), launch); err != nil {
				return err
			}
			path, _, err := captureSpeedLabIdentity(f.a)
			if err != nil {
				return err
			}
			return verifySpeedLabPath(f.a.connectionOperationContextOrBackground(), f.a, path)
		},
		network: func(context.Context, *app, speedLabPathIdentity) (desktopExternalComparisonNetwork, error) {
			return f.network, nil
		},
	}
}

func (f *desktopComparisonFixture) operation(connect bool) (*desktopExternalComparisonOperation, context.Context) {
	f.t.Helper()
	id, err := desktopComparisonCatalogToken(f.a.profiles)
	if err != nil {
		f.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	f.t.Cleanup(cancel)
	return &desktopExternalComparisonOperation{request: desktopExternalComparisonRequest{Request: strings.Repeat("b", 32), Cohort: id, ConnectFastest: connect}, cancel: cancel, done: make(chan struct{}),
		view: desktopExternalComparisonView{Rows: []desktopExternalComparisonRow{}, Restored: true, Drained: true}}, ctx
}

func TestDesktopExternalComparisonActualNativeMailboxRestoresOriginalBetweenAllTrials(t *testing.T) {
	for _, connected := range []bool{false, true} {
		t.Run(map[bool]string{false: "original-off", true: "original-connected"}[connected], func(t *testing.T) {
			f := newDesktopComparisonFixture(t, connected)
			before := cloneRouterProfileStore(f.a.profiles)
			initial := f.a.cmd
			op, ctx := f.operation(false)
			if err := f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime()); err != nil {
				t.Fatal(err, op.snapshot())
			}
			view := op.snapshot()
			if view.WinnerID != "a-fast" || view.Committed || !view.Restored || !view.Drained || len(view.Rows) != 3 || !reflect.DeepEqual(before, f.a.profiles) {
				t.Fatal("batch lost original state or metric separation", view)
			}
			for _, row := range view.Rows {
				if row.Status != "complete" || !validDesktopComparisonBenchmark(row.Benchmark) || row.Benchmark.TrimmedMean != 4.5 {
					t.Fatal("bad complete native score", row)
				}
			}
			if f.preparations != 3 || f.network.starts != 6 || f.network.ends != 6 || !f.network.closed {
				t.Fatal("batch skipped trial restoration or observer join", f.preparations, f.network)
			}
			if connected && (f.a.cmd == nil || f.a.cmd == initial || f.a.state.RouterID != "z-original" || f.restorations != 3) {
				t.Fatal("original owner was not freshly restored after every candidate")
			}
			if !connected && (f.a.cmd != nil || f.a.state.Connected || f.restorations != 0) {
				t.Fatal("original off state changed")
			}
			history, err := readDesktopExternalComparisonHistory(f.a)
			if err != nil || len(history.Rows) != 3 {
				t.Fatal("complete native history missing", err, history)
			}
			for _, p := range f.a.profiles.Profiles {
				if p.UseCount != 7 || p.LatencySamples != before.Profiles[0].LatencySamples {
					t.Fatal("temporary measurement counted usage or relabeled Router TCP")
				}
			}
		})
	}
}

func TestDesktopExternalComparisonFastestReprovesSealedLeafAndCountsOnlyFinalAdoption(t *testing.T) {
	f := newDesktopComparisonFixture(t, true)
	op, ctx := f.operation(true)
	if err := f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime()); err != nil {
		t.Fatal(err, op.snapshot())
	}
	view := op.snapshot()
	if !view.Committed || view.Restored || view.WinnerID != "a-fast" || f.a.profiles.SelectedID != "a-fast" || !f.a.state.Connected || f.a.state.RouterID != "a-fast" || f.preparations != 3 || f.restorations != 4 {
		t.Fatal("final adoption changed captured execution or reran selection", view, f.preparations, f.restorations)
	}
	for _, p := range f.a.profiles.Profiles {
		want := 7
		if p.ID == "a-fast" {
			want++
		}
		if p.UseCount != want || p.EffectiveMTU != 9000 {
			t.Fatal("wrong usage or saved MTU", p.ID, p.UseCount, p.EffectiveMTU)
		}
	}
	selection, err := f.a.loadStartupSelection()
	if err != nil || selection.RouterID != "a-fast" || selection.External == nil || selection.External.Execution != "local" {
		t.Fatal("startup leaf was not retained", selection, err)
	}
	identity, _, err := captureSpeedLabIdentity(f.a)
	if err != nil || identity.External == nil {
		t.Fatal("winner did not survive temporary owner cancellation", err)
	}
	if mtu, err := captureDesktopMTURestore(identity.External); err != nil || mtu != 1280 {
		t.Fatal("winner did not retain observed interface MTU", mtu, err)
	}
}

func TestDesktopExternalComparisonInvalidCandidateGetsNoScoreAndCorruptHistoryIsPreserved(t *testing.T) {
	f := newDesktopComparisonFixture(t, true)
	f.kinds["b-second"] = "latency-incomplete"
	bad := []byte("{ corrupt private statistics }")
	if err := os.WriteFile(desktopComparisonHistoryPath(f.a), bad, 0600); err != nil {
		t.Fatal(err)
	}
	op, ctx := f.operation(true)
	if err := f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime()); err != nil {
		t.Fatal(err, op.snapshot())
	}
	view := op.snapshot()
	if !view.Committed || view.Warning == "" || view.Rows[1].Benchmark != nil || view.Rows[1].Status != "invalid" || view.Rows[1].Failure == "" {
		t.Fatal("invalid sample became zero or old history was hidden", view)
	}
	readback, err := os.ReadFile(desktopComparisonHistoryPath(f.a))
	if err != nil || !bytes.Equal(readback, bad) {
		t.Fatal("corrupt sidecar was silently replaced", err)
	}
}

func TestDesktopExternalComparisonPostProofPolicyOrOwnerReplacementCannotCommit(t *testing.T) {
	for _, kind := range []string{"saved-policy", "native-owner"} {
		t.Run(kind, func(t *testing.T) {
			f := newDesktopComparisonFixture(t, true)
			op, ctx := f.operation(true)
			checks, changed, stops := 0, false, 0
			replacement := &exec.Cmd{}
			f.network.check = func() error {
				if op.snapshot().Stage == "reproving-winner" {
					checks++
				}
				if checks == 2 && !changed {
					changed, stops = true, f.stops
					f.a.mu.Lock()
					if kind == "saved-policy" {
						f.a.profiles.Profiles[0].DNSHost = "203.0.113.54"
					} else {
						f.a.cmd = replacement
						f.a.state.RouterID = "b-second"
					}
					f.a.mu.Unlock()
				}
				return nil
			}
			err := f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime())
			op.finish(ctx, err)
			if err == nil || !changed || op.snapshot().Committed {
				t.Fatal("post-proof replacement acquired adoption", err, op.snapshot())
			}
			if kind == "native-owner" && (f.a.cmd != replacement || f.a.state.RouterID != "b-second" || f.stops != stops) {
				t.Fatal("failed adoption retired a replacement native owner")
			}
			if kind == "saved-policy" && (f.a.profiles.Profiles[0].DNSHost != "203.0.113.54" || f.a.cmd != nil) {
				t.Fatal("failed adoption overwrote changed policy or left its trial running")
			}
			var saved common.RouterProfileStore
			raw, readErr := readPrivateRegular(f.a.cfg.ProfilesFile, maxPrivateStoreBytes)
			if readErr != nil || json.Unmarshal(raw, &saved) != nil || saved.SelectedID != "z-original" || saved.Profiles[0].UseCount != 7 {
				t.Fatal("rejected adoption wrote selection or usage", readErr)
			}
			clear(raw)
		})
	}
}

func TestDesktopExternalComparisonTorRecordsEveryProvedTransientBeforeClose(t *testing.T) {
	f, previous := speedLabTorCompareFixture(t, "tor", "server", "tor-compare-driver")
	q := speedLabTorCompareRequest(f)
	_, snapshot, finish, err := f.a.beginSpeedLabTemporaryOperationExpected(&q)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	var captured []*desktopNodeLaunch
	network := &desktopComparisonNetworkFixture{record: func(ctx context.Context, launch *desktopNodeLaunch) error {
		if ctx.Err() != nil || launch == nil || launch.tor == nil || desktopNodeProcessExited(launch) {
			return errors.New("transient was recorded after retirement")
		}
		if _, err := f.a.readDesktopTorProof(launch); err != nil {
			return err
		}
		f.a.mu.Lock()
		owned := f.a.speedLabOwnerCurrentLocked(snapshot.Owner) && f.a.cmd == launch.command && snapshot.Owner.runtime == launch.command
		f.a.mu.Unlock()
		if !owned {
			return errors.New("transient lost exact temporary/native owner")
		}
		captured = append(captured, launch)
		return nil
	}}
	f.a.mu.Lock()
	snapshot.Owner.cohortNetwork = network
	f.a.mu.Unlock()
	defer func() { f.a.mu.Lock(); snapshot.Owner.cohortNetwork = nil; f.a.mu.Unlock() }()
	prepared, err := f.a.prepareSpeedLabExternalPathWithRuntime(q, nil, f.driver)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.releaseUnused()
	q.preparedExternal = prepared
	if err := f.a.speedLabSuspendPrevious(snapshot, false); err != nil {
		t.Fatal(err)
	}
	path, err := f.a.startSpeedLabTemporaryPath(q)
	if err != nil {
		t.Fatal(err)
	}
	if path.Execution != "server" || len(captured) != 3 || network.transients != 3 || !desktopNodeProcessExited(previous) {
		t.Fatal("Compare failed to retain all native route owners", path, len(captured))
	}
	for index, launch := range captured {
		if launch != f.launches[index] || desktopNodeProcessExited(launch) != (index < 2) {
			t.Fatal("transient route owner was missed or captured after close", index)
		}
	}
	if err := f.a.recordDesktopComparisonTransient(context.Background(), &desktopNodeLaunch{command: &exec.Cmd{}}); err == nil || network.transients != 3 {
		t.Fatal("foreign command supplied a transient routing receipt", err)
	}
	snapshot.Owner.cancelTest()
	speedLabTorCompareRestore(t, f, snapshot)
	if network.transients != 3 || len(f.probes) != 3 || !f.a.state.Connected || f.launch.tor.expected.SessionID == previous.tor.expected.SessionID {
		t.Fatal("original restoration reran Compare or lost fresh ownership")
	}
}

func TestDesktopExternalComparisonCohortSealsSharedAssetsAndBoundsBeforeStop(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", root)
	entry, files := desktopNodeFixture(t, "198.51.100.11")
	entry.BaseTunnel = "wg"
	if err := common.NormalizeRouterProfile(&entry); err != nil {
		t.Fatal(err)
	}
	directory, err := nativeGeneratedDir(root, entry.ID, "wg")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	base, _ := desktopExternalNativeFixture(t, "hysteria2")
	profiles := []common.RouterProfile{entry}
	for _, id := range []string{"first-exit", "second-exit"} {
		p := cloneRouterProfile(base)
		p.ID = id
		p.MultihopEnabled = true
		p.MultihopEntryID, p.MultihopExitID = entry.ID, id
		p.MultihopEntryMode = "wg"
		p.MultihopExecution = "local"
		if err := common.NormalizeRouterProfile(&p); err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, p)
	}
	a := &app{profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion, SelectedID: entry.ID, Profiles: profiles}}
	cohort, err := captureDesktopExternalComparisonCohort(a, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cohort.close()
	if len(cohort.files) != 2 || len(cohort.candidates) != 2 || cohort.candidates[0].Failure != "" || cohort.candidates[1].Failure != "" {
		t.Fatal("shared entry capture was duplicated or invalid", cohort.candidates)
	}
	file := cohort.files[filepath.Join(directory, "wg.conf")]
	encoded, _ := json.Marshal(cohort.profiles)
	if cohort.bytes != len(encoded)+len(file.data) {
		t.Fatal("shared entry counted more than once", cohort.bytes)
	}
	clear(encoded)
	if err := cohort.current(a, entry.ID); err != nil {
		t.Fatal(err)
	}
	// Restore the exact bytes after an edit but retain its new file revision.
	if err := os.WriteFile(file.path, []byte("foreign source while relinking"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file.path, file.data, 0600); err != nil {
		t.Fatal(err)
	}
	changed := file.info.ModTime().Add(time.Second)
	if err := os.Chtimes(file.path, changed, changed); err != nil {
		t.Fatal(err)
	}
	if err := cohort.current(a, entry.ID); err == nil {
		t.Fatal("edit-away-and-back reused the original source revision")
	}
	bounded := &desktopExternalComparisonCohort{files: map[string]desktopExternalComparisonFile{}, bytes: desktopExternalComparisonBytes - 1}
	defer bounded.close()
	if err := bounded.captureAssets(a, entry, "wg"); !errors.Is(err, errDesktopComparisonSourceBound) {
		t.Fatal("aggregate source cap did not reject before Stop", err)
	}
	tooMany := cloneRouterProfileStore(a.profiles)
	for len(tooMany.Profiles) <= desktopExternalComparisonLimit+1 {
		p := cloneRouterProfile(base)
		p.ID = "extra-" + strconv.Itoa(len(tooMany.Profiles))
		tooMany.Profiles = append(tooMany.Profiles, p)
	}
	if _, err := desktopComparisonCatalogToken(tooMany); err == nil {
		t.Fatal("candidate count cap was bypassed")
	}
	if a.cmd != nil || a.state.Connected {
		t.Fatal("source validation started a runtime")
	}
}

func TestDesktopExternalComparisonPostProofStoreReplacementIsPreserved(t *testing.T) {
	f := newDesktopComparisonFixture(t, true)
	op, ctx := f.operation(true)
	checks := 0
	changed := false
	f.network.check = func() error {
		if op.snapshot().Stage == "reproving-winner" {
			checks++
		}
		if checks == 2 && !changed {
			changed = true
			newer := cloneRouterProfileStore(f.a.profiles)
			newer.SelectedID = "b-second"
			newer.Profiles[0].DNSHost = "203.0.113.54"
			return f.a.speedLabWriteStore(newer)
		}
		return nil
	}
	err := f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime())
	if err == nil || !changed || op.snapshot().Committed {
		t.Fatal("post-proof replacement acquired final save", err, op.snapshot())
	}
	raw, readErr := os.ReadFile(f.a.cfg.ProfilesFile)
	var saved common.RouterProfileStore
	if readErr != nil || json.Unmarshal(raw, &saved) != nil || saved.SelectedID != "b-second" || saved.Profiles[0].DNSHost != "203.0.113.54" {
		t.Fatal("failed adoption overwrote newer private file", readErr)
	}
}

func TestDesktopExternalComparisonPreflightReplacementCannotBeRecapturedAsOriginal(t *testing.T) {
	f := newDesktopComparisonFixture(t, true)
	replacement := &exec.Cmd{}
	f.beforePrepare = func(speedLabRequest) error {
		f.a.mu.Lock()
		f.a.cmd = replacement
		f.a.state.RouterID = "b-second"
		f.a.mu.Unlock()
		return errors.New("replacement fixture")
	}
	op, ctx := f.operation(false)
	err := f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime())
	if err == nil || f.a.cmd != replacement || f.stops != 0 || f.a.state.RouterID != "b-second" {
		t.Fatal("captured or tore down a replacement owner", err)
	}
}

func TestDesktopExternalComparisonCancelKeepsMTULeaseUntilNativeDrainAndOriginalRestore(t *testing.T) {
	f := newDesktopComparisonFixture(t, true)
	f.kinds["a-fast"] = "latency-cancel-delay"
	op, ctx := f.operation(false)
	done := make(chan error, 1)
	go func() { done <- f.a.runDesktopExternalComparisonWith(ctx, op, f.runtime()) }()
	deadline := time.After(10 * time.Second)
	for !desktopLatencyNativePhase(op.snapshot().Progress) {
		select {
		case <-deadline:
			t.Fatal("native batch measurement never started", op.snapshot())
		case <-time.After(10 * time.Millisecond):
		}
	}
	op.cancel()
	for op.snapshot().Progress != "draining" {
		select {
		case <-deadline:
			t.Fatal("batch did not enter native drain", op.snapshot())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !mtuSuspended(f.a) {
		t.Fatal("cancel released the shared MTU lease before native drain")
	}
	select {
	case err := <-done:
		t.Fatal("batch returned before native drain", err)
	default:
	}
	f.mu.Lock()
	launch := f.last
	f.mu.Unlock()
	if err := os.WriteFile(filepath.Join(launch.directory, "latency-drain-release.fixture"), []byte("release explicit fixture worker"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled batch reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("batch did not drain and restore")
	}
	if !f.a.state.Connected || f.a.state.RouterID != "z-original" || op.snapshot().Committed || !op.snapshot().Restored || mtuSuspended(f.a) {
		t.Fatal("cancel did not restore exact original owner", op.snapshot())
	}
	if _, err := os.Stat(desktopComparisonHistoryPath(f.a)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled batch saved partial history", err)
	}
}

func TestDesktopExternalComparisonOfferCancelAndReplayAreExact(t *testing.T) {
	f := newDesktopComparisonFixture(t, false)
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		mux := http.NewServeMux()
		registerSpeedLabRoutes(mux, f.a)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(raw)))
		return w
	}
	w := call(http.MethodGet, "/api/speed-lab/external-comparison", nil)
	var offered struct {
		Request string `json:"request_id"`
		Cohort  string `json:"cohort_id"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &offered) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	request := desktopExternalComparisonRequest{Request: offered.Request, Cohort: offered.Cohort, ConnectFastest: true}
	foreign := request
	foreign.Request = strings.Repeat("f", 32)
	if w := call(http.MethodPost, "/api/speed-lab/external-comparison/cancel", foreign); w.Code != 409 {
		t.Fatal("foreign cancellation accepted", w.Code)
	}
	if w := call(http.MethodPost, "/api/speed-lab/external-comparison/cancel", request); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call(http.MethodPost, "/api/speed-lab/external-comparison", request); w.Code != 409 {
		t.Fatal("cancelled offer replayed", w.Code)
	}
	if f.a.cmd != nil || f.a.state.Connected {
		t.Fatal("rejected start mutated the original")
	}
}

// Native form gates consume the actual public JSON types and send their
// captured request bodies back through the shipping strict decoder.
func TestDesktopExternalComparisonFormFixtures(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_EXTERNAL_COMPARISON_FORM_FIXTURES")
	if directory == "" {
		t.Skip("native form fixture output not requested")
	}
	f := newDesktopComparisonFixture(t, false)
	w := httptest.NewRecorder()
	f.a.desktopExternalComparison(w, httptest.NewRequest(http.MethodGet, "/api/speed-lab/external-comparison", nil))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	var offer struct {
		Request string `json:"request_id"`
		Cohort  string `json:"cohort_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &offer); err != nil {
		t.Fatal(err)
	}
	write := func(name string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(directory, name+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "offer.json"), w.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	row := desktopExternalComparisonRow{ID: "a-fast", Name: "Saved fastest", Protocol: "hysteria2", Status: "complete", SourceToken: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), NetworkSHA256: strings.Repeat("d", 64), Execution: "local", MeasuredAt: time.Now().UnixMilli(), Benchmark: desktopLatencyStatusFixture("request", "a-fast").Results[0].Benchmark}
	active := desktopExternalComparisonView{Request: offer.Request, Cohort: offer.Cohort, Stage: "measuring", CurrentID: "a-fast", Progress: "exit: HTTPS response 1/50", Rows: []desktopExternalComparisonRow{}, Note: desktopExternalComparisonNote}
	write("active", active)
	complete := active
	complete.Stage = "complete"
	complete.Complete = true
	complete.Drained = true
	complete.Restored = true
	complete.Rows = []desktopExternalComparisonRow{row}
	complete.WinnerID = row.ID
	write("compared", complete)
	complete.Stage = "connected"
	complete.Committed = true
	complete.Restored = false
	complete.ConnectFastest = true
	write("connected", complete)
	warning := complete
	warning.Stage, warning.Warning, warning.Drained = "connected-with-warning", "Late network event during observer cleanup", false
	warning.Rows = []desktopExternalComparisonRow{}
	write("connected-warning", warning)
	draining := active
	draining.Stage = "cancelled"
	draining.Complete = true
	draining.Failure = "Cancellation fixture; no score"
	write("draining", draining)
	draining.Drained = true
	draining.Restored = true
	write("cancelled", draining)
	foreign := complete
	foreign.Request = strings.Repeat("f", 32)
	write("foreign", foreign)
	bad := complete
	bad.Rows = append([]desktopExternalComparisonRow(nil), complete.Rows...)
	bad.Rows[0].Benchmark = cloneDesktopComparisonBenchmark(row.Benchmark)
	bad.Rows[0].Benchmark.Distribution.Samples = 49
	write("incomplete", bad)
}

func TestDesktopExternalComparisonFormPayloads(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_EXTERNAL_COMPARISON_FORM_FIXTURES")
	if directory == "" {
		t.Skip("native form payload input not requested")
	}
	var offer struct {
		Request string `json:"request_id"`
		Cohort  string `json:"cohort_id"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "offer.json"))
	if err != nil || json.Unmarshal(raw, &offer) != nil {
		t.Fatal("missing actual offer", err)
	}
	for _, name := range []string{"compare-body", "connect-body", "cancel-body"} {
		raw, err := os.ReadFile(filepath.Join(directory, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		request, err := readDesktopExternalComparisonRequest(w, httptest.NewRequest(http.MethodPost, "/api/speed-lab/external-comparison", bytes.NewReader(raw)))
		if err != nil || request.Request != offer.Request || request.Cohort != offer.Cohort || request.ConnectFastest != (name == "connect-body") {
			t.Fatal("native form changed immutable request or explicit final adoption", name, request, err)
		}
	}
}
