package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/routechoice"
)

type desktopTorComparisonProbeFixture struct {
	mobiletor.Comparison
	target                   string
	last, external, verifies int
	closeFailure             bool
}

func (p *desktopTorComparisonProbeFixture) Verify(ctx context.Context) error {
	p.verifies++
	return p.Comparison.Verify(ctx)
}

func (p *desktopTorComparisonProbeFixture) ProbeLast(ctx context.Context) (time.Duration, error) {
	p.last++
	return p.Comparison.ProbeLast(ctx)
}

func (p *desktopTorComparisonProbeFixture) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	p.external++
	if target != p.target {
		return 0, errors.New("fixture observed a changed round target")
	}
	return p.Comparison.ProbeExternal(ctx, target)
}

func (p *desktopTorComparisonProbeFixture) Close(ctx context.Context) error {
	if p.closeFailure {
		p.closeFailure = false
		return errors.New("explicit retained close failure fixture")
	}
	return p.Comparison.Close(ctx)
}

type desktopTorComparisonDriverFixture struct {
	connection *desktopTorConnectFixture
	driver     *desktopTorComparisonDriver
	probes     []*desktopTorComparisonProbeFixture
	launches   []*desktopNodeLaunch
	created    chan *desktopTorComparisonClient
}

func newDesktopTorComparisonDriverFixture(t *testing.T, kind string) *desktopTorComparisonDriverFixture {
	t.Helper()
	f := newDesktopTorConnectFixture(t)
	_, finish, err := f.a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	fixture := &desktopTorComparisonDriverFixture{connection: f, created: make(chan *desktopTorComparisonClient, 8)}
	command := f.driver.command
	f.driver.command = func(a *app, prepared torBridgeRuntime, environment []string) (*exec.Cmd, error) {
		cmd, err := command(a, prepared, environment)
		if err == nil {
			fixture.launches = append(fixture.launches, prepared.Launch)
			selectedKind := kind
			if kind == "tor-compare-driver-final-failure" {
				selectedKind = "tor-compare-driver"
				if len(fixture.launches) == 3 {
					selectedKind = "tor-compare-driver-failed"
				}
			}
			cmd.Env = envWithValue(cmd.Env, "ROUTERVPN_TOR_TEST_CHILD", selectedKind)
		}
		return cmd, err
	}
	f.driver.comparison = func(a *app, launch *desktopNodeLaunch, target string) (mobiletor.Comparison, error) {
		c, err := newDesktopTorComparisonClient(a, launch, target)
		if c == nil {
			return nil, err
		}
		probe := &desktopTorComparisonProbeFixture{Comparison: c, target: target}
		fixture.probes = append(fixture.probes, probe)
		fixture.created <- c
		return probe, err
	}
	profile := f.a.profiles.Profiles[0]
	q := externalProfileConnectRequest{ProfileID: profile.ID, Execution: "auto", ExpectedSelectedNodeID: &f.a.profiles.SelectedID,
		ExpectedProfileTokens: map[string]string{profile.ID: publicProfileToken(profile), f.a.profiles.Profiles[1].ID: publicProfileToken(f.a.profiles.Profiles[1])}}
	driver, err := newDesktopTorComparisonDriver(f.a, profile, q, nil, f.driver)
	if err != nil {
		finish()
		t.Fatal(err)
	}
	fixture.driver = driver
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if driver.last != nil {
			_ = driver.last.Close(ctx)
		}
		finish()
		for _, launch := range fixture.launches {
			if launch.command != nil && launch.command.Process != nil {
				_ = launch.command.Process.Kill()
				<-desktopNodeProcessDone(launch)
			}
		}
	})
	return fixture
}

func desktopTorComparisonTestOptions() routechoice.Options {
	return routechoice.Options{Targets: comparisonTargets, StartupTimeout: 5 * time.Second, ProbeTimeout: time.Second, CleanupTimeout: 3 * time.Second, Preferred: routechoice.Local}
}

func TestDesktopTorComparisonDriverUsesActualLocalServerAndRetainedWinner(t *testing.T) {
	f := newDesktopTorComparisonDriverFixture(t, "tor-compare-driver")
	a := f.connection.a
	a.mu.Lock()
	before := cloneRouterProfileStore(a.profiles)
	err := a.persistProfilesLocked()
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, active, err := routechoice.Compare(ctx, f.driver.candidates, f.driver, desktopTorComparisonTestOptions())
	if err != nil || result.Winner == nil || result.Winner.Execution != routechoice.Server || result.Final == nil || result.Final.ScoreMS == nil || *result.Final.ScoreMS != 20 || len(result.Measurements) != 2 {
		t.Fatal("actual candidate comparison or exact two-operand average failed", result, err)
	}
	if *result.Measurements[0].ScoreMS != 30 || *result.Measurements[1].ScoreMS != 20 || len(f.launches) != 3 || len(f.probes) != 3 {
		t.Fatal("comparison did not run Local, Server, then the proved winner", result, len(f.launches), len(f.probes))
	}
	for i, launch := range f.launches {
		want := "server"
		if i == 0 {
			want = "local"
		}
		if desktopTorExecution(launch.tor.expected.Execution) != want || f.probes[i].target != result.Target || f.probes[i].last != 1 || f.probes[i].external != 1 || f.probes[i].verifies != 1 {
			t.Fatal("actual native capture or final repeat differed from the round", i, launch.tor.expected.Execution, f.probes[i])
		}
		if i < 2 && !desktopNodeProcessExited(launch) {
			t.Fatal("a trial process remained alive beside the winner")
		}
	}
	winner, ok := active.(*desktopTorComparisonSession)
	if !ok || winner != f.driver.last || winner.Identity() == "" || a.state.Connected {
		t.Fatal("trial driver published Connected or lost the final candidate")
	}
	proof, err := winner.retainPath(ctx)
	if err != nil || proof.Policy.Execution != "server" || desktopNodeProcessExited(winner.prelaunch.workspace) || winner.Identity() == "" {
		t.Fatal("measurement cleanup replaced the proved winner", err)
	}
	afterBytes, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil || string(beforeBytes) != string(afterBytes) || !reflect.DeepEqual(before, a.profiles) || a.state.Connected {
		t.Fatal("a trial or measurement drain changed saved source or Connected state", err)
	}
	if err := winner.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopTorComparisonDriverDisqualifiesFailuresAndRepeatsFinalFallback(t *testing.T) {
	for _, scenario := range []struct {
		kind, winner string
		count        int
	}{
		{"tor-compare-driver-local-failed", "server", 3},
		{"tor-compare-driver-final-failure", "local", 4},
		{"tor-compare-driver-failed", "", 2},
	} {
		t.Run(scenario.kind, func(t *testing.T) {
			f := newDesktopTorComparisonDriverFixture(t, scenario.kind)
			before := cloneRouterProfileStore(f.connection.a.profiles)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			result, active, err := routechoice.Compare(ctx, f.driver.candidates, f.driver, desktopTorComparisonTestOptions())
			if scenario.winner == "" {
				if !errors.Is(err, routechoice.ErrNoWinner) || active != nil || result.Winner != nil {
					t.Fatal("two invalid paths produced a winner", result, err)
				}
				for _, measurement := range result.Measurements {
					if measurement.Eligible || measurement.ScoreMS != nil {
						t.Fatal("failed path received a score", measurement)
					}
				}
			} else if err != nil || result.Winner == nil || string(result.Winner.Execution) != scenario.winner || result.Final == nil || !result.Final.Eligible {
				t.Fatal("final repeat did not retain the lowest still-valid candidate", result, err)
			}
			if len(f.launches) != scenario.count || !reflect.DeepEqual(before, f.connection.a.profiles) || f.connection.a.state.Connected {
				t.Fatal("trial count, saved source or Connected state changed", len(f.launches))
			}
			for _, probe := range f.probes {
				if probe.target != result.Target {
					t.Fatal("fallback chose another external endpoint")
				}
			}
			if active != nil && active.Close(ctx) != nil {
				t.Fatal("winner cleanup failed")
			}
		})
	}
}

func TestDesktopTorComparisonDriverCancellationJoinsCandidateBeforeReturning(t *testing.T) {
	f := newDesktopTorComparisonDriverFixture(t, "tor-compare-held")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := routechoice.Compare(ctx, f.driver.candidates, f.driver, desktopTorComparisonTestOptions())
		done <- err
	}()
	var captured *desktopTorComparisonClient
	select {
	case captured = <-f.created:
	case <-time.After(5 * time.Second):
		t.Fatal("candidate did not reach captured comparison preparation")
	}
	waitDesktopTorComparisonAction(t, captured, mobiletor.DesktopTorCompareLast)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled comparison succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("comparison cancellation did not join its exact candidate")
	}
	if len(f.launches) != 1 || !desktopNodeProcessExited(f.launches[0]) || captured.claimed() || f.connection.a.state.Connected {
		t.Fatal("cancelled trial retained an active path or started a replacement")
	}
}

func TestDesktopTorComparisonDriverCannotStopReplacementOrChangeTarget(t *testing.T) {
	f := newDesktopTorComparisonDriverFixture(t, "tor-compare-driver")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	active, err := f.driver.OpenTarget(ctx, f.driver.candidates[0], comparisonTargets[0])
	if err != nil {
		t.Fatal(err)
	}
	real := active.(*desktopTorComparisonSession)
	if d, err := active.ProbeExternal(ctx, comparisonTargets[1]); d != 0 || err == nil {
		t.Fatal("candidate substituted approved targets")
	}
	replacement := exec.Command("explicit-unstarted-replacement-fixture")
	a := f.connection.a
	a.mu.Lock()
	a.cmd = replacement
	a.mu.Unlock()
	if err := real.Close(ctx); err == nil || a.cmd != replacement || desktopNodeProcessExited(real.prelaunch.workspace) {
		t.Fatal("old cleanup changed a replacement owner or discarded its pending process", err)
	}
	a.mu.Lock()
	a.cmd = real.command
	a.mu.Unlock()
	if err := real.Close(ctx); err != nil {
		t.Fatal("retained old candidate could not be drained", err)
	}
}

func TestDesktopTorComparisonDriverTeardownFailurePreventsNextCandidate(t *testing.T) {
	f := newDesktopTorComparisonDriverFixture(t, "tor-compare-driver")
	create := f.driver.runtime.comparison
	f.driver.runtime.comparison = func(a *app, launch *desktopNodeLaunch, target string) (mobiletor.Comparison, error) {
		probe, err := create(a, launch, target)
		if fixture, ok := probe.(*desktopTorComparisonProbeFixture); ok {
			fixture.closeFailure = true
		}
		return probe, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, active, err := routechoice.Compare(ctx, f.driver.candidates, f.driver, desktopTorComparisonTestOptions())
	if !errors.Is(err, routechoice.ErrTeardown) || active == nil || len(f.launches) != 1 {
		t.Fatal("unfinished cleanup admitted another candidate or lost its owner", err, len(f.launches))
	}
	if err := active.Close(ctx); err != nil {
		t.Fatal("failed cleanup could not retry its exact candidate", err)
	}
}

func TestDesktopTorComparisonDriverFreezesRequestAndRejectsSourceChanges(t *testing.T) {
	f := newDesktopTorComparisonDriverFixture(t, "tor-compare-driver")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := f.driver.Open(ctx, f.driver.candidates[0]); err == nil {
		t.Fatal("targetless startup bypassed round selection")
	}
	profile := f.connection.a.profiles.Profiles[0]
	q := externalProfileConnectRequest{ProfileID: profile.ID, Execution: "auto", ExpectedSelectedNodeID: &profile.ID,
		ExpectedProfileTokens: map[string]string{profile.ID: publicProfileToken(profile), f.connection.a.profiles.Profiles[1].ID: publicProfileToken(f.connection.a.profiles.Profiles[1])}}
	driver, err := newDesktopTorComparisonDriver(f.connection.a, profile, q, nil, f.connection.driver)
	if err != nil {
		t.Fatal(err)
	}
	*q.ExpectedSelectedNodeID = "replacement"
	q.ExpectedProfileTokens[driver.profile.ID] = strings.Repeat("0", 64)
	if err := driver.current(); err != nil {
		t.Fatal("caller mutation changed captured request", err)
	}
	f.connection.a.mu.Lock()
	f.connection.a.profiles.Profiles[0].DNSPort++
	f.connection.a.mu.Unlock()
	if active, err := driver.OpenTarget(ctx, driver.candidates[0], comparisonTargets[0]); err == nil || active != nil || f.connection.commands != 0 {
		t.Fatal("changed resolver source reached native startup", err)
	}
}
