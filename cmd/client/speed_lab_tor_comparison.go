package main

import (
	"context"
	"errors"
	"reflect"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/routechoice"
)

type speedLabTorComparisonPreparation struct {
	runtime  desktopTorConnectRuntime
	paths    map[routechoice.Execution]*speedLabTorPreparation
	failures map[routechoice.Execution]error
}

// Prepare both concrete candidates while the previous VPN and full saved
// configuration remain intact. A missing native candidate receives no score;
// if neither can be prepared, no live connection has to be disturbed.
func (a *app) prepareSpeedLabTorComparison(q speedLabRequest, profile common.RouterProfile, runtime desktopTorConnectRuntime) (_ *speedLabTorPreparation, failure error) {
	comparison := &speedLabTorComparisonPreparation{runtime: runtime,
		paths: make(map[routechoice.Execution]*speedLabTorPreparation), failures: make(map[routechoice.Execution]error)}
	var prepared *speedLabTorPreparation
	defer func() {
		if failure != nil {
			for _, candidate := range comparison.paths {
				failure = errors.Join(failure, candidate.releaseUnused())
			}
		}
	}()
	for _, execution := range []routechoice.Execution{routechoice.Local, routechoice.Server} {
		choice := q
		choice.Execution = string(execution)
		candidate, err := a.prepareSpeedLabTorPathWithRuntime(choice, profile, nil, runtime)
		if err != nil {
			comparison.failures[execution] = err
			continue
		}
		comparison.paths[execution] = candidate
		entry := candidate.selection.predecessor
		if entry == nil || entry.native == nil || !entry.native.IsRouter() {
			return nil, errors.New("Tor Speed Lab Compare requires an authenticated private Router entry")
		}
		candidate.selection.preference = "auto"
		if prepared == nil {
			copy := *candidate
			prepared = &copy
			prepared.comparison, prepared.request = comparison, speedLabTorRequest(q, profile)
			continue
		}
		local, other := cloneRouterProfile(prepared.selection.policy), cloneRouterProfile(candidate.selection.policy)
		local.MultihopExecution, other.MultihopExecution = "", ""
		if !reflect.DeepEqual(local, other) || candidate.operation != prepared.operation || candidate.temporary != prepared.temporary ||
			candidate.sourceToken != prepared.sourceToken || candidate.selection.profileToken != prepared.selection.profileToken ||
			entry.profileToken != prepared.selection.predecessor.profileToken || entry.assetsSHA256 != prepared.selection.predecessor.assetsSHA256 || entry.mode != prepared.selection.predecessor.mode {
			return nil, errors.New("Tor Speed Lab candidates differ in captured source, entry, resolver or protection policy")
		}
	}
	if prepared == nil {
		return nil, errors.Join(errors.New("neither Tor Speed Lab candidate could be prepared"), comparison.failures[routechoice.Local], comparison.failures[routechoice.Server])
	}
	if err := prepared.current(a, false); err != nil {
		return nil, err
	}
	return prepared, nil
}

func (a *app) startPreparedSpeedLabTorComparison(q speedLabRequest, profile common.RouterProfile, prepared *speedLabTorPreparation) (path speedLabPath, failure error) {
	comparison := prepared.comparison
	if comparison == nil || prepared.temporary == nil || prepared.current(a, true) != nil {
		return path, errors.New("Tor Speed Lab Compare lost its prepared temporary owner")
	}
	id, err := randomHex(16)
	if err != nil {
		return path, err
	}
	driver := &desktopTorComparisonDriver{app: a, profile: cloneRouterProfile(profile), request: cloneDesktopTorConnectRequest(prepared.request),
		operation: prepared.operation, selected: profile.ID, network: prepared.temporary.network, runtime: comparison.runtime,
		temporary: prepared.temporary, selections: make(map[routechoice.Execution]*desktopTorSelection),
		prepared: make(map[routechoice.Execution]*speedLabTorPreparation), prepareFailures: comparison.failures}
	ctx, cancel := context.WithTimeout(prepared.operation, 8*time.Minute)
	defer cancel()
	for _, execution := range []routechoice.Execution{routechoice.Local, routechoice.Server} {
		driver.candidates = append(driver.candidates, routechoice.Candidate{Execution: execution, Transport: profile.External.Protocol,
			EntryID: prepared.selection.predecessor.entry.ID, ExitID: profile.ID})
		if candidate := comparison.paths[execution]; candidate != nil {
			candidate.selection.adoption = ctx
			driver.selections[execution], driver.prepared[execution] = candidate.selection, candidate
		}
	}
	progress := &comparisonOwner{value: routeComparisonProgress{ID: id, RequestID: q.ComparisonRequestID, Stage: "starting", Measurements: []routechoice.Measurement{},
		LastNodeMeasurement: "tor-last-relay-http", ExternalMeasurement: "same-captured-endpoint-http"}}
	desktopComparisons.Store(a, progress)
	var active routechoice.Session
	defer func() {
		if failure != nil && active != nil {
			cleanup, cancelCleanup := context.WithTimeout(context.Background(), 30*time.Second)
			failure = errors.Join(failure, active.Close(cleanup))
			cancelCleanup()
		}
		progress.mu.Lock()
		progress.value.Complete = true
		if failure != nil {
			progress.value.Stage, progress.value.Failure = "failed", failure.Error()
		} else {
			progress.value.Stage, progress.value.Execution = "selected", path.Execution
		}
		progress.mu.Unlock()
	}()
	if err := driver.current(); err != nil {
		return path, err
	}
	base := desktopExternalEntryBase(prepared.selection.predecessor.mode)
	sessionTrackerFor(a).declareRequest("speed-lab:external", base)
	if err := a.speedLabStopRuntime(true); err != nil {
		return path, err
	}
	options := routechoice.Options{Targets: append([]string(nil), comparisonTargets...), StartupTimeout: 2 * time.Minute,
		ProbeTimeout: 10 * time.Second, CleanupTimeout: 30 * time.Second, Preferred: routechoice.Local,
		Notify: progress.observe}
	result, active, err := routechoice.Compare(ctx, driver.candidates, driver, options)
	if err != nil {
		return path, err
	}
	winner, ok := active.(*desktopTorComparisonSession)
	if !ok || winner == nil || winner != driver.last || result.Winner == nil || result.Final == nil || !result.Final.Eligible || result.Final.ScoreMS == nil ||
		*result.Winner != winner.candidate || result.Final.Candidate != winner.candidate || result.Target != winner.target || winner.Identity() == "" {
		return path, errors.New("Tor Speed Lab winner differs from its repeated path measurements")
	}
	cleanup, cancelCleanup := context.WithTimeout(ctx, 30*time.Second)
	proof, err := winner.retainPath(cleanup)
	cancelCleanup()
	if err != nil {
		return path, err
	}
	if err := driver.current(); err != nil {
		return path, err
	}
	if ctx.Err() != nil || desktopTorExecution(proof.Policy.Execution) != string(winner.candidate.Execution) {
		return path, errors.New("Tor Speed Lab final proof belongs to a cancelled or different execution")
	}
	launch := winner.prelaunch.workspace
	a.mu.Lock()
	if !a.speedLabOwnerCurrentLocked(prepared.temporary) || prepared.temporary.runtime != winner.command || a.cmd != winner.command ||
		desktopTorOperationCurrentLocked(a, prepared.operation, profile.ID) != nil || winner.selection.currentLocked(a) != nil {
		a.mu.Unlock()
		return path, errors.New("Tor Speed Lab Compare cannot adopt a replaced temporary runtime")
	}
	a.state.Connected, a.state.Phase = true, "connected"
	captureDesktopMTUBaselineLocked(a, launch)
	a.mu.Unlock()
	a.monitorDesktopTorRuntime(launch)
	if _, err := waitForSpeedLabConnectedIdentity(a, 2500*time.Millisecond); err != nil {
		return path, err
	}
	path = speedLabPath{Scope: "temporary", Topology: "external", Temporary: true, NodeID: profile.ID, NodeName: profile.Name,
		EntryID: winner.selection.predecessor.entry.ID, EntryName: winner.selection.predecessor.entry.Name, EntryMode: winner.selection.predecessor.mode,
		ExitID: profile.ID, ExitName: profile.Name, RuntimeMode: launch.mode, LogicalMode: "external-node", Base: base,
		ExternalProtocol: profile.External.Protocol, Execution: string(winner.candidate.Execution), StartedAt: launch.tor.started,
		Comparison: &result, LastNodeMeasurement: "tor-last-relay-http", ExternalMeasurement: "same-captured-endpoint-http",
		Description: "temporary Tor path selected by last-relay and same-endpoint HTTP response times, with both winner probes repeated"}
	return path, nil
}
