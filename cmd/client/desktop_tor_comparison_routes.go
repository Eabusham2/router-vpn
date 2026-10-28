package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/routechoice"
)

// Public Connect already holds the connection transaction and rejects an
// existing connected VPN. Trials therefore cannot displace a live connection.
// They preserve the saved node, full policy and Startup Last until a winner
// earns two fresh operands and the normal durable choice/adoption transaction.
func (a *app) torBridgeCompareSelectionOwned(w http.ResponseWriter, profile common.RouterProfile, q externalProfileConnectRequest, startup *startupPolicyCapture, runtime desktopTorConnectRuntime) {
	driver, err := newDesktopTorComparisonDriver(a, profile, q, startup, runtime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := randomHex(16)
	if err != nil {
		http.Error(w, "could not allocate Tor comparison identity", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(driver.operation, 8*time.Minute)
	defer cancel()
	for _, selection := range driver.selections {
		selection.adoption = ctx
	}
	if runtime.requestContext != nil {
		if runtime.requestContext.Err() != nil {
			cancel()
		}
		stop := context.AfterFunc(runtime.requestContext, cancel)
		defer stop()
	}
	progress := &comparisonOwner{value: routeComparisonProgress{ID: id, Stage: "starting", Measurements: []routechoice.Measurement{},
		LastNodeMeasurement: "tor-last-relay-http", ExternalMeasurement: "same-captured-endpoint-http"}}
	desktopComparisons.Store(a, progress)
	finish := func(failure error, execution string) {
		progress.mu.Lock()
		defer progress.mu.Unlock()
		progress.value.Complete = true
		progress.value.Execution = execution
		if failure != nil {
			progress.value.Stage, progress.value.Failure = "failed", failure.Error()
		} else {
			progress.value.Stage = "selected"
		}
	}
	failed := func(cause error, active routechoice.Session, status int) {
		if active != nil {
			cleanup, cancelCleanup := context.WithTimeout(context.Background(), 30*time.Second)
			cleanupErr := active.Close(cleanup)
			cancelCleanup()
			if cleanupErr != nil {
				cause = errors.Join(cause, routechoice.ErrTeardown, cleanupErr)
				status = http.StatusInternalServerError
			}
		}
		finish(cause, "")
		a.mu.Lock()
		// A stale HTTP or native completion must not relabel another runtime.
		owned := a.connectionContext == driver.operation && a.profiles.SelectedID == driver.selected
		if owned && (a.cmd == nil || driver.last != nil && a.cmd == driver.last.command) {
			a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", cause.Error()
		}
		a.mu.Unlock()
		if owned {
			sessionTrackerFor(a).markRequestFailure(cause.Error())
		}
		http.Error(w, cause.Error(), status)
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return driver.current()
	}
	if err := check(); err != nil {
		failed(err, nil, http.StatusConflict)
		return
	}
	base := desktopExternalEntryBase(driver.selections[routechoice.Local].predecessor.mode)
	sessionTrackerFor(a).declareRequest("external-node", base)
	if err := a.stopModeWithIntent(true); err != nil {
		failed(err, nil, http.StatusInternalServerError)
		return
	}
	options := routechoice.Options{Targets: append([]string(nil), comparisonTargets...), StartupTimeout: 2 * time.Minute,
		ProbeTimeout: 10 * time.Second, CleanupTimeout: 30 * time.Second, Preferred: routechoice.Local,
		Notify: func(event routechoice.Event) {
			progress.mu.Lock()
			progress.value.Stage = event.Stage
			if event.Stage == "measured" && event.Result != nil {
				progress.value.Measurements = append(progress.value.Measurements, *event.Result)
			}
			progress.mu.Unlock()
		}}
	result, active, err := routechoice.Compare(ctx, driver.candidates, driver, options)
	if err != nil {
		failed(err, active, http.StatusBadGateway)
		return
	}
	winner, ok := active.(*desktopTorComparisonSession)
	if !ok || winner == nil || winner != driver.last || result.Winner == nil || result.Final == nil ||
		!result.Final.Eligible || result.Final.ScoreMS == nil || result.Final.Candidate != winner.candidate ||
		*result.Winner != winner.candidate || result.Target != winner.target || winner.Identity() == "" || check() != nil {
		failed(errors.New("Tor comparison winner changed before adoption"), active, http.StatusConflict)
		return
	}
	cleanup, cancelCleanup := context.WithTimeout(ctx, 30*time.Second)
	proof, err := winner.retainPath(cleanup)
	cancelCleanup()
	if err == nil {
		err = check()
	}
	if err != nil {
		failed(errors.Join(errors.New("Tor winner could not retain its proved path"), err), active, http.StatusConflict)
		return
	}
	saved, err := a.commitDesktopTorChoice(winner.selection, winner.prelaunch.workspace, q, startup, driver.operation, driver.selected, proof.Proof.IP)
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, errDesktopTorChoiceSave) {
			status = http.StatusInternalServerError
		}
		failed(err, active, status)
		return
	}
	// After persistence the source token deliberately changes. The adoption
	// owner checks that new durable identity; the old trial capture is retired.
	if err = ctx.Err(); err == nil {
		proof, err = saved.adopt(a)
	}
	if err != nil {
		failed(errors.Join(errors.New("Tor Compare choice was saved, but the runtime could not be retained"), err), active, http.StatusConflict)
		return
	}
	a.monitorDesktopTorRuntime(winner.prelaunch.workspace)
	a.startDesktopExternalAutomaticMTU(winner.prelaunch.workspace)
	finish(nil, string(winner.candidate.Execution))
	writeDesktopTorConnectedResponse(w, winner.selection, proof, result)
}
