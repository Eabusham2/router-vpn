package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"
)

type desktopPathRequest struct {
	Schema       int    `json:"schema"`
	Session      string `json:"session_id"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	Generation   uint64 `json:"generation"`
	Request      string `json:"request_id"`
}

type desktopPathRecord struct {
	desktopPathRequest
	Complete  bool  `json:"complete"`
	Verified  bool  `json:"verified"`
	Cancelled bool  `json:"cancelled"`
	CheckedAt int64 `json:"checked_at,omitempty"`
}

func decodeDesktopPathRecord(launch *desktopNodeLaunch, raw []byte) (desktopPathRecord, error) {
	var record desktopPathRecord
	bad := errors.New("native fresh-path receipt differs from its captured request or graph")
	identity, err := capturedDesktopMeasurementRuntime(launch)
	if err != nil || len(raw) == 0 || len(raw) > 4096 || decodeRelayControlJSON(raw, &record) != nil {
		return record, bad
	}
	if record.Schema != 1 || record.Session != identity.session || record.SourceSHA256 != identity.source || record.ConfigSHA256 != identity.config {
		return record, bad
	}
	if record.Generation == 0 {
		if record.Request != "" || !record.Complete || record.Verified || record.Cancelled || record.CheckedAt != 0 {
			return record, bad
		}
	} else if !desktopMTURequestPattern.MatchString(record.Request) || record.Verified && (!record.Complete || record.Cancelled || record.CheckedAt <= 0) || !record.Verified && record.CheckedAt != 0 {
		return record, bad
	}
	return record, nil
}

func readDesktopPathRecord(launch *desktopNodeLaunch) (desktopPathRecord, error) {
	raw, err := readDesktopRuntimeFile(launch, "path-status.json", 4096)
	if err != nil {
		return desktopPathRecord{}, err
	}
	return decodeDesktopPathRecord(launch, raw)
}

// This cleanup-only read may follow a renamed old workspace through its pinned
// handle. It can establish that the old worker drained, never attest a new path
// or write to a replacement directory. Adoption always uses the strict reader.
func readDesktopPathDrainRecord(launch *desktopNodeLaunch) (desktopPathRecord, error) {
	raw, err := readDesktopPathDrainFile(launch, "path-status.json")
	if err != nil {
		return desktopPathRecord{}, err
	}
	return decodeDesktopPathRecord(launch, raw)
}

func readDesktopPathDrainFile(launch *desktopNodeLaunch, name string) ([]byte, error) {
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if launch.directoryRoot == nil || launch.directoryInfo == nil || name != "path-status.json" && name != "stopped.json" {
		return nil, errors.New("native path cleanup lost its workspace handle")
	}
	actual, err := launch.directoryRoot.Stat(".")
	if err != nil || !os.SameFile(launch.directoryInfo, actual) {
		return nil, errors.New("native path cleanup belongs to another workspace")
	}
	return readDesktopRuntimeSnapshot(launch.directoryRoot, name, 4096)
}

func desktopPathNativeClosed(launch *desktopNodeLaunch) bool {
	owner := launch.external
	owner.mu.Lock()
	acknowledged := owner.stopAcknowledged
	owner.mu.Unlock()
	if acknowledged {
		return true
	}
	raw, err := readDesktopPathDrainFile(launch, "stopped.json")
	var closed desktopExternalStop
	return err == nil && decodeRelayControlJSON(raw, &closed) == nil && closed.Schema == 1 && closed.SessionID == owner.session && closed.SourceSHA256 == owner.expected.SourceSHA256 && closed.Closed
}

func writeDesktopPathRequest(launch *desktopNodeLaunch, name string, request desktopPathRequest) error {
	if name != "path-request.json" && name != "path-cancel.json" {
		return errors.New("invalid native fresh-path command")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	err = writeDesktopRuntimeFile(launch, name, raw, true)
	if err == nil {
		return nil
	}
	// Native completion may consume the exact input before the writer's final
	// identity check. Only the matching generation and nonce can acknowledge it.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		record, readErr := readDesktopPathRecord(launch)
		if readErr == nil && record.desktopPathRequest == request && (name == "path-request.json" || record.Complete && record.Cancelled) {
			return nil
		}
		if desktopExternalDirectoryCurrent(launch) != nil {
			return err
		}
		select {
		case <-deadline.C:
			return err
		case <-tick.C:
		}
	}
}

// verifyDesktopExternalCurrentPath is independent of MTU selection and Compare.
// A fresh nonce forces one synchronous check in the captured native process;
// cached proof.json health alone cannot authorize a measurement phase or save.
func (a *app) verifyDesktopExternalCurrentPath(parent context.Context, launch *desktopNodeLaunch) (failure error) {
	owner, err := capturedDesktopMeasurementRuntime(launch)
	if err != nil || parent == nil {
		return errors.New("fresh path verification has no captured native owner")
	}
	budget := 8 * time.Second
	if launch.tor != nil {
		budget = 35 * time.Second // Native Tor fresh proof is bounded to 30s.
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !owner.pathMu.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	defer owner.pathMu.Unlock()
	if *owner.pathFailed {
		return errors.New("native fresh-path control is retired; reconnect before measuring")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.waitDesktopMeasurementProof(ctx, launch); err != nil {
			return err
		}
		record, err := readDesktopPathRecord(launch)
		if err == nil {
			if !record.Complete || record.Generation != *owner.pathGeneration || *owner.pathGeneration == ^uint64(0) {
				return errors.New("native fresh-path generation has another owner")
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	identifier, err := randomHex(16)
	if err != nil {
		return err
	}
	*owner.pathGeneration++
	request := desktopPathRequest{Schema: 1, Session: owner.session, SourceSHA256: owner.source, ConfigSHA256: owner.config, Generation: *owner.pathGeneration, Request: identifier}
	drained := false
	issuedAt := time.Now()
	defer func() {
		if drained {
			return
		}
		if err := a.drainDesktopPathRequest(launch, request); err != nil {
			*owner.pathFailed = true
			failure = errors.Join(failure, err)
		}
	}()
	if err = writeDesktopPathRequest(launch, "path-request.json", request); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.waitDesktopMeasurementProof(ctx, launch); err != nil {
			return err
		}
		record, err := readDesktopPathRecord(launch)
		if err != nil {
			return err
		}
		if record.Generation == request.Generation {
			if record.desktopPathRequest != request {
				return errors.New("fresh native path result belongs to a different request")
			}
			if record.Complete {
				drained = true
				now := time.Now()
				if !record.Verified || record.Cancelled || record.CheckedAt < issuedAt.UnixMilli() || record.CheckedAt > now.Add(time.Second).UnixMilli() || record.CheckedAt < now.Add(-2*time.Second).UnixMilli() {
					return errors.New("captured native path failed its fresh verification")
				}
				if err := a.waitDesktopMeasurementProof(ctx, launch); err != nil {
					return err
				}
				return ctx.Err()
			}
		} else if record.Generation+1 != request.Generation {
			return errors.New("fresh native path result has a stale or replaced generation")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func (a *app) drainDesktopPathRequest(launch *desktopNodeLaunch, request desktopPathRequest) error {
	// A read-only result that already completed is drained even when request
	// cancellation won the host race. It is deliberately discarded by the caller.
	if record, err := readDesktopPathDrainRecord(launch); err == nil && record.desktopPathRequest == request && record.Complete {
		return nil
	}
	_ = writeDesktopPathRequest(launch, "path-cancel.json", request)
	drainBudget := 4 * time.Second
	if launch != nil && launch.tor != nil {
		// Cancellation joins the connection-owned Tor control inventory (5s)
		// before the native worker can publish its terminal acknowledgement.
		drainBudget = 8 * time.Second
	}
	deadline := time.NewTimer(drainBudget)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		record, err := readDesktopPathDrainRecord(launch)
		if err == nil && record.desktopPathRequest == request && record.Complete {
			return nil
		}
		if desktopMeasurementNativeClosed(launch) {
			return nil // Exact native close is published only after worker drain.
		}
		select {
		case <-deadline.C:
			return a.retireDesktopPathOwner(launch)
		case <-tick.C:
		}
	}
}

func (a *app) retireDesktopPathOwner(launch *desktopNodeLaunch) error {
	// Never substitute whichever process is selected after this request. The
	// existing stop handshake checks the captured command and private lease owner.
	if err := a.prepareDesktopMeasurementStop(launch); err != nil {
		return errors.Join(errors.New("fresh path cancellation is still draining; captured protection and cleanup ownership retained"), err)
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	select {
	case <-desktopMeasurementProcessDone(launch):
		if !desktopMeasurementNativeClosed(launch) {
			return errors.New("native wrapper exited without proof-worker drain acknowledgement; captured protection and cleanup ownership retained")
		}
		a.mu.Lock()
		if a.cmd == launch.command {
			a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", "Native path verification did not drain; its captured runtime was retired with protection retained"
		}
		a.mu.Unlock()
		return errors.New("native fresh-path request did not drain normally; captured runtime was retired")
	case <-deadline.C:
		return errors.New("fresh path cancellation is still draining; captured native process and protection ownership retained")
	}
}

func verifySpeedLabPath(ctx context.Context, a *app, identity speedLabPathIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSpeedLabIdentity(a, identity); err != nil {
		return err
	}
	if identity.External != nil {
		if err := a.verifyDesktopExternalCurrentPath(ctx, identity.External); err != nil {
			return err
		}
	}
	if err := validateSpeedLabIdentity(a, identity); err != nil {
		return err
	}
	return ctx.Err()
}

func (s desktopMTUSnapshot) verifyCurrentPath(ctx context.Context, a *app) error {
	if err := s.currentContext(ctx, a); err != nil {
		return err
	}
	if err := a.verifyDesktopExternalCurrentPath(ctx, s.launch); err != nil {
		return err
	}
	return s.currentContext(ctx, a)
}
