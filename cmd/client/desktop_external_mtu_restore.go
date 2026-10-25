package main

import (
	"context"
	"errors"
	"os"
	"time"
)

func captureDesktopMTURestore(launch *desktopNodeLaunch) (int, error) {
	record, err := readDesktopMTURecord(launch)
	if err != nil {
		return 0, err
	}
	if record.Status.Running || record.WaitingCommit || record.Status.EffectiveMTU < 1280 || record.Status.EffectiveMTU > 9000 {
		return 0, errors.New("native MTU must finish its exact rollback before a restoration snapshot")
	}
	return record.Status.EffectiveMTU, nil
}

func (a *app) waitDesktopMTUIdle(ctx context.Context, launch *desktopNodeLaunch) (desktopMTURecord, error) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := a.readDesktopExternalProof(launch); err != nil {
			return desktopMTURecord{}, err
		}
		record, err := readDesktopMTURecord(launch)
		if err == nil {
			if record.Status.Running || record.WaitingCommit {
				return record, errors.New("another native MTU operation has not drained")
			}
			return record, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return record, err
		}
		select {
		case <-ctx.Done():
			return record, ctx.Err()
		case <-ticker.C:
		}
	}
}

// Speed Lab calls this while it still owns the temporary connection transaction
// and MTU measurement hold. The original saved Auto policy remains untouched;
// one captured value is re-proved through the restored winner, never Compare.
func (a *app) restoreDesktopCapturedMTU(parent context.Context, launch *desktopNodeLaunch) error {
	launch.external.mu.Lock()
	owner := launch.external.mtu
	launch.external.mu.Unlock()
	if owner == nil || owner.restoreMTU == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	identifier, err := randomHex(16)
	if err != nil {
		return err
	}
	initial, err := a.waitDesktopMTUIdle(ctx, launch)
	if err != nil {
		return err
	}
	owner.mu.Lock()
	owner.generation = initial.Generation + 1
	generation, target := owner.generation, owner.restoreMTU
	owner.mu.Unlock()
	request := desktopMTURequest{Schema: 1, Session: launch.external.session, SourceSHA256: launch.external.expected.SourceSHA256, ConfigSHA256: launch.external.expected.ConfigSHA256, Generation: generation, Request: identifier, Force: true, RestoreMTU: target}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	issued, completed := false, false
	defer func() {
		if issued && !completed {
			_ = a.cancelDesktopMTU(launch, desktopMTUControlFor(request))
		}
	}()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := a.readDesktopExternalProof(launch); err != nil {
			return err
		}
		record, err := readDesktopMTURecord(launch)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && !issued {
			if record.Status.Running || record.WaitingCommit {
				return errors.New("restored native path already has another MTU operation")
			}
			if record.Status.EffectiveMTU == target {
				owner.mu.Lock()
				owner.generation--
				owner.restoreMTU = 0
				owner.mu.Unlock()
				return nil
			}
			if !record.Requested {
				return errors.New("fixed or Jumbo MTU differs from captured restoration value")
			}
			if err = writeDesktopMTUControl(launch, "mtu-request.json", request); err != nil {
				return err
			}
			issued = true
		}
		if err == nil && issued && record.Generation == generation && record.Status.Request == identifier && record.Status.Complete && !record.Status.Running {
			if !record.Status.Restored || record.Status.Source != "restored-captured-system-tun" || record.RestoredMTU != target || record.Status.EffectiveMTU != target {
				return errors.New("captured live MTU failed its fresh restored-path verification")
			}
			if _, err := a.readDesktopExternalProof(launch); err != nil {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			owner.mu.Lock()
			owner.restoreMTU = 0
			owner.mu.Unlock()
			completed = true
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
