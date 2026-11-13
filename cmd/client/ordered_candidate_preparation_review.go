package main

import (
	"context"
	"errors"
	"os"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
)

// Mutable job fields use the existing candidate control mutex. Its native and
// physical owners are private retained capabilities, never reconstructed from
// the HTTP response or a persisted result.
type orderedCandidatePreparedJob struct {
	view             *orderedCandidatePreparedView
	preparation      *orderedCandidatePreparation
	results          []hopmeasure.CandidateStatus
	failures         []viaEntryCandidateError
	current, failure string
	accepted         bool
	nativeDown       bool
	expires          time.Time
	saved            *connectionProfileRecord
	savedCandidate   string
	savedRequest     *orderedCandidateSaveRequest
	cleanupError     string
}

// This narrow source-file check does not acquire app.mu, so the guarded Save
// can retain its original catalog transaction across the final atomic rename.
func (p *orderedCandidatePreparation) savedInventoryFilesCurrent(ctx context.Context) error {
	if p == nil || p.inventory == nil {
		return errors.New("candidate saved file inventory is unavailable")
	}
	for _, file := range p.inventory.files {
		info, err := os.Lstat(file.path)
		if err != nil || !sameDesktopCandidateSourceFile(file, desktopCandidateSourceFile{file.path, info}) {
			return errors.New("candidate original saved file was replaced")
		}
	}
	for _, asset := range p.inventory.assets {
		if err := ctx.Err(); err != nil {
			return err
		}
		files, err := readDesktopNodeAssets(p.inventory.launch.root, asset.id, asset.mode)
		valid := err == nil && viaEntryAssetDigest(files) == asset.digest
		clearViaEntryAssets(files)
		if !valid {
			return errors.New("candidate original saved assets changed")
		}
	}
	return ctx.Err()
}

// Caller holds this original owner's closeMu and app.mu. A saved source view,
// a cancelled HTTP request, or an unjoined native worker cannot create DOWN.
func (p *orderedCandidatePreparation) reviewBoundaryLocked() error {
	if p == nil || p.app == nil || !p.nativeDown || p.down || p.invalidated.Load() || p.releaseLease != nil ||
		p.pending != nil || p.app.candidatePreparation != p || p.app.connectionContext != nil ||
		!orderedCandidatePreparationDownLocked(p.app) || p.selection.Native == nil || p.selection.Native.chain == nil ||
		[3]bool{p.app.state.DAITA, p.app.state.Jumbo, p.app.state.Socks} != [3]bool{p.state.DAITA, p.state.Jumbo, p.state.Socks} {
		return errors.New("candidate choices require the original completed native DOWN boundary")
	}
	if p.workerDone == nil {
		return errors.New("candidate choices have no original joined measurement worker")
	}
	select {
	case <-p.workerDone:
	default:
		return errors.New("candidate choices preceded the original measurement worker join")
	}
	revision, err := p.app.candidateCatalogRevisionLocked()
	if err != nil || revision != p.revision || !p.selection.Native.chain.profilesCurrent(p.selection.Control, p.app.profiles.Profiles) {
		return errors.Join(err, errors.New("candidate review changed its original saved graph"))
	}
	return nil
}

// Caller holds owner.closeMu throughout; cancellation may mark the owner but
// cannot close/reopen this observer during an actual Save or status check.
func (p *orderedCandidatePreparation) reviewCurrent(ctx context.Context) (failure error) {
	defer func() {
		if failure != nil && p != nil {
			p.invalidate()
		}
	}()
	if ctx == nil || ctx.Err() != nil || p == nil || p.runtime == nil || p.runtime.preparation != p ||
		p.runtime.cohort == nil || p.runtime.transition || p.runtime.receipt != nil {
		return errors.New("candidate review has no original DOWN physical observer")
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return err
	}
	err := p.reviewBoundaryLocked()
	p.app.mu.Unlock()
	if err != nil {
		return err
	}
	if err := p.savedSourcesCurrent(ctx); err != nil {
		return err
	}
	if err := p.runtime.cohort.CurrentContext(ctx); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return err
	}
	defer p.app.mu.Unlock()
	return errors.Join(p.reviewBoundaryLocked(), ctx.Err())
}

func (p *orderedCandidatePreparation) finishForReview(job *orderedCandidatePreparedJob) error {
	if p == nil || job == nil || job.preparation != p || p.runtime == nil || p.owner.prepared != job {
		return errors.New("candidate completion lost its original retained job")
	}
	if err := p.runtime.current(p.operation); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := desktopnetwork.LockContext(ctx, &p.owner.closeMu); err != nil {
		return err
	}
	defer p.owner.closeMu.Unlock()
	if err := p.retireNative(ctx); err != nil {
		return err
	}
	p.cancel() // Work is joined; the independent physical observer remains owned.
	if err := p.reviewCurrent(ctx); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &p.control.mu); err != nil {
		return err
	}
	defer p.control.mu.Unlock()
	if p.control.owner != p.owner || p.owner.cancelled || !p.owner.running || len(job.results) == 0 || ctx.Err() != nil {
		return errors.New("candidate completion was cancelled or has no successful original rows")
	}
	valid := job.results[:0]
	for _, result := range job.results {
		if validateOrderedCandidatePreparedStatus(p, result.CandidateID, result, time.Now()) == nil {
			valid = append(valid, result)
		}
	}
	job.results = valid
	if len(valid) == 0 {
		return errors.New("candidate rows expired before original native DOWN")
	}
	job.accepted, job.nativeDown, job.expires, job.current = true, true, orderedCandidateResultExpiry(valid), ""
	finished := false
	p.finishOnce.Do(func() {
		p.owner.running = false
		close(p.owner.done)
		p.app.operationMu.Unlock()
		finished = true
	})
	if !finished {
		return errors.New("candidate result completion was already consumed")
	}
	go expireOrderedCandidatePreparedJob(p.control, p.owner, job)
	return nil
}

func expireOrderedCandidatePreparedJob(control *viaEntryControl, owner *viaEntryOwner, job *orderedCandidatePreparedJob) {
	timer := time.NewTimer(time.Until(job.expires))
	defer timer.Stop()
	<-timer.C
	control.mu.Lock()
	if owner.prepared != job || owner.drained {
		control.mu.Unlock()
		return
	}
	job.accepted = false
	if job.saved == nil {
		job.failure = "Candidate results expired; retest before Save."
	}
	owner.cancel()
	control.mu.Unlock()
	err := cleanupViaEntryOwner(control, owner)
	control.mu.Lock()
	if err != nil {
		job.cleanupError = "Original observer cleanup is pending; Cancel retries this same owner."
	}
	control.mu.Unlock()
}
