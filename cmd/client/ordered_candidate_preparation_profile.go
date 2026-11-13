package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
)

// The identity returned by the original atomic rename is the sole rollback
// authority. A later writer's bytes, inode or generation cannot be overwritten.
type orderedCandidateProfilePublication struct {
	path          string
	published     os.FileInfo
	before, after []byte
}

func (write *orderedCandidateProfilePublication) current() error {
	if write == nil || write.published == nil {
		return errors.New("candidate profile append has no original publication")
	}
	before, err := os.Lstat(write.path)
	if err != nil || !desktopComparisonSameFile(write.published, before) {
		return errors.New("candidate profile append was replaced; newer writer retained")
	}
	raw, err := readPrivateRegular(write.path, connectionProfileStoreMaxBytes)
	equal := err == nil && bytes.Equal(raw, write.after)
	clear(raw)
	after, err := os.Lstat(write.path)
	if !equal || err != nil || !desktopComparisonSameFile(write.published, after) {
		return errors.New("candidate profile append changed; newer writer retained")
	}
	return nil
}

func (write *orderedCandidateProfilePublication) rollback() error {
	if err := write.current(); err != nil {
		return err
	}
	_, err := atomicWritePrivateChecked(write.path, write.before, write.current)
	return err
}

// Caller owns the profile-store transaction and keeps its original physical
// observer alive. Checks run again after fsync immediately before the rename.
// A nonnil publication means the append actually committed, including when the
// final observation fails; callers must not report that as an unsaved retry.
func appendOrderedCandidateProfile(a *app, record connectionProfileRecord, current func() error) (*orderedCandidateProfilePublication, error) {
	if a == nil || current == nil {
		return nil, errors.New("candidate profile append requires its original transaction")
	}
	if err := current(); err != nil {
		return nil, err
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil {
		return nil, err
	}
	if len(store.Profiles) >= connectionProfileStoreMaxEntries {
		return nil, errors.New("connection profile limit reached")
	}
	path := connectionProfileStorePath(a)
	info, err := desktopComparisonCaptureFileInfo(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var original []byte
	if info != nil {
		original, err = readPrivateRegular(path, connectionProfileStoreMaxBytes)
		if err != nil {
			return nil, err
		}
	}
	again, err := loadConnectionProfileStore(a)
	if err != nil || !reflect.DeepEqual(store, again) {
		clear(original)
		return nil, errors.Join(err, errors.New("connection profile store changed while capturing its original append"))
	}
	before, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return nil, err
	}
	before = append(before, '\n')
	if original != nil {
		// Rollback restores the exact captured file, including its original
		// representation, rather than a normalized reserialization.
		clear(before)
		before = append([]byte(nil), original...)
	}
	store.Profiles = append(store.Profiles, record)
	after, err := json.MarshalIndent(store, "", "  ")
	if err != nil || len(after)+1 > connectionProfileStoreMaxBytes {
		clear(before)
		return nil, errors.New("candidate profile append exceeds its bounded store")
	}
	after = append(after, '\n')
	check := func() error {
		if err := current(); err != nil {
			return err
		}
		if err := atomicWritePrivateTargetUnchanged(path, info); err != nil {
			return err
		}
		if info != nil {
			raw, err := readPrivateRegular(path, connectionProfileStoreMaxBytes)
			equal := err == nil && bytes.Equal(raw, original)
			clear(raw)
			if !equal {
				return errors.New("candidate profile store changed before original append")
			}
		}
		return nil
	}
	published, err := atomicWritePrivateChecked(path, after, check)
	clear(original)
	if err != nil {
		clear(before)
		clear(after)
		return nil, err
	}
	write := &orderedCandidateProfilePublication{path: path, published: published, before: before, after: after}
	if err := write.current(); err != nil {
		return write, err
	}
	return write, current()
}

func preparedCandidateAdoptableLocked(owner *viaEntryOwner, q orderedCandidateSaveRequest, now time.Time) bool {
	if owner == nil || owner.running || owner.drained || owner.cancelled || owner.id != q.RequestID || owner.prepared == nil {
		return false
	}
	job := owner.prepared
	if job.view == nil || job.view.token != q.ViewToken || !job.accepted || !job.nativeDown || job.saved != nil ||
		job.preparation == nil || job.preparation.invalidated.Load() || !now.Before(job.expires) ||
		job.preparation.runtime == nil || job.preparation.runtime.catalog == nil {
		return false
	}
	for _, result := range job.results {
		if result.CandidateID == q.CandidateID && validateDesktopNodeChainCandidateStatus(job.preparation.runtime.catalog.plan, q.CandidateID, result, now) == nil {
			return true
		}
	}
	return false
}

func (a *app) saveOrderedCandidatePreparedProfile(w http.ResponseWriter, request *http.Request) {
	var q orderedCandidateSaveRequest
	if !viaEntryDecode(w, request, &q) {
		return
	}
	q.Name = strings.TrimSpace(q.Name)
	if !validViaEntryRequestID(q.RequestID) || q.ViewToken == "" || !validProfileID(q.CandidateID) || validateConnectionProfileName(q.Name) != nil {
		http.Error(w, "an original completed result, exact candidate/path and explicit profile name are required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	if !a.operationMu.TryLock() {
		http.Error(w, "another operation owns profile adoption", 409)
		return
	}
	defer a.operationMu.Unlock()
	control := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(ctx, &control.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	owner := control.owner
	if owner == nil || owner.id != q.RequestID || owner.prepared == nil || owner.prepared.view.token != q.ViewToken {
		control.mu.Unlock()
		http.Error(w, "original temporary candidate result is unavailable", 409)
		return
	}
	job := owner.prepared
	control.mu.Unlock()
	if err := desktopnetwork.LockContext(ctx, &owner.closeMu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	defer owner.closeMu.Unlock()
	if err := desktopnetwork.LockContext(ctx, &control.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	if job.saved != nil {
		matched := job.savedRequest != nil && reflect.DeepEqual(q, *job.savedRequest)
		control.mu.Unlock()
		if !matched {
			http.Error(w, "this result already saved its one named profile", 409)
			return
		}
		a.completePreparedProfileResponse(w, owner, job)
		return
	}
	valid := control.owner == owner && preparedCandidateAdoptableLocked(owner, q, time.Now())
	control.mu.Unlock()
	if !valid {
		http.Error(w, "candidate result is not awaiting original DOWN review; retest", 409)
		return
	}
	p := job.preparation
	if err := p.reviewCurrent(ctx); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	candidate, found := a.profileByIDLocked(q.CandidateID)
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	a.mu.Unlock()
	if !found {
		http.Error(w, "original saved candidate disappeared", 409)
		return
	}
	profile, nodes, err := orderedCandidateProposal(p.selection.Nodes, p.request.Position, candidate, profiles)
	if err != nil || !reflect.DeepEqual(nodes, q.ProposedPath) {
		http.Error(w, "proposed path differs from the exact supported saved replacement or insertion", 409)
		return
	}
	for i := range profiles {
		if profiles[i].ID == profile.ID {
			profiles[i] = profile
		}
	}
	compiled, err := captureDesktopNodeChain(ctx, p.selection.Native.root, profile, profiles, nodes, "local", nil)
	if err != nil {
		http.Error(w, "proposed full saved path failed source compilation: "+err.Error(), 409)
		return
	}
	if err := p.reviewCurrent(ctx); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	release, err := a.lockCandidatePublicationContext(ctx, control)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	check := func() error {
		if ctx.Err() != nil || control.owner != owner || !preparedCandidateAdoptableLocked(owner, q, time.Now()) {
			return errors.New("original candidate result changed before profile append")
		}
		if err := p.reviewBoundaryLocked(); err != nil {
			return err
		}
		if err := p.savedInventoryFilesCurrent(ctx); err != nil {
			return err
		}
		if err := p.selection.Native.chain.validate(ctx, p.selection.Control, a.profiles.Profiles); err != nil {
			return err
		}
		if err := compiled.validate(ctx, profile, profiles); err != nil {
			return err
		}
		return p.runtime.cohort.CurrentContext(ctx)
	}
	if err := check(); err != nil {
		release()
		http.Error(w, err.Error(), 409)
		return
	}
	record, err := a.orderedCandidateProfileRecordLocked(profile, q.Name)
	if err != nil {
		release()
		http.Error(w, err.Error(), 409)
		return
	}
	publication, appendErr := appendOrderedCandidateProfile(a, record, check)
	if publication == nil {
		release()
		http.Error(w, errors.Join(appendErr, errors.New("candidate profile append did not commit")).Error(), 409)
		return
	}
	defer func() { clear(publication.before); clear(publication.after) }()
	job.accepted = false
	if appendErr != nil {
		p.invalidate()
		job.failure = "The original source or physical network changed during profile Save."
		if rollbackErr := publication.rollback(); rollbackErr == nil {
			release()
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			cleanupErr := p.retire(cleanup)
			stop()
			control.mu.Lock()
			owner.drained = cleanupErr == nil
			if cleanupErr != nil {
				job.cleanupError = "Original observer cleanup remains pending; Cancel retries it."
			}
			control.mu.Unlock()
			http.Error(w, "Profile Save was revoked after the source/network changed; original store restored. Retest.", 409)
			return
		}
		job.cleanupError = "The named profile was written, but its result was invalidated and exact rollback could not complete. Inspect the saved profile and retest."
	}
	copy := q
	copy.ProposedPath = append([]common.MultihopNodeSelection(nil), q.ProposedPath...)
	job.saved, job.savedCandidate, job.savedRequest = &record, q.CandidateID, &copy
	release()
	a.completePreparedProfileResponse(w, owner, job)
}

// owner.closeMu remains held from the exact Save transaction. A committed
// profile survives observer-close failure; this response never invites another
// append, and an identical retry returns the original saved profile identity.
func (a *app) completePreparedProfileResponse(w http.ResponseWriter, owner *viaEntryOwner, job *orderedCandidatePreparedJob) {
	cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
	err := job.preparation.retire(cleanup)
	stop()
	control := viaEntryControlFor(a)
	control.mu.Lock()
	owner.drained = err == nil
	if err != nil {
		job.cleanupError = "Profile saved; original observer cleanup remains pending. Cancel retries cleanup without another Save."
	} else if job.failure == "" {
		job.cleanupError = ""
	}
	response := orderedCandidatePreparedResponseLocked(owner, time.Now())
	response["ok"], response["saved"] = true, true
	response["proposed_path"] = append([]common.MultihopNodeSelection(nil), job.savedRequest.ProposedPath...)
	response["note"] = "Saved a separate profile for the next connection. The temporary VPN is DOWN."
	control.mu.Unlock()
	viaEntryJSON(w, response)
}
