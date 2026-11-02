//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
)

// This capability exists only in the disposable Full test worker. It retains
// the exact Limited process already authenticated by the private bootstrap,
// then opens that process's real primary token. The linked identification
// handle remains observational and is never duplicated or impersonated.
type fixtureFreshUACLimitedParent struct {
	mu       sync.Mutex
	api      *nativeAPI
	context  context.Context
	process  *Process
	token    syscall.Token
	identity TokenIdentity
	captured fixtureFreshUACParentObservation
	expected fixtureFreshUACIdentity
	linked   fixtureFreshUACIdentity
	lease    fixtureFreshUACParentLease
}

var fixtureFreshUACParentAuthority *fixtureFreshUACLimitedParent

func fixtureRetainFreshUACLimitedParent(ctx context.Context, api *nativeAPI, parent *Process, expected, linked fixtureFreshUACIdentity) (_ *fixtureFreshUACLimitedParent, result error) {
	if ctx == nil || ctx.Err() != nil || api == nil || parent == nil {
		return nil, errors.New("fresh Limited access has no live authenticated parent")
	}
	retained, err := parent.retain()
	if err != nil {
		return nil, err
	}
	owner := &fixtureFreshUACLimitedParent{api: api, context: ctx, process: retained, expected: expected, linked: linked}
	accepted := false
	defer func() {
		if !accepted {
			result = errors.Join(result, owner.close())
		}
	}()
	handle, release, err := retained.borrow()
	if err != nil {
		return nil, err
	}
	err = syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY|syscall.TOKEN_DUPLICATE, &owner.token)
	release()
	if err != nil || owner.token == 0 {
		return nil, errors.Join(err, errors.New("fresh Limited process did not grant its exact primary-token query/duplicate access"))
	}
	owner.identity, _, err = readTokenIdentity(owner.token)
	if err != nil {
		return nil, err
	}
	observed, err := fixtureFreshUACObserveToken(api, owner.token)
	if err != nil {
		return nil, err
	}
	created, err := retained.StartTimeUTCTicks()
	if err != nil {
		return nil, err
	}
	owner.captured = fixtureFreshUACParentObservation{PID: retained.PID(), Created: created, Token: observed, Live: true}
	if err := owner.currentLocked(linked); err != nil {
		return nil, err
	}
	accepted = true
	return owner, nil
}

// The caller holds mu, or is constructing this unpublished capability.
func (owner *fixtureFreshUACLimitedParent) currentLocked(linked fixtureFreshUACIdentity) error {
	if owner.lease.closed || owner.context == nil || owner.context.Err() != nil || owner.process == nil || owner.token == 0 {
		return errors.New("fresh Limited primary source is closed or its private caller lifetime ended")
	}
	if err := owner.process.Alive(); err != nil {
		return err
	}
	created, err := owner.process.StartTimeUTCTicks()
	if err != nil {
		return err
	}
	processToken, err := fixtureFreshUACProcessIdentity(owner.api, owner.process)
	if err != nil {
		return err
	}
	held, err := fixtureFreshUACObserveToken(owner.api, owner.token)
	if err != nil {
		return err
	}
	current := fixtureFreshUACParentObservation{PID: owner.process.PID(), Created: created, Token: processToken, Live: owner.context.Err() == nil}
	if !fixtureFreshUACParentMatches(owner.captured, current, held, owner.expected, linked) ||
		!fixtureFreshUACAuthorityMatches(linked, owner.linked) {
		return errors.New("fresh Limited primary source changed its process, token object or captured reciprocal authority")
	}
	// Unlike the linked-observation comparator, these same-object checks keep
	// the TokenID and ModifiedID. A replaced or adjusted primary token fails.
	identity, _, tokenErr := readTokenIdentity(owner.token)
	processIdentity, processErr := owner.process.Identity()
	if tokenErr != nil || processErr != nil || identity != owner.identity || processIdentity != owner.identity {
		return errors.Join(tokenErr, processErr, errors.New("fresh Limited primary token changed while its process was retained"))
	}
	return errors.Join(fixtureDenyOnlyAdministrator(owner.token), owner.process.Alive(), owner.context.Err())
}

func (owner *fixtureFreshUACLimitedParent) acquire(linked fixtureFreshUACIdentity) (syscall.Token, TokenIdentity, func() error, func(), error) {
	if owner == nil {
		return 0, TokenIdentity{}, nil, nil, errors.New("fresh Full worker has no retained genuine Limited primary source")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.lease.active {
		return 0, TokenIdentity{}, nil, nil, errors.New("fresh Limited primary source already has an owned thread access attempt")
	}
	if err := owner.currentLocked(linked); err != nil {
		return 0, TokenIdentity{}, nil, nil, err
	}
	operation, err := owner.lease.begin()
	if err != nil {
		return 0, TokenIdentity{}, nil, nil, err
	}
	current := func() error {
		owner.mu.Lock()
		defer owner.mu.Unlock()
		if !owner.lease.current(operation) {
			return errors.New("fresh Limited thread access lost its captured lease")
		}
		return owner.currentLocked(linked)
	}
	release := func() {
		owner.mu.Lock()
		owner.lease.release(operation)
		owner.mu.Unlock()
	}
	return owner.token, owner.identity, current, release, nil
}

func (owner *fixtureFreshUACLimitedParent) close() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.lease.retire(); err != nil {
		return err
	}
	var result error
	if owner.token != 0 {
		if err := owner.token.Close(); err != nil {
			result = err
		} else {
			owner.token = 0
		}
	}
	if owner.process != nil {
		if err := owner.process.Close(); err != nil {
			result = errors.Join(result, err)
		} else {
			owner.process = nil
		}
	}
	return result
}

// The fresh Full worker invokes this on its real retained kernel handles. It
// complements the portable policy cases; no fixture token or process replaces
// the already-authenticated Limited source.
func fixtureFreshUACVerifyLimitedParentLifetime(t *testing.T) {
	t.Helper()
	owner, receipt := fixtureFreshUACParentAuthority, fixtureFreshUACWorkerReceipt
	if owner == nil || receipt == nil || receipt.Role != "full" {
		t.Fatal("actual Limited lifetime check has no captured Full continuation")
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	limited, full, pairErr := fixtureFreshUACReadPair(owner.api, token, receipt.Full.SID)
	closeErr := token.Close()
	if pairErr != nil || closeErr != nil || !fixtureFreshUACFullWorkerMatches(limited, full, receipt.Limited, receipt.Full) {
		t.Fatal("actual Limited lifetime check lost reciprocal identities", pairErr, closeErr)
	}
	first, identity, current, release, err := owner.acquire(limited)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if owner.close() == nil || current() != nil {
		t.Fatal("live retained primary closed before its exact access lease joined")
	}
	release()
	if current() == nil {
		t.Fatal("released primary access kept its old current capability")
	}
	second, secondIdentity, next, releaseNext, err := owner.acquire(limited)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseNext()
	release() // An old callback must not release the newer captured operation.
	if second != first || secondIdentity != identity || next() != nil {
		t.Fatal("old primary access release changed its replacement source")
	}
	releaseNext()
	ctx, cancel := context.WithCancel(owner.context)
	defer cancel()
	retained, err := fixtureRetainFreshUACLimitedParent(ctx, owner.api, owner.process, owner.expected, limited)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := retained.close(); err != nil {
			t.Error("cancelled retained primary did not close its exact handles", err)
		}
	})
	cancel()
	if rejected, _, _, _, err := retained.acquire(limited); err == nil || rejected != 0 {
		t.Fatal("cancelled private lifetime supplied primary access authority")
	}
	if err := retained.close(); err != nil || retained.token != 0 || retained.process != nil {
		t.Fatal("joined cancelled source retained unproved token/process closure", err)
	}
	if rejected, _, _, _, err := retained.acquire(limited); err == nil || rejected != 0 {
		t.Fatal("closed primary source supplied another access capability")
	}
	final, finalIdentity, check, releaseFinal, err := owner.acquire(limited)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFinal()
	if final != first || finalIdentity != identity || check() != nil {
		t.Fatal("cancelled sibling source changed the original retained primary")
	}
	releaseFinal()
	t.Log("Actual authenticated Limited parent primary token retained its original process incarnation and TokenID; early closure, stale releases and cancelled/closed source acquisition rejected, and independent token/process handles closed after join.")
}
