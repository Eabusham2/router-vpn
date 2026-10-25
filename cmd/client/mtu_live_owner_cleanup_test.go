package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMTULiveKernelCloseRestoresItsOwnMutationAfterProfileChange(t *testing.T) {
	owner, kernel := newMTUCapabilityFixture(t)
	code, _, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1380}`)
	if err != nil || code != http.StatusOK {
		t.Fatal("fixture did not change its owned interface", code, err)
	}
	owner.a.mu.Lock()
	owner.a.profiles.Profiles[0].DNSMode = "system"
	owner.a.mu.Unlock()
	if owner.Validate() == nil || owner.Restore() == nil {
		t.Fatal("changed profile authorized ordinary measurement or adoption")
	}
	ctx, operation, err := beginMTUViewOperation(owner.a, context.Background(), mtuViewRequest{}, mtuViewIdentity{Session: owner.snapshot.SessionID, Profile: owner.snapshot.Profile.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer operation.cancel()
	_ = ctx
	t.Cleanup(func() { mtuViewSlots.Delete(owner.a) })
	writer := &mtuViewResponse{ResponseWriter: httptest.NewRecorder(), operation: operation}
	http.Error(writer, "profile changed before adoption", http.StatusConflict)
	finishMTULiveOwner(writer, owner)
	writer.finish()
	actual, _ := kernel.Read()
	if actual.MTU != 1420 || !owner.closed || owner.changed {
		t.Fatal("legacy kernel close abandoned its provisional MTU", actual, owner.closed)
	}
	operation.mu.Lock()
	if !operation.status.Restored || operation.status.Running || !operation.status.Complete || operation.status.Measured || operation.status.EffectiveMTU != 1420 {
		t.Error("final cleanup omitted its verified rollback receipt", operation.status)
	}
	operation.mu.Unlock()
	owner.a.mu.Lock()
	if owner.a.profiles.Profiles[0].DNSMode != "system" {
		t.Error("rollback reverted the user's newer profile edit")
	}
	owner.a.mu.Unlock()
}

func TestMTULiveKernelCloseCannotRestoreThroughReplacementRegistry(t *testing.T) {
	owner, kernel := newMTUCapabilityFixture(t)
	code, _, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1380}`)
	if err != nil || code != http.StatusOK {
		t.Fatal(code, err)
	}
	replacement := &mtuLiveOwner{}
	mtuLiveOwners.Store(owner.a, replacement)
	if owner.Close() == nil || owner.closed {
		t.Fatal("old kernel cleanup acted through a replacement owner")
	}
	actual, _ := kernel.Read()
	if current, _ := mtuLiveOwners.Load(owner.a); current != replacement || actual.MTU != 1380 {
		t.Fatal("old cleanup changed a replacement registry/interface")
	}
	// Retire the synthetic replacement and let this test's actual retained
	// owner perform the checked rollback. Production never swaps it back.
	mtuLiveOwners.Store(owner.a, owner)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	actual, _ = kernel.Read()
	if actual.MTU != 1420 {
		t.Fatal("owned retry failed to restore the original MTU")
	}
}
