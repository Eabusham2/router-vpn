package mobiletor

import (
	"crypto/sha256"
	"fmt"
	"sync/atomic"
	"time"
)

// These observations grant no authority, refresh no receipt and never select a
// current socket by name. Keep the first loss on the original retained object,
// including after its broker has drained it or admitted a replacement.
type desktopSocketAdmissionObservation struct {
	first atomic.Pointer[desktopSocketAdmissionLoss]
}

type desktopSocketAdmissionLoss struct {
	phase             string
	owner             [32]byte
	when              int64
	request, receipt  uint64
	observed, expires int64
	valid, applying   bool
	parent            [32]byte
	parentReceipt     uint64
	parentObserved    int64
	parentExpires     int64
	parentValid       bool
	failure           desktopRetirementFailure
}

func desktopSocketObservationOwner(capture DesktopSocketCapture, owner DesktopSocketKernelOwner, socketID string) [32]byte {
	// Length-delimited hashing binds the whole capture without disclosing node
	// addresses, account names, source paths, arbitrary errors or packet bytes.
	return sha256.Sum256([]byte(fmt.Sprintf("%q|%q|%q|%q|%q|%d|%d|%q", capture.SessionID,
		capture.SourceSHA256, capture.NetworkID, owner.Kind, owner.IdentitySHA256, owner.Generation, owner.ProcessID, socketID)))
}

func (s *desktopSocket) recordAdmissionLoss(phase string, peer *desktopSocketPeer, cause error) {
	if s.admission.first.Load() != nil {
		return
	}
	s.mu.Lock()
	loss := desktopSocketAdmissionLoss{phase: phase, when: time.Now().UnixMilli(),
		owner: desktopSocketObservationOwner(s.broker.capture, s.binding.Owner, s.id)}
	if peer == nil {
		peer = s.peers[s.remote]
	}
	parent := s.parent
	s.mu.Unlock()
	if peer != nil {
		peer.mu.Lock()
		loss.request, loss.receipt = peer.request.Sequence, peer.receipt.Grant.Sequence
		loss.observed, loss.expires = peer.receipt.ObservedAt, peer.receipt.ExpiresAt
		loss.valid, loss.applying = peer.valid, peer.applying
		peer.mu.Unlock()
	}
	if parent != nil {
		parent.mu.Lock()
		loss.parent = desktopSocketObservationOwner(parent.broker.capture, parent.binding.Owner, parent.id)
		control := parent.peers[parent.remote]
		parent.mu.Unlock()
		if control != nil {
			control.mu.Lock()
			loss.parentReceipt, loss.parentObserved, loss.parentExpires = control.receipt.Grant.Sequence, control.receipt.ObservedAt, control.receipt.ExpiresAt
			loss.parentValid = control.valid
			control.mu.Unlock()
		}
	}
	var classified desktopRetirementState
	classified.failure(cause)
	if failure := classified.first.Load(); failure != nil {
		loss.failure = *failure
	}
	s.admission.first.CompareAndSwap(nil, &loss)
}

func (s desktopSocketAdmissionLoss) String() string {
	return fmt.Sprintf("owner=%x phase=%s at_ms=%d request=%d receipt=%d age_ms=%d remaining_ms=%d valid=%t applying=%t parent=%x parent_receipt=%d parent_age_ms=%d parent_remaining_ms=%d parent_valid=%t cause_class=%d errno=%d",
		s.owner, s.phase, s.when, s.request, s.receipt, s.when-s.observed, s.expires-s.when, s.valid, s.applying,
		s.parent, s.parentReceipt, s.when-s.parentObserved, s.parentExpires-s.when, s.parentValid, s.failure.class, s.failure.errno)
}
