package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sort"
	"time"
)

// A renewal group is captured before it enters the native FIFO. It cannot add
// members while queued, borrow another policy generation, or create a permit.
// Sixteen complete grants and receipts fit the unchanged 32 KiB Darwin frame.
const desktopSocketRenewalLimit = 16

// Queue before one preceding native operation and this group's own operation
// can consume their existing guardian budgets. The polling allowance is the
// actual monitor interval; neither value extends an acknowledged receipt.
// More queued work can still exceed the five-second readback window and must
// retain the ordinary expiry/retirement path instead of borrowing freshness.
const desktopSocketRenewalLead = 2*desktopSocketNativeWork + desktopSocketMonitorInterval

type desktopSocketRenewal struct {
	context context.Context
	grant   DesktopSocketGrant
}

type desktopSocketRenewalResult struct {
	receipt DesktopSocketReceipt
	err     error
}

// Only the native policy owner can implement this private capability. Every
// member still owns its original peer operation, receipt and joined teardown.
type desktopSocketRenewalPolicy interface {
	renewSocketsAdmitted(context.Context, []desktopSocketRenewal) []desktopSocketRenewalResult
}

type desktopSocketRenewalNotSubmitted struct {
	requests []DesktopSocketGrant
	cause    error
}

func (e *desktopSocketRenewalNotSubmitted) Error() string { return e.cause.Error() }
func (e *desktopSocketRenewalNotSubmitted) Unwrap() error { return e.cause }

func desktopSocketUnsubmittedRenewals(requests []DesktopSocketGrant, cause error) error {
	return &desktopSocketRenewalNotSubmitted{slices.Clone(requests), cause}
}

// This shared control path retains the real FIFO admission and its original
// bounded context. A member cancelled while queued never becomes a native
// write. A cancellation after sending does not abandon the other captured
// members: the bounded transaction joins before each owner independently
// accepts its result or retires its attempted sequence.
func desktopSocketControlRenewals(ctx context.Context, members []desktopSocketRenewal,
	admit func(context.Context) (context.Context, func(), error),
	call func(context.Context, []DesktopSocketGrant) ([]DesktopSocketReceipt, error)) []desktopSocketRenewalResult {
	results := make([]desktopSocketRenewalResult, len(members))
	unsubmitted := func(cause error) []desktopSocketRenewalResult {
		for index, member := range members {
			results[index].err = desktopSocketUnsubmittedGrant(member.grant, cause)
		}
		return results
	}
	if ctx == nil || len(members) == 0 || len(members) > desktopSocketRenewalLimit || admit == nil || call == nil {
		return unsubmitted(errors.New("desktop renewal requires its bounded captured native control"))
	}
	seen := make(map[string]bool)
	for _, member := range members {
		grant := member.grant
		identity := grant.SocketID + "/" + grant.Remote.String()
		if member.context == nil || !grant.Capture.valid() || !grant.Binding.Owner.valid() || grant.Sequence <= 1 ||
			grant.Capture != members[0].grant.Capture || grant.Binding.Owner != members[0].grant.Binding.Owner || seen[identity] {
			return unsubmitted(errors.New("desktop renewal changed its captured policy, sequence or unique original tuple"))
		}
		seen[identity] = true
	}
	bounded, release, err := admit(ctx)
	if err != nil {
		return unsubmitted(err)
	}
	defer release()
	requests := make([]DesktopSocketGrant, 0, len(members))
	indices := make([]int, 0, len(members))
	for index, member := range members {
		if err := member.context.Err(); err != nil {
			results[index].err = desktopSocketUnsubmittedGrant(member.grant, err)
			continue
		}
		requests, indices = append(requests, member.grant), append(indices, index)
	}
	if len(requests) == 0 {
		return results
	}
	receipts, err := call(bounded, requests)
	err = errors.Join(err, bounded.Err())
	if err == nil {
		if len(receipts) != len(requests) {
			err = errors.New("desktop renewal lost its complete native receipt inventory")
		} else {
			for index, receipt := range receipts {
				if !validDesktopSocketReceipt(receipt, requests[index], time.Now()) {
					err = errors.New("desktop renewal returned a foreign, reordered, stale or invalid native receipt")
					break
				}
			}
		}
	}
	if err != nil {
		var notSent *desktopSocketRenewalNotSubmitted
		provedUnsubmitted := len(receipts) == 0 && errors.As(err, &notSent) && slices.Equal(notSent.requests, requests)
		for _, index := range indices {
			results[index].err = err
			if provedUnsubmitted {
				results[index].err = desktopSocketUnsubmittedGrant(members[index].grant, err)
			}
		}
		return results
	}
	for index, receipt := range receipts {
		results[indices[index]].receipt = receipt
	}
	return results
}

type desktopSocketRenewalPeer struct {
	socket *desktopSocket
	peer   *desktopSocketPeer
	until  int64
	remote netip.AddrPort
}

func desktopSocketRenewalUntil(receipt DesktopSocketReceipt) int64 {
	return min(receipt.ExpiresAt, receipt.ObservedAt+DesktopSocketReadbackAge.Milliseconds())
}

// The regular monitor still inspects every last acknowledged receipt even when
// a native renewal is queued. No queue position, pending transaction, sibling's
// readback or heartbeat grants extra freshness to any member.
func (b *DesktopSocketBroker) refreshRenewals(sockets []*desktopSocket) bool {
	policy, ok := b.policy.(desktopSocketRenewalPolicy)
	if !ok {
		return false
	}
	var candidates []desktopSocketRenewalPeer
	due := false
	for _, socket := range sockets {
		socket.mu.Lock()
		if socket.closing {
			socket.mu.Unlock()
			continue
		}
		peers := make([]*desktopSocketPeer, 0, len(socket.peers))
		for _, peer := range socket.peers {
			peers = append(peers, peer)
		}
		socket.mu.Unlock()
		for _, peer := range peers {
			receipt, valid := peer.snapshot()
			if !valid {
				continue
			}
			if !validDesktopSocketReceipt(receipt, receipt.Grant, time.Now()) {
				socket.recordAdmissionLoss("receipt-expired", peer, nil)
				socket.stop()
				continue
			}
			until := desktopSocketRenewalUntil(receipt)
			candidates = append(candidates, desktopSocketRenewalPeer{socket, peer, until, receipt.Grant.Remote})
			if until-time.Now().UnixMilli() <= desktopSocketRenewalLead.Milliseconds() {
				due = true
			}
		}
	}
	if !due {
		return true
	}
	// Retain one queued/running transaction for this original broker. Capture
	// already acknowledged siblings now: they may become due during the same
	// foreground queue and native transaction, when a second batch would be too
	// late. No new peer or acknowledgement can join this captured group later.
	// Expiry inspection above never waits for or borrows freshness from this
	// owner. Foreground requests already in the native FIFO remain ahead.
	b.mu.Lock()
	if b.renewing || b.closing {
		b.mu.Unlock()
		return true
	}
	b.renewing = true
	b.mu.Unlock()
	releaseGroup := func() {
		b.mu.Lock()
		b.renewing = false
		b.mu.Unlock()
	}
	// Choose by the real deadline before adding acknowledged siblings. Sorting
	// all roots first would let fresh roots fill every frame ahead of a due
	// derived peer. Parent-before-child execution is established after capture.
	less := func(a, c desktopSocketRenewalPeer) bool {
		if a.until != c.until {
			return a.until < c.until
		}
		if a.socket.id != c.socket.id {
			return a.socket.id < c.socket.id
		}
		return a.remote.Compare(c.remote) < 0
	}
	sort.Slice(candidates, func(i, j int) bool { return less(candidates[i], candidates[j]) })
	available := make(map[*desktopSocketPeer]desktopSocketRenewalPeer, len(candidates))
	for _, candidate := range candidates {
		available[candidate.peer] = candidate
	}
	group := make([]desktopSocketRenewalPeer, 0, desktopSocketRenewalLimit)
	selected := make(map[*desktopSocketPeer]bool)
	capture := func(candidate desktopSocketRenewalPeer) bool {
		socket, peer := candidate.socket, candidate.peer
		if !peer.op.TryLock() {
			return false
		}
		if err := socket.beginIO(); err != nil {
			peer.op.Unlock()
			return false
		}
		peer.mu.Lock()
		valid := peer.valid && !peer.applying && peer.request == peer.receipt.Grant &&
			validDesktopSocketReceipt(peer.receipt, peer.request, time.Now())
		if valid {
			peer.applying = true
		}
		peer.mu.Unlock()
		if !valid {
			socket.io.Done()
			peer.op.Unlock()
			return false
		}
		selected[peer] = true
		group = append(group, candidate)
		return true
	}
	for _, candidate := range candidates {
		if len(group) == desktopSocketRenewalLimit || len(group) == 0 && candidate.until-time.Now().UnixMilli() > desktopSocketRenewalLead.Milliseconds() {
			break
		}
		if selected[candidate.peer] {
			continue
		}
		if parent := candidate.socket.parent; parent != nil {
			parent.mu.Lock()
			control := parent.peers[parent.remote]
			parent.mu.Unlock()
			if control == nil {
				continue
			}
			control.mu.Lock()
			pending := control.applying || desktopSocketRenewalUntil(control.receipt)-time.Now().UnixMilli() <= desktopSocketRenewalLead.Milliseconds()
			control.mu.Unlock()
			if pending && !selected[control] {
				// A due child may have the earlier deadline after a genuine
				// parent renewal. Reserve both slots and capture that exact
				// parent now instead of skipping the child behind fresh roots.
				owner, ok := available[control]
				if !ok || len(group)+2 > desktopSocketRenewalLimit || !capture(owner) {
					continue
				}
			}
		}
		capture(candidate)
	}
	if len(group) != 0 {
		sort.Slice(group, func(i, j int) bool {
			a, c := group[i], group[j]
			if (a.socket.parent == nil) != (c.socket.parent == nil) {
				return a.socket.parent == nil
			}
			return less(a, c)
		})
		go func() {
			defer releaseGroup()
			b.applyRenewals(policy, group)
		}()
	} else {
		releaseGroup()
	}
	return true
}

func (b *DesktopSocketBroker) applyRenewals(policy desktopSocketRenewalPolicy, group []desktopSocketRenewalPeer) {
	defer func() {
		for _, member := range group {
			member.peer.op.Unlock()
			member.socket.io.Done()
		}
	}()
	requests := make([]desktopSocketRenewal, len(group))
	previous := make([]DesktopSocketGrant, len(group))
	for index, member := range group {
		member.peer.mu.Lock()
		previous[index] = member.peer.request
		member.peer.request.Sequence++
		requests[index] = desktopSocketRenewal{member.socket.ctx, member.peer.request}
		member.peer.mu.Unlock()
	}
	results := policy.renewSocketsAdmitted(b.ctx, requests)
	complete := len(results) == len(requests)
	if complete {
		for index, result := range results {
			if result.err == nil && !validDesktopSocketReceipt(result.receipt, requests[index].grant, time.Now()) || result.err != nil && result.receipt != (DesktopSocketReceipt{}) {
				complete = false
				break
			}
		}
	}
	if !complete {
		results = make([]desktopSocketRenewalResult, len(requests))
		for index := range results {
			results[index].err = errors.New("desktop native renewal omitted its complete captured result inventory")
		}
	}
	// Roots are acknowledged before descendants. Each result is checked against
	// its own immutable request; a foreign, reordered, late or partial response
	// cannot become a sibling's receipt or replace a newer owner.
	for index, member := range group {
		result := results[index]
		if requests[index].context.Err() != nil && result.err == nil {
			result.err = net.ErrClosed
		}
		_ = member.socket.finishApply(requests[index].context, member.peer, previous[index], requests[index].grant, result.receipt, result.err)
	}
}
