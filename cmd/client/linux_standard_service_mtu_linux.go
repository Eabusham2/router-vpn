//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
)

// The installed service owns this state beside its actual child. No RPC can
// acquire another child, interface, observer or protection creator from a name.
type linuxStandardServiceMTU struct {
	session   *linuxStandardServiceSession
	native    *linuxStandardEngine
	current   standardengine.ReaderBinding
	ready     string
	sequence  uint64
	active    *linuxStandardServiceMTUOperation
	seen      map[string]struct{}
	exhausted bool
}

type linuxStandardServiceMTUOperation struct {
	command      standardengine.OperationCommand
	transition   *desktopnetwork.Transition
	original     string
	report       *standardengine.OperationReport
	ended        bool
	settled      bool
	submitted    bool
	noSubmission bool
	rejection    string
	historyValid bool
	reserved     bool
}

func (s *linuxStandardService) mtuOwner(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest) (*linuxStandardServiceMTU, error) {
	session := s.session
	recovery := request.Action == "mtu-status" || request.Action == "mtu-cancel" || request.Action == "mtu-evidence" || request.Action == "mtu-ack" || request.Action == "mtu-cleanup"
	if session == nil || session.peer == nil || peer == nil || session.peer.record != peer.record || session.request.Session != request.Session ||
		session.joined || session.cleanupPending && !recovery || session.owner == nil || session.owner.native == nil || session.network == nil {
		return nil, errors.New("standard MTU lost its original live service session")
	}
	native := session.owner.native
	if session.network.observer != native.tracker || session.network.owner != session.owner || session.network.session != session || session.network.closed || session.network.failure != nil && !recovery {
		return nil, errors.New("standard MTU cannot replace its original network observer")
	}
	if recovery && session.mtu != nil {
		if err := native.operations.Current(); err != nil {
			return nil, err
		}
		if err := session.owner.namespaceCurrent(); err != nil {
			return nil, err
		}
	} else {
		if err := native.current(ctx); err != nil {
			return nil, err
		}
		if err := s.loadProfiles(); err != nil {
			return nil, err
		}
		if err := session.owner.legacyDNSCurrent(ctx); err != nil {
			return nil, err
		}
	}
	if session.mtu == nil {
		if native.routingReceipt == nil || !native.ready {
			return nil, errors.New("standard MTU preceded original native readiness")
		}
		ready, err := desktopnetwork.CanonicalDesktopNetworkReceipt(*native.routingReceipt)
		if err != nil {
			return nil, err
		}
		session.mtu = &linuxStandardServiceMTU{session: session, native: native, ready: ready, current: standardengine.InitialReaderBinding(native.captureSHA, ready)}
		native.mtuStopOwner = session.mtu
	}
	m := session.mtu
	if m.session != session || m.native != native || m.ready != "" && m.current.InitialReceiptSHA256 != standardengine.SHA256([]byte(m.ready)) || m.ready == "" && (m.current != (standardengine.ReaderBinding{}) || m.active == nil || !m.active.ended) {
		return nil, errors.New("standard MTU changed its original native reader binding")
	}
	return m, ctx.Err()
}

func (m *linuxStandardServiceMTU) response() *linuxStandardServiceMTUResponse {
	response := &linuxStandardServiceMTUResponse{CaptureSHA256: m.native.captureSHA, Current: m.current, Ready: m.ready, Remaining: m.remaining()}
	if op := m.active; op != nil {
		if op.noSubmission {
			response.Pending, response.Settled = !op.ended, op.settled
			if op.ended {
				key := op.command.Reservation.Key
				response.Rejected = &linuxStandardServiceMTURejected{ID: key.ID, DeadlineNS: key.DeadlineNS, Expected: key.Original, Reason: op.rejection}
			}
			return response
		}
		command := op.command
		response.Command = &command
		response.Pending, response.Settled = !op.ended, op.settled
		if op.report != nil {
			result := op.report.Result
			response.Result = &result
			response.Pending = result.Pending || !op.ended
		}
	}
	return response
}

func (m *linuxStandardServiceMTU) remaining() int {
	used := max(m.sequence, uint64(len(m.seen)))
	if m.exhausted || used >= standardengine.OperationTransactions {
		return 0
	}
	return standardengine.OperationTransactions - int(used)
}

func (m *linuxStandardServiceMTU) matches(request *linuxStandardServiceMTURequest) error {
	if request == nil || m.active == nil {
		return errors.New("standard MTU request has no retained original operation")
	}
	key := m.active.command.Reservation.Key
	if request.Reservation != nil {
		if *request.Reservation != m.active.command.Reservation || request.ID != "" || request.Expected != nil || request.DeadlineNS != 0 {
			return errors.New("standard MTU request substituted its original reservation")
		}
	} else if request.ID != key.ID || request.Expected == nil || *request.Expected != key.Original || request.DeadlineNS != key.DeadlineNS {
		// A lost admission response may be recovered only by the full original
		// intent, never by whichever operation happens to occupy the session.
		return errors.New("standard MTU recovery changed its original admission")
	}
	return nil
}

func (m *linuxStandardServiceMTU) begin(ctx context.Context, request *linuxStandardServiceMTURequest) error {
	if request == nil || !desktopMTURequestPattern.MatchString(request.ID) || request.Expected == nil || *request.Expected != m.current ||
		request.Reservation != nil || request.Digest != "" || request.Role != 0 || request.Phase != 0 || request.Offset != 0 || request.Retiring || request.MTU < 1280 || request.MTU > 9000 ||
		request.DeadlineNS <= time.Now().UnixNano() {
		return errors.New("standard MTU candidate lost its bounded captured intent")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || request.DeadlineNS > deadline.UnixNano() {
		return errors.New("standard MTU candidate extended its original request deadline")
	}
	if prior := m.active; prior != nil {
		key := prior.command.Reservation.Key
		if key.ID == request.ID && key.DeadlineNS == request.DeadlineNS && key.Original == *request.Expected && (prior.command.MTU == request.MTU || prior.noSubmission) {
			return m.poll(ctx) // Retry observes the exact intent; never resubmits.
		}
		if !prior.settled {
			return errors.New("standard MTU still retains its original unsettled transaction")
		}
	}
	if _, used := m.seen[request.ID]; used {
		return errors.New("standard MTU operation identity was already retired")
	}
	if m.sequence == ^uint64(0) {
		return errors.New("standard MTU sequence is exhausted")
	}
	original, err := desktopnetwork.ParseDesktopNetworkReceipt(m.ready)
	if err != nil {
		return err
	}
	tracker, ok := m.native.tracker.(interface {
		BeginRetained(context.Context, *desktopnetwork.DesktopNetworkReceipt) (*desktopnetwork.Transition, error)
	})
	if !ok {
		return errors.New("standard MTU lost its original retained transition capability")
	}
	m.sequence++
	key := standardengine.OperationKey{CaptureSHA256: m.native.captureSHA, ID: request.ID, Sequence: m.sequence, DeadlineNS: request.DeadlineNS, Original: m.current}
	op := &linuxStandardServiceMTUOperation{command: standardengine.OperationCommand{Reservation: standardengine.OperationReservation{Key: key}, MTU: request.MTU}, original: m.ready, noSubmission: true}
	m.active = op
	m.remember(request.ID)
	if m.exhausted {
		op.rejection = "standard MTU history capacity is exhausted for this connection"
		return m.poll(ctx)
	}
	reservation, err := m.native.operations.Reserve(ctx, key)
	if err != nil {
		op.rejection = "standard MTU reservation was not submitted"
		return err // Capacity is reserved before any native mutation is possible.
	}
	op.command.Reservation, op.reserved = reservation, true
	transition, err := tracker.BeginRetained(ctx, &original)
	op.transition = transition
	if err != nil {
		op.rejection = "standard MTU observer admission was not submitted"
		return err
	}
	if transition == nil {
		op.rejection = "standard MTU observer admission was not submitted"
		return errors.New("standard MTU did not retain its original observer transition")
	}
	op.noSubmission = false // A failed write can still have published its frame.
	if err := m.native.operations.SubmitCommand(ctx, op.command); err != nil {
		// Submission can fail after writing its frame. Keep the admitted
		// transition and reservation for owned cancellation/status/Stop.
		op.rejection = "standard MTU command was not submitted"
		return err
	}
	op.submitted = true
	return ctx.Err()
}

func (m *linuxStandardServiceMTU) remember(id string) {
	if m.seen == nil {
		m.seen = make(map[string]struct{})
	}
	if len(m.seen) >= standardengine.OperationTransactions {
		m.exhausted = true
		return
	}
	m.seen[id] = struct{}{}
}

// A cancellation/status can overtake a lost begin packet. Retain that exact
// never-submitted intent so the delayed begin cannot execute after rejection.
func (m *linuxStandardServiceMTU) rejectUnknown(ctx context.Context, q *linuxStandardServiceMTURequest) error {
	if q == nil || q.Reservation != nil || !desktopMTURequestPattern.MatchString(q.ID) || q.Expected == nil || *q.Expected != m.current || q.DeadlineNS <= 0 || q.DeadlineNS > time.Now().Add(120*time.Second).UnixNano() || m.ready == "" {
		return errors.New("standard MTU unknown intent cannot acquire cancellation authority")
	}
	if m.active != nil && !m.active.settled {
		return errors.New("standard MTU retains another admitted original intent")
	}
	if _, used := m.seen[q.ID]; used {
		return errors.New("standard MTU cannot reject a previously admitted identity")
	}
	m.remember(q.ID)
	key := standardengine.OperationKey{CaptureSHA256: m.native.captureSHA, ID: q.ID, DeadlineNS: q.DeadlineNS, Original: *q.Expected}
	m.active = &linuxStandardServiceMTUOperation{command: standardengine.OperationCommand{Reservation: standardengine.OperationReservation{Key: key}}, original: m.ready, noSubmission: true, rejection: "standard MTU request was cancelled before native submission"}
	return m.poll(ctx)
}

func (m *linuxStandardServiceMTU) finishRejection(ctx context.Context, op *linuxStandardServiceMTUOperation) error {
	if op.ended {
		return nil
	}
	if !op.noSubmission {
		return errors.New("standard MTU cannot reject a possibly submitted native worker")
	}
	if op.reserved {
		absent, err := m.native.operations.AbortUnsubmitted(ctx, op.command.Reservation)
		if err != nil || !absent {
			return errors.Join(err, errors.New("standard MTU admission could not be permanently retired before rejection"))
		}
	}
	original, err := desktopnetwork.ParseDesktopNetworkReceipt(op.original)
	if err != nil {
		return err
	}
	if op.transition != nil {
		err = op.transition.Complete(ctx, &original)
	} else {
		err = m.native.tracker.CurrentContext(ctx)
	}
	if err != nil {
		return err
	}
	op.ended, op.settled = true, true
	if op.rejection == "" {
		op.rejection = "standard MTU request did not submit native work"
	}
	return ctx.Err()
}

// The service gate is held only for a bounded observation. Native mutation is
// performed by the original fixed child's independent worker, so a Cancel RPC
// never waits behind that mutation or behind its work-region lock.
func (m *linuxStandardServiceMTU) poll(ctx context.Context) error {
	op := m.active
	if op == nil || op.settled {
		return nil
	}
	if op.noSubmission {
		return m.finishRejection(ctx, op)
	}
	if !op.submitted {
		absent, err := m.native.operations.AbortUnsubmitted(ctx, op.command.Reservation)
		if err != nil {
			return err
		}
		if absent {
			op.noSubmission = true
			return m.finishRejection(ctx, op)
		}
		op.submitted = true
	}
	report, err := m.readOperationReport(ctx, op)
	if errors.Is(err, standardengine.ErrOperationPending) {
		return nil
	}
	if err != nil {
		return err
	}
	result := report.Result
	if op.report != nil && op.report.Result.Revision > result.Revision {
		return errors.New("standard MTU native result went backwards")
	}
	if op.ended {
		if op.report == nil || op.report.Result != result {
			return errors.New("standard MTU changed evidence after original observer completion")
		}
		return nil
	}
	op.report = &report // Retain joined partial cleanup evidence as well.
	if result.Pending {
		return nil
	}
	current, err := validateLinuxStandardServiceMTUReport(report, op.original)
	if err != nil {
		return err
	}
	if err := m.native.retainMTURetirements(report); err != nil {
		return err
	}
	op.historyValid = true
	// This describes actual native ownership for later cleanup. It is retained
	// even when an independent network observation prevents healthy adoption.
	if current != nil {
		m.native.retainRoutingReceipt(*current)
	}
	for _, entry := range report.Readers {
		if entry == nil {
			continue
		}
		if len(entry.Ready) != 0 {
			receipt, _ := desktopnetwork.ParseDesktopNetworkReceipt(string(entry.Ready))
			if err := op.transition.Record(ctx, receipt); err != nil {
				return err
			}
		}
		if len(entry.Retirement) != 0 {
			receipt, _ := desktopnetwork.ParseDesktopNetworkRetirementReceipt(string(entry.Retirement))
			if err := op.transition.RecordRetirement(ctx, receipt); err != nil {
				return err
			}
		}
	}
	if err := op.transition.Complete(ctx, current); err != nil {
		return err
	}
	op.ended = true
	if current == nil {
		m.ready, m.current = "", standardengine.ReaderBinding{}
	} else {
		entry := report.Readers[result.CurrentRole]
		m.ready, m.current = string(entry.Ready), entry.Binding
		m.native.retainRoutingReceipt(*current)
	}
	return m.native.operations.Acknowledge(ctx, op.command.Reservation, standardengine.ServiceObserver, result.Digest)
}

func (m *linuxStandardServiceMTU) acknowledge(ctx context.Context, request *linuxStandardServiceMTURequest) error {
	if err := m.matches(request); err != nil {
		return err
	}
	if err := m.poll(ctx); err != nil {
		return err
	}
	op := m.active
	if !op.ended || op.report == nil || op.report.Result.Pending || request.Digest != op.report.Result.Digest {
		return errors.New("standard MTU acknowledgement preceded original joined observer evidence")
	}
	if op.settled {
		return nil
	}
	if err := m.native.operations.Acknowledge(ctx, op.command.Reservation, standardengine.ServiceObserver, request.Digest); err != nil {
		return err
	}
	if err := m.native.operations.Acknowledge(ctx, op.command.Reservation, standardengine.ControllerObserver, request.Digest); err != nil {
		return err
	}
	if err := m.native.operations.Settle(ctx, op.command.Reservation, request.Digest); err != nil {
		return err
	}
	op.settled = true
	return ctx.Err()
}

func (s *linuxStandardService) mtuRequest(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest) (*linuxStandardServiceMTUResponse, error) {
	if request.Schema != 1 || request.Transfer != nil || request.MTU == nil || !validControllerOwnerToken(request.Session) || request.Release || request.BudgetMS < 1 || request.BudgetMS > 120000 || request.DeadlineNS <= time.Now().UnixNano() ||
		request.Directory != "" || request.ConfigSHA256 != "" || request.ProfileID != "" || request.ProfileSHA256 != "" || request.NetworkID != "" || request.RouterID != "" || request.Endpoint != "" || request.RuntimeMode != "" || request.Base != "" || request.ProfileRevision != "" || request.ResultRevision != "" {
		return nil, errors.New("standard MTU RPC changed its bounded original scope")
	}
	if err := peer.Current(ctx); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.quiescing {
		return nil, errors.New("standard MTU service is quiescing")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	actual, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(actual, s.namespace) {
		return nil, errors.Join(err, errors.New("standard MTU left its original namespace"))
	}
	// The service can autonomously retire a failed original engine before its
	// controller observes the joined MTU result. Preserve read-only evidence for
	// that controller's explicit Stop; closed native objects cannot be reopened.
	if session := s.session; session != nil && session.mtu != nil &&
		(session.joined || session.network != nil && session.network.closed || session.owner != nil && session.owner.native != nil && session.owner.native.closed) {
		response, err := s.retiredMTUResponse(request, peer)
		return response, errors.Join(err, ctx.Err(), peer.Current(ctx))
	}
	m, err := s.mtuOwner(ctx, peer, request)
	if err != nil {
		return nil, err
	}
	q := request.MTU
	if request.Action == "mtu-ack" {
		if err := m.native.current(ctx); err != nil {
			return nil, err
		}
		if err := s.loadProfiles(); err != nil {
			return nil, err
		}
		if err := m.session.owner.legacyDNSCurrent(ctx); err != nil {
			return nil, err
		}
	}
	var observationError error
	switch request.Action {
	case "mtu-capture":
		if *q != (linuxStandardServiceMTURequest{}) || m.active != nil && !m.active.settled {
			return nil, errors.New("standard MTU capture has an outstanding original operation")
		}
		err = s.networkCurrent(ctx, m.session, true)
	case "mtu-begin":
		err = m.begin(ctx, q)
	case "mtu-status", "mtu-cancel", "mtu-evidence", "mtu-ack", "mtu-cleanup":
		if q.Retiring && request.Action == "mtu-ack" || request.Action == "mtu-cleanup" && !q.Retiring {
			return nil, errors.New("standard MTU retirement cannot acknowledge a healthy successor")
		}
		if err := validateLinuxStandardMTUFollowup(request.Action, q); err != nil {
			return nil, err
		}
		if err = m.matches(q); err != nil {
			if (request.Action != "mtu-status" && request.Action != "mtu-cancel") || q.Reservation != nil {
				return nil, err
			}
			if err = m.rejectUnknown(ctx, q); err != nil {
				return nil, err
			}
		}
		if request.Action == "mtu-cancel" {
			if m.active.settled {
				err = nil
			} else if m.active.noSubmission {
				err = m.poll(ctx)
			} else {
				err = m.native.operations.Cancel(ctx, m.active.command.Reservation)
			}
		} else if request.Action == "mtu-ack" {
			err = m.acknowledge(ctx, q)
		} else if request.Action == "mtu-cleanup" {
			err = m.requestCleanup(ctx)
		} else {
			err = m.poll(ctx)
		}
		if q.Retiring && err != nil && (m.active.noSubmission || m.active.historyValid && m.active.report != nil && m.active.report.Result.WorkerJoined && !m.active.report.Result.Pending) {
			observationError, err = err, nil
		}
		if err == nil && request.Action == "mtu-evidence" {
			response, err := m.evidenceResponse(q, observationError)
			return response, errors.Join(err, ctx.Err(), peer.Current(ctx))
		}
	case "mtu-resolve":
		if q.Expected == nil || *q.Expected != m.current || q.ID != "" || q.MTU != 0 || q.DeadlineNS != 0 || q.Reservation != nil || q.Digest != "" || q.Role != 0 || q.Phase != 0 || q.Offset != 0 || q.Retiring || m.active != nil && !m.active.settled {
			return nil, errors.New("standard MTU resolver changed its original settled TUN")
		}
		addresses, failure := s.resolveMTUPublicHost(ctx, m.session)
		if failure != nil {
			return nil, failure
		}
		response := m.response()
		response.Addresses = addresses
		return response, ctx.Err()
	default:
		return nil, errors.New("standard MTU action is unavailable")
	}
	if err != nil {
		return nil, err
	}
	if request.Action == "mtu-ack" {
		if err := m.native.current(ctx); err != nil {
			return nil, err
		}
		if err := s.loadProfiles(); err != nil {
			return nil, err
		}
		if err := m.session.owner.legacyDNSCurrent(ctx); err != nil {
			return nil, err
		}
		if err := s.networkCurrent(ctx, m.session, true); err != nil {
			return nil, err
		}
	}
	return m.responseFor(q.Retiring, observationError), errors.Join(ctx.Err(), peer.Current(ctx))
}

func validateLinuxStandardMTUFollowup(action string, q *linuxStandardServiceMTURequest) error {
	if q == nil || q.MTU != 0 || q.Role > standardengine.RollbackReader || q.Phase > standardengine.RetirementEvidence || action != "mtu-evidence" && (q.Role != 0 || q.Phase != 0 || q.Offset != 0) ||
		action != "mtu-evidence" && action != "mtu-ack" && q.Digest != "" {
		return errors.New("standard MTU follow-up supplied another operation's fields")
	}
	return nil
}

func (m *linuxStandardServiceMTU) evidenceResponse(q *linuxStandardServiceMTURequest, observationError error) (*linuxStandardServiceMTUResponse, error) {
	if q == nil || q.Role > standardengine.RollbackReader || q.Phase > standardengine.RetirementEvidence || m.active == nil || m.active.report == nil || q.Digest != m.active.report.Result.Digest {
		return nil, errors.New("standard MTU evidence page changed its original joined result")
	}
	entry := m.active.report.Readers[q.Role]
	if entry == nil {
		return nil, errors.New("standard MTU requested an absent original reader")
	}
	response := m.responseFor(q.Retiring, observationError)
	response.Ready = "" // One raw page must fit the unchanged packet bound.
	binding := entry.Binding
	response.Binding = &binding
	page := entry.Ready
	if q.Phase == standardengine.RetirementEvidence {
		page = entry.Retirement
	}
	if q.Offset < 0 || q.Offset >= len(page) || q.Offset%linuxStandardServiceMTUEvidencePart != 0 {
		return nil, errors.New("standard MTU evidence offset is outside its original page")
	}
	end := min(q.Offset+linuxStandardServiceMTUEvidencePart, len(page))
	response.Evidence, response.EvidenceSize, response.NextOffset = append([]byte(nil), page[q.Offset:end]...), len(page), end
	return response, nil
}

// Called under the same authenticated service gate and namespace as live RPCs.
// This reads already retained bytes only. No closed descriptor, source proof or
// observer is reconstructed, and no new work or healthy ACK is admitted.
func (s *linuxStandardService) retiredMTUResponse(request linuxStandardServiceRequest, peer *linuxStandardServicePeer) (*linuxStandardServiceMTUResponse, error) {
	session, q := s.session, request.MTU
	if session == nil || session.mtu == nil || session.peer == nil || peer == nil || session.peer.record != peer.record || session.request.Session != request.Session ||
		q == nil || !q.Retiring || request.Action != "mtu-status" && request.Action != "mtu-cancel" && request.Action != "mtu-evidence" {
		return nil, errors.New("standard MTU retired evidence lost its original authenticated Stop owner")
	}
	m := session.mtu
	if m.session != session || session.owner == nil || m.native == nil || m.native != session.owner.native || m.active == nil ||
		!session.joined && (session.network == nil || !session.network.closed) && !m.native.closed {
		return nil, errors.New("standard MTU retired evidence has no retained original retirement")
	}
	if err := validateLinuxStandardMTUFollowup(request.Action, q); err != nil {
		return nil, err
	}
	if err := m.matches(q); err != nil {
		return nil, err
	}
	op := m.active
	if !op.noSubmission {
		if !op.historyValid || op.report == nil || !op.report.Result.WorkerJoined || op.report.Result.Pending {
			return nil, errors.New("standard MTU retirement has no complete joined original evidence")
		}
		if _, err := validateLinuxStandardServiceMTUReport(*op.report, op.original); err != nil {
			return nil, err
		}
	}
	retired := errors.New("original service activation has retired; retained evidence authorizes only its owned Stop")
	response := m.responseFor(true, retired)
	if request.Action == "mtu-evidence" {
		var err error
		response, err = m.evidenceResponse(q, retired)
		if err != nil {
			return nil, err
		}
	}
	response.Settled = false
	return response, nil
}

func (m *linuxStandardServiceMTU) responseFor(retiring bool, observationError error) *linuxStandardServiceMTUResponse {
	response := m.response()
	if !retiring || m.active == nil {
		return response
	}
	op := m.active
	if op.noSubmission {
		key := op.command.Reservation.Key
		response.Rejected = &linuxStandardServiceMTURejected{ID: key.ID, DeadlineNS: key.DeadlineNS, Expected: key.Original, Reason: op.rejection}
		response.Pending = false
	} else if op.historyValid && op.report != nil && op.report.Result.WorkerJoined {
		response.Pending = op.report.Result.Pending
	}
	if observationError != nil {
		response.ObservationError = "original network observation failed; evidence is retained only for owned Stop"
	}
	return response
}

func (m *linuxStandardServiceMTU) requestCleanup(ctx context.Context) error {
	if err := m.poll(ctx); err != nil {
		return err
	}
	op := m.active
	if op == nil || op.noSubmission || op.report == nil || !op.report.Result.WorkerJoined || !op.report.Result.Pending || op.ended || op.settled {
		return errors.New("standard MTU cleanup retry lacks its original joined pending native transaction")
	}
	// This is an explicit bounded cleanup request. It cannot create a new
	// candidate or renew the original measurement's cleanup allowance.
	return m.native.operations.RequestCleanup(ctx, op.command.Reservation)
}

func (m *linuxStandardServiceMTU) drainForStop(ctx context.Context) error {
	if m == nil || m.active == nil || m.active.settled {
		return nil
	}
	op := m.active
	if m.session != nil && (m.session.joined || m.native != nil && m.native.closed || m.session.network != nil && m.session.network.closed && (op.noSubmission || op.historyValid && op.report != nil && op.report.Result.WorkerJoined && !op.report.Result.Pending)) {
		if m.session.mtu != m || m.native == nil || m.session.owner == nil || m.session.owner.native != m.native {
			return errors.New("standard MTU retired drain lost its original native owner")
		}
		if !op.noSubmission {
			if !op.historyValid || op.report == nil || !op.report.Result.WorkerJoined || op.report.Result.Pending {
				return errors.New("standard MTU retired drain lacks its complete joined original history")
			}
			if _, err := validateLinuxStandardServiceMTUReport(*op.report, op.original); err != nil {
				return err
			}
		}
		// A completed autonomous retirement already drained this exact worker.
		// Its closed FD11 cannot acquire a fresh Cancel; continue the original
		// native/detached-protection Stop without claiming healthy settlement.
		return ctx.Err()
	}
	if !op.noSubmission {
		if err := m.native.operations.Cancel(ctx, op.command.Reservation); err != nil {
			return err
		}
	}
	// FD10 owns explicit Stop. An unfinished FD11 call must not prevent that
	// original child from receiving its cancellation/join request. Keep every
	// reservation, token and partial result; no healthy settlement is inferred.
	err := m.poll(ctx)
	if op.ended || op.noSubmission || op.historyValid && op.report != nil && op.report.Result.WorkerJoined && !op.report.Result.Pending {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	return ctx.Err()
}

// During the exact admitted transition the original observer retains events
// for Complete; calling ordinary Current would incorrectly reject our own
// mutation. This bounded branch performs no successful connection proof.
func (s *linuxStandardService) watchNetworkCurrent(ctx context.Context, session *linuxStandardServiceSession) error {
	if m := session.mtu; m != nil && m.active != nil && !m.active.ended {
		if s.session != session || m.session != session || m.native == nil || session.owner == nil || session.owner.native != m.native || m.native.owner != session.owner || session.network == nil || session.network.session != session || session.network.owner != session.owner || session.network.observer != m.native.tracker || session.network.closed || session.network.lifetime == nil || session.network.lifetime.Err() != nil {
			return errors.New("standard MTU watch lost its original transition")
		}
		if session.network.failure != nil {
			return session.network.failure
		}
		if err := m.native.current(ctx); err != nil {
			return err
		}
		if err := m.poll(ctx); err != nil {
			return err
		}
		if !m.active.ended {
			if time.Now().UnixNano() > m.active.command.Reservation.Key.DeadlineNS+int64(8*time.Second) {
				return errors.New("standard MTU original work and cleanup deadline expired")
			}
			return ctx.Err()
		}
	}
	return s.networkCurrent(ctx, session, false)
}
