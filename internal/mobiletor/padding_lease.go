package mobiletor

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

// PaddingLeaseOptions captures a single proved Tor path. Current and
// ProofValidUntil must read that same immutable owner, including selected DNS;
// they must not read the UI selection or depend on this lease's Healthy method.
// ProofValidUntil is the expiry of an actual completed proof, never now+TTL.
// Callbacks must be bounded and must not hold host locks across lease methods.
// Retire revokes the captured host on failure; it runs outside our locks after
// the worker has joined and must enqueue any longer host teardown.
type PaddingLeaseOptions struct {
	SessionSHA256, SourceSHA256, Username, Password string
	RateKbps                                        int
	Current                                         func() bool
	ProofValidUntil                                 func() time.Time
	Retire                                          func(error)
}

// PaddingLease borrows one authenticated control owner. Construction does no
// I/O. Start requires actual channel accounting before returning success. The
// host must retain this object and its native process until Close succeeds or
// that exact native process has been joined; Cancel alone is not a drain.
type PaddingLease struct {
	control                                    *Control
	options                                    PaddingLeaseOptions
	ctx                                        context.Context
	cancel                                     context.CancelFunc
	mu                                         sync.Mutex
	closeMu                                    chan struct{}
	started, cancelled, closed, ready, issued  bool
	done                                       chan struct{}
	identity                                   PaddingIdentity
	status                                     PaddingStatus
	known                                      bool
	observed, validUntil, channelAt, nextRenew time.Time
	startedAt                                  time.Time
	failure                                    error
}

func NewPaddingLease(parent context.Context, control *Control, options PaddingLeaseOptions) (*PaddingLease, error) {
	identity := PaddingIdentity{SessionSHA256: options.SessionSHA256, SourceSHA256: options.SourceSHA256, Generation: 1}
	_, err := identity.arguments()
	if parent == nil || control == nil || control.conn == nil || err != nil || options.Current == nil || options.ProofValidUntil == nil || options.Retire == nil ||
		!paddingHex(options.Username, 32, 64) || !paddingHex(options.Password, 64) || options.RateKbps < PaddingMinRateKbps || options.RateKbps > PaddingMaxRateKbps {
		return nil, errors.New("Tor padding lease requires its captured owner, proof, rate and isolation")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	return &PaddingLease{control: control, options: options, ctx: ctx, cancel: cancel, closeMu: make(chan struct{}, 1)}, nil
}

func (l *PaddingLease) proof() (time.Time, error) {
	if err := l.ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if !l.options.Current() {
		return time.Time{}, errors.New("Tor padding lost its captured path or DNS owner")
	}
	until := l.options.ProofValidUntil()
	if time.Until(until) < PaddingMinTTL {
		return time.Time{}, errors.New("Tor padding requires a fresh captured path and DNS proof")
	}
	return until, nil
}

// A normal Disconnect must not interrupt a valid framed reply and destroy the
// mobile process's sole resident control stream. Finish the already-issued
// operation within a separate bound, then reject a cancelled/stale owner.
// Malformed replies and operations that exceed this bound still retire Control.
func paddingLeaseCommandContext(request context.Context, until time.Time) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(5 * time.Second)
	if until.Before(deadline) {
		deadline = until
	}
	if end, ok := request.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	return context.WithDeadline(context.Background(), deadline)
}

// record never moves a receipt's expiry forward by the control round trip.
// The timestamp is the command's send instant, and renewal is capped by the
// captured proof's absolute deadline. Counters are cumulative in one generation.
func (l *PaddingLease) record(status PaddingStatus, sent, proofUntil time.Time, grant bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.known && (status.QueuedCells < l.status.QueuedCells || status.QueuedBytes < l.status.QueuedBytes ||
		status.ChannelCells < l.status.ChannelCells || status.ChannelBytes < l.status.ChannelBytes ||
		status.DroppedCells < l.status.DroppedCells || status.DroppedBytes < l.status.DroppedBytes) {
		return errors.New("Tor padding counters regressed within the captured generation")
	}
	if status.ChannelCells > l.status.ChannelCells {
		l.channelAt = sent
	}
	until := sent.Add(status.Expires)
	if status.State != "running" {
		until = time.Time{}
	} else {
		if proofUntil.Before(until) {
			until = proofUntil
		}
		if !grant && l.known && l.validUntil.Before(until) {
			until = l.validUntil
		}
	}
	l.status, l.observed, l.validUntil, l.known = status, sent, until, true
	if grant {
		l.nextRenew = sent.Add(min(2*time.Second, until.Sub(sent)/2))
	}
	return nil
}

func (l *PaddingLease) command(ctx context.Context, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	proofUntil, err := l.proof()
	if err != nil {
		return err
	}
	l.mu.Lock()
	progressAt := l.channelAt
	if progressAt.IsZero() {
		progressAt = l.startedAt
	}
	l.mu.Unlock()
	if progressUntil := progressAt.Add(PaddingMaxTTL); progressUntil.Before(proofUntil) {
		proofUntil = progressUntil
	}
	sent := time.Now()
	ttl := min(PaddingMaxTTL, proofUntil.Sub(sent)).Truncate(time.Millisecond)
	if ttl < PaddingMinTTL {
		return errors.New("Tor padding proof expired before its control operation")
	}
	operation, cancel := paddingLeaseCommandContext(ctx, proofUntil)
	defer cancel()
	l.mu.Lock()
	identity := l.identity
	if action == "start" {
		l.issued = true
	}
	l.mu.Unlock()
	var status PaddingStatus
	switch action {
	case "start":
		status, err = l.control.StartPadding(operation, identity, l.options.RateKbps, ttl, l.options.Username, l.options.Password)
	case "renew":
		status, err = l.control.RenewPadding(operation, identity, l.options.RateKbps, ttl)
	default:
		status, err = l.control.PaddingStatus(operation, identity, l.options.RateKbps)
	}
	if err != nil {
		return err
	}
	if status.State != "running" {
		return errors.New("Tor padding native generation retired")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := l.proof(); err != nil {
		return err
	}
	if err := l.record(status, sent, proofUntil, action != "status"); err != nil {
		_ = l.control.Close()
		return err
	}
	return nil
}

// Start is one-shot, including failed attempts. A cancelled/failed attempt may
// have reached native START and must still be passed to Close by its host.
func (l *PaddingLease) Start(ctx context.Context) error {
	if l == nil || ctx == nil {
		return errors.New("Tor padding start requires its captured lifetime")
	}
	l.mu.Lock()
	if l.started || l.cancelled || l.closed {
		l.mu.Unlock()
		return errors.New("Tor padding lease has already started or retired")
	}
	l.started, l.done, l.startedAt = true, make(chan struct{}), time.Now()
	l.mu.Unlock()
	startup, cancel := context.WithTimeout(ctx, PaddingMaxTTL)
	stop := context.AfterFunc(l.ctx, cancel)
	defer func() { stop(); cancel() }()
	err := l.start(startup)
	if err == nil {
		err = startup.Err()
	}
	if err == nil {
		err = l.ctx.Err()
	}
	if err != nil {
		l.finish(err)
		return err
	}
	l.mu.Lock()
	l.ready = !l.cancelled && l.ctx.Err() == nil
	ready := l.ready
	l.mu.Unlock()
	if !ready {
		err := errors.New("Tor padding was cancelled before activation")
		l.finish(err)
		return err
	}
	go func() { l.finish(l.monitor()) }()
	return nil
}

func (l *PaddingLease) start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	proofUntil, err := l.proof()
	if err != nil {
		return err
	}
	operation, cancel := paddingLeaseCommandContext(ctx, proofUntil)
	capability, err := l.control.PaddingInfo(operation)
	cancel()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if capability.GenerationHighWater == math.MaxInt64 {
		return errors.New("Tor padding generation is exhausted")
	}
	l.mu.Lock()
	l.identity = PaddingIdentity{SessionSHA256: l.options.SessionSHA256, SourceSHA256: l.options.SourceSHA256, Generation: capability.GenerationHighWater + 1}
	l.mu.Unlock()
	if err := l.command(ctx, "start"); err != nil {
		return err
	}
	for {
		l.mu.Lock()
		hasChannel := l.status.ChannelCells > 0
		l.mu.Unlock()
		if hasChannel {
			return nil
		}
		if err := l.tick(ctx); err != nil {
			return err
		}
	}
}

func (l *PaddingLease) tick(ctx context.Context) error {
	proofUntil, err := l.proof()
	if err != nil {
		return err
	}
	l.mu.Lock()
	validUntil, channelAt, renewAt := l.validUntil, l.channelAt, l.nextRenew
	l.mu.Unlock()
	if !channelAt.IsZero() && time.Since(channelAt) >= PaddingMaxTTL {
		return errors.New("Tor padding has no recent native channel progress")
	}
	wait := min(100*time.Millisecond, time.Until(validUntil), time.Until(proofUntil))
	if wait <= 0 {
		return errors.New("Tor padding native or path proof expired")
	}
	if untilRenew := time.Until(renewAt); untilRenew > 0 {
		timer := time.NewTimer(min(wait, untilRenew))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.ctx.Done():
			return l.ctx.Err()
		case <-timer.C:
		}
	}
	// Status readback cannot extend the current grant. Renew at most every two
	// seconds, and earlier for a short proof, while retaining that proof expiry.
	action := "status"
	if !time.Now().Before(renewAt) {
		action = "renew"
	}
	return l.command(ctx, action)
}

func (l *PaddingLease) monitor() error {
	for {
		if err := l.tick(l.ctx); err != nil {
			return err
		}
	}
}

func (l *PaddingLease) finish(err error) {
	l.mu.Lock()
	l.ready = false
	retire := err != nil && !l.cancelled
	if retire && l.failure == nil {
		l.failure = err
	}
	done := l.done
	l.mu.Unlock()
	l.cancel()
	// No worker remains when the host receives failure. A host callback may
	// safely request Close without waiting for the callback that invoked it.
	close(done)
	if retire {
		l.options.Retire(err)
	}
}

// Receipt is an atomic cache snapshot, with conservative absolute observation
// and expiry times. The boolean means current, proved, recently advancing and
// actually active, not merely that an old receipt exists.
func (l *PaddingLease) Receipt() (PaddingStatus, time.Time, time.Time, bool) {
	if l == nil {
		return PaddingStatus{}, time.Time{}, time.Time{}, false
	}
	l.mu.Lock()
	status, observed, until, channel := l.status, l.observed, l.validUntil, l.channelAt
	valid := l.known && l.ready && !l.cancelled && !l.closed && l.failure == nil
	l.mu.Unlock()
	if !valid || l.ctx.Err() != nil || status.State != "running" || status.ChannelCells == 0 || !time.Now().Before(until) ||
		time.Since(channel) >= PaddingMaxTTL || !l.options.Current() {
		return status, observed, until, false
	}
	if proofUntil := l.options.ProofValidUntil(); proofUntil.Before(until) {
		until = proofUntil
	}
	if !time.Now().Before(until) {
		return status, observed, until, false
	}
	return status, observed, until, true
}

func (l *PaddingLease) Healthy() bool { _, _, _, valid := l.Receipt(); return valid }

// Snapshot and Status expose the last actual native receipt, including
// stopping/stopped. They do not establish current health or a new observation.
func (l *PaddingLease) Snapshot() (PaddingStatus, time.Time, bool) {
	if l == nil {
		return PaddingStatus{}, time.Time{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.status, l.observed, l.known
}

func (l *PaddingLease) Status() (PaddingStatus, bool) {
	status, _, known := l.Snapshot()
	return status, known
}

func (l *PaddingLease) Error() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failure
}

// Cancel revokes host health immediately. It neither claims queued ciphertext
// disappeared nor relinquishes the native process that must drain it.
func (l *PaddingLease) Cancel() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.cancelled, l.ready = true, false
	l.mu.Unlock()
	l.cancel()
}

// Join revokes health and joins this lease's control worker. It does not stop
// native cover, acknowledge queued ciphertext, or release the native process.
// A resident host may Join, quiesce the exact native network owner, then Close;
// that ordering preserves the framed controller while Tor discards its queues.
func (l *PaddingLease) Join(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("Tor padding join requires its cleanup lifetime")
	}
	l.Cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	done := l.done
	l.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (l *PaddingLease) Close(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("Tor padding close requires its cleanup lifetime")
	}
	l.Cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case l.closeMu <- struct{}{}:
		defer func() { <-l.closeMu }()
	case <-ctx.Done():
		return ctx.Err()
	}
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return nil
	}
	if err := l.Join(ctx); err != nil {
		return err
	}
	l.mu.Lock()
	issued, identity := l.issued, l.identity
	l.mu.Unlock()
	if issued {
		if err := ctx.Err(); err != nil {
			return err
		}
		sent := time.Now()
		status, err := l.control.StopPadding(ctx, identity, l.options.RateKbps)
		for {
			if err != nil {
				return err
			}
			if err := l.record(status, sent, time.Time{}, false); err != nil {
				_ = l.control.Close()
				return err
			}
			if status.State == "stopped" && status.PendingCells == 0 {
				break
			}
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			sent = time.Now()
			status, err = l.control.PaddingStatus(ctx, identity, l.options.RateKbps)
		}
	}
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return nil
}
