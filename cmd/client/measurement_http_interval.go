package main

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"sync"
)

// The caller supplies its already captured checked interval. This marker cannot
// select a clock or replace the native owner. Only the captured native transport
// claims it; every other transport retains the original elapsed measurement.
type clientHTTPRequestIntervalKey struct{}

type clientHTTPIntervalOwner interface {
	MatchesOriginal() bool
	Current(context.Context) error
}

type clientHTTPRequestInterval struct {
	mu                                 sync.Mutex
	caller                             context.Context
	original                           clientMeasurementInterval
	owner                              clientHTTPIntervalOwner
	body                               *clientMeasuredHTTPBody
	last, excluded, completed          float64
	guarding, exchanging, started, eof bool
	validated, closed                  bool
	failure                            error
}

func captureClientHTTPRequestInterval(request *http.Request, interval clientMeasurementInterval) (*http.Request, clientMeasurementInterval) {
	timing := &clientHTTPRequestInterval{caller: request.Context(), original: interval}
	return request.WithContext(context.WithValue(request.Context(), clientHTTPRequestIntervalKey{}, timing)), timing
}

func clientHTTPRequestTiming(ctx context.Context) *clientHTTPRequestInterval {
	timing, _ := ctx.Value(clientHTTPRequestIntervalKey{}).(*clientHTTPRequestInterval)
	return timing
}

func (t *clientHTTPRequestInterval) rejectLocked(err error) error {
	if t.failure == nil {
		t.failure = err
	}
	return t.failure
}

func (t *clientHTTPRequestInterval) checkpointLocked(ctx context.Context) (float64, error) {
	if t.failure != nil {
		return 0, t.failure
	}
	if err := errors.Join(context.Cause(t.caller), context.Cause(ctx)); err != nil {
		return 0, t.rejectLocked(err)
	}
	value, err := clientMeasurementMilliseconds(t.caller, t.original)
	if err != nil || value <= t.last {
		return 0, t.rejectLocked(errors.Join(err, errors.New("HTTP measurement lost its original increasing clock")))
	}
	t.last = value
	return value, nil
}

func (t *clientHTTPRequestInterval) claim(owner clientHTTPIntervalOwner) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.owner != nil || owner == nil || !owner.MatchesOriginal() {
		return t.rejectLocked(errors.New("HTTP interval belongs to another request or native owner"))
	}
	t.owner = owner
	return nil
}

// Only native transport boundaries with no DNS query or HTTP bytes in flight
// may exclude a check. TCP connection, socket binding, DNS exchange and parsing,
// TLS and every request/response byte remain inside the original interval.
func (t *clientHTTPRequestInterval) currentBeforeIO(ctx context.Context, owner clientHTTPIntervalOwner) error {
	t.mu.Lock()
	if owner == nil || t.owner != owner || t.guarding || t.exchanging || t.started || t.eof || !owner.MatchesOriginal() {
		err := t.rejectLocked(errors.New("HTTP ownership check overlaps transfer or changed its original owner"))
		t.mu.Unlock()
		return err
	}
	begin, err := t.checkpointLocked(ctx)
	if err != nil {
		t.mu.Unlock()
		return err
	}
	t.guarding = true
	t.mu.Unlock()
	err = owner.Current(ctx)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.guarding = false
	end, clockErr := t.checkpointLocked(ctx)
	if err != nil || clockErr != nil || !owner.MatchesOriginal() {
		return t.rejectLocked(errors.Join(err, clockErr, errors.New("HTTP pre-transfer ownership validation failed")))
	}
	t.excluded += end - begin
	return nil
}

// Called immediately before the original TCP connection is handed to HTTP.
// Once TLS/request work can start, retries or concurrent dials cannot pause it.
func (t *clientHTTPRequestInterval) beginHTTP(owner clientHTTPIntervalOwner) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failure != nil {
		return t.failure
	}
	if owner == nil || t.owner != owner || t.started || t.guarding || t.exchanging || !owner.MatchesOriginal() {
		return t.rejectLocked(errors.New("HTTP transfer lost its exclusive original connection"))
	}
	t.started = true
	return nil
}

func (t *clientHTTPRequestInterval) beginDNS(owner clientHTTPIntervalOwner) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failure != nil {
		return t.failure
	}
	if owner == nil || t.owner != owner || t.started || t.guarding || t.exchanging || !owner.MatchesOriginal() {
		return t.rejectLocked(errors.New("DNS exchange lost its original measured request"))
	}
	t.exchanging = true
	return nil
}

func (t *clientHTTPRequestInterval) endDNS(owner clientHTTPIntervalOwner) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failure != nil {
		return t.failure
	}
	if owner == nil || t.owner != owner || !t.exchanging || t.started || t.guarding || !owner.MatchesOriginal() {
		return t.rejectLocked(errors.New("DNS completion changed its original measured exchange"))
	}
	t.exchanging = false
	return nil
}

func (t *clientHTTPRequestInterval) responseBody(ctx context.Context, owner clientHTTPIntervalOwner, raw io.ReadCloser) (io.ReadCloser, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.owner != owner || !t.started || t.guarding || t.body != nil || t.failure != nil || !owner.MatchesOriginal() {
		return nil, t.rejectLocked(errors.New("HTTP response has no original measured transfer"))
	}
	body := &clientMeasuredHTTPBody{ReadCloser: raw, timing: t, owner: owner, caller: ctx}
	t.body = body
	return body, nil
}

func (t *clientHTTPRequestInterval) complete(body *clientMeasuredHTTPBody) error {
	t.mu.Lock()
	if t.body != body || t.guarding || t.closed || !body.owner.MatchesOriginal() {
		err := t.rejectLocked(errors.New("HTTP body completion changed its original owner"))
		t.mu.Unlock()
		return err
	}
	if t.eof {
		err := t.failure
		t.mu.Unlock()
		return err
	}
	end, err := t.checkpointLocked(body.caller)
	if err != nil {
		t.mu.Unlock()
		return err
	}
	t.completed, t.eof, t.guarding = end, true, true
	t.mu.Unlock()
	// Response bytes may arrive during a post-header Current call. Defer that
	// complete check until real EOF, freeze before it, and publish only after it.
	err = body.owner.Current(body.caller)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.guarding = false
	_, clockErr := t.checkpointLocked(body.caller)
	if err != nil || clockErr != nil || !body.owner.MatchesOriginal() {
		return t.rejectLocked(errors.Join(err, clockErr, errors.New("HTTP completed body lost its native ownership proof")))
	}
	t.validated = true
	return nil
}

func (t *clientHTTPRequestInterval) close(body *clientMeasuredHTTPBody, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if err != nil || t.body != body || !t.eof || !t.validated || t.guarding || !body.owner.MatchesOriginal() {
		t.rejectLocked(errors.Join(err, errors.New("HTTP measurement closed without complete original body validation")))
	}
}

func (t *clientHTTPRequestInterval) Milliseconds() (float64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failure != nil {
		return 0, t.failure
	}
	if t.owner == nil {
		return t.original.Milliseconds()
	}
	if !t.closed || !t.validated || t.guarding || !t.owner.MatchesOriginal() {
		return 0, t.rejectLocked(errors.New("HTTP measurement has no joined validated original response"))
	}
	if _, err := t.checkpointLocked(t.caller); err != nil {
		return 0, err
	}
	value := t.completed - t.excluded
	if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, t.rejectLocked(errors.New("HTTP measurement has no positive finite network interval"))
	}
	return value, nil
}

type clientMeasuredHTTPBody struct {
	io.ReadCloser
	timing *clientHTTPRequestInterval
	owner  clientHTTPIntervalOwner
	caller context.Context
	once   sync.Once
	err    error
}

func (b *clientMeasuredHTTPBody) Read(raw []byte) (int, error) {
	if !b.owner.MatchesOriginal() {
		_ = b.Close()
		return 0, errors.New("measured HTTP response retired its original reader")
	}
	n, err := b.ReadCloser.Read(raw)
	if !b.owner.MatchesOriginal() {
		_ = b.Close()
		return 0, errors.New("measured HTTP response changed its original reader")
	}
	if err == io.EOF {
		if completeErr := b.timing.complete(b); completeErr != nil {
			return 0, completeErr
		}
	}
	return n, err
}

func (b *clientMeasuredHTTPBody) Close() error {
	b.once.Do(func() {
		b.err = b.ReadCloser.Close()
		b.timing.close(b, b.err)
	})
	return b.err
}
