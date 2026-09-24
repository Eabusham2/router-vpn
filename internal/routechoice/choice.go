// Package routechoice compares proved local and server-owned multihop sessions.
// Neither a missing measurement nor a failed tunnel is a zero-latency candidate.
package routechoice

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

type Execution string

const (
	Local  Execution = "local"
	Server Execution = "server"
)

type Candidate struct {
	Execution Execution `json:"execution"`
	Transport string    `json:"transport"`
	EntryID   string    `json:"entry_id"`
	ExitID    string    `json:"exit_id"`
}

func (c Candidate) Valid() bool {
	return (c.Execution == Local || c.Execution == Server) && c.Transport != "" && c.EntryID != "" && c.ExitID != "" && c.EntryID != c.ExitID
}

type Measurement struct {
	Candidate  Candidate `json:"candidate"`
	LastNodeMS float64   `json:"last_node_ms,omitempty"`
	ExternalMS float64   `json:"external_ms,omitempty"`
	ScoreMS    *float64  `json:"score_ms,omitempty"`
	Eligible   bool      `json:"eligible"`
	Failure    string    `json:"failure,omitempty"`
}

// Session owns an actual running path. Methods must honor context deadlines.
// Identity changes (node, execution, transport, reconnect or underlying network)
// invalidate its measurements and activation. Close must confirm teardown.
// Probes must stay on this path; direct/system fallback is never permitted.
type Session interface {
	Identity() string
	Verify(context.Context) error
	ProbeLast(context.Context) (time.Duration, error)
	ProbeExternal(context.Context, string) (time.Duration, error)
	Close(context.Context) error
}
type Driver interface {
	Open(context.Context, Candidate) (Session, error)
}
type Event struct {
	Stage     string
	Candidate Candidate
	Result    *Measurement
}
type Options struct {
	// Targets must already be approved, bounded response endpoints. One is chosen
	// uniformly for this round and used for EVERY candidate and final recheck.
	Targets        []string
	ProbeTimeout   time.Duration
	StartupTimeout time.Duration
	CleanupTimeout time.Duration
	Preferred      Execution // Tie only: retain a proved preferred execution.
	Notify         func(Event)
}
type Result struct {
	Target       string        `json:"target"`
	Measurements []Measurement `json:"measurements"`
	Winner       *Candidate    `json:"winner,omitempty"`
	Final        *Measurement  `json:"final,omitempty"`
}

var ErrNoWinner = errors.New("no multihop candidate passed both routed probes")
var ErrTeardown = errors.New("previous multihop teardown could not be verified; no further candidate was started")

func durationMS(v time.Duration) float64 { return float64(v) / float64(time.Millisecond) }
func Score(c Candidate, last, external time.Duration) (Measurement, error) {
	m := Measurement{Candidate: c}
	if !c.Valid() || last <= 0 || external <= 0 {
		return m, errors.New("two positive measurements from a valid candidate are required")
	}
	m.LastNodeMS = durationMS(last)
	m.ExternalMS = durationMS(external)
	// Convert before addition: adding time.Duration values could overflow.
	value := m.LastNodeMS/2 + m.ExternalMS/2
	m.ScoreMS = &value
	m.Eligible = true
	return m, nil
}
func defaults(o Options) (Options, error) {
	if len(o.Targets) < 1 || len(o.Targets) > 32 {
		return o, errors.New("provide between one and 32 approved external probe targets")
	}
	seen := map[string]bool{}
	for _, v := range o.Targets {
		if v == "" || len(v) > 2048 || seen[v] {
			return o, errors.New("external probe targets must be nonempty, bounded and unique")
		}
		seen[v] = true
	}
	if o.ProbeTimeout == 0 {
		o.ProbeTimeout = 2500 * time.Millisecond
	}
	if o.StartupTimeout == 0 {
		o.StartupTimeout = 15 * time.Second
	}
	if o.CleanupTimeout == 0 {
		o.CleanupTimeout = 5 * time.Second
	}
	if o.ProbeTimeout < time.Millisecond || o.ProbeTimeout > 30*time.Second || o.StartupTimeout <= 0 || o.StartupTimeout > 2*time.Minute || o.CleanupTimeout <= 0 || o.CleanupTimeout > 30*time.Second {
		return o, errors.New("invalid multihop comparison time budget")
	}
	if o.Preferred != "" && o.Preferred != Local && o.Preferred != Server {
		return o, errors.New("invalid preferred execution")
	}
	return o, nil
}
func identity(s Session, want string) error {
	if want == "" || s.Identity() != want {
		return errors.New("multihop session or underlying path changed during the measurement")
	}
	return nil
}
func measure(ctx context.Context, c Candidate, s Session, target string, o Options) (m Measurement) {
	m.Candidate = c
	fail := func(stage string) Measurement { m.Eligible = false; m.ScoreMS = nil; m.Failure = stage; return m }
	generation := s.Identity()
	child, cancel := context.WithTimeout(ctx, o.ProbeTimeout)
	err := s.Verify(child)
	expired := child.Err()
	cancel()
	if err != nil || expired != nil || identity(s, generation) != nil {
		return fail("path proof failed or expired")
	}
	child, cancel = context.WithTimeout(ctx, o.ProbeTimeout)
	last, err := s.ProbeLast(child)
	expired = child.Err()
	cancel()
	if err != nil || expired != nil || last <= 0 || last > o.ProbeTimeout || identity(s, generation) != nil {
		return fail("last-node probe failed, timed out or changed session")
	}
	m.LastNodeMS = durationMS(last)
	child, cancel = context.WithTimeout(ctx, o.ProbeTimeout)
	external, err := s.ProbeExternal(child, target)
	expired = child.Err()
	cancel()
	if err != nil || expired != nil || external <= 0 || external > o.ProbeTimeout || identity(s, generation) != nil {
		return fail("external-server probe failed, timed out or changed session")
	}
	if ctx.Err() != nil {
		return fail("comparison cancelled")
	}
	m, err = Score(c, last, external)
	if err != nil {
		return fail("invalid probe result")
	}
	return m
}
func closeSession(s Session, o Options) error {
	if s == nil {
		return nil
	}
	// Cleanup must still run when the user's comparison context is cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), o.CleanupTimeout)
	defer cancel()
	err := s.Close(ctx)
	if err != nil || ctx.Err() != nil {
		return ErrTeardown
	}
	return nil
}
func notify(o Options, stage string, c Candidate, m *Measurement) {
	if o.Notify != nil {
		o.Notify(Event{Stage: stage, Candidate: c, Result: m})
	}
}
func open(ctx context.Context, d Driver, c Candidate, o Options) (Session, error) {
	child, cancel := context.WithTimeout(ctx, o.StartupTimeout)
	defer cancel()
	s, err := d.Open(child, c)
	if err != nil || child.Err() != nil || s == nil {
		if cleanErr := closeSession(s, o); cleanErr != nil {
			return s, cleanErr
		}
		return nil, errors.New("candidate startup failed or timed out")
	}
	return s, nil
}

// Compare tests candidates sequentially, stops each verified trial, then starts
// the lowest-score survivor and reproves BOTH measurements. The returned Session
// is the ONLY path left running. Caller owns its lifetime. On ErrTeardown the
// returned Session is still owned and must be retained for recovery, not lost.
// Failed final activation tries the next eligible candidate, never a timeout.
func Compare(ctx context.Context, candidates []Candidate, d Driver, o Options) (result Result, active Session, err error) {
	o, err = defaults(o)
	if err != nil {
		return result, nil, err
	}
	if ctx == nil || d == nil || len(candidates) < 2 || len(candidates) > 64 {
		return result, nil, errors.New("comparison requires a driver and two to 64 candidates")
	}
	seen := map[Candidate]bool{}
	pair := candidates[0]
	executions := map[Execution]bool{}
	for _, c := range candidates {
		if !c.Valid() || seen[c] || c.EntryID != pair.EntryID || c.ExitID != pair.ExitID {
			return result, nil, errors.New("candidates must be unique and use the same entry and last node")
		}
		seen[c] = true
		executions[c.Execution] = true
	}
	if !executions[Local] || !executions[Server] {
		return result, nil, errors.New("compare both local and server execution; do not disguise an unimplemented path as local")
	}
	if err = ctx.Err(); err != nil {
		return result, nil, err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(o.Targets))))
	if err != nil {
		return result, nil, err
	}
	result.Target = o.Targets[n.Int64()]
	for _, c := range candidates {
		if err = ctx.Err(); err != nil {
			return result, nil, err
		}
		notify(o, "starting", c, nil)
		s, startErr := open(ctx, d, c, o)
		if errors.Is(startErr, ErrTeardown) {
			return result, s, startErr
		}
		m := Measurement{Candidate: c, Failure: "candidate startup failed or timed out"}
		if startErr == nil {
			notify(o, "probing", c, nil)
			m = measure(ctx, c, s, result.Target, o)
			notify(o, "stopping", c, &m)
			if err = closeSession(s, o); err != nil {
				return result, s, err
			}
		}
		result.Measurements = append(result.Measurements, m)
		notify(o, "measured", c, &m)
	}
	if err = ctx.Err(); err != nil {
		return result, nil, err
	}
	var eligible []Measurement
	for _, m := range result.Measurements {
		if m.Eligible {
			eligible = append(eligible, m)
		}
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		a, b := eligible[i], eligible[j]
		if *a.ScoreMS == *b.ScoreMS {
			return a.Candidate.Execution == o.Preferred && b.Candidate.Execution != o.Preferred
		}
		return *a.ScoreMS < *b.ScoreMS
	})
	for _, m := range eligible {
		if err = ctx.Err(); err != nil {
			return result, nil, err
		}
		c := m.Candidate
		notify(o, "activating", c, &m)
		s, startErr := open(ctx, d, c, o)
		if errors.Is(startErr, ErrTeardown) {
			return result, s, startErr
		}
		if startErr != nil {
			notify(o, "activation-failed", c, nil)
			continue
		}
		final := measure(ctx, c, s, result.Target, o)
		if !final.Eligible {
			if err = closeSession(s, o); err != nil {
				return result, s, err
			}
			notify(o, "activation-failed", c, &final)
			continue
		}
		result.Winner = &c
		result.Final = &final
		notify(o, "selected", c, &final)
		return result, s, nil
	}
	return result, nil, fmt.Errorf("%w; failed and timed-out candidates were excluded", ErrNoWinner)
}
