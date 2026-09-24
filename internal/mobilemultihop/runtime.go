package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
)

type controlError struct{ status int }

func (e controlError) Error() string { return "private entry rejected the lease operation" }
func (c *Controller) exchange(ctx context.Context, tag, method, target, token string, payload []byte) ([]byte, time.Duration, error) {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 2500 * time.Millisecond,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, errors.New("unsupported probe network")
			}
			return c.engine.Dial(ctx, tag, address)
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not permitted") }}
	request, e := http.NewRequestWithContext(ctx, method, target, strings.NewReader(string(payload)))
	if e != nil {
		return nil, 0, errors.New("invalid private request")
	}
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Accept-Encoding", "identity")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if len(payload) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	start := time.Now()
	response, e := client.Do(request)
	if e != nil {
		return nil, 0, errors.New("routed request failed or timed out")
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
	_ = response.Body.Close()
	elapsed := time.Since(start)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, 0, controlError{response.StatusCode}
	}
	if readErr != nil || len(data) > 8192 || ctx.Err() != nil {
		return nil, 0, errors.New("routed response was oversized or expired")
	}
	return data, elapsed, nil
}
func healthURL(raw string) string { u, _ := url.Parse(raw); u.Path = "/health"; return u.String() }
func (c *Controller) prove(ctx context.Context, tag, api, token, node string) (time.Duration, error) {
	if e := c.requireValid(); e != nil {
		return 0, e
	}
	data, elapsed, e := c.exchange(ctx, tag, "GET", healthURL(api), token, nil)
	if e != nil {
		return 0, e
	}
	var response struct {
		OK     bool   `json:"ok"`
		NodeID string `json:"node_id"`
		Proof  string `json:"proof"`
	}
	if exactJSON(data, &response, 8192) != nil || !response.OK || response.NodeID != node || response.Proof != "router-vpn-private-agent-v1" {
		return 0, errors.New("candidate returned the wrong node proof")
	}
	return elapsed, c.requireValid()
}
func (c *Controller) leaseRequest(ctx context.Context, method string, body []byte) ([]byte, error) {
	target, _ := url.Parse(c.meta.EntryAPI)
	target.Path = "/api/multihop/lease"
	data, _, e := c.exchange(ctx, c.meta.EntryTag, method, target.String(), c.meta.EntryToken, body)
	return data, e
}
func (c *Controller) acquire(ctx context.Context) error {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if c.ownsLease {
		return errors.New("a previous server lease has not been released")
	}
	data, e := c.leaseRequest(ctx, "GET", nil)
	if e != nil {
		return e
	}
	var caps struct {
		NodeID    string `json:"node_id"`
		Execution string `json:"execution"`
		Exits     []struct {
			ID        string `json:"exit_id"`
			Mode      string `json:"exit_mode"`
			Node      string `json:"exit_node_id"`
			PublicKey string `json:"client_public_key,omitempty"`
		} `json:"exits"`
	}
	if exactJSON(data, &caps, 8192) != nil || caps.NodeID != c.meta.EntryNodeID || caps.Execution != "server" {
		return errors.New("unproved entry relay capabilities")
	}
	found := false
	for _, exit := range caps.Exits {
		if exit.ID == c.meta.ExitID && exit.Mode == c.meta.ExitMode && exit.Node == c.meta.ExitNodeID {
			if c.meta.ExitMode == "wg" && (exit.PublicKey == "" || exit.PublicKey == c.localPublicKey) {
				return errors.New("server WireGuard needs separately paired client credentials to avoid peer roaming")
			}
			found = true
		}
	}
	if !found {
		return errors.New("the selected exit is not paired on the entry server")
	}
	c.ownsLease = true // An expired HTTP request may nevertheless have created it.
	if e = c.renewLocked(ctx); e != nil {
		var rejected controlError
		if errors.As(e, &rejected) && rejected.status >= 400 && rejected.status < 500 {
			c.ownsLease = false
		}
	}
	return e
}
func (c *Controller) renewLocked(ctx context.Context) error {
	body, _ := json.Marshal(c.proposal)
	data, e := c.leaseRequest(ctx, "PUT", body)
	if e != nil {
		return e
	}
	var lease multihoprelay.Lease
	if exactJSON(data, &lease, 8192) != nil || lease.Request != c.proposal || lease.NodeID != c.meta.EntryNodeID || lease.ExitNodeID != c.meta.ExitNodeID || lease.Host != c.expected.Host || lease.Port != c.expected.Port || lease.Username != c.expected.Username || lease.Password != c.expected.Password {
		return errors.New("server relay response changed the frozen lease")
	}
	remaining := time.Until(lease.ExpiresAt)
	if remaining < 2*time.Second || remaining > 305*time.Second {
		return errors.New("relay expiry is invalid")
	}
	c.expected.ExpiresAt = lease.ExpiresAt
	return nil
}
func (c *Controller) release() error {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if !c.ownsLease {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	body, _ := json.Marshal(c.proposal)
	data, e := c.leaseRequest(ctx, "DELETE", body)
	if e != nil {
		return errors.New("server lease cleanup is unverified; it remains owned until confirmed or expired")
	}
	var response struct {
		Node    string `json:"node_id"`
		Session string `json:"session_id"`
		Stopped bool   `json:"stopped"`
	}
	if exactJSON(data, &response, 8192) != nil || !response.Stopped || response.Node != c.meta.EntryNodeID || response.Session != c.proposal.SessionID {
		return errors.New("server lease stop acknowledgement is invalid")
	}
	c.ownsLease = false
	return nil
}
func (c *Controller) renew() {
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.renewCancel = cancel
	c.renewDone = make(chan struct{})
	done := c.renewDone
	c.mu.Unlock()
	go func() {
		defer close(done)
		for {
			c.leaseMu.Lock()
			remaining := time.Until(c.expected.ExpiresAt)
			c.leaseMu.Unlock()
			period := remaining / 3
			if period > 20*time.Second {
				period = 20 * time.Second
			}
			if period < time.Second {
				period = time.Second
			}
			timer := time.NewTimer(period)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			child, stop := context.WithTimeout(ctx, 8*time.Second)
			c.leaseMu.Lock()
			err := c.renewLocked(child)
			c.leaseMu.Unlock()
			stop()
			if err != nil || !c.valid() {
				c.failed("Server lease renewal failed; this path is no longer proved.")
				c.invalidate()
				return
			}
		}
	}()
}

type trial struct {
	owner     *Controller
	candidate routechoice.Candidate
	tag       string
}

func (s *trial) Identity() string {
	if !s.owner.valid() {
		return ""
	}
	return s.owner.engineID + ":" + s.tag
}
func (s *trial) Verify(ctx context.Context) error {
	c := s.owner
	if _, e := c.prove(ctx, c.meta.EntryTag, c.meta.EntryAPI, c.meta.EntryToken, c.meta.EntryNodeID); e != nil {
		return e
	}
	_, e := c.prove(ctx, s.tag, c.meta.ExitAPI, c.meta.ExitToken, c.meta.ExitNodeID)
	return e
}
func (s *trial) ProbeLast(ctx context.Context) (time.Duration, error) {
	c := s.owner
	return c.prove(ctx, s.tag, c.meta.ExitAPI, c.meta.ExitToken, c.meta.ExitNodeID)
}
func (s *trial) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	allowed := false
	for _, t := range Targets {
		if t == target {
			allowed = true
		}
	}
	if !allowed || s.Identity() == "" {
		return 0, errors.New("unapproved or stale external probe")
	}
	_, elapsed, e := s.owner.exchange(ctx, s.tag, "GET", target, "", nil)
	if e != nil {
		return 0, e
	}
	return elapsed, s.owner.requireValid()
}
func (s *trial) Close(context.Context) error {
	if s.candidate.Execution == routechoice.Server {
		return s.owner.release()
	}
	return nil
}

type driver struct{ owner *Controller }

func (d driver) Open(ctx context.Context, candidate routechoice.Candidate) (routechoice.Session, error) {
	c := d.owner
	if e := c.requireValid(); e != nil {
		return nil, e
	}
	if candidate != c.candidate(candidate.Execution) {
		return nil, errors.New("candidate no longer matches the selected graph")
	}
	s := &trial{owner: c, candidate: candidate, tag: LocalTag}
	if candidate.Execution == routechoice.Server {
		s.tag = ServerTag
		if e := c.acquire(ctx); e != nil {
			return s, e
		}
	}
	return s, nil
}
func (c *Controller) Run(parent context.Context, engine Engine) error {
	c.mu.Lock()
	if c.runDone != nil || engine == nil {
		c.mu.Unlock()
		return errors.New("multihop controller cannot be reused")
	}
	ctx, cancel := context.WithTimeout(parent, 100*time.Second)
	c.cancel = cancel
	c.runDone = make(chan struct{})
	done := c.runDone
	c.engine = engine
	c.engineID = engine.Identity()
	c.mu.Unlock()
	defer close(done)
	defer cancel()
	var active routechoice.Session
	var result routechoice.Result
	var err error
	options := routechoice.Options{Targets: Targets, StartupTimeout: 15 * time.Second, ProbeTimeout: 2500 * time.Millisecond, CleanupTimeout: 10 * time.Second, Preferred: routechoice.Local, Notify: c.event}
	if c.meta.Execution == "auto" {
		result, active, err = routechoice.Compare(ctx, []routechoice.Candidate{c.candidate(routechoice.Local), c.candidate(routechoice.Server)}, driver{c}, options)
	} else {
		candidate := c.candidate(routechoice.Execution(c.meta.Execution))
		child, stop := context.WithTimeout(ctx, 15*time.Second)
		active, err = (driver{c}).Open(child, candidate)
		stop()
		if err == nil {
			child, stop = context.WithTimeout(ctx, 2500*time.Millisecond)
			err = active.Verify(child)
			stop()
		}
		if err == nil {
			child, stop = context.WithTimeout(ctx, 2500*time.Millisecond)
			last, e := active.ProbeLast(child)
			stop()
			err = e
			if err == nil {
				child, stop = context.WithTimeout(ctx, 2500*time.Millisecond)
				external, e := active.ProbeExternal(child, Targets[0])
				stop()
				err = e
				if err == nil {
					measurement, e := routechoice.Score(candidate, last, external)
					err = e
					result.Winner = &candidate
					result.Final = &measurement
					c.event(routechoice.Event{Stage: "measured", Candidate: candidate, Result: &measurement})
				}
			}
		}
	}
	if err == nil {
		err = c.requireValid()
	}
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil && result.Winner != nil {
		tag := LocalTag
		if result.Winner.Execution == routechoice.Server {
			tag = ServerTag
		}
		err = engine.Select(tag)
		if err == nil && engine.Selected() != tag {
			err = errors.New("native selector did not retain the proved winner")
		}
	}
	if err != nil || result.Winner == nil {
		if active != nil {
			_ = active.Close(context.Background())
		}
		c.failed("No eligible path remained after comparison or activation.")
		if err == nil {
			err = routechoice.ErrNoWinner
		}
		return err
	}
	c.mu.Lock()
	c.progress.Stage = "selected"
	c.progress.Complete = true
	c.progress.Execution = string(result.Winner.Execution)
	c.mu.Unlock()
	if result.Winner.Execution == routechoice.Server {
		c.renew()
	}
	return nil
}
func (c *Controller) Healthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.engine != nil && c.generation.Load() == 1 && c.engine.Identity() == c.engineID
}
func (c *Controller) Close() error {
	c.invalidate()
	c.mu.Lock()
	if c.renewCancel != nil {
		c.renewCancel()
	}
	renewDone, runDone := c.renewDone, c.runDone
	c.mu.Unlock()
	for _, done := range []chan struct{}{renewDone, runDone} {
		if done != nil {
			select {
			case <-done:
			case <-time.After(12 * time.Second):
				return errors.New("mobile comparison teardown is still pending")
			}
		}
	}
	return c.release()
}
