package mobiletor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"router-vpn/internal/multihoprelay"
)

const ServerTorClientType = "routervpn-server-tor"

const serverTorLeasePath = "/api/multihop/tor/lease"

var errServerTorClient = errors.New("captured Tor server lease is unavailable or changed")

// ServerTorClient owns a single server lease through a captured private Router
// dialer. No default resolver, HTTP proxy, physical dialer, or local Tor process
// exists here. Its receipt is server readiness, never the client's exit proof.
type ServerTorClient struct {
	ctx           context.Context
	cancel        context.CancelFunc
	entry         *PredecessorProof
	policy        *ServerTorPolicy
	session       string
	current       func() bool
	control       *Network
	data          *Network
	operation     chan struct{}
	mu            sync.Mutex
	closing       bool
	attempt       bool
	request       multihoprelay.TorRequest
	lease         multihoprelay.TorLease
	sequence      uint64
	ready         bool
	started       time.Time
	padding       *multihoprelay.TorPaddingReceipt
	paddingExpiry *time.Timer
	dial          DialContext
	comparison    *ServerTorComparison
	stoppedOwner  string
}

func NewServerTorClient(parent context.Context, policy *ServerTorPolicy, entry *PredecessorProof, session string, dial DialContext, current func() bool) (*ServerTorClient, error) {
	if parent == nil || parent.Err() != nil || policy == nil || entry == nil || policy.EntryNodeID() != entry.node || !capturedHex(session, 16) || dial == nil || current == nil || !current() {
		return nil, errServerTorClient
	}
	ctx, cancel := context.WithCancel(parent)
	c := &ServerTorClient{ctx: ctx, cancel: cancel, entry: entry, policy: policy, session: session, current: current, dial: dial, operation: make(chan struct{}, 1)}
	// Cleanup keeps this exact entry alive until DELETE is acknowledged. User
	// cancellation closes data immediately but cannot cancel its own cleanup.
	control, err := NewNetwork(context.WithoutCancel(parent), func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != entry.address || !current() {
			return nil, errServerTorClient
		}
		return dial(ctx, network, address)
	}, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	c.control = control
	c.data, err = NewNetwork(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		c.mu.Lock()
		lease, allowed := c.lease, c.ready && !c.closing && c.lease.ExpiresAt.After(time.Now()) && c.paddingCurrentLocked(time.Now())
		c.mu.Unlock()
		if !allowed || !current() || network != "tcp" {
			return nil, errServerTorClient
		}
		return dialServerTorSOCKS(ctx, net.JoinHostPort(lease.Host, strconv.Itoa(lease.Port)), lease.Username, lease.Password, address, dial)
	}, nil)
	if err != nil {
		cancel()
		_ = control.Close(context.Background())
		return nil, err
	}
	return c, nil
}

func (c *ServerTorClient) lock(ctx context.Context) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return errServerTorClient
	}
	select {
	case c.operation <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *ServerTorClient) unlock() { <-c.operation }
func (c *ServerTorClient) Current() bool {
	if c == nil {
		return false
	}
	if c.ctx.Err() != nil || !c.current() {
		c.cancel()
		return false
	}
	c.mu.Lock()
	now := time.Now()
	current := !c.closing && c.attempt && c.lease.OwnerID != "" && c.lease.ExpiresAt.After(now) && (!c.ready || c.paddingCurrentLocked(now))
	expired := c.lease.OwnerID != "" && (!c.lease.ExpiresAt.After(now) || c.ready && !c.paddingCurrentLocked(now))
	c.mu.Unlock()
	if expired {
		c.cancel()
	}
	return current
}

func (c *ServerTorClient) paddingCurrentLocked(now time.Time) bool {
	return !c.policy.Padding().Enabled || c.padding != nil && c.padding.ExpiresAt > now.UnixMilli() && now.UnixMilli()-c.padding.ObservedAt < 5000
}

func (c *ServerTorClient) adoptPaddingLocked(receipt multihoprelay.TorReceipt) bool {
	policy := c.policy.Padding()
	if receipt.Phase != multihoprelay.TorReady {
		return receipt.Padding == nil && c.padding == nil
	}
	if !policy.Enabled {
		return receipt.Padding == nil
	}
	p := receipt.Padding
	if p == nil || p.RateKbps != policy.RateKbps {
		return false
	}
	if c.padding != nil && (p.Generation != c.padding.Generation || p.ObservedAt < c.padding.ObservedAt || p.ChannelCells < c.padding.ChannelCells || p.ChannelBytes < c.padding.ChannelBytes) {
		return false
	}
	if c.padding != nil {
		cells, bytes := p.ChannelCells-c.padding.ChannelCells, p.ChannelBytes-c.padding.ChannelBytes
		if bytes < cells*512 || bytes > cells*514 {
			return false
		}
	}
	copy := *p
	c.padding = &copy
	if c.paddingExpiry != nil {
		c.paddingExpiry.Stop()
	}
	deadline := time.UnixMilli(copy.ExpiresAt)
	if observationDeadline := time.UnixMilli(copy.ObservedAt).Add(5 * time.Second); observationDeadline.Before(deadline) {
		deadline = observationDeadline
	}
	c.paddingExpiry = time.AfterFunc(time.Until(deadline), func() { c.expirePadding(&copy) })
	return true
}

func (c *ServerTorClient) expirePadding(receipt *multihoprelay.TorPaddingReceipt) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// An old timer may already be waiting for this lock when a newer nonce
	// response is adopted. Only that exact still-current receipt can cancel.
	// The timer already captured the conservative remaining duration. A wall
	// clock adjustment cannot extend that grant when the timer actually fires.
	if c.padding == receipt && !c.closing {
		c.cancel()
	}
}
func (c *ServerTorClient) Ready() bool {
	if !c.Current() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ready
}
func (c *ServerTorClient) ProveEntry(ctx context.Context) (*EntryProof, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || c.ctx.Err() != nil || !c.current() {
		return nil, errServerTorClient
	}
	if err := c.entry.Prove(ctx, c.control.DialContext); err != nil {
		return nil, err
	}
	if c.ctx.Err() != nil || !c.current() {
		return nil, errServerTorClient
	}
	return &EntryProof{EntryID: c.entry.id, EntrySHA256: c.entry.Fingerprint(), CheckedAt: time.Now(), EntryKind: RouterPredecessorProofKind}, nil
}

func (c *ServerTorClient) Acquire(ctx context.Context) (failure error) {
	defer func() {
		if failure != nil && c != nil {
			c.cancel()
		}
	}()
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	c.mu.Lock()
	used := c.attempt || c.closing
	c.mu.Unlock()
	if used || c.ctx.Err() != nil || !c.current() {
		return errServerTorClient
	}
	if _, err := c.ProveEntry(ctx); err != nil {
		return err
	}
	var catalog struct {
		NodeID    string                                `json:"node_id"`
		Challenge multihoprelay.ExternalPacketChallenge `json:"challenge"`
		Sources   []multihoprelay.TorExitSource         `json:"sources"`
	}
	if err := c.exchange(ctx, http.MethodGet, nil, &catalog, false); err != nil {
		return err
	}
	now := time.Now()
	peer, peerErr := netip.ParseAddr(catalog.Challenge.Peer)
	if catalog.NodeID != c.entry.node || catalog.Challenge.Validate() != nil || peerErr != nil || !peer.IsPrivate() ||
		catalog.Challenge.ExpiresAt <= now.Unix() || catalog.Challenge.ExpiresAt > now.Add(61*time.Second).Unix() || len(catalog.Sources) < 1 || len(catalog.Sources) > multihoprelay.MaxPairedExits {
		return errServerTorClient
	}
	expected := multihoprelay.TorExitSource{ID: c.policy.ID(), Mode: c.policy.Mode(), SourceSHA256: c.policy.SourceSHA256(), DNSPolicySHA256: c.policy.DNSPolicySHA256()}
	matched := 0
	for _, source := range catalog.Sources {
		if source.ID == expected.ID && source.Mode == expected.Mode {
			if source != expected {
				return errServerTorClient
			}
			matched++
		}
	}
	if matched != 1 || c.ctx.Err() != nil || !c.current() {
		return errServerTorClient
	}
	request := multihoprelay.TorRequest{SessionID: c.session, EntryNodeID: c.entry.node, ExitID: expected.ID, ExitMode: expected.Mode,
		SourceSHA256: expected.SourceSHA256, DNSPolicySHA256: expected.DNSPolicySHA256, Epoch: catalog.Challenge.Epoch, Peer: catalog.Challenge.Peer, AcquireExpiresAt: catalog.Challenge.ExpiresAt}
	// Record the attempt before sending. A late or lost PUT response must still
	// be deleted with this request, never adopted by a replacement connection.
	c.mu.Lock()
	c.request, c.attempt, c.started = request, true, now
	c.mu.Unlock()
	var lease multihoprelay.TorLease
	if err := c.exchange(ctx, http.MethodPut, request, &lease, false); err != nil {
		return err
	}
	return c.adoptLease(lease, false)
}

func (c *ServerTorClient) capture(lease multihoprelay.TorLease) multihoprelay.TorCapture {
	return multihoprelay.TorCapture{Schema: 1, Request: lease.Request, Source: multihoprelay.TorExitSource{ID: c.policy.ID(), Mode: c.policy.Mode(), SourceSHA256: c.policy.SourceSHA256(), DNSPolicySHA256: c.policy.DNSPolicySHA256()},
		RegistrySHA256: lease.RegistrySHA256, OwnerID: lease.OwnerID, Peer: lease.Request.Peer, Host: lease.Host, Port: lease.Port, Username: lease.Username, Password: lease.Password, BootstrapDeadline: lease.BootstrapDeadline}
}

func (c *ServerTorClient) adoptLease(lease multihoprelay.TorLease, existing bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	api, _ := url.Parse(c.entry.target)
	if c.closing || c.ctx.Err() != nil || !c.current() || lease.Request != c.request || lease.NodeID != c.entry.node ||
		lease.Host != api.Hostname() || lease.DNSPolicySHA256 != c.policy.DNSPolicySHA256() || c.capture(lease).Validate() != nil ||
		lease.Phase != multihoprelay.TorPending && lease.Phase != multihoprelay.TorReady ||
		!lease.ExpiresAt.After(now) || lease.ExpiresAt.After(now.Add(305*time.Second)) ||
		lease.BootstrapDeadline.Before(c.started) || lease.BootstrapDeadline.After(c.started.Add(multihoprelay.TorBootstrapLimit+time.Second)) {
		return errServerTorClient
	}
	if existing {
		before, after := c.lease, lease
		before.ExpiresAt, after.ExpiresAt = time.Time{}, time.Time{}
		before.Phase, after.Phase = "", ""
		if before != after || c.ready && lease.Phase != multihoprelay.TorReady {
			return errServerTorClient
		}
	}
	c.lease = lease
	return nil
}

// Status performs a fresh nonce-bound worker proof and renews only this lease.
// The caller must separately prove its own selected DNS and dynamic exit path.
func (c *ServerTorClient) Status(ctx context.Context) (result multihoprelay.TorReceipt, failure error) {
	defer func() {
		if failure != nil && c != nil {
			c.cancel()
		}
	}()
	if err := c.lock(ctx); err != nil {
		return multihoprelay.TorReceipt{}, err
	}
	defer c.unlock()
	if !c.Current() {
		return multihoprelay.TorReceipt{}, errServerTorClient
	}
	c.mu.Lock()
	request, renew := c.request, time.Until(c.lease.ExpiresAt) < 10*time.Second
	c.mu.Unlock()
	if renew {
		var lease multihoprelay.TorLease
		if err := c.exchange(ctx, http.MethodPut, request, &lease, false); err != nil {
			return multihoprelay.TorReceipt{}, err
		}
		if err := c.adoptLease(lease, true); err != nil {
			return multihoprelay.TorReceipt{}, err
		}
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return multihoprelay.TorReceipt{}, errServerTorClient
	}
	nonce := hex.EncodeToString(random[:])
	raw, _ := json.Marshal(request)
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	payload["status_nonce"] = nonce
	var status multihoprelay.TorLeaseStatus
	if err := c.exchange(ctx, http.MethodPost, payload, &status, false); err != nil {
		return multihoprelay.TorReceipt{}, err
	}
	if err := c.adoptLease(status.Lease, true); err != nil {
		return multihoprelay.TorReceipt{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.ctx.Err() != nil || !c.current() || multihoprelay.ValidateTorReceipt(status.Receipt, c.capture(c.lease), nonce, c.started, time.Now()) != nil || status.Receipt.Sequence <= c.sequence || status.Receipt.Phase != c.lease.Phase || c.ready && status.Receipt.Phase != multihoprelay.TorReady || !c.adoptPaddingLocked(status.Receipt) {
		return multihoprelay.TorReceipt{}, errServerTorClient
	}
	c.sequence, c.ready = status.Receipt.Sequence, status.Receipt.Phase == multihoprelay.TorReady
	return status.Receipt, nil
}

func (c *ServerTorClient) Wait(ctx context.Context) (result multihoprelay.TorReceipt, failure error) {
	defer func() {
		if failure != nil && c != nil {
			c.cancel()
		}
	}()
	if ctx == nil {
		return multihoprelay.TorReceipt{}, errServerTorClient
	}
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		receipt, err := c.Status(ctx)
		if err != nil {
			return multihoprelay.TorReceipt{}, err
		}
		if receipt.Phase == multihoprelay.TorReady {
			return receipt, nil
		}
		c.mu.Lock()
		expired := !c.lease.BootstrapDeadline.After(time.Now())
		c.mu.Unlock()
		if expired {
			return multihoprelay.TorReceipt{}, errServerTorClient
		}
		select {
		case <-ctx.Done():
			return multihoprelay.TorReceipt{}, ctx.Err()
		case <-c.ctx.Done():
			return multihoprelay.TorReceipt{}, errServerTorClient
		case <-tick.C:
		}
	}
}

func (c *ServerTorClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !c.Ready() || ctx == nil || ctx.Err() != nil || network != "tcp" {
		return nil, errServerTorClient
	}
	connection, err := c.data.DialContext(ctx, network, address)
	if err != nil || !c.Ready() {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, errServerTorClient
	}
	return connection, nil
}

// DialRetainedContext is used by native DNS/measurement owners that must keep
// a late or failed-close socket reachable for retry. It never publishes that
// socket as successful traffic after the exact lease or captured path retires.
func (c *ServerTorClient) DialRetainedContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !c.Ready() || ctx == nil || ctx.Err() != nil || network != "tcp" {
		return nil, errServerTorClient
	}
	connection, err := c.data.DialRetainedContext(ctx, network, address)
	if err != nil || !c.Ready() {
		return connection, errServerTorClient
	}
	return connection, nil
}

func (c *ServerTorClient) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return errServerTorClient
	}
	c.mu.Lock()
	c.closing, c.ready = true, false
	comparison := c.comparison
	if c.paddingExpiry != nil {
		c.paddingExpiry.Stop()
	}
	c.mu.Unlock()
	c.cancel()
	if comparison != nil {
		comparison.Cancel()
	}
	if err := c.data.Close(ctx); err != nil {
		return err
	}
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	c.mu.Lock()
	attempt, request := c.attempt, c.request
	c.mu.Unlock()
	if attempt {
		var receipt struct {
			Node    string `json:"node_id"`
			Session string `json:"session_id"`
			Stopped bool   `json:"stopped"`
		}
		if err := c.exchange(ctx, http.MethodDelete, request, &receipt, true); err != nil {
			return err
		}
		if receipt.Node != c.entry.node || receipt.Session != c.session || !receipt.Stopped {
			return errServerTorClient
		}
		c.mu.Lock()
		c.attempt = false
		c.stoppedOwner = c.lease.OwnerID
		c.mu.Unlock()
	}
	// Measurement CLOSE can require the exact native join after an ambiguous
	// control reply. DELETE must be allowed to establish that witness first;
	// otherwise candidate stop and measurement cleanup would wait on each other.
	if comparison != nil {
		if err := comparison.Close(ctx); err != nil {
			return err
		}
	}
	return c.control.Close(ctx)
}

func (c *ServerTorClient) exchange(parent context.Context, method string, payload, result any, cleanup bool) (failure error) {
	if parent == nil || parent.Err() != nil || !c.current() || !cleanup && c.ctx.Err() != nil {
		return errServerTorClient
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	stop := func() bool { return true }
	if !cleanup {
		stop = context.AfterFunc(c.ctx, cancel)
	}
	defer stop()
	connection, err := c.control.DialContext(ctx, "tcp", c.entry.address)
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return errServerTorClient
	}
	closed := make(chan struct{})
	stopIO := context.AfterFunc(ctx, func() { _ = connection.Close(); close(closed) })
	defer func() {
		if !stopIO() {
			<-closed
		}
		if ctx.Err() != nil {
			failure = errServerTorClient
		}
	}()
	defer func() {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			failure = errServerTorClient
		}
	}()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return errServerTorClient
	}
	var body []byte
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil || len(body) > 4096 {
			return errServerTorClient
		}
	}
	target, _ := url.Parse(c.entry.target)
	target.Path = serverTorLeasePath
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return errServerTorClient
	}
	request.Close = true
	request.Header.Set("Authorization", "Bearer "+c.entry.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-store")
	if request.Write(connection) != nil {
		return errServerTorClient
	}
	limit := 16 << 10
	if method == http.MethodGet {
		limit = multihoprelay.MaxCapabilitiesBytes
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(connection, int64(limit+8193))), request)
	if err != nil {
		return errServerTorClient
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return errServerTorClient
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit+1)))
	if err != nil || len(raw) > limit || ctx.Err() != nil || !c.current() {
		return errServerTorClient
	}
	if _, err := profileObject(string(raw), limit); err != nil {
		return errServerTorClient
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(result) != nil {
		return errServerTorClient
	}
	return nil
}
