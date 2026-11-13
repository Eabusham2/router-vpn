package mobilemultihop

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ExternalProofEngine is supplied by the captured native Box. DNSProof uses
// its real DNS router and TUN metadata; Dial accepts only this graph's tags.
// Neither operation may fall back to a process or platform default network.
type ExternalProofEngine interface {
	Identity() string
	DNSProof(context.Context, string) error
	Dial(context.Context, string, string) (net.Conn, error)
}

type ExternalProofResult struct {
	Schema       int    `json:"schema"`
	SessionID    string `json:"session_id"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	ExitID       string `json:"exit_id"`
	EntryID      string `json:"entry_id"`
	EntryNodeID  string `json:"entry_node_id"`
	IP           string `json:"ip"`
	DNSProven    bool   `json:"dns_proven"`
	EntryProven  bool   `json:"entry_proven"`
	CheckedAt    int64  `json:"checked_at"`
	Execution    string `json:"execution,omitempty"`
}

// ExternalProofRequest owns one immutable graph and one cancellable proof.
// A result is usable only while Healthy still reports the captured owner;
// hosts also compare their connection/network generation before publishing UP.
type ExternalProofRequest struct {
	ctx       context.Context
	cancel    context.CancelFunc
	engine    ExternalProofEngine
	identity  string
	policy    *ExternalPolicy
	meta      externalPolicyMetadata
	session   string
	started   atomic.Bool
	succeeded atomic.Bool
	runMu     sync.Mutex
	runDone   chan struct{}
	// Unexported test seams exercise the lifecycle without public networking.
	public           func(context.Context, string, string) error
	private          func(context.Context) error
	execution        *Controller
	openvpnTransport map[string]any
	openvpnRemote    atomic.Pointer[nativeopenvpn.RemoteReceipt]
}

func NewExternalProofRequest(parent context.Context, policy *ExternalPolicy, session string, engine ExternalProofEngine) (*ExternalProofRequest, error) {
	if parent == nil {
		return nil, errors.New("external proof has no captured VPN owner")
	}
	caller, cancel := context.WithTimeout(parent, 1500*time.Millisecond)
	defer cancel()
	return NewExternalProofRequestContext(caller, parent, policy, session, engine)
}

// caller owns construction only; parent retains the actual VPN lifetime. A
// returned request must still perform its original DNS, entry and exit proof.
func NewExternalProofRequestContext(caller, parent context.Context, policy *ExternalPolicy, session string, engine ExternalProofEngine) (*ExternalProofRequest, error) {
	if caller == nil || parent == nil || policy == nil || !exactID.MatchString(session) || engine == nil {
		return nil, errors.New("external proof has no captured VPN owner")
	}
	if err := errors.Join(caller.Err(), parent.Err()); err != nil {
		return nil, err
	}
	identity, err := externalObservedIdentity(caller, engine)
	if err != nil || caller.Err() != nil || parent.Err() != nil {
		return nil, errors.Join(err, caller.Err(), parent.Err())
	}
	if identity == "" {
		return nil, errors.New("external proof owner is already retired")
	}
	var meta externalPolicyMetadata
	if exactJSON([]byte(policy.Metadata()), &meta, 64<<10) != nil || meta.SourceSHA256 != policy.SourceSHA256() || meta.ConfigSHA256 != externalDigest([]byte(policy.Config())) {
		return nil, errors.New("external proof compilation is not bound to its source")
	}
	ctx, cancel := context.WithCancel(parent)
	r := &ExternalProofRequest{ctx: ctx, cancel: cancel, engine: engine, identity: identity, policy: policy, meta: meta, session: session}
	if policy.capture.Execution != nil {
		if _, ok := engine.(Engine); !ok {
			cancel()
			return nil, errors.New("external execution requires the captured native selector")
		}
		var err error
		r.execution, err = newExternalExecution(policy)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	if policy.capture.Execution == nil && policy.capture.Protocol == "openvpn" {
		// Every ordinary OpenVPN proof belongs to one actual connected native
		// transport generation. Optional provider response probes authorize
		// comparison measurements; their absence cannot waive path ownership.
		external, _ := policy.capture.Profile["external"].(map[string]any)
		if _, ok := engine.(OpenVPNRemoteEngine); !ok {
			cancel()
			return nil, errors.New("native OpenVPN remote observation is required")
		}
		var err error
		r.openvpnTransport, err = multihoprelay.ExternalTransport("openvpn", external)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	r.public = r.provePublic
	r.private = r.provePrivateEntry
	current, err := externalObservedIdentity(caller, engine)
	if err != nil || caller.Err() != nil || parent.Err() != nil || current != identity {
		cancel()
		return nil, errors.Join(err, caller.Err(), parent.Err(), errors.New("external proof owner changed during capture"))
	}
	return r, nil
}

func (r *ExternalProofRequest) current() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	return r.currentContext(ctx) == nil
}
func (r *ExternalProofRequest) Cancel() {
	if r != nil {
		r.cancel()
		r.succeeded.Store(false)
		if r.execution != nil {
			// The comparison caller is already joined to r.ctx. Revoke its
			// authority without waiting on a state mutex held by an observer;
			// Close retains the original worker/lease join responsibility.
			r.execution.generation.Add(1)
		}
	}
}
func (r *ExternalProofRequest) Healthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	return r.HealthyContext(ctx) == nil
}

// VerifyCurrentPath exposes a fresh synchronous retained-path check to native
// MTU, measurements and hosts. No private provider information is returned.
func (r *ExternalProofRequest) VerifyCurrentPath() error {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	return r.VerifyCurrentPathContext(ctx)
}

func (r *ExternalProofRequest) verifyCurrentPath(ctx context.Context) error {
	if err := r.currentContext(ctx); err != nil {
		return err
	}
	if err := r.localOpenVPNHealthyContext(ctx); err != nil {
		return err
	}
	if r.execution != nil {
		return r.execution.verifyCurrentPathContext(ctx)
	}
	return ctx.Err()
}

func (r *ExternalProofRequest) localOpenVPNHealthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	return r.currentContext(ctx) == nil && r.localOpenVPNHealthyContext(ctx) == nil
}

func (r *ExternalProofRequest) captureLocalOpenVPNRemote(ctx context.Context) error {
	if r.openvpnTransport == nil {
		return nil
	}
	for {
		if err := r.currentContext(ctx); err != nil {
			return err
		}
		receipt, err := externalObservedRemote(ctx, r.engine, ExternalFinalTag)
		if err := errors.Join(ctx.Err(), r.ctx.Err()); err != nil {
			return err
		}
		if err == nil {
			if !receipt.Matches(r.openvpnTransport) {
				return errors.New("OpenVPN remote does not match its captured transport")
			}
			if err := r.currentContext(ctx); err != nil {
				return err
			}
			r.openvpnRemote.Store(&receipt)
			return nil
		}
		if !errors.Is(err, nativeopenvpn.ErrRemotePending) {
			return errors.New("OpenVPN native remote is unavailable")
		}
		timer := time.NewTimer(40 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func (r *ExternalProofRequest) Close() error {
	if r == nil {
		return nil
	}
	r.Cancel()
	r.runMu.Lock()
	done := r.runDone
	r.runMu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-time.After(12 * time.Second):
			return errors.New("external proof teardown is still pending")
		}
	}
	if r.execution != nil {
		return r.execution.Close()
	}
	return nil
}
func (r *ExternalProofRequest) ProgressJSON() string {
	if r == nil || r.execution == nil {
		return ""
	}
	return r.execution.ProgressJSON()
}
func (r *ExternalProofRequest) Execution() string {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	outcome, _ := r.ExecutionContext(ctx)
	return outcome
}
func (r *ExternalProofRequest) Run() (string, error) {
	return r.RunObserved(nil)
}

func (r *ExternalProofRequest) RunObserved(observe func(context.Context) error) (string, error) {
	if r == nil {
		return "", errors.New("external proof request is unavailable")
	}
	return r.RunContext(r.ctx, observe)
}

// The optional observation belongs to the captured native host. It receives
// the same operation as proof traffic, including final result delivery. The
// caller may end this attempt; a successful request retains its VPN lifetime.
func (r *ExternalProofRequest) RunContext(parent context.Context, observe func(context.Context) error) (result string, failure error) {
	if r == nil || parent == nil {
		return "", errors.New("external proof request is unavailable or already used")
	}
	if err := errors.Join(parent.Err(), r.ctx.Err()); err != nil {
		return "", err
	}
	operation, release := context.WithCancel(parent)
	stop := context.AfterFunc(r.ctx, release)
	defer func() { stop(); release() }()
	if err := externalObservationLock(operation, &r.runMu); err != nil {
		return "", err
	}
	if r.ctx.Err() != nil || !r.started.CompareAndSwap(false, true) {
		r.runMu.Unlock()
		return "", errors.New("external proof request is unavailable or already used")
	}
	r.runDone = make(chan struct{})
	done := r.runDone
	r.runMu.Unlock()
	defer close(done)
	defer func() {
		if failure != nil {
			r.Cancel()
		}
	}()
	current := func(ctx context.Context) error {
		if err := r.currentContext(ctx); err != nil {
			return err
		}
		if observe != nil {
			if err := observe(ctx); err != nil {
				return err
			}
		}
		return errors.Join(ctx.Err(), r.ctx.Err())
	}
	admission, finishAdmission := context.WithTimeout(operation, 1500*time.Millisecond)
	err := current(admission)
	finishAdmission()
	if err != nil {
		return "", err
	}
	if r.execution != nil {
		if err := r.execution.runCaptured(operation, r.engine.(Engine), r.identity); err != nil {
			return "", err
		}
	}
	ctx, cancel := context.WithTimeout(operation, 45*time.Second)
	defer cancel()
	if err := current(ctx); err != nil {
		return "", err
	}
	if err := r.captureLocalOpenVPNRemote(ctx); err != nil {
		return "", err
	}
	if err := r.verifyCurrentPath(ctx); err != nil {
		return "", err
	}
	if r.meta.EntryID != "" {
		var err error
		if r.meta.EntryNodeID != "" {
			err = r.private(ctx)
		} else {
			external, _ := r.policy.capture.Entry["external"].(map[string]any)
			ip, _ := external["expected_public_ip"].(string)
			err = r.public(ctx, r.meta.EntryTag, ip)
		}
		if err != nil || r.verifyCurrentPath(ctx) != nil || current(ctx) != nil {
			return "", errors.Join(ctx.Err(), errors.New("captured external entry proof failed or became stale"))
		}
	}
	// Keep the original failure phase without exposing resolver/provider errors.
	// These checks retain their original order and short-circuit on failure.
	if err := r.engine.DNSProof(ctx, r.meta.TUNTag); err != nil {
		return "", errors.Join(ctx.Err(), errors.New("captured external DNS proof failed during exchange"))
	}
	if err := r.verifyCurrentPath(ctx); err != nil {
		return "", errors.Join(ctx.Err(), errors.New("captured external DNS proof lost its original path"))
	}
	if err := current(ctx); err != nil {
		return "", errors.Join(ctx.Err(), errors.New("captured external DNS proof lost its original host"))
	}
	if err := r.public(ctx, ExternalFinalTag, r.meta.ExpectedPublicIP); err != nil || r.verifyCurrentPath(ctx) != nil || current(ctx) != nil {
		return "", errors.Join(ctx.Err(), errors.New("captured public exit proof failed or became stale"))
	}
	proof := ExternalProofResult{Schema: 1, SessionID: r.session, SourceSHA256: r.meta.SourceSHA256, ConfigSHA256: r.meta.ConfigSHA256, ExitID: r.meta.ExitID, EntryID: r.meta.EntryID, EntryNodeID: r.meta.EntryNodeID, IP: r.meta.ExpectedPublicIP, DNSProven: true, EntryProven: r.meta.EntryID != "", CheckedAt: time.Now().UnixMilli()}
	if r.execution != nil {
		if err := externalObservationLock(ctx, &r.execution.mu); err != nil {
			return "", err
		}
		proof.Execution = r.execution.progress.Execution
		r.execution.mu.Unlock()
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return "", errors.New("external proof could not be encoded")
	}
	r.succeeded.Store(true)
	if err := current(ctx); err != nil {
		return "", err
	}
	if err := r.HealthyContext(ctx); err != nil {
		return "", err
	}
	return string(raw), nil
}

func (r *ExternalProofRequest) provePrivateEntry(ctx context.Context) error {
	entry := r.policy.capture.Entry
	api, _ := entry["router_api"].(string)
	token, _ := entry["api_token"].(string)
	data, err := externalProofHTTP(ctx, r.engine.Dial, r.meta.EntryTag, healthURL(api), token, nil)
	if err != nil {
		return err
	}
	var proof struct {
		OK    bool   `json:"ok"`
		Node  string `json:"node_id"`
		Proof string `json:"proof"`
	}
	if exactJSON(data, &proof, 8192) != nil || !proof.OK || proof.Node != r.meta.EntryNodeID || proof.Proof != "router-vpn-private-agent-v1" {
		return errors.New("external entry returned the wrong private identity")
	}
	return nil
}

func (r *ExternalProofRequest) provePublic(ctx context.Context, tag, expected string) error {
	return ProveExternalPublicIP(ctx, r.engine.Dial, tag, expected)
}

func externalTraceAddress(data []byte, expected string) error {
	failure := errors.New("the actual external public address differs from the selected exit")
	if len(data) == 0 || len(data) > 8192 || !externalPublicIP(expected) {
		return failure
	}
	count, actual := 0, ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ip=") {
			count++
			actual = strings.TrimSpace(strings.TrimPrefix(line, "ip="))
		}
	}
	want, _ := netip.ParseAddr(expected)
	got, err := netip.ParseAddr(actual)
	if count != 1 || err != nil || !externalPublicIP(actual) || got != want {
		return failure
	}
	return nil
}

// Synchronous bounded HTTP retains late dial/close completion. Cancellation
// closes the exact socket; TLS verifies the literal origin, redirects are not
// followed, and no environment proxy, hostname resolver or keepalive is used.
func externalProofHTTP(parent context.Context, dial func(context.Context, string, string) (net.Conn, error), tag, target, token string, testTLS *tls.Config) (data []byte, failure error) {
	return externalProofHTTPName(parent, dial, tag, target, token, "", testTLS)
}

type externalProofOwnedConnection struct {
	net.Conn
	close func() error
}

func (c *externalProofOwnedConnection) Close() error { return c.close() }

func externalProofHTTPName(parent context.Context, dial func(context.Context, string, string) (net.Conn, error), tag, target, token, serverName string, testTLS *tls.Config) (data []byte, failure error) {
	u, err := url.Parse(target)
	if err != nil || u.User != nil || u.Fragment != "" || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("invalid captured external proof endpoint")
	}
	if _, err = netip.ParseAddr(u.Hostname()); err != nil {
		return nil, errors.New("external proof requires a literal destination")
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	connection, err := dial(ctx, tag, net.JoinHostPort(u.Hostname(), port))
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, errors.New("captured external proof dial failed")
	}
	var once sync.Once
	var closeErr error
	closed := make(chan struct{})
	closeOwned := func() { once.Do(func() { closeErr = connection.Close(); close(closed) }) }
	stop := context.AfterFunc(ctx, closeOwned)
	defer func() {
		if !stop() {
			<-closed
		}
		closeOwned()
		if ctx.Err() != nil || closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && !errors.Is(closeErr, io.ErrClosedPipe) {
			data = nil
			failure = errors.New("external proof was canceled or did not close cleanly")
		}
	}()
	deadline, _ := ctx.Deadline()
	if ctx.Err() != nil || connection.SetDeadline(deadline) != nil {
		return nil, errors.New("external proof socket cannot enforce its deadline")
	}
	// HandshakeContext closes its connection when cancellation wins. Give TLS
	// the same close owner as the outer deadline callback, including its join,
	// so neither path closes or abandons the captured raw socket twice.
	var stream net.Conn = &externalProofOwnedConnection{Conn: connection, close: func() error {
		closeOwned()
		return closeErr
	}}
	if u.Scheme == "https" {
		config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if testTLS != nil {
			config = testTLS.Clone()
			config.ServerName = u.Hostname()
		}
		if serverName != "" {
			config.ServerName = serverName
		}
		secure := tls.Client(stream, config)
		if secure.HandshakeContext(ctx) != nil {
			return nil, errors.New("external proof TLS identity failed")
		}
		stream = secure
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.New("external proof request invalid")
	}
	request.Close = true
	if serverName != "" {
		// Route and URL remain pinned to the captured literal server. The
		// separately verified TLS name also selects its HTTPS virtual host.
		request.Host = serverName
		if u.Port() != "" && u.Port() != "443" {
			request.Host = net.JoinHostPort(serverName, u.Port())
		}
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-store")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if request.Write(stream) != nil {
		return nil, errors.New("external proof request failed")
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(stream, 16385)), request)
	if err != nil {
		return nil, errors.New("external proof HTTP response failed")
	}
	defer func() { closeOwned(); _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, errors.New("external proof returned an invalid status or encoding")
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(data) > 8192 || ctx.Err() != nil {
		return nil, errors.New("external proof response exceeded its bound or deadline")
	}
	return data, nil
}
