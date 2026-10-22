package mobilemultihop

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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
	public    func(context.Context, string, string) error
	private   func(context.Context) error
	execution *Controller
}

func NewExternalProofRequest(parent context.Context, policy *ExternalPolicy, session string, engine ExternalProofEngine) (*ExternalProofRequest, error) {
	if parent == nil || parent.Err() != nil || policy == nil || !exactID.MatchString(session) || engine == nil {
		return nil, errors.New("external proof has no captured VPN owner")
	}
	identity := engine.Identity()
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
	r.public = r.provePublic
	r.private = r.provePrivateEntry
	return r, nil
}

func (r *ExternalProofRequest) current() bool {
	return r != nil && r.ctx.Err() == nil && r.engine.Identity() == r.identity
}
func (r *ExternalProofRequest) Cancel() {
	if r != nil {
		r.cancel()
		r.succeeded.Store(false)
		if r.execution != nil {
			r.execution.NetworkChanged()
		}
	}
}
func (r *ExternalProofRequest) Healthy() bool {
	return r != nil && r.succeeded.Load() && r.current() && (r.execution == nil || r.execution.Healthy())
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
	if !r.Healthy() || r.execution == nil {
		return ""
	}
	r.execution.mu.Lock()
	defer r.execution.mu.Unlock()
	return r.execution.progress.Execution
}
func (r *ExternalProofRequest) Run() (result string, failure error) {
	if r == nil {
		return "", errors.New("external proof request is unavailable or already used")
	}
	r.runMu.Lock()
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
	if !r.current() {
		return "", errors.New("external proof belongs to a retired connection")
	}
	if r.execution != nil {
		if err := r.execution.Run(r.ctx, r.engine.(Engine)); err != nil {
			return "", err
		}
		if !r.current() || !r.execution.Healthy() {
			return "", errors.New("external execution retired before final proof")
		}
	}
	ctx, cancel := context.WithTimeout(r.ctx, 45*time.Second)
	defer cancel()
	if r.meta.EntryID != "" {
		var err error
		if r.meta.EntryNodeID != "" {
			err = r.private(ctx)
		} else {
			external, _ := r.policy.capture.Entry["external"].(map[string]any)
			ip, _ := external["expected_public_ip"].(string)
			err = r.public(ctx, r.meta.EntryTag, ip)
		}
		if err != nil || !r.current() || ctx.Err() != nil {
			return "", errors.New("captured external entry proof failed or became stale")
		}
	}
	if err := r.engine.DNSProof(ctx, r.meta.TUNTag); err != nil || !r.current() || ctx.Err() != nil {
		return "", errors.New("captured external DNS proof failed or became stale")
	}
	if err := r.public(ctx, ExternalFinalTag, r.meta.ExpectedPublicIP); err != nil || !r.current() || ctx.Err() != nil {
		return "", errors.New("captured public exit proof failed or became stale")
	}
	proof := ExternalProofResult{Schema: 1, SessionID: r.session, SourceSHA256: r.meta.SourceSHA256, ConfigSHA256: r.meta.ConfigSHA256, ExitID: r.meta.ExitID, EntryID: r.meta.EntryID, EntryNodeID: r.meta.EntryNodeID, IP: r.meta.ExpectedPublicIP, DNSProven: true, EntryProven: r.meta.EntryID != "", CheckedAt: time.Now().UnixMilli()}
	if r.execution != nil {
		r.execution.mu.Lock()
		proof.Execution = r.execution.progress.Execution
		r.execution.mu.Unlock()
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return "", errors.New("external proof could not be encoded")
	}
	r.succeeded.Store(true)
	if !r.current() || ctx.Err() != nil || r.execution != nil && !r.execution.Healthy() {
		return "", errors.New("external proof delivery was canceled")
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
	if !externalPublicIP(expected) {
		return errors.New("external public proof has no selected address")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("external proof nonce unavailable")
	}
	data, err := externalProofHTTP(ctx, r.engine.Dial, tag, "https://1.1.1.1/cdn-cgi/trace?routervpn_proof="+hex.EncodeToString(nonce[:]), "", nil)
	if err != nil {
		return err
	}
	return externalTraceAddress(data, expected)
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
	var stream net.Conn = connection
	if u.Scheme == "https" {
		config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if testTLS != nil {
			config = testTLS.Clone()
			config.ServerName = u.Hostname()
		}
		if serverName != "" {
			config.ServerName = serverName
		}
		secure := tls.Client(connection, config)
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
