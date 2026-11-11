package mobilemultihop

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// All five fields belong to the same retained native observation. A process,
// session or network replacement cannot adopt a previous chain's proof.
type NodeChainIdentity struct {
	EngineID     string `json:"engine_id"`
	SessionID    string `json:"session_id"`
	NetworkID    string `json:"network_id"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
}

// NodeChainEngine adapts one original native owner. It is not another process
// registry. Each callback must honor its caller context and retain late I/O
// completion; DNSProofContext must use the exact retained native router.
// The existing platform connection owner alone retires the native process/TUN.
type NodeChainEngine interface {
	ObserveChainContext(context.Context) (NodeChainIdentity, error)
	Dial(context.Context, string, string) (net.Conn, error)
	SelectContext(context.Context, string) error
	SelectedContext(context.Context) (string, error)
	DNSProofContext(context.Context, NodeChainDNSCapture) error
}

type NodeChainPrefixProgress struct {
	Position   int     `json:"position"`
	ProfileID  string  `json:"profile_id"`
	ResponseMS float64 `json:"response_ms"`
	Proven     bool    `json:"proven"`
}

// Progress is public and carries no private source, credential, API or key.
// ResponseMS is elapsed routed private HTTP, never ICMP or a saved benchmark.
type NodeChainProgress struct {
	Stage        string                    `json:"stage"`
	Complete     bool                      `json:"complete"`
	Ready        bool                      `json:"ready"`
	Execution    string                    `json:"execution"`
	Prefixes     []NodeChainPrefixProgress `json:"prefixes"`
	DNSProven    bool                      `json:"dns_proven"`
	PublicProven bool                      `json:"public_proven"`
	Failure      string                    `json:"failure,omitempty"`
}

type nodeChainRuntime struct {
	mu          sync.Mutex
	generation  atomic.Uint64
	engine      NodeChainEngine
	identity    NodeChainIdentity
	cancel      context.CancelFunc
	startDone   chan struct{}
	observeDone chan struct{}
	closed      bool
	progress    NodeChainProgress
	checkedAt   time.Time
	testTLS     *tls.Config // Private package-test roots; never exposed to a host.
}

func (c *NodeChain) Progress() NodeChainProgress {
	c.runtime.mu.Lock()
	defer c.runtime.mu.Unlock()
	result := c.runtime.progress
	result.Prefixes = append([]NodeChainPrefixProgress(nil), result.Prefixes...)
	if c.runtime.generation.Load() != 1 || c.runtime.closed ||
		time.Since(c.runtime.checkedAt) > time.Duration(15+5*len(c.nodes))*time.Second {
		result.Ready = false
	}
	return result
}

func nodeChainIdentityText(value string) bool {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (c *NodeChain) identityMatches(identity NodeChainIdentity) bool {
	return nodeChainIdentityText(identity.EngineID) && nodeChainIdentityText(identity.SessionID) &&
		nodeChainIdentityText(identity.NetworkID) && identity.SourceSHA256 == c.sourceSHA &&
		identity.ConfigSHA256 == c.dns.ConfigSHA256
}

func (c *NodeChain) currentContext(ctx context.Context, selected bool) error {
	if c == nil || ctx == nil {
		return nodeChainError
	}
	if err := externalObservationLock(ctx, &c.runtime.mu); err != nil {
		return err
	}
	engine, identity := c.runtime.engine, c.runtime.identity
	alive := c.runtime.generation.Load() == 1 && !c.runtime.closed
	c.runtime.mu.Unlock()
	if engine == nil || !alive || !c.identityMatches(identity) {
		return errors.New("ordered chain owner retired")
	}
	observed, err := engine.ObserveChainContext(ctx)
	if err != nil {
		return err
	}
	if observed != identity {
		return errors.New("ordered chain native source, session or network changed")
	}
	if selected {
		actual, err := engine.SelectedContext(ctx)
		if err != nil {
			return err
		}
		if actual != c.FinalTag() {
			return errors.New("ordered chain selected path changed")
		}
	}
	if err := externalObservationLock(ctx, &c.runtime.mu); err != nil {
		return err
	}
	defer c.runtime.mu.Unlock()
	if c.runtime.generation.Load() != 1 || c.runtime.closed || c.runtime.identity != identity || c.runtime.engine != engine {
		return errors.New("ordered chain retired during native observation")
	}
	return ctx.Err()
}

func (c *NodeChain) dial(ctx context.Context, tag, address string) (net.Conn, error) {
	allowed := false
	for _, proof := range c.proofs {
		allowed = allowed || proof.Tag == tag
	}
	if !allowed {
		return nil, errors.New("ordered chain proof has no captured prefix")
	}
	if err := c.currentContext(ctx, true); err != nil {
		return nil, err
	}
	c.runtime.mu.Lock()
	engine := c.runtime.engine
	c.runtime.mu.Unlock()
	conn, err := engine.Dial(ctx, tag, address)
	if err == nil {
		err = c.currentContext(ctx, true)
	}
	if err != nil {
		if conn != nil {
			err = errors.Join(err, conn.Close())
		}
		return nil, err
	}
	return conn, nil
}

func (c *NodeChain) provePrefix(parent context.Context, position int) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := c.currentContext(ctx, true); err != nil {
		return 0, err
	}
	node, proof := c.nodes[position], c.proofs[position]
	started := time.Now()
	data, err := externalProofHTTP(ctx, c.dial, proof.Tag,
		healthURL(predecessorText(node.profile, "router_api")), predecessorText(node.profile, "api_token"), nil)
	if err != nil {
		return 0, errors.Join(ctx.Err(), err)
	}
	// The same exact paired identity and proof marker used by Controller.prove.
	var result struct {
		OK     bool   `json:"ok"`
		NodeID string `json:"node_id"`
		Proof  string `json:"proof"`
	}
	if exactJSON(data, &result, 8192) != nil || !result.OK ||
		result.NodeID != proof.NodeID || result.Proof != "router-vpn-private-agent-v1" {
		return 0, errors.New("ordered chain returned the wrong prefix node proof")
	}
	return time.Since(started), c.currentContext(ctx, true)
}

func (c *NodeChain) provePrefixes(ctx context.Context, publish bool) error {
	for position, proof := range c.proofs {
		elapsed, err := c.provePrefix(ctx, position)
		if err != nil {
			return err
		}
		if publish {
			if err := externalObservationLock(ctx, &c.runtime.mu); err != nil {
				return err
			}
			if c.runtime.generation.Load() != 1 {
				c.runtime.mu.Unlock()
				return errors.New("ordered chain retired before prefix publication")
			}
			c.runtime.progress.Prefixes = append(c.runtime.progress.Prefixes, NodeChainPrefixProgress{
				position, proof.ProfileID, float64(elapsed) / float64(time.Millisecond), true})
			c.runtime.mu.Unlock()
		}
	}
	return nil
}

func (c *NodeChain) proveDNS(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := c.currentContext(ctx, true); err != nil {
		return err
	}
	c.runtime.mu.Lock()
	engine := c.runtime.engine
	c.runtime.mu.Unlock()
	if err := engine.DNSProofContext(ctx, c.dns); err != nil {
		return errors.Join(ctx.Err(), err)
	}
	return c.currentContext(ctx, true)
}

func (c *NodeChain) provePublic(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("ordered chain public proof nonce unavailable")
	}
	data, err := externalProofHTTP(ctx, c.dial, c.FinalTag(),
		"https://1.1.1.1/cdn-cgi/trace?routervpn_proof="+hex.EncodeToString(nonce[:]), "", c.runtime.testTLS)
	if err != nil {
		return errors.Join(ctx.Err(), err)
	}
	address, count := "", 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ip=") {
			address, count = strings.TrimSpace(strings.TrimPrefix(line, "ip=")), count+1
		}
	}
	if count != 1 || !externalPublicIP(address) {
		return errors.New("ordered chain final public response has no valid address")
	}
	return c.currentContext(ctx, true)
}

func (c *NodeChain) retire(message string) {
	if c == nil {
		return
	}
	for {
		generation := c.runtime.generation.Load()
		if generation == 2 || c.runtime.generation.CompareAndSwap(generation, 2) {
			break
		}
	}
	c.runtime.mu.Lock()
	if c.runtime.cancel != nil {
		c.runtime.cancel()
	}
	c.runtime.progress.Ready = false
	c.runtime.progress.Complete = true
	if message != "" {
		c.runtime.progress.Stage, c.runtime.progress.Failure = "failed", message
	}
	c.runtime.mu.Unlock()
}

// Run uses the native connection owner's lifetime context, not a detached
// request worker. A startup error retires proof admission. The original platform
// connection owner joins this controller and its existing native retirement.
func (c *NodeChain) Run(parent context.Context, engine NodeChainEngine) (failure error) {
	if parent == nil || engine == nil || c.validateCapture() != nil {
		return nodeChainError
	}
	if err := externalObservationLock(parent, &c.runtime.mu); err != nil {
		return err
	}
	if !c.runtime.generation.CompareAndSwap(0, 1) {
		c.runtime.mu.Unlock()
		return errors.New("ordered chain controller cannot be reused")
	}
	lifetime, cancel := context.WithCancel(parent)
	c.runtime.cancel, c.runtime.engine = cancel, engine
	c.runtime.startDone = make(chan struct{})
	c.runtime.progress = NodeChainProgress{Stage: "verifying", Execution: "local", Prefixes: []NodeChainPrefixProgress{}}
	startDone := c.runtime.startDone
	c.runtime.mu.Unlock()
	defer func() {
		if failure != nil {
			c.retire("Captured ordered path proof failed")
		}
		close(startDone)
	}()
	ctx, finish := context.WithTimeout(lifetime, time.Duration(10+10*len(c.nodes))*time.Second)
	defer finish()
	identity, err := engine.ObserveChainContext(ctx)
	if err != nil || !c.identityMatches(identity) {
		return errors.Join(ctx.Err(), err, errors.New("ordered chain native capture differs from its original source"))
	}
	if err := externalObservationLock(ctx, &c.runtime.mu); err != nil {
		return err
	}
	if c.runtime.generation.Load() != 1 {
		c.runtime.mu.Unlock()
		return errors.New("ordered chain retired during capture")
	}
	c.runtime.identity = identity
	c.runtime.mu.Unlock()
	if err := engine.SelectContext(ctx, c.FinalTag()); err != nil {
		return err
	}
	if err := c.provePrefixes(ctx, true); err != nil {
		return err
	}
	if err := c.proveDNS(ctx); err != nil {
		return err
	}
	if err := c.provePublic(ctx); err != nil {
		return err
	}
	if err := c.provePrefixes(ctx, false); err != nil {
		return err
	}
	if err := c.currentContext(ctx, true); err != nil {
		return err
	}
	if err := externalObservationLock(ctx, &c.runtime.mu); err != nil {
		return err
	}
	if c.runtime.generation.Load() != 1 || ctx.Err() != nil {
		c.runtime.mu.Unlock()
		return errors.New("ordered chain retired before activation")
	}
	c.runtime.progress.Stage, c.runtime.progress.Complete, c.runtime.progress.Ready = "selected", true, true
	c.runtime.progress.DNSProven, c.runtime.progress.PublicProven = true, true
	c.runtime.checkedAt = time.Now()
	c.runtime.observeDone = make(chan struct{})
	done := c.runtime.observeDone
	c.runtime.mu.Unlock()
	go c.observe(lifetime, done)
	return c.currentContext(ctx, true)
}

func (c *NodeChain) observe(lifetime context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var failure error
	for failure == nil {
		select {
		case <-lifetime.Done():
			failure = lifetime.Err()
		case <-ticker.C:
			if failure = c.provePrefixes(lifetime, false); failure == nil {
				failure = c.proveDNS(lifetime)
			}
			if failure == nil {
				failure = c.currentContext(lifetime, true)
			}
			if failure == nil {
				c.runtime.mu.Lock()
				if c.runtime.generation.Load() == 1 {
					c.runtime.checkedAt = time.Now()
				}
				c.runtime.mu.Unlock()
			}
		}
	}
	c.retire("Captured ordered path owner or prefix retired")
}

func (c *NodeChain) HealthyContext(ctx context.Context) error {
	if c == nil || ctx == nil {
		return nodeChainError
	}
	if err := externalObservationLock(ctx, &c.runtime.mu); err != nil {
		return err
	}
	active := c.runtime.progress.Ready && c.runtime.progress.Complete
	ready := active &&
		time.Since(c.runtime.checkedAt) <= time.Duration(15+5*len(c.nodes))*time.Second
	c.runtime.mu.Unlock()
	if !ready {
		if active {
			c.retire("Captured ordered prefix proof expired")
		}
		return errors.New("ordered chain has no current complete prefix proof")
	}
	if err := c.currentContext(ctx, true); err != nil {
		if ctx.Err() == nil {
			c.retire("Captured ordered path observation failed")
		}
		return err
	}
	return ctx.Err()
}

// CloseContext joins only proof/observer work. It never closes a caller's Box,
// process or TUN. A deadline leaves the original join handles available for
// retry; the platform reports stopped only after its native retirement joins.
func (c *NodeChain) CloseContext(ctx context.Context) error {
	if c == nil || ctx == nil {
		return nodeChainError
	}
	c.retire("")
	if err := externalObservationLock(ctx, &c.runtime.mu); err != nil {
		return err
	}
	started, observed := c.runtime.startDone, c.runtime.observeDone
	c.runtime.mu.Unlock()
	for _, done := range []chan struct{}{started, observed} {
		if done == nil {
			continue
		}
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := externalObservationLock(ctx, &c.runtime.mu); err != nil {
		return err
	}
	c.runtime.closed = true
	c.runtime.progress.Ready = false
	c.runtime.progress.Stage = "closed"
	c.runtime.mu.Unlock()
	return ctx.Err()
}
