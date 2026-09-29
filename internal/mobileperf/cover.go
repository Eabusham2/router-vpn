// Package mobileperf owns bounded performance services on the retained VPN
// dataplane. It never creates an underlay socket or accepts an arbitrary target.
package mobileperf

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const CoverType = "routervpn-cover"
const CoverPort = 45999
const MaxCoverKbps = 192

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)
var nodePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type CoverOptions struct {
	NodeID    string `json:"node_id"`
	API       string `json:"api"`
	Sink      string `json:"sink"`
	RateKbps  int    `json:"rate_kbps"`
	ProofTag  string `json:"proof_tag"`
	PacketTag string `json:"packet_tag"`
}
type CoverEngine interface {
	Identity() string
	Dial(context.Context, string, string, string) (net.Conn, error)
}
type CoverStatus struct {
	Requested     bool   `json:"requested"`
	Active        bool   `json:"active"`
	SentBytes     uint64 `json:"sent_bytes"`
	ReceivedBytes uint64 `json:"received_bytes"`
	RateKbps      int    `json:"rate_kbps"`
	Failure       string `json:"failure,omitempty"`
}

// Cover uses one bounded worker, one datagram reader, and one immutable option
// snapshot. Cancel/Close interrupt every outstanding operation and join it.
type Cover struct {
	engine     CoverEngine
	options    CoverOptions
	mu         sync.Mutex
	closed     bool
	running    bool
	generation uint64
	cancel     context.CancelFunc
	done       chan struct{}
	status     CoverStatus
	identity   string
	activeCtx  context.Context
	lastReply  time.Time
}

func privateAddress(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && !ip.Is4In6() && ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}
func (o CoverOptions) Validate() error {
	if !nodePattern.MatchString(o.NodeID) || !tokenPattern.MatchString(o.ProofTag) || !tokenPattern.MatchString(o.PacketTag) || !privateAddress(o.Sink) || o.RateKbps < 32 || o.RateKbps > MaxCoverKbps {
		return errors.New("invalid bounded cover policy")
	}
	u, err := url.Parse(o.API)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" || !privateAddress(u.Hostname()) {
		return errors.New("cover proof requires the paired private literal API")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("cover proof requires its explicit private API port")
	}
	return nil
}
func NewCover(engine CoverEngine, options CoverOptions) (*Cover, error) {
	if engine == nil {
		return nil, errors.New("cover service has no retained VPN engine")
	}
	if err := options.Validate(); err != nil {
		return nil, err
	}
	return &Cover{engine: engine, options: options, status: CoverStatus{Requested: true, RateKbps: options.RateKbps}}, nil
}
func (c *Cover) Start(parent context.Context) error {
	if parent == nil {
		return errors.New("cover service has no lifetime context")
	}
	c.mu.Lock()
	if c.closed || c.running {
		c.mu.Unlock()
		return errors.New("cover service is closed or already starting")
	}
	identity := c.engine.Identity()
	if identity == "" {
		c.mu.Unlock()
		return errors.New("cover engine is not running")
	}
	ctx, cancel := context.WithCancel(parent)
	c.generation++
	generation := c.generation
	done := make(chan struct{})
	c.identity = identity
	c.activeCtx = ctx
	c.cancel = cancel
	c.done = done
	c.running = true
	c.status.Active = false
	c.status.Failure = ""
	c.mu.Unlock()
	// Publish ownership before any blocking proof, so teardown always cancels it.
	err := c.prove(ctx, identity)
	if err != nil {
		cancel()
		c.finish(generation, done, "private-node proof failed")
		return errors.New("cover service could not prove the selected private node")
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	conn, err := c.engine.Dial(dialCtx, "udp", c.options.PacketTag, net.JoinHostPort(c.options.Sink, strconv.Itoa(CoverPort)))
	dialCancel()
	if err != nil {
		cancel()
		c.finish(generation, done, "private cover path unavailable")
		return errors.New("private cover path unavailable")
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	probe := make([]byte, 128)
	_, randomError := rand.Read(probe)
	if randomError != nil {
		_ = conn.Close()
		cancel()
		c.finish(generation, done, "cover randomness unavailable")
		return errors.New("cover randomness unavailable")
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	written, writeError := conn.Write(probe)
	response := make([]byte, 129)
	received, readError := 0, error(nil)
	if writeError == nil && written == len(probe) {
		received, readError = conn.Read(response)
	}
	stop()
	if randomError != nil || writeError != nil || readError != nil || written != len(probe) || received != len(probe) || !c.valid(ctx, identity) {
		_ = conn.Close()
		cancel()
		c.finish(generation, done, "private cover endpoint did not respond")
		return errors.New("private cover endpoint did not respond")
	}
	_ = conn.SetDeadline(time.Time{})
	c.mu.Lock()
	if c.generation == generation {
		c.status.Active = true
		c.status.SentBytes += uint64(written)
		c.status.ReceivedBytes += uint64(received)
		c.lastReply = time.Now()
	}
	c.mu.Unlock()
	go c.run(ctx, identity, generation, done, conn)
	return nil
}
func (c *Cover) valid(ctx context.Context, identity string) bool {
	return ctx.Err() == nil && identity != "" && c.engine.Identity() == identity
}
func (c *Cover) prove(parent context.Context, identity string) error {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	if !c.valid(ctx, identity) {
		return errors.New("stale cover engine")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 4096, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		u, _ := url.Parse(c.options.API)
		if network != "tcp" || address != u.Host || !c.valid(ctx, identity) {
			return nil, errors.New("unowned cover proof socket")
		}
		return c.engine.Dial(ctx, "tcp", c.options.ProofTag, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("cover proof redirect refused") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.options.API, "/")+"/health", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || response.StatusCode != 200 || len(data) > 16384 {
		return errors.New("invalid cover proof response")
	}
	var body struct {
		OK     bool   `json:"ok"`
		NodeID string `json:"node_id"`
		Proof  string `json:"proof"`
	}
	if exact(string(data), &body, 16384) != nil || !body.OK || body.NodeID != c.options.NodeID || body.Proof != "router-vpn-private-agent-v1" || !c.valid(ctx, identity) {
		return errors.New("cover proof identity mismatch")
	}
	return nil
}
func (c *Cover) run(ctx context.Context, identity string, generation uint64, done chan struct{}, conn net.Conn) {
	failure := ""
	defer func() { c.finish(generation, done, failure) }()
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	readerDone := make(chan struct{})
	readerStop := make(chan struct{})
	go func() {
		defer close(readerDone)
		packet := make([]byte, 1201)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			n, err := conn.Read(packet)
			if err != nil {
				select {
				case <-readerStop:
					return
				case <-ctx.Done():
					return
				default:
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					continue
				}
				return
			}
			if n > 0 && n <= 1200 {
				c.mu.Lock()
				if c.generation == generation {
					c.status.ReceivedBytes += uint64(n)
					c.lastReply = time.Now()
				}
				c.mu.Unlock()
			}
		}
	}()
	defer func() { close(readerStop); _ = conn.Close(); <-readerDone }()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	proofTicker := time.NewTicker(10 * time.Second)
	defer proofTicker.Stop()
	// At most 20 datagrams/second. Jitter only reduces payload; it never raises
	// the requested per-direction payload rate or 1200-byte ceiling.
	ceiling := c.options.RateKbps * 1000 / 8 / 20
	if ceiling > 1200 {
		ceiling = 1200
	}
	buffer := make([]byte, ceiling)
	for {
		select {
		case <-ctx.Done():
			return
		case <-readerDone:
			failure = "private cover reply stream ended"
			return
		case <-proofTicker.C:
			if err := c.prove(ctx, identity); err != nil {
				failure = "private-node proof expired"
				return
			}
		case <-ticker.C:
			c.mu.Lock()
			lastReply := c.lastReply
			c.mu.Unlock()
			if time.Since(lastReply) > 2*time.Second {
				failure = "private cover replies stopped"
				return
			}
			if !c.valid(ctx, identity) {
				failure = "VPN path changed"
				return
			}
			if _, err := rand.Read(buffer); err != nil {
				failure = "cover randomness unavailable"
				return
			}
			n := ceiling * (75 + int(buffer[0])%26) / 100
			_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			written, err := conn.Write(buffer[:n])
			if err != nil || written != n {
				failure = "private cover datagram failed"
				return
			}
			c.mu.Lock()
			if c.generation == generation {
				c.status.SentBytes += uint64(n)
			}
			c.mu.Unlock()
		}
	}
}
func (c *Cover) finish(generation uint64, done chan struct{}, failure string) {
	c.mu.Lock()
	var cancel context.CancelFunc
	if c.generation == generation {
		c.running = false
		c.status.Active = false
		c.status.Failure = failure
		cancel = c.cancel
	}
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	close(done)
}
func (c *Cover) Invalidate() {
	c.mu.Lock()
	cancel := c.cancel
	c.status.Active = false
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
func (c *Cover) Close() error {
	c.mu.Lock()
	c.closed = true
	cancel, done := c.cancel, c.done
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	return nil
}
func (c *Cover) StatusJSON() string {
	c.mu.Lock()
	status := c.status
	c.mu.Unlock()
	data, err := json.Marshal(status)
	if err != nil {
		return fmt.Sprintf(`{"active":false,"failure":%q}`, "invalid cover status")
	}
	return string(data)
}

func (c *Cover) Healthy() bool {
	c.mu.Lock()
	active := !c.closed && c.running && c.status.Active
	ctx, identity, lastReply := c.activeCtx, c.identity, c.lastReply
	c.mu.Unlock()
	return active && ctx != nil && ctx.Err() == nil && time.Since(lastReply) <= 2*time.Second && c.engine.Identity() == identity
}
