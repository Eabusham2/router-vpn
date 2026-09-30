package mobilemtu

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mtuprobe"
)

// State identifies the actual virtual interface and the enclosing encrypted
// session separately. Changing only the TUN reader may replace Interface while
// the encrypted Session and physical Path must remain exactly the same.
type State struct {
	Session   string
	Path      string
	Interface string
	MTU       int
}
type Owner interface {
	Capture() (State, error)
	ChangeMTU(context.Context, State, int) (State, error)
	DialThroughTunnel(context.Context, State, string, string) (net.Conn, error)
}
type Cache interface {
	Lookup(string) (int, bool)
	Save(string, int, func() bool) error
}
type Candidate struct {
	MTU             int                  `json:"mtu"`
	Working         bool                 `json:"working"`
	PacketsSent     int                  `json:"packets_sent"`
	PacketsReceived int                  `json:"packets_received"`
	DatagramBytes   int                  `json:"datagram_bytes"`
	MedianRTT       float64              `json:"median_rtt_ms"`
	Download        *hopmeasure.Transfer `json:"download,omitempty"`
	Upload          *hopmeasure.Transfer `json:"upload,omitempty"`
	Failure         string               `json:"failure,omitempty"`
}
type Status struct {
	Request      string      `json:"request_id"`
	Phase        string      `json:"phase"`
	Running      bool        `json:"running"`
	Complete     bool        `json:"complete"`
	Measured     bool        `json:"measured"`
	Restored     bool        `json:"restored"`
	OriginalMTU  int         `json:"original_mtu"`
	EffectiveMTU int         `json:"effective_mtu"`
	Source       string      `json:"source"`
	PathKey      string      `json:"path_key,omitempty"`
	Failure      string      `json:"failure,omitempty"`
	Candidates   []Candidate `json:"candidates"`
}

type Controller struct {
	owner         Owner
	profile       Profile
	frozenConfig  string
	cache         Cache
	mu            sync.Mutex
	closed        bool
	invalid       bool
	cancel        context.CancelFunc
	done          chan struct{}
	status        Status
	currentConfig string
}

func New(owner Owner, config, profile string, cache Cache) (*Controller, error) {
	if owner == nil {
		return nil, errors.New("MTU owner is missing")
	}
	policy, err := ReadProfile(profile)
	if err != nil {
		return nil, err
	}
	state, err := owner.Capture()
	if err != nil || state.Session == "" || state.Path == "" || state.Interface == "" || state.MTU < MinMTU || state.MTU > MaxMTU {
		return nil, errors.New("MTU must capture a running native VPN interface")
	}
	// A fixed or Jumbo connection does not enter the optimizer. Keep it visible
	// without interpreting its stored effective_mtu as a current measurement.
	if policy.Automatic && !policy.Jumbo {
		if _, err = NewPlan(config, state.MTU); err != nil {
			return nil, err
		}
	}
	return &Controller{owner: owner, profile: policy, frozenConfig: config, currentConfig: config, cache: cache, status: Status{Phase: "idle", EffectiveMTU: state.MTU, Source: "configured-unmeasured", Candidates: []Candidate{}}}, nil
}
func (c *Controller) Requested() bool { return c.profile.Automatic && !c.profile.Jumbo }
func (c *Controller) live(ctx context.Context, expected State) bool {
	if ctx.Err() != nil {
		return false
	}
	c.mu.Lock()
	valid := !c.closed && !c.invalid
	c.mu.Unlock()
	if !valid {
		return false
	}
	current, err := c.owner.Capture()
	// A platform read may synchronously race a Stop or network callback.
	c.mu.Lock()
	valid = !c.closed && !c.invalid
	c.mu.Unlock()
	return valid && ctx.Err() == nil && err == nil && current == expected && current.Session != "" && current.Path != "" && current.Interface != ""
}
func (c *Controller) sessionLive(ctx context.Context, expected State) (State, bool) {
	if ctx.Err() != nil {
		return State{}, false
	}
	c.mu.Lock()
	valid := !c.closed && !c.invalid
	c.mu.Unlock()
	if !valid {
		return State{}, false
	}
	current, err := c.owner.Capture()
	c.mu.Lock()
	valid = !c.closed && !c.invalid
	c.mu.Unlock()
	return current, valid && ctx.Err() == nil && err == nil && current.Session == expected.Session && current.Path == expected.Path && current.Interface == expected.Interface
}
func (c *Controller) phase(value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed && !c.invalid {
		c.status.Phase = value
	}
}

// Run and native asynchronous Start use the same published operation and
// completion path. Neither entrypoint can bypass cancellation or invalidation.
func (c *Controller) Run(request string, force bool) error {
	op, err := c.begin(request)
	if err != nil {
		return err
	}
	return c.execute(op, force)
}
func (c *Controller) run(ctx context.Context, config string, force bool) (runErr error) {
	original, err := c.owner.Capture()
	if err != nil || !c.live(ctx, original) {
		return errors.New("MTU interface changed before capture")
	}
	plan, err := NewPlan(config, original.MTU)
	if err != nil {
		return err
	}
	keyPlan := *plan
	keyPlan.source = c.frozenConfig
	key := keyPlan.PathKey(c.profile, original.Path)
	c.mu.Lock()
	c.status.OriginalMTU = original.MTU
	c.status.EffectiveMTU = original.MTU
	c.status.PathKey = key
	c.mu.Unlock()
	expected := original
	dirty := false
	adopted := false
	defer func() {
		if adopted || !dirty {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		// A stop, replaced runtime, or changed path is never undone by rollback.
		if _, ok := c.sessionLive(rollbackCtx, expected); !ok {
			c.mu.Lock()
			c.status.Failure = "MTU owner or path changed; no stale interface was restarted"
			c.mu.Unlock()
			return
		}
		state, err := c.owner.ChangeMTU(rollbackCtx, expected, original.MTU)
		if err != nil || state.MTU != original.MTU || state.Session != original.Session || state.Path != original.Path || !c.live(rollbackCtx, state) {
			c.mu.Lock()
			c.status.Failure = "Exact pre-test MTU rollback could not be confirmed"
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		if c.closed || c.invalid || rollbackCtx.Err() != nil {
			c.mu.Unlock()
			return
		}
		c.currentConfig = config
		c.status.Restored = true
		c.status.EffectiveMTU = original.MTU
		c.status.Source = "restored-unmeasured"
		c.status.Phase = "restored"
		c.mu.Unlock()
	}()
	engine := &probeEngine{controller: c, state: expected}
	hop := hopmeasure.Hop{ID: c.profile.ID, Role: "exit", Tag: "proxy", API: c.profile.API, Token: c.profile.Token, Proof: c.profile.Proof}
	if _, err = hopmeasure.ProvePath(ctx, engine, hop); err != nil {
		return errors.New("selected private node was not proved through the captured system TUN")
	}
	cached := 0
	if c.cache != nil && !force {
		if value, ok := c.cache.Lookup(key); ok {
			cached = value
		}
	}
	passed := []Candidate{}
	for _, mtu := range plan.Candidates(cached) {
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 10*time.Second && len(passed) > 0 {
			break
		}
		if !c.live(ctx, expected) {
			return context.Canceled
		}
		c.phase("applying " + strconv.Itoa(mtu))
		dirty = true
		state, err := c.owner.ChangeMTU(ctx, expected, mtu)
		// The native adapter returns its owned post-error state as well. It cannot
		// give another session's state permission to run a rollback.
		if state.Session == original.Session && state.Path == original.Path && state.Interface != "" {
			expected = state
			engine.state = state
		}
		if err != nil || state.MTU != mtu || !c.live(ctx, expected) {
			return errors.New("candidate did not become the actual owned system TUN MTU")
		}
		c.phase("measuring " + strconv.Itoa(mtu))
		candidate := Candidate{MTU: mtu}
		candidateCtx, stop := context.WithTimeout(ctx, 8*time.Second)
		_, measureErr := hopmeasure.ProvePath(candidateCtx, engine, hop)
		if measureErr == nil {
			measureErr = c.packets(candidateCtx, engine, &candidate)
		}
		if measureErr == nil {
			result, transferErr := hopmeasure.MeasurePath(candidateCtx, engine, hop, 256<<10)
			if transferErr == nil {
				candidate.Working = true
				candidate.Download = result.Download
				candidate.Upload = result.Upload
			} else {
				candidate.Failure = "private transfer did not complete"
			}
		} else {
			candidate.Failure = "private identity or authenticated packet-size test failed"
		}
		stop()
		c.mu.Lock()
		c.status.Candidates = append(c.status.Candidates, candidate)
		c.mu.Unlock()
		if !c.live(ctx, expected) {
			return context.Canceled
		}
		if candidate.Working {
			passed = append(passed, candidate)
		}
	}
	if len(passed) == 0 {
		return errors.New("no MTU candidate passed the private packet and transfer measurements")
	}
	winner := Choose(passed, original.MTU)
	if !winner.Working {
		return errors.New("no finite eligible MTU measurement remained")
	}
	c.phase("adopting " + strconv.Itoa(winner.MTU))
	if !c.live(ctx, expected) {
		return context.Canceled
	}
	state, err := c.owner.ChangeMTU(ctx, expected, winner.MTU)
	if state.Session == original.Session && state.Path == original.Path && state.Interface != "" {
		expected = state
		engine.state = state
	}
	if err != nil || state.MTU != winner.MTU || !c.live(ctx, expected) {
		return errors.New("measured winner was not applied to its captured interface")
	}
	verified := Candidate{MTU: winner.MTU}
	if err = c.packets(ctx, engine, &verified); err != nil {
		return errors.New("winner failed its fresh bidirectional verification")
	}
	if _, err = hopmeasure.ProvePath(ctx, engine, hop); err != nil {
		return errors.New("winner's selected-node identity changed")
	}
	valid := func() bool { return c.live(ctx, expected) }
	if !valid() {
		return context.Canceled
	}
	if c.cache != nil {
		if err = c.cache.Save(key, winner.MTU, valid); err != nil {
			return errors.New("fresh MTU result could not be durably saved")
		}
	}
	if !valid() {
		return context.Canceled
	}
	final, err := plan.Config(winner.MTU)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed || c.invalid || ctx.Err() != nil {
		c.mu.Unlock()
		return context.Canceled
	}
	c.currentConfig = final
	c.status.Measured = true
	c.status.EffectiveMTU = winner.MTU
	c.status.Source = "measured-private-system-tun"
	c.status.Phase = "complete"
	c.mu.Unlock()
	adopted = true
	return nil
}
func (c *Controller) packets(ctx context.Context, engine *probeEngine, result *Candidate) error {
	ip, err := netip.ParseAddr(c.profile.Sink)
	if err != nil {
		return err
	}
	overhead := 28
	if ip.Is6() {
		overhead = 48
	}
	size := result.MTU - overhead
	if size < mtuprobe.HeaderBytes || size > mtuprobe.MaxBytes {
		return errors.New("invalid probe packet envelope")
	}
	result.DatagramBytes = size
	address := net.JoinHostPort(c.profile.Sink, strconv.Itoa(ProbePort))
	conn, err := engine.dial(ctx, "udp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	samples := []float64{}
	for i := 0; i < 6; i++ {
		if !c.live(ctx, engine.state) {
			return context.Canceled
		}
		request, err := mtuprobe.Request(size, c.profile.Token, c.profile.Proof, time.Now())
		if err != nil {
			return err
		}
		deadline := time.Now().Add(600 * time.Millisecond)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		if err = conn.SetDeadline(deadline); err != nil {
			return errors.New("MTU socket cannot enforce its bounded deadline")
		}
		result.PacketsSent++
		started := time.Now()
		n, err := conn.Write(request)
		if err != nil || n != len(request) {
			return errors.New("MTU packet write failed")
		}
		reply := make([]byte, size+1)
		n, err = conn.Read(reply)
		if err != nil || n < 0 || n > len(reply) || mtuprobe.ValidateReply(request, reply[:n], c.profile.Token, c.profile.Proof, time.Now()) != nil {
			continue
		}
		result.PacketsReceived++
		samples = append(samples, float64(time.Since(started).Nanoseconds())/1e6)
	}
	if result.PacketsReceived != 6 {
		return errors.New("MTU candidate lost authenticated packet replies")
	}
	sort.Float64s(samples)
	result.MedianRTT = (samples[2] + samples[3]) / 2
	return nil
}

// Choose refuses throughput changes within a 5% noise band and never trades
// over 0.2 ms of measured packet RTT for the apparent transfer-rate improvement.
func Choose(candidates []Candidate, original int) Candidate {
	rate := func(candidate Candidate) float64 {
		if !candidate.Working || candidate.MTU < MinMTU || candidate.MTU > MaxMTU || candidate.MedianRTT <= 0 ||
			math.IsNaN(candidate.MedianRTT) || math.IsInf(candidate.MedianRTT, 0) || candidate.Download == nil || candidate.Upload == nil {
			return 0
		}
		a, b := candidate.Download.Mbps, candidate.Upload.Mbps
		if a <= 0 || b <= 0 || math.IsNaN(a) || math.IsNaN(b) || math.IsInf(a, 0) || math.IsInf(b, 0) {
			return 0
		}
		low, high := math.Min(a, b), math.Max(a, b)
		return low / ((1 + low/high) / 2)
	}
	winner := Candidate{}
	for _, candidate := range candidates {
		if rate(candidate) == 0 {
			continue
		}
		if !winner.Working || candidate.MTU == original {
			winner = candidate
		}
		if candidate.MTU == original {
			break
		}
	}
	if !winner.Working {
		return Candidate{}
	}
	baselineRTT := winner.MedianRTT
	for _, candidate := range candidates {
		if rate(candidate) > rate(winner)*1.05 && candidate.MedianRTT <= baselineRTT+0.2 {
			winner = candidate
		}
	}
	return winner
}

type probeEngine struct {
	controller *Controller
	state      State
}

func (e *probeEngine) Identity() string {
	if !e.controller.live(context.Background(), e.state) {
		return ""
	}
	return e.state.Session + ":" + e.state.Path + ":" + e.state.Interface
}
func (e *probeEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if tag != "proxy" {
		return nil, errors.New("unowned MTU proof route")
	}
	return e.dial(ctx, "tcp", address)
}
func (e *probeEngine) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c := e.controller
	api, _ := url.Parse(c.profile.API)
	allowed := (network == "tcp" && address == api.Host) || (network == "udp" && address == net.JoinHostPort(c.profile.Sink, strconv.Itoa(ProbePort)))
	if !allowed || !c.live(ctx, e.state) {
		return nil, errors.New("MTU socket is not owned by the captured private path")
	}
	conn, err := c.owner.DialThroughTunnel(ctx, e.state, network, address)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("MTU owner returned no through-tunnel socket")
	}
	if !c.live(ctx, e.state) {
		conn.Close()
		return nil, errors.New("MTU interface changed while opening its socket")
	}
	return conn, nil
}
func (c *Controller) Cancel(request string) {
	c.mu.Lock()
	if c.status.Request == request && c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
}

// revokeLocked keeps historical samples without presenting them as current.
// A zero effective MTU means unknown; it is never passed to ChangeMTU.
func (c *Controller) revokeLocked(phase string) {
	c.status.Measured = false
	c.status.Restored = false
	c.status.EffectiveMTU = 0
	c.status.Source = "unavailable-stale-owner"
	c.status.Phase = phase
}
func (c *Controller) Invalidate() {
	c.mu.Lock()
	c.invalid = true
	if c.closed {
		c.revokeLocked("stopped")
	} else {
		c.revokeLocked("invalidated")
	}
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
}
func (c *Controller) Close() error {
	c.mu.Lock()
	c.closed = true
	c.revokeLocked("stopped")
	if c.cancel != nil {
		c.cancel()
	}
	done := c.done
	c.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			return errors.New("MTU owner did not finish draining")
		}
	}
	return nil
}
func (c *Controller) StatusJSON() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, _ := json.Marshal(c.status)
	return string(data)
}
func (c *Controller) Config() string { c.mu.Lock(); defer c.mu.Unlock(); return c.currentConfig }
