package mobilemtu

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

type externalTestOwner struct {
	*testOwner
	proofs    []State
	dials     []State
	wrongExit bool
}

func (o *externalTestOwner) VerifyExternal(ctx context.Context, expected State) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx.Err() != nil || o.state != expected || o.wrongExit {
		return errors.New("public exit differs or TUN retired")
	}
	o.proofs = append(o.proofs, expected)
	return nil
}

func (o *externalTestOwner) DialThroughTunnel(ctx context.Context, expected State, network, address string) (net.Conn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx.Err() != nil || o.state != expected || network != "tcp" || address != hopmeasure.PublicAddress {
		return nil, errors.New("unowned external TUN socket")
	}
	o.dials = append(o.dials, expected)
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

func externalFixtureAuthority() map[string]any {
	return map[string]any{"schema": 1, "id": "external-home-exit", "source_sha256": strings.Repeat("a", 64), "expected_public_ip": "198.51.100.9", "mtu_policy": "auto", "jumbo_tun": false}
}

func externalFixtureGraph() string {
	g := fixtureGraph()
	g["outbounds"].([]any)[0].(map[string]any)["tag"] = "custom-exit"
	g["route"].(map[string]any)["final"] = "custom-exit"
	g["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] = "custom-exit"
	return encoded(g)
}

func externalFixtureController(t *testing.T) (*Controller, *externalTestOwner, *testPreferences) {
	return publicFixtureController(t, false)
}

func publicFixtureController(t *testing.T, tor bool) (*Controller, *externalTestOwner, *testPreferences) {
	t.Helper()
	o := &externalTestOwner{testOwner: &testOwner{state: State{Session: "native-external-session", Path: "WiFi-one", Interface: "tun-reader-0", MTU: 1380}}}
	p := &testPreferences{}
	graph, authority := externalFixtureGraph(), externalFixtureAuthority()
	constructor, expectedTag := NewExternal, "custom-exit"
	if tor {
		graph = strings.ReplaceAll(graph, "custom-exit", "routervpn-tor-exit")
		authority["source_kind"] = "tor"
		delete(authority, "expected_public_ip")
		constructor, expectedTag = NewTor, "routervpn-tor-exit"
	}
	c, err := constructor(o, graph, encoded(authority), NewCache(p))
	if err != nil {
		t.Fatal(err)
	}
	// Public TLS framing/byte counts are exercised by hopmeasure's actual TLS
	// fixture. This seam isolates the MTU application/ownership state machine.
	c.external.measure = func(ctx context.Context, engine hopmeasure.Engine, hop hopmeasure.Hop, size int) (hopmeasure.Result, error) {
		if hop.Kind != "public-path" || hop.Tag != expectedTag || hop.API != "" || hop.Token != "" || hop.Proof != "" || size != 256<<10 {
			t.Fatal("public optimizer manufactured private authority or changed payload")
		}
		conn, err := engine.Dial(ctx, hop.Tag, hopmeasure.PublicAddress)
		if err != nil {
			return hopmeasure.Result{}, err
		}
		conn.Close()
		state, _ := o.Capture()
		seconds := 1.0
		if state.MTU == 1500 {
			seconds = .5
		}
		transfer := func() *hopmeasure.Transfer {
			return &hopmeasure.Transfer{Bytes: int64(size), Seconds: seconds, Mbps: float64(size) * 8 / seconds / 1e6}
		}
		return hopmeasure.Result{ID: hop.ID, Role: hop.Role, Kind: hop.Kind, Ready: true, Idle: &hopmeasure.Latency{Samples: 3, Median: 1, Average: 1}, Download: transfer(), Upload: transfer()}, nil
	}
	t.Cleanup(func() { c.Close() })
	return c, o, p
}

func TestExternalMTUAppliesReadbackBeforeThroughTUNMeasurements(t *testing.T) {
	c, o, prefs := externalFixtureController(t)
	if err := c.Run(strings.Repeat("a", 32), true); err != nil {
		t.Fatal(err, c.StatusJSON())
	}
	s := readStatus(t, c)
	state, _ := o.Capture()
	if !s.Measured || s.Source != "measured-public-system-tun-transfer" || s.EffectiveMTU != 1500 || state.MTU != 1500 || prefs.data == "" {
		t.Fatal(s, state)
	}
	if len(o.dials) != len(s.Candidates)+1 || len(o.proofs) != 1+2*len(o.dials) {
		t.Fatal("winner did not repeat both proof and actual transfer", len(o.dials), len(o.proofs))
	}
	for i, candidate := range s.Candidates {
		if !candidate.Working || candidate.MTU != o.dials[i].MTU || candidate.LatencyKind != "https-response" || candidate.PacketsSent != 0 || candidate.PacketsReceived != 0 || candidate.DatagramBytes != 0 {
			t.Fatal("public transfer was mislabeled or measured another TUN", candidate, o.dials[i])
		}
	}
	// Cached values remain only candidate hints and must be measured again.
	before := len(o.dials)
	if err := c.Run(strings.Repeat("b", 32), false); err != nil {
		t.Fatal(err)
	}
	if len(o.dials) <= before {
		t.Fatal("cache was accepted as a fresh measurement")
	}
}

func TestExternalMTUCannotProbeWrongTagOrPrivateEndpoint(t *testing.T) {
	c, o, _ := externalFixtureController(t)
	s, _ := o.Capture()
	e := &probeEngine{controller: c, state: s}
	for _, target := range [][2]string{{"proxy", hopmeasure.PublicAddress}, {"custom-exit", "1.1.1.1:443"}, {"custom-exit", "10.77.0.1:8787"}, {"custom-exit", "example.test:443"}} {
		if conn, err := e.Dial(context.Background(), target[0], target[1]); err == nil {
			if conn != nil {
				conn.Close()
			}
			t.Fatal("unowned optimization socket accepted", target)
		}
	}
	if _, err := e.dial(context.Background(), "udp", hopmeasure.PublicAddress); err == nil {
		t.Fatal("public transfer became an unauthenticated packet probe")
	}
	if len(o.dials) != 0 {
		t.Fatal("unowned target reached OS adapter")
	}
}

func TestExternalMTURejectsFalseOrIncompleteTransfers(t *testing.T) {
	mutations := []func(*hopmeasure.Result){
		func(r *hopmeasure.Result) { r.Ready = false }, func(r *hopmeasure.Result) { r.ID = "other" },
		func(r *hopmeasure.Result) { r.Kind = "private-node" }, func(r *hopmeasure.Result) { r.Role = "entry" },
		func(r *hopmeasure.Result) { r.Idle.Samples = 2 }, func(r *hopmeasure.Result) { r.Idle.Median = math.NaN() },
		func(r *hopmeasure.Result) { r.Download.Bytes-- }, func(r *hopmeasure.Result) { r.Upload.Seconds = 0 },
		func(r *hopmeasure.Result) { r.Upload.Mbps = math.Inf(1) },
	}
	for index, mutate := range mutations {
		t.Run(strings.Repeat("x", index+1), func(t *testing.T) {
			c, o, p := externalFixtureController(t)
			base := c.external.measure
			c.external.measure = func(ctx context.Context, e hopmeasure.Engine, h hopmeasure.Hop, n int) (hopmeasure.Result, error) {
				r, err := base(ctx, e, h, n)
				mutate(&r)
				return r, err
			}
			if err := c.Run(strings.Repeat("c", 32), true); err == nil {
				t.Fatal("invalid transfer won")
			}
			s := readStatus(t, c)
			state, _ := o.Capture()
			if s.Measured || !s.Restored || state.MTU != 1380 || p.data != "" {
				t.Fatal("failed candidate persisted or lost rollback", s)
			}
		})
	}
}

func TestExternalMTUCancelRetainsExactRollback(t *testing.T) {
	c, o, p := externalFixtureController(t)
	entered := make(chan struct{})
	c.external.measure = func(ctx context.Context, e hopmeasure.Engine, h hopmeasure.Hop, n int) (hopmeasure.Result, error) {
		close(entered)
		<-ctx.Done()
		return hopmeasure.Result{}, ctx.Err()
	}
	done := make(chan error, 1)
	id := strings.Repeat("d", 32)
	go func() { done <- c.Run(id, true) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("measurement did not start")
	}
	c.Cancel(id)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled measurement won")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not drain")
	}
	s := readStatus(t, c)
	state, _ := o.Capture()
	if s.Measured || !s.Restored || state.MTU != 1380 || p.data != "" {
		t.Fatal(s)
	}
}

func TestExternalMTUWrongExitOrReplacedTUNNeverWins(t *testing.T) {
	for _, replace := range []bool{false, true} {
		c, o, p := externalFixtureController(t)
		base := c.external.measure
		c.external.measure = func(ctx context.Context, e hopmeasure.Engine, h hopmeasure.Hop, n int) (hopmeasure.Result, error) {
			r, err := base(ctx, e, h, n)
			o.mu.Lock()
			if replace {
				o.state.Session = "replacement"
				o.state.Interface = "other-tun"
			} else {
				o.wrongExit = true
			}
			o.mu.Unlock()
			return r, err
		}
		if err := c.Run(strings.Repeat("e", 32), true); err == nil {
			t.Fatal("stale/wrong exit won")
		}
		s := readStatus(t, c)
		if s.Measured || p.data != "" {
			t.Fatal("unproved measurement published", s)
		}
		if replace && len(o.applied) != 1 {
			t.Fatal("stale rollback touched replacement TUN", o.applied)
		}
	}
}

func TestExternalMTUAuthorityAndPolicy(t *testing.T) {
	_, o, _ := externalFixtureController(t)
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { p["schema"] = 2 }, func(p map[string]any) { p["source_sha256"] = "saved-mtu" },
		func(p map[string]any) { p["expected_public_ip"] = "10.0.0.1" }, func(p map[string]any) { p["expected_public_ip"] = "exit.test" },
		func(p map[string]any) { p["expected_public_ip"] = "::ffff:198.51.100.9" }, func(p map[string]any) { p["mtu_policy"] = true },
		func(p map[string]any) { p["mtu_policy"] = "unknown" }, func(p map[string]any) { p["jumbo_tun"] = "false" },
	} {
		p := externalFixtureAuthority()
		mutate(p)
		if _, err := NewExternal(o, externalFixtureGraph(), encoded(p), nil); err == nil {
			t.Fatal("invalid captured authority accepted")
		}
	}
	for _, mode := range []string{"fixed", "manual", "default"} {
		p := externalFixtureAuthority()
		p["mtu_policy"] = mode
		c, err := NewExternal(o, externalFixtureGraph(), encoded(p), nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Requested() || c.Run(strings.Repeat("f", 32), true) == nil {
			t.Fatal("fixed/default policy became automatic")
		}
		c.Close()
	}
	if _, err := NewExternal(o, encoded(fixtureGraph()), encoded(externalFixtureAuthority()), nil); err == nil {
		t.Fatal("private route accepted as external")
	}
	if _, err := ReadProfile(encoded(externalFixtureAuthority())); err == nil {
		t.Fatal("public optimization authority became a private packet proof")
	}
}
