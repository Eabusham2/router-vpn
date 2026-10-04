package mobilemtu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mtuprobe"
)

type testPreferences struct {
	mu         sync.Mutex
	data       string
	fail       bool
	afterWrite func()
}

func (p *testPreferences) ReadMTUCache() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.data, nil
}
func (p *testPreferences) CompareAndSwapMTUCache(old, next string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return false, errors.New("injected private persistence failure")
	}
	if p.data != old {
		return false, nil
	}
	p.data = next
	if p.afterWrite != nil {
		p.afterWrite()
	}
	return true, nil
}

type testOwner struct {
	mu            sync.Mutex
	state         State
	version       int
	applied       []int
	reads         int
	failApply     int
	wrongReadback bool
	wrongProof    bool
	blindEcho     bool
	blockDownload chan struct{}
	entered       sync.Once
	server        *httptest.Server
}

func (o *testOwner) Capture() (State, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reads++
	return o.state, nil
}
func (o *testOwner) ChangeMTU(ctx context.Context, expected State, mtu int) (State, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx.Err() != nil || expected != o.state || o.state.Session == "" {
		return o.state, errors.New("unowned TUN change")
	}
	if mtu < 1280 || mtu > 1500 {
		return o.state, errors.New("test TUN bound violated")
	}
	o.version++
	o.state.Interface = fmt.Sprintf("native-interface-%d", o.version)
	o.state.MTU = mtu
	o.applied = append(o.applied, mtu)
	if o.wrongReadback && len(o.applied) == 1 {
		o.state.MTU++
	}
	if len(o.applied) == o.failApply {
		return o.state, errors.New("injected platform apply failure")
	}
	return o.state, nil
}
func (o *testOwner) DialThroughTunnel(ctx context.Context, expected State, network, address string) (net.Conn, error) {
	o.mu.Lock()
	state, blind := o.state, o.blindEcho
	o.mu.Unlock()
	if state != expected {
		return nil, errors.New("stale OS interface")
	}
	if network == "tcp" && address == "10.77.0.1:8787" {
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(o.server.URL, "http://"))
	}
	if network != "udp" || address != "10.77.0.1:45999" {
		return nil, errors.New("unowned measurement destination")
	}
	c, s := net.Pipe()
	go func() {
		defer s.Close()
		packet := make([]byte, 9001)
		for {
			n, err := s.Read(packet)
			if err != nil {
				return
			}
			if n > state.MTU-28 {
				return
			}
			reply, err := mtuprobe.Reply(packet[:n], "private-fixture-token", strings.Repeat("a", 64), time.Now())
			if err != nil {
				return
			}
			if blind {
				copy(reply, packet[:n])
			}
			if _, err = s.Write(reply); err != nil {
				return
			}
		}
	}()
	return c, nil
}

// Keep completion validation strict while distinguishing an intentional
// request cancellation from a complete-but-malformed upload. This is a test
// server boundary; production transfer validation is unchanged.
func readFixtureUpload(r *http.Request) (int64, error) {
	const size = 256 << 10
	if r.ContentLength != size || len(r.TransferEncoding) != 0 {
		return 0, errors.New("upload declaration not bounded")
	}
	n, err := io.Copy(io.Discard, io.LimitReader(r.Body, size+1))
	if n > size {
		return n, errors.New("upload payload exceeds declared bound")
	}
	if cancelled := r.Context().Err(); cancelled != nil {
		return n, cancelled
	}
	if err != nil || n != size {
		return n, fmt.Errorf("complete upload payload not bounded: bytes=%d error=%v", n, err)
	}
	return n, nil
}

func fixtureController(t *testing.T) (*Controller, *testOwner, *testPreferences) {
	t.Helper()
	owner := &testOwner{state: State{Session: "native-encrypted-owner", Path: "physical-WiFi", Interface: "native-interface-0", MTU: 1380}}
	owner.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-fixture-token" {
			t.Error("wrong private token")
		}
		owner.mu.Lock()
		wrong, block := owner.wrongProof, owner.blockDownload
		owner.mu.Unlock()
		if block != nil && r.URL.Path == "/api/benchmark/download" {
			owner.entered.Do(func() { close(block) })
			<-r.Context().Done()
			return
		}
		switch r.URL.Path {
		case "/health":
			proof := strings.Repeat("a", 64)
			if wrong {
				proof = strings.Repeat("b", 64)
			}
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": proof, "proof": "router-vpn-private-agent-v1"})
		case "/api/benchmark/download":
			size, err := strconv.Atoi(r.URL.Query().Get("bytes"))
			if err != nil || size != 256<<10 {
				t.Error("unbounded private measurement request")
			}
			w.Header().Set("Content-Length", strconv.Itoa(size))
			w.Header().Set("X-Routervpn-Benchmark", "download-v1")
			w.Header().Set("X-Routervpn-Benchmark-Bytes", strconv.Itoa(size))
			w.Write(make([]byte, size))
		case "/api/benchmark/upload":
			n, err := readFixtureUpload(r)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				// Client cancellation intentionally interrupts the body. Never
				// acknowledge that partial upload as a successful measurement.
				return
			}
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "direction": "upload", "bytes": n, "server_receive_ms": 1, "peer": "10.77.0.2", "proof": "authenticated tunnel-peer private throughput sink"})
		default:
			t.Error("unowned private MTU request", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(owner.server.Close)
	prefs := &testPreferences{}
	c, err := New(owner, encoded(fixtureGraph()), encoded(fixtureProfile()), NewCache(prefs))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, owner, prefs
}
func readStatus(t *testing.T, c *Controller) Status {
	t.Helper()
	var value Status
	if err := json.Unmarshal([]byte(c.StatusJSON()), &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func TestRealPacketAndByteMeasurementAppliesBeforeReporting(t *testing.T) {
	c, owner, prefs := fixtureController(t)
	if err := c.Run(strings.Repeat("a", 32), true); err != nil {
		t.Fatal(err, c.StatusJSON())
	}
	result := readStatus(t, c)
	if !result.Measured || !result.Complete || result.Running || result.Source != "measured-private-system-tun" || len(result.Candidates) < 3 {
		t.Fatal(result)
	}
	state, _ := owner.Capture()
	if state.MTU != result.EffectiveMTU {
		t.Fatal("reported a size that is not applied")
	}
	owner.mu.Lock()
	applied := append([]int{}, owner.applied...)
	owner.mu.Unlock()
	if len(applied) != len(result.Candidates)+1 {
		t.Fatal("candidate or final application omitted", applied, result)
	}
	for i, row := range result.Candidates {
		if !row.Working || row.MTU != applied[i] || row.PacketsSent != 6 || row.PacketsReceived != 6 || row.DatagramBytes != row.MTU-28 || row.Download == nil || row.Upload == nil {
			t.Fatal("measurement not executed", row)
		}
		for _, transfer := range []*hopmeasure.Transfer{row.Download, row.Upload} {
			if transfer.Bytes != 256<<10 || transfer.Seconds <= 0 {
				t.Fatal("transfer measurement missing")
			}
			want := float64(transfer.Bytes) * 8 / transfer.Seconds / 1e6
			if math.Abs(want-transfer.Mbps) > 0.000001 {
				t.Fatal("rate was not derived from observed bytes/time")
			}
		}
	}
	raw, _ := prefs.ReadMTUCache()
	if strings.Contains(raw, "private-fixture-token") || strings.Contains(raw, "10.77") || strings.Contains(c.StatusJSON(), "private-fixture-token") {
		t.Fatal("private node data leaked into result/cache")
	}
	if err := c.Run(strings.Repeat("b", 32), false); err != nil {
		t.Fatal("second retest failed", err, c.StatusJSON())
	}
	second := readStatus(t, c)
	if second.OriginalMTU != state.MTU || !second.Measured || second.PathKey != result.PathKey {
		t.Fatal("Retest did not capture the current applied state", second)
	}
}
func TestExactRollbackAfterApplyReadbackAndSaveFailure(t *testing.T) {
	for _, mode := range []string{"apply", "readback", "persistence"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, prefs := fixtureController(t)
			before := c.Config()
			switch mode {
			case "apply":
				owner.failApply = 2
			case "readback":
				owner.wrongReadback = true
			default:
				prefs.fail = true
			}
			if err := c.Run(strings.Repeat("c", 32), true); err == nil {
				t.Fatal("failure accepted")
			}
			status := readStatus(t, c)
			state, _ := owner.Capture()
			if !status.Restored || status.Measured || state.MTU != 1380 || c.Config() != before {
				t.Fatal("failed to restore exact pre-test live/config snapshot", status, state)
			}
		})
	}
}
func TestCancellationRollbackAndStopNeverResurrects(t *testing.T) {
	for _, action := range []string{"cancel", "stop", "network", "replacement"} {
		t.Run(action, func(t *testing.T) {
			c, owner, _ := fixtureController(t)
			entered := make(chan struct{})
			owner.blockDownload = entered
			request := strings.Repeat("d", 32)
			done := make(chan error, 1)
			go func() { done <- c.Run(request, true) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("measurement did not start")
			}
			owner.mu.Lock()
			before := len(owner.applied)
			owner.mu.Unlock()
			if err := c.Run(strings.Repeat("e", 32), true); err == nil {
				t.Fatal("concurrent MTU mutation accepted")
			}
			switch action {
			case "cancel":
				c.Cancel(request)
			case "stop":
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
			case "network":
				owner.mu.Lock()
				owner.state.Path = "new-physical-network"
				owner.mu.Unlock()
				c.Invalidate()
			case "replacement":
				owner.mu.Lock()
				owner.state.Session = "new-native-session"
				owner.mu.Unlock()
				c.Invalidate()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled/stale measurement adopted")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation did not drain")
			}
			status := readStatus(t, c)
			owner.mu.Lock()
			after := len(owner.applied)
			owner.mu.Unlock()
			if action == "cancel" {
				if !status.Restored || after != before+1 {
					t.Fatal("cancel did not roll back", status)
				}
			} else if status.Restored || after != before {
				t.Fatal("old operation restarted or modified a newer/stopped session", action, status)
			}
		})
	}
}
func TestWrongNodeAndBlindEchoDoNotProveAnMTU(t *testing.T) {
	c, owner, _ := fixtureController(t)
	owner.wrongProof = true
	if err := c.Run(strings.Repeat("f", 32), true); err == nil {
		t.Fatal("wrong node accepted")
	}
	if len(owner.applied) != 0 {
		t.Fatal("MTU changed before node proof")
	}
	c2, owner2, _ := fixtureController(t)
	owner2.blindEcho = true
	if err := c2.Run(strings.Repeat("a", 32), true); err == nil {
		t.Fatal("blind UDP echo counted as authenticated reply")
	}
	result := readStatus(t, c2)
	if !result.Restored || result.Measured {
		t.Fatal("failed packet-size experiment adopted")
	}
	for _, row := range result.Candidates {
		if row.Working || row.PacketsReceived != 0 {
			t.Fatal("invalid reply was counted")
		}
	}
}
func TestSelectionNeedsRealRateGainWithoutLatencyRegression(t *testing.T) {
	row := func(mtu int, rate, rtt float64) Candidate {
		return Candidate{MTU: mtu, Working: true, MedianRTT: rtt, Download: &hopmeasure.Transfer{Mbps: rate}, Upload: &hopmeasure.Transfer{Mbps: rate}}
	}
	base := row(1380, 100, 2)
	for _, candidate := range []Candidate{row(1280, 104, 1), row(1280, 150, 2.21), row(1280, math.NaN(), 1), row(1280, math.Inf(1), 1)} {
		if Choose([]Candidate{base, candidate}, 1380).MTU != 1380 {
			t.Fatal("noisy/invalid/laggier candidate replaced baseline")
		}
	}
	if Choose([]Candidate{base, row(1280, 150, 1.9)}, 1380).MTU != 1280 {
		t.Fatal("measured improvement ignored")
	}
	if Choose(nil, 1380).Working {
		t.Fatal("empty measurement fabricated winner")
	}
}
func TestFixedAndJumboPoliciesAreNotMutated(t *testing.T) {
	for _, kind := range []string{"manual", "jumbo"} {
		_, owner, _ := fixtureController(t)
		profile := fixtureProfile()
		if kind == "manual" {
			profile["mtu_policy"] = "manual"
		} else {
			profile["jumbo_tun"] = true
		}
		c, err := New(owner, encoded(fixtureGraph()), encoded(profile), nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Requested() {
			t.Fatal("fixed/Jumbo triggered Auto")
		}
		if c.Run(strings.Repeat("a", 32), true) == nil {
			t.Fatal("Retest silently changed a non-Auto policy")
		}
		c.Close()
	}
}

func TestMTUChooserDoesNotAccumulateLatencyAllowance(t *testing.T) {
	row := func(mtu int, rate, rtt float64) Candidate {
		return Candidate{MTU: mtu, Working: true, MedianRTT: rtt, Download: &hopmeasure.Transfer{Mbps: rate}, Upload: &hopmeasure.Transfer{Mbps: rate}}
	}
	result := Choose([]Candidate{row(1380, 100, 2), row(1360, 150, 2.1), row(1340, 200, 2.25), row(1320, 250, 2.4)}, 1380)
	if result.MTU != 1360 {
		t.Fatal("successive candidates accumulated more than the original RTT budget", result)
	}
}
