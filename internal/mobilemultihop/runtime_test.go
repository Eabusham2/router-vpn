package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, execution string) (string, string) {
	t.Helper()
	graph := map[string]any{"dns": map[string]any{"servers": []any{map[string]any{"type": "tls", "tag": "selected", "server": "1.1.1.1", "detour": "proxy"}}, "final": "selected"},
		"inbounds":  []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}},
		"endpoints": []any{map[string]any{"type": "wireguard", "tag": "entry-wg"}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "detour": "entry-wg", "server": "192.0.2.2", "server_port": 8388}},
		"route":     map[string]any{"final": "proxy", "rules": []any{map[string]any{"inbound": []string{"multihop-proof"}, "outbound": "proxy"}}}}
	meta := Metadata{EntryID: "entry", ExitID: "exit", EntryNodeID: strings.Repeat("a", 64), ExitNodeID: strings.Repeat("b", 64), EntryAPI: "http://10.77.0.1:8787", ExitAPI: "http://10.88.0.1:8787", EntryToken: "entry-private-token", ExitToken: "exit-private-token", EntryTag: "entry-wg", ExitMode: "shadowsocks", Execution: execution}
	a, _ := json.Marshal(graph)
	b, _ := json.Marshal(meta)
	return string(a), string(b)
}
func TestExecutionGraphPreservesSelectedPolicy(t *testing.T) {
	original, meta := fixture(t, "auto")
	c, err := New(original, meta)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	json.Unmarshal([]byte(original), &before)
	json.Unmarshal([]byte(c.Config()), &after)
	bd, _ := json.Marshal(before["dns"])
	ad, _ := json.Marshal(after["dns"])
	if string(bd) != string(ad) {
		t.Fatal("DNS changed")
	}
	out := after["outbounds"].([]any)
	if len(out) != 3 || out[0].(map[string]any)["tag"] != LocalTag || out[0].(map[string]any)["detour"] != "entry-wg" {
		t.Fatal("local dataplane lost")
	}
	selector := out[2].(map[string]any)
	if selector["type"] != "selector" || selector["default"] != LocalTag || selector["tag"] != "proxy" {
		t.Fatal("unproved direct fallback")
	}
	relay := out[1].(map[string]any)
	if relay["type"] != "socks" || relay["detour"] != "entry-wg" || relay["network"] != nil {
		t.Fatal("relay is not TCP+UDP through entry")
	}
	if strings.Contains(c.ProgressJSON(), c.proposal.Password) || strings.Contains(c.ProgressJSON(), "private-token") {
		t.Fatal("public progress leaked secrets")
	}
}
func TestExecutionPlanRejectsAmbiguousInputs(t *testing.T) {
	graph, metadata := fixture(t, "auto")
	for _, bad := range []string{metadata + "{}", `{"execution":"local","execution":"server"}`, strings.Replace(metadata, `"entry_tag":"entry-wg"`, `"entry_tag":"direct"`, 1), strings.Replace(metadata, `"entry_api":"http://10.77.0.1:8787"`, `"entry_api":"http://example.com:8787"`, 1), strings.Replace(metadata, `"execution":"auto"`, `"execution":"invented"`, 1)} {
		if _, err := New(graph, bad); err == nil {
			t.Fatal("unsafe metadata accepted")
		}
	}
	for _, bad := range []string{graph + "{}", strings.Replace(graph, `"detour":"entry-wg"`, `"detour":"direct"`, 1), strings.Replace(graph, `"final":"proxy"`, `"final":"direct"`, 1)} {
		if _, err := New(bad, metadata); err == nil {
			t.Fatal("unsafe graph accepted")
		}
	}
}

type fakeEngine struct {
	mu            sync.Mutex
	servers       map[string]*httptest.Server
	selected      string
	identity      string
	lease         *multihoprelay.Request
	errors        []string
	badLocal      bool
	badServer     bool
	rejectCleanup bool
	unavailable   bool
	secretLeak    bool
}

func (e *fakeEngine) Identity() string { e.mu.Lock(); defer e.mu.Unlock(); return e.identity }
func (e *fakeEngine) Select(tag string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.identity == "" {
		return errors.New("stale")
	}
	e.selected = tag
	return nil
}
func (e *fakeEngine) Selected() string { e.mu.Lock(); defer e.mu.Unlock(); return e.selected }
func (e *fakeEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	server := e.servers[tag]
	if server == nil {
		return nil, errors.New("no route")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
}
func (e *fakeEngine) handler(tag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		defer e.mu.Unlock()
		switch r.URL.Path {
		case "/api/multihop/lease":
			if tag != "entry-wg" || r.Header.Get("Authorization") != "Bearer entry-private-token" {
				e.errors = append(e.errors, "control path escaped")
				w.WriteHeader(403)
				return
			}
			if e.unavailable {
				w.WriteHeader(503)
				return
			}
			switch r.Method {
			case "GET":
				json.NewEncoder(w).Encode(map[string]any{"node_id": strings.Repeat("a", 64), "execution": "server", "exits": []any{map[string]any{"exit_id": "exit", "exit_mode": "shadowsocks", "exit_node_id": strings.Repeat("b", 64)}}})
			case "PUT":
				var q multihoprelay.Request
				if json.NewDecoder(r.Body).Decode(&q) != nil {
					w.WriteHeader(400)
					return
				}
				e.lease = &q
				json.NewEncoder(w).Encode(multihoprelay.Lease{Request: q, NodeID: strings.Repeat("a", 64), ExitNodeID: strings.Repeat("b", 64), Host: "10.77.0.1", Port: q.Port, Username: q.Username, Password: q.Password, ExpiresAt: time.Now().Add(90 * time.Second)})
			case "DELETE":
				if e.rejectCleanup {
					w.WriteHeader(500)
					return
				}
				var q multihoprelay.Request
				json.NewDecoder(r.Body).Decode(&q)
				e.lease = nil
				json.NewEncoder(w).Encode(map[string]any{"node_id": strings.Repeat("a", 64), "session_id": q.SessionID, "stopped": true})
			}
			return
		case "/health":
			node := strings.Repeat("b", 64)
			token := "Bearer exit-private-token"
			if tag == "entry-wg" {
				node = strings.Repeat("a", 64)
				token = "Bearer entry-private-token"
			}
			if r.Header.Get("Authorization") != token {
				e.errors = append(e.errors, "wrong node credential")
			}
			if tag == LocalTag && e.badLocal || tag == ServerTag && e.badServer {
				w.WriteHeader(500)
				return
			}
			if tag == LocalTag {
				time.Sleep(15 * time.Millisecond)
			}
			json.NewEncoder(w).Encode(map[string]any{"node_id": node, "ok": true, "proof": "router-vpn-private-agent-v1"})
			return
		default:
			if r.Header.Get("Authorization") != "" {
				e.secretLeak = true
			}
			if tag == LocalTag {
				time.Sleep(20 * time.Millisecond)
			}
			w.WriteHeader(204)
		}
	}
}
func makeEngine(t *testing.T) *fakeEngine {
	t.Helper()
	e := &fakeEngine{servers: map[string]*httptest.Server{}, selected: LocalTag, identity: "one-owned-instance"}
	for _, tag := range []string{"entry-wg", LocalTag, ServerTag} {
		e.servers[tag] = httptest.NewServer(e.handler(tag))
		t.Cleanup(e.servers[tag].Close)
	}
	return e
}
func TestRealSharedControllerRequestsScoresSelectsAndCleans(t *testing.T) {
	// Only test transport is plaintext: each Dial remains a separate owned fake
	// outbound. Production Targets are HTTPS literals with normal TLS validation.
	before := Targets
	Targets = []string{"http://1.1.1.1/check", "http://1.0.0.1/check"}
	defer func() { Targets = before }()
	graph, meta := fixture(t, "auto")
	c, err := New(graph, meta)
	if err != nil {
		t.Fatal(err)
	}
	e := makeEngine(t)
	if err = c.Run(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if e.Selected() != ServerTag || !c.Healthy() {
		t.Fatal("faster verified server was not retained")
	}
	var progress Progress
	if json.Unmarshal([]byte(c.ProgressJSON()), &progress) != nil || !progress.Complete || progress.Execution != "server" || len(progress.Measurements) != 2 {
		t.Fatal(c.ProgressJSON())
	}
	for _, m := range progress.Measurements {
		if !m.Eligible || m.ScoreMS == nil || *m.ScoreMS != (m.LastNodeMS+m.ExternalMS)/2 {
			t.Fatal("wrong arithmetic")
		}
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if e.lease != nil || e.secretLeak || len(e.errors) != 0 {
		t.Fatal("ownership/credential leak", e.errors)
	}
}
func TestFailedOrUnavailableServerDoesNotReplaceValidLocal(t *testing.T) {
	old := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = old }()
	for _, unavailable := range []bool{false, true} {
		graph, meta := fixture(t, "auto")
		c, _ := New(graph, meta)
		e := makeEngine(t)
		e.badServer = true
		e.unavailable = unavailable
		if err := c.Run(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		if e.Selected() != LocalTag {
			t.Fatal("failed candidate selected")
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
func TestAllFailuresNeverMarkConnected(t *testing.T) {
	old := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = old }()
	graph, meta := fixture(t, "auto")
	c, _ := New(graph, meta)
	e := makeEngine(t)
	e.badLocal = true
	e.badServer = true
	err := c.Run(context.Background(), e)
	if !errors.Is(err, routechoice.ErrNoWinner) {
		t.Fatal("both failures selected", err)
	}
	_ = c.Close()
}
func TestNetworkCancellationAndCleanupOwnership(t *testing.T) {
	old := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = old }()
	graph, meta := fixture(t, "server")
	c, _ := New(graph, meta)
	e := makeEngine(t)
	if err := c.Run(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	c.NetworkChanged()
	if c.Healthy() {
		t.Fatal("network mutation retained proof")
	}
	e.mu.Lock()
	e.rejectCleanup = true
	e.mu.Unlock()
	if err := c.Close(); err == nil {
		t.Fatal("unconfirmed lease falsely cleaned")
	}
	c.leaseMu.Lock()
	owned := c.ownsLease
	c.leaseMu.Unlock()
	if !owned {
		t.Fatal("lease ownership lost")
	}
	e.mu.Lock()
	e.rejectCleanup = false
	e.mu.Unlock()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}
