//go:build go1.25

package mobilemultihop

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/multihoprelay"
)

type startupPipeEngine struct {
	c             *Controller
	selected      string
	delay         time.Duration
	puts, deletes int
	wg            sync.WaitGroup
}

func (e *startupPipeEngine) Identity() string        { return "captured-native-owner" }
func (e *startupPipeEngine) Select(tag string) error { e.selected = tag; return nil }
func (e *startupPipeEngine) Selected() string        { return e.selected }
func (e *startupPipeEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	a, b := net.Pipe()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer b.Close()
		request, err := http.ReadRequest(bufio.NewReader(b))
		if err != nil {
			return
		}
		defer request.Body.Close()
		var body any
		switch request.URL.Path {
		case "/api/multihop/lease":
			switch request.Method {
			case "GET":
				body = map[string]any{"node_id": e.c.meta.EntryNodeID, "execution": "server", "exits": []any{map[string]any{"exit_id": e.c.meta.ExitID, "exit_mode": e.c.meta.ExitMode, "exit_node_id": e.c.meta.ExitNodeID, "client_public_key": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'q'}, 32)), "pq_client_identity": strings.Repeat("f", 64)}}}
			case "PUT":
				var q multihoprelay.Request
				if json.NewDecoder(request.Body).Decode(&q) != nil {
					return
				}
				e.puts++
				time.Sleep(e.delay)
				body = multihoprelay.Lease{Request: q, NodeID: e.c.meta.EntryNodeID, ExitNodeID: e.c.meta.ExitNodeID, Host: "10.77.0.1", Port: q.Port, Username: q.Username, Password: q.Password, ExpiresAt: time.Now().Add(90 * time.Second)}
			case "DELETE":
				e.deletes++
				body = map[string]any{"node_id": e.c.meta.EntryNodeID, "session_id": e.c.proposal.SessionID, "stopped": true}
			}
		case "/health":
			node := e.c.meta.ExitNodeID
			if tag == e.c.meta.EntryTag {
				node = e.c.meta.EntryNodeID
			}
			body = map[string]any{"ok": true, "node_id": node, "proof": "router-vpn-private-agent-v1"}
			if tag == LocalTag {
				time.Sleep(2 * time.Millisecond)
			} else {
				time.Sleep(time.Millisecond)
			}
		default:
			if tag == LocalTag {
				time.Sleep(2 * time.Millisecond)
			} else {
				time.Sleep(time.Millisecond)
			}
			body = map[string]any{"ok": true}
		}
		raw, _ := json.Marshal(body)
		response := http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw)), Close: true}
		_ = response.Write(b)
	}()
	return a, nil
}
func TestCapturedMobileServerStartupAllowsInitialKeyAndRecheck(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = previous }()
	for _, execution := range []string{"server", "auto"} {
		for _, mode := range []string{"wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
			t.Run(execution+"/"+mode, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var graph, metadata, a, b string
					if MAXMode(mode) {
						input, meta, entry, exit, al, bl := maxCompositeFixture(t, "wg", mode, "", "", execution)
						var err error
						graph, err = ComposeMAXMultihop(input, meta, entry, exit)
						if err != nil {
							t.Fatal(err)
						}
						metadata, a, b = meta, al, bl
					} else {
						graph, metadata, a, b = pqExitGraph(t, "wg", mode, "", "", execution, false)
					}
					graph, err := ApplyMTUPolicy(graph, `{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`)
					if err != nil {
						t.Fatal(err)
					}
					c, err := NewWithStartLayers(graph, metadata, a, b)
					if err != nil {
						t.Fatal(err)
					}
					e := &startupPipeEngine{c: c, selected: LocalTag, delay: 31 * time.Second}
					begin := time.Now()
					err = c.Run(context.Background(), e)
					if err != nil || !c.Healthy() || e.Selected() != ServerTag {
						t.Fatal("legitimate delayed Server startup lost its captured proof", err)
					}
					expected := 1
					if execution == "auto" {
						expected = 2
					}
					if e.puts != expected || time.Since(begin) < time.Duration(expected)*31*time.Second {
						t.Fatal("Server did not complete its initial and final captured acquisitions", e.puts)
					}
					if err = c.Close(); err != nil {
						t.Fatal(err)
					}
					e.wg.Wait()
					if e.deletes != expected || c.Healthy() {
						t.Fatal("retained server ownership did not drain", e.deletes)
					}
				})
			})
		}
	}
}
