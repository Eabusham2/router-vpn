package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

// Exercise the production HTTP decoder and manager together. Only the owned
// native process is doubled; no successful encrypted traffic is implied.
type layerProcess struct {
	alive bool
	stops int
}

func (p *layerProcess) Alive() bool                { return p.alive }
func (p *layerProcess) Stop(context.Context) error { p.alive = false; p.stops++; return nil }

type layerRunner struct {
	starts  int
	body    []byte
	process *layerProcess
}

func (r *layerRunner) Start(_ context.Context, body []byte, _ multihoprelay.Lease) (multihoprelay.Process, error) {
	r.starts++
	r.body = append([]byte(nil), body...)
	r.process = &layerProcess{alive: true}
	return r.process, nil
}

func TestRelayHTTPRetainsCapturedExitLayerAcrossLeaseLifecycle(t *testing.T) {
	for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, proposed := range []bool{false, true} {
			t.Run(layer+map[bool]string{true: "/proposed", false: "/allocated"}[proposed], func(t *testing.T) {
				entry, exit := strings.Repeat("a", 64), strings.Repeat("b", 64)
				key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
				transport := map[string]any{"type": "shadowsocks", "tag": "exit", "server": "192.0.2.2", "server_port": float64(8388), "method": "2022-blake3-aes-256-gcm", "password": key}
				item := multihoprelay.Exit{ID: "exit", Mode: "shadowsocks", NodeID: exit, DNS: "10.88.0.1", Transport: transport}
				if layer != "" {
					item.StartLayer = &multihoprelay.StartLayer{Mode: layer, API: "http://10.88.0.1:8787", Transport: transport}
				}
				runner := &layerRunner{}
				manager, err := multihoprelay.New(multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26241, Exits: []multihoprelay.Exit{item}}, entry, runner)
				if err != nil {
					t.Fatal(err)
				}
				defer manager.Close(context.Background())
				_, subnet, _ := net.ParseCIDR("10.77.0.0/24")
				s := &server{cfg: cfg{Token: "private-test-token", NodeID: entry}, nets: []*net.IPNet{subnet}, relay: manager}
				q := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: entry, ExitID: "exit", ExitMode: "shadowsocks", ExitStartLayer: layer}
				if proposed {
					q.Port = 26241
					q.Username = strings.Repeat("d", 48)
					q.Password = strings.Repeat("e", 48)
				}
				call := func(method string, value multihoprelay.Request) *httptest.ResponseRecorder {
					t.Helper()
					raw, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					request := httptest.NewRequest(method, multihopRelayPath, strings.NewReader(string(raw)))
					request.RemoteAddr = "10.77.0.2:4321"
					request.Header.Set("Authorization", "Bearer private-test-token")
					response := httptest.NewRecorder()
					s.multihopRelay(response, request)
					return response
				}
				response := call(http.MethodPut, q)
				if response.Code != 200 {
					t.Fatalf("selected layer never reached relay: %d %s", response.Code, response.Body.String())
				}
				var lease multihoprelay.Lease
				if json.Unmarshal(response.Body.Bytes(), &lease) != nil || lease.ExitStartLayer != layer || lease.Request.ExitID != q.ExitID || lease.NodeID != entry {
					t.Fatal("captured lease identity lost")
				}
				if runner.starts != 1 {
					t.Fatal("wrong process count")
				}
				var graph map[string]any
				if err = json.Unmarshal(runner.body, &graph); err != nil {
					t.Fatal(err)
				}
				expected := 1
				if layer != "" {
					expected = 2
				}
				if len(graph["outbounds"].([]any)) != expected {
					t.Fatal("wrong bare/layered server graph")
				}
				renewed := call(http.MethodPut, q)
				if renewed.Code != 200 || runner.starts != 1 {
					t.Fatal("renewal replaced captured session")
				}
				wrong := q
				wrong.ExitStartLayer = "aes-256-gcm"
				if wrong.ExitStartLayer == layer {
					wrong.ExitStartLayer = "aes-256-gcm+xor-whitening"
				}
				if rejected := call(http.MethodDelete, wrong); rejected.Code != 403 || !runner.process.alive {
					t.Fatal("different layer could delete this session")
				}
				if stopped := call(http.MethodDelete, q); stopped.Code != 200 || runner.process.alive || runner.process.stops != 1 {
					t.Fatal("owned layered session did not close")
				}
				if again := call(http.MethodDelete, q); again.Code != 200 || runner.process.stops != 1 {
					t.Fatal("delete not idempotent")
				}
				// A request for another layer must never fall back to a paired bare
				// transport, or vice versa, after the first session is gone.
				if missing := call(http.MethodPut, wrong); missing.Code != 503 || runner.starts != 1 {
					t.Fatal("missing requested layer was silently substituted")
				}
			})
		}
	}
}

func TestRelayExitLayerExactInputAndNoEmbeddedTransport(t *testing.T) {
	base := `{"session_id":"` + strings.Repeat("c", 32) + `","entry_node_id":"` + strings.Repeat("a", 64) + `","exit_id":"exit","exit_mode":"wg-pq"`
	for _, value := range []string{`""`, `"off"`, `null`, `false`, `7`, `{}`, `"aes"`, `"xor"`, `"aes-256-gcm\n"`, `"AES-256-GCM"`} {
		if _, err := decodeRelayRequest(strings.NewReader(base + `,"exit_start_layer":` + value + `}`)); err == nil {
			t.Fatal("invalid layer accepted", value)
		}
	}
	for _, extra := range []string{
		`,"exit_start_layer":"aes-256-gcm","exit_start_layer":"aes-256-gcm"`,
		`,"exit_start_layer":"aes-256-gcm","transport":{}`,
		`,"exit_start_layer":"aes-256-gcm","listener_username":"` + strings.Repeat("a", 48) + `"`,
		`,"exit_start_layer":"aes-256-gcm","listen_port":26240`,
		`,"exit_start_layer":"aes-256-gcm","listen_port":26240,"listen_port":26240`,
	} {
		if _, err := decodeRelayRequest(strings.NewReader(base + extra + `}`)); err == nil {
			t.Fatal("ambiguous lease accepted", extra)
		}
	}
}
