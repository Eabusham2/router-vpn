//go:build go1.25

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/multihoprelay"
)

type startupDeadlineRunner struct {
	delay   time.Duration
	process *layerProcess
	starts  int
	budget  time.Duration
}

func (r *startupDeadlineRunner) Start(ctx context.Context, _ []byte, _ multihoprelay.Lease) (multihoprelay.Process, error) {
	r.starts++
	r.process = &layerProcess{alive: true}
	deadline, ok := ctx.Deadline()
	if !ok {
		panic("server startup lost its deadline")
	}
	r.budget = time.Until(deadline)
	select {
	case <-time.After(r.delay):
		return r.process, nil
	case <-ctx.Done():
		return r.process, ctx.Err()
	}
}

// The registered HTTP route, compiler, registry and cleanup manager are real.
// Only the native child is doubled, under virtual monotonic time; this is not
// cryptographic, public network or deployment evidence.
func TestRelayStartupDeadlineRetainsInitialKeyAndFreshLease(t *testing.T) {
	for _, mode := range []string{"shadowsocks", "wg-pq", "awg2-pq"} {
		for _, cancelled := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/ready", true: "/cancel"}[cancelled], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					node := strings.Repeat("a", 64)
					exit := multihoprelay.Exit{ID: "exit", Mode: mode, NodeID: strings.Repeat("b", 64), DNS: "10.88.0.1", Transport: map[string]any{"type": "shadowsocks", "server": "192.0.2.2", "server_port": 8388, "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA=="}}
					if mode != "shadowsocks" {
						assets, id := pqPairingFixture(mode)
						exit.NodeID = id
						raw, _ := json.Marshal(assets)
						var compiled bytes.Buffer
						if err := compilePQRelayProfile(bytes.NewReader(raw), &compiled, mode, id, "198.51.100.2"); err != nil {
							t.Fatal(err)
						}
						exit.Transport = nil
						if err := json.Unmarshal(compiled.Bytes(), &exit.Transport); err != nil {
							t.Fatal(err)
						}
					}
					runner := &startupDeadlineRunner{delay: 31 * time.Second}
					manager, err := multihoprelay.New(multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26241, TTLSeconds: 15, Exits: []multihoprelay.Exit{exit}}, node, runner)
					if err != nil {
						t.Fatal(err)
					}
					defer manager.Close(context.Background())
					_, subnet, _ := net.ParseCIDR("10.77.0.0/24")
					s := &server{cfg: cfg{Token: "startup-private-token", NodeID: node}, nets: []*net.IPNet{subnet}, relay: manager}
					mux := http.NewServeMux()
					registerMultihopRelayRoute(mux, s)
					caps := manager.Available()
					q := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: node, ExitID: "exit", ExitMode: mode, ExpectedPacketPublicKey: caps[0]["client_public_key"], ExpectedPQClientIdentity: caps[0]["pq_client_identity"]}
					raw, _ := json.Marshal(q)
					req := httptest.NewRequest(http.MethodPut, multihopRelayPath, bytes.NewReader(raw))
					req.RemoteAddr = "10.77.0.2:4321"
					req.Header.Set("Authorization", "Bearer startup-private-token")
					if cancelled {
						ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
						defer cancel()
						req = req.WithContext(ctx)
					}
					response := httptest.NewRecorder()
					begin := time.Now()
					mux.ServeHTTP(response, req)
					wantReady := mode != "shadowsocks" && !cancelled
					if (response.Code == http.StatusOK) != wantReady || runner.starts != 1 {
						t.Fatalf("native startup outcome changed: mode=%s cancel=%v status=%d body=%s", mode, cancelled, response.Code, response.Body.String())
					}
					if wantReady {
						var lease multihoprelay.Lease
						if err := json.Unmarshal(response.Body.Bytes(), &lease); err != nil {
							t.Fatal(err)
						}
						if time.Since(begin) != 31*time.Second || lease.ExpiresAt.Sub(time.Now()) != 15*time.Second || runner.process.stops != 0 || !runner.process.alive {
							t.Fatal("startup consumed the live lease or lost its native owner")
						}
						if runner.budget != 38*time.Second {
							t.Fatal("wrong native acquisition budget", runner.budget)
						}
					} else {
						bound := 8 * time.Second
						if cancelled {
							bound = 2 * time.Second
						}
						if time.Since(begin) != bound || runner.process.alive || runner.process.stops != 1 {
							t.Fatal("cancelled or ordinary startup failed to stop its exact native child")
						}
					}
				})
			})
		}
	}
}
