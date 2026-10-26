package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func relayPinController(t *testing.T, mode string) (*Controller, *fakeEngine, string, string) {
	t.Helper()
	return relayPinControllerExecution(t, mode, "server")
}

func relayPinControllerExecution(t *testing.T, mode, execution string) (*Controller, *fakeEngine, string, string) {
	t.Helper()
	var graph, meta string
	if IsPQMode(mode) {
		graph, meta, _, _ = pqExitGraph(t, "wg", mode, "", "", execution, false)
	} else if MAXMode(mode) {
		input, metadata, a, b, _, _ := maxCompositeFixture(t, "wg", mode, "", "", execution)
		var err error
		graph, err = ComposeMAXMultihop(input, metadata, a, b)
		if err != nil {
			t.Fatal(err)
		}
		meta = metadata
	} else {
		graph, meta, _, _ = exitLayerFixture(t, "wg", mode, "", "", execution)
	}
	c, err := New(graph, meta)
	if err != nil {
		t.Fatal(err)
	}
	e := makeEngine(t)
	e.exitMode, e.exitNode, e.entryNode = mode, c.meta.ExitNodeID, c.meta.EntryNodeID
	e.clientPublic = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32)))
	if IsPQMode(mode) || MAXMode(mode) {
		e.pqIdentity = strings.Repeat("a", 64)
	}
	c.engine, c.engineID = e, e.Identity()
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c, e, graph, meta
}

func TestServerIdentityDiscoveryIsRetainedInTheExactLease(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		t.Run(mode, func(t *testing.T) {
			c, e, _, _ := relayPinController(t, mode)
			if err := c.acquire(context.Background()); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(c.proposal)
			var fields map[string]any
			if json.Unmarshal(raw, &fields) != nil || fields["expected_packet_public_key"] != e.clientPublic {
				t.Fatal("authenticated discovery did not pin the packet identity in the exact lease")
			}
			if (IsPQMode(mode) || MAXMode(mode)) && fields["expected_pq_client_identity"] != e.pqIdentity {
				t.Fatal("authenticated discovery did not pin the independent PQ identity in the exact lease")
			}
			captured := c.proposal
			if c.expected.Request != captured {
				t.Fatal("expected lease did not retain the exact request")
			}
			if err := c.renewLocked(context.Background()); err != nil || c.proposal != captured || c.expected.Request != captured {
				t.Fatal("renewal changed captured pins", err)
			}
			if err := c.release(); err != nil {
				t.Fatal(err)
			}
			if err := c.acquire(context.Background()); err != nil || c.proposal != captured || c.expected.Request != captured {
				t.Fatal("retained comparison reacquisition changed captured pins", err)
			}
		})
	}
}

func TestRetainedServerIdentityPinsRejectChangedDiscovery(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		changes := []string{"packet", "missing-packet"}
		if IsPQMode(mode) || MAXMode(mode) {
			changes = append(changes, "pq", "missing-pq")
		}
		for _, changed := range changes {
			t.Run(mode+"/"+changed, func(t *testing.T) {
				c, e, _, _ := relayPinController(t, mode)
				if err := c.acquire(context.Background()); err != nil {
					t.Fatal(err)
				}
				captured := c.proposal
				if err := c.release(); err != nil {
					t.Fatal(err)
				}
				e.mu.Lock()
				switch changed {
				case "packet":
					e.clientPublic = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
				case "missing-packet":
					e.clientPublic = ""
				case "pq":
					e.pqIdentity = strings.Repeat("b", 64)
				case "missing-pq":
					e.pqIdentity = ""
				}
				e.mu.Unlock()
				if err := c.acquire(context.Background()); err == nil || c.proposal != captured || c.expected.Request != captured || c.ownsLease {
					t.Fatal("new catalog replaced the retained identity pins", err)
				}
				e.mu.Lock()
				mutated := e.lease != nil
				e.mu.Unlock()
				if mutated {
					t.Fatal("changed discovery sent a server mutation")
				}
			})
		}
	}
}

func TestServerIdentityLeaseEchoCannotDropOrReplacePins(t *testing.T) {
	for _, mode := range []string{"wg", "wg-pq", "awg2-pq", "max-quic-awg"} {
		for _, changed := range []string{"packet", "pq", "omit"} {
			t.Run(mode+"/"+changed, func(t *testing.T) {
				c, e, _, _ := relayPinController(t, mode)
				if err := c.acquire(context.Background()); err != nil {
					t.Fatal(err)
				}
				captured, expiry, deadline := c.proposal, c.expected.ExpiresAt, c.leaseDeadline.Load()
				fallback := e.handler(c.meta.EntryTag)
				entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPut {
						fallback(w, r)
						return
					}
					recorder := httptest.NewRecorder()
					fallback(recorder, r)
					var reply multihoprelay.Lease
					if json.Unmarshal(recorder.Body.Bytes(), &reply) != nil {
						w.WriteHeader(500)
						return
					}
					switch changed {
					case "packet":
						reply.ExpectedPacketPublicKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
					case "pq":
						reply.ExpectedPQClientIdentity = strings.Repeat("b", 64)
					case "omit":
						reply.ExpectedPacketPublicKey, reply.ExpectedPQClientIdentity = "", ""
					}
					_ = json.NewEncoder(w).Encode(reply)
				}))
				t.Cleanup(entry.Close)
				e.servers[c.meta.EntryTag] = entry
				if err := c.renewLocked(context.Background()); err == nil || c.proposal != captured || c.expected.Request != captured || c.expected.ExpiresAt != expiry || c.leaseDeadline.Load() != deadline || !c.ownsLease {
					t.Fatal("changed reply refreshed or discarded the owned lease", err)
				}
				if err := c.release(); err != nil {
					t.Fatal("rejected renewal prevented exact cleanup", err)
				}
			})
		}
	}
}

func TestServerIdentityCatalogCannotMutateCancelledOrStaleOwner(t *testing.T) {
	for _, changed := range []string{"network", "engine", "cancel"} {
		t.Run(changed, func(t *testing.T) {
			c, e, _, _ := relayPinController(t, "wg-pq")
			captured := c.proposal
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var puts atomic.Int32
			fallback := e.handler(c.meta.EntryTag)
			entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					puts.Add(1)
				}
				fallback(w, r)
				if r.Method == http.MethodGet {
					switch changed {
					case "network":
						c.NetworkChanged()
					case "engine":
						e.mu.Lock()
						e.identity = "replacement"
						e.mu.Unlock()
					case "cancel":
						cancel()
					}
				}
			}))
			t.Cleanup(entry.Close)
			e.servers[c.meta.EntryTag] = entry
			if err := c.acquire(ctx); err == nil || c.proposal != captured || c.expected.Request != captured || c.ownsLease || puts.Load() != 0 {
				t.Fatal("stale discovery installed pins or acquired a lease", err)
			}
		})
	}
}

func TestRestoredServerIdentityMetadataPreservesTheCapturedPair(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, changed := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/same", true: "/changed"}[changed], func(t *testing.T) {
				c, e, graph, metadata := relayPinController(t, mode)
				if err := c.acquire(context.Background()); err != nil {
					t.Fatal(err)
				}
				captured := c.proposal
				if err := c.release(); err != nil {
					t.Fatal(err)
				}
				meta := startObject(t, metadata)
				meta["expected_packet_public_key"] = captured.ExpectedPacketPublicKey
				if captured.ExpectedPQClientIdentity != "" {
					meta["expected_pq_client_identity"] = captured.ExpectedPQClientIdentity
				}
				restored, err := New(graph, startJSON(t, meta))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := restored.Close(); err != nil {
						t.Error(err)
					}
				})
				restored.engine, restored.engineID = e, e.Identity()
				if restored.proposal.ExpectedPacketPublicKey != captured.ExpectedPacketPublicKey || restored.proposal.ExpectedPQClientIdentity != captured.ExpectedPQClientIdentity || restored.proposal.SessionID == captured.SessionID {
					t.Fatal("reconstruction lost pins or reused the old lease session")
				}
				if changed {
					e.mu.Lock()
					if captured.ExpectedPQClientIdentity != "" {
						e.pqIdentity = strings.Repeat("b", 64)
					} else {
						e.clientPublic = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
					}
					e.mu.Unlock()
				}
				err = restored.acquire(context.Background())
				if (err == nil) == changed {
					t.Fatal("restoration accepted changed pins or rejected the exact pair", err)
				}
				if restored.proposal.ExpectedPacketPublicKey != captured.ExpectedPacketPublicKey || restored.proposal.ExpectedPQClientIdentity != captured.ExpectedPQClientIdentity {
					t.Fatal("restored discovery overwrote captured pins")
				}
			})
		}
	}
}

func TestRestoredServerIdentityMetadataRejectsInvalidOrReusedPins(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq", "max-quic-wg"} {
		for _, fault := range []string{"no-packet", "no-pq", "empty-packet", "empty-pq", "null-packet", "null-pq", "both-null", "bad-packet", "noncanonical-packet", "bad-pq", "same-packet", "same-pq"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				c, e, graph, metadata := relayPinController(t, mode)
				meta := startObject(t, metadata)
				meta["expected_packet_public_key"], meta["expected_pq_client_identity"] = e.clientPublic, e.pqIdentity
				switch fault {
				case "no-packet":
					delete(meta, "expected_packet_public_key")
				case "no-pq":
					delete(meta, "expected_pq_client_identity")
				case "empty-packet":
					meta["expected_packet_public_key"] = ""
				case "empty-pq":
					meta["expected_pq_client_identity"] = ""
				case "null-packet":
					meta["expected_packet_public_key"] = nil
				case "null-pq":
					meta["expected_pq_client_identity"] = nil
				case "both-null":
					meta["expected_packet_public_key"], meta["expected_pq_client_identity"] = nil, nil
				case "bad-packet":
					meta["expected_packet_public_key"] = "bad"
				case "noncanonical-packet":
					meta["expected_packet_public_key"] = e.clientPublic + "\n"
				case "bad-pq":
					meta["expected_pq_client_identity"] = strings.Repeat("A", 64)
				case "same-packet":
					meta["expected_packet_public_key"] = c.localPublicKey
				case "same-pq":
					meta["expected_pq_client_identity"] = c.localPQIdentity
				}
				if restored, err := New(graph, startJSON(t, meta)); err == nil || restored != nil {
					t.Fatal("invalid restored identity pair was accepted", fault)
				}
			})
		}
	}
	for _, mode := range []string{"wg", "awg2-fast", "shadowsocks"} {
		_, e, graph, metadata := relayPinController(t, mode)
		meta := startObject(t, metadata)
		meta["expected_packet_public_key"], meta["expected_pq_client_identity"] = e.clientPublic, strings.Repeat("a", 64)
		if c, err := New(graph, startJSON(t, meta)); err == nil || c != nil {
			t.Fatal("unowned PQ pin accepted", mode)
		}
	}
}

func TestLayeredIdentityMetadataCannotEraseRestorationConstraints(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, layers := range [][2]string{{"aes-256-gcm", ""}, {"", "aes-256-gcm+xor-whitening"}, {"aes-256-gcm", "aes-256-gcm+xor-whitening"}} {
			t.Run(mode+"/"+layers[0]+"/"+layers[1], func(t *testing.T) {
				graph, metadata, entry, exit := pqExitGraph(t, "wg", mode, layers[0], layers[1], "server", false)
				if layers[1] == "" {
					exit = ""
				}
				for _, fault := range []string{"valid", "empty", "null", "partial"} {
					meta := startObject(t, metadata)
					meta["expected_packet_public_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32)))
					meta["expected_pq_client_identity"] = strings.Repeat("a", 64)
					switch fault {
					case "empty":
						meta["expected_packet_public_key"], meta["expected_pq_client_identity"] = "", ""
					case "null":
						meta["expected_packet_public_key"], meta["expected_pq_client_identity"] = nil, nil
					case "partial":
						delete(meta, "expected_pq_client_identity")
					}
					c, err := NewWithStartLayers(graph, startJSON(t, meta), entry, exit)
					if fault == "valid" {
						if err != nil || c.proposal.ExpectedPacketPublicKey != meta["expected_packet_public_key"] || c.proposal.ExpectedPQClientIdentity != meta["expected_pq_client_identity"] || c.proposal.ExitStartLayer != layers[1] || c.expected.Request != c.proposal {
							t.Fatal("layer composition lost valid identity constraints", err)
						}
						if err := c.Close(); err != nil {
							t.Fatal(err)
						}
					} else if err == nil || c != nil {
						t.Fatal("layer preparation erased explicit invalid restoration pins", fault)
					}
				}
			})
		}
	}
}

func TestServerIdentitySnapshotRequiresTheActualHealthySelection(t *testing.T) {
	localProbeTargets(t)
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "shadowsocks"} {
		for _, execution := range []string{"local", "server"} {
			t.Run(mode+"/"+execution, func(t *testing.T) {
				c, e, _, _ := relayPinControllerExecution(t, mode, execution)
				if raw, err := c.ServerIdentityPinsJSON(); err == nil || raw != "" {
					t.Fatal("unproved owner exported restoration pins")
				}
				if err := c.Run(context.Background(), e); err != nil {
					t.Fatal(err)
				}
				raw, err := c.ServerIdentityPinsJSON()
				if err != nil {
					t.Fatal(err)
				}
				if execution == "local" || mode == "shadowsocks" {
					if raw != "{}" {
						t.Fatal("local/proxy owner fabricated packet pins", raw)
					}
				} else {
					var fields map[string]string
					if json.Unmarshal([]byte(raw), &fields) != nil || fields["expected_packet_public_key"] != e.clientPublic || fields["expected_pq_client_identity"] != e.pqIdentity {
						t.Fatal("healthy snapshot changed the captured identity pins", raw)
					}
					want := 1
					if e.pqIdentity != "" {
						want = 2
					}
					if len(fields) != want {
						t.Fatal("snapshot exposed fields beyond public identity pins")
					}
				}
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
				if raw, err := c.ServerIdentityPinsJSON(); err == nil || raw != "" {
					t.Fatal("closed owner exported usable restoration pins")
				}
			})
		}
	}
}

func TestServerIdentitySnapshotRejectsStaleOrIncompleteOwner(t *testing.T) {
	localProbeTargets(t)
	for _, fault := range []string{"network", "engine", "selector", "expiry", "missing", "partial", "expected-request", "not-owned", "unproved"} {
		t.Run(fault, func(t *testing.T) {
			c, e, _, _ := relayPinController(t, "wg-pq")
			if err := c.Run(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			captured := c.proposal
			switch fault {
			case "network":
				c.NetworkChanged()
			case "engine":
				e.mu.Lock()
				e.identity = "replacement"
				e.mu.Unlock()
			case "selector":
				e.mu.Lock()
				e.selected = LocalTag
				e.mu.Unlock()
			case "expiry":
				expired := time.Now().Add(-time.Second)
				c.leaseDeadline.Store(&expired)
			case "missing", "partial", "expected-request", "not-owned":
				c.leaseMu.Lock()
				if fault == "missing" {
					c.proposal.ExpectedPacketPublicKey, c.proposal.ExpectedPQClientIdentity = "", ""
					c.expected.Request = c.proposal
				}
				if fault == "partial" {
					c.proposal.ExpectedPQClientIdentity = ""
					c.expected.Request = c.proposal
				}
				if fault == "expected-request" {
					c.expected.ExpectedPQClientIdentity = strings.Repeat("b", 64)
				}
				if fault == "not-owned" {
					c.ownsLease = false
				}
				c.leaseMu.Unlock()
			case "unproved":
				c.mu.Lock()
				c.progress.Complete = false
				c.mu.Unlock()
			}
			if raw, err := c.ServerIdentityPinsJSON(); err == nil || raw != "" {
				t.Fatal("stale or incomplete server owner exported restoration pins", fault)
			}
			// Restore only the fixture's exact cleanup request, not health.
			c.leaseMu.Lock()
			c.proposal, c.expected.Request, c.ownsLease = captured, captured, true
			c.leaseMu.Unlock()
		})
	}
}

type identitySnapshotEngine struct {
	*fakeEngine
	afterRead func()
}

func (e *identitySnapshotEngine) Selected() string {
	selected := e.fakeEngine.Selected()
	if e.afterRead != nil {
		e.afterRead()
	}
	return selected
}

func TestServerIdentitySnapshotJoinsNativeCallbacksWithoutStateLocks(t *testing.T) {
	localProbeTargets(t)
	for _, change := range []string{"network-release", "engine"} {
		for _, boundary := range []int32{1, 2} {
			t.Run(change+"/"+map[int32]string{1: "before-copy", 2: "after-copy"}[boundary], func(t *testing.T) {
				c, raw, _, _ := relayPinController(t, "awg2-pq")
				e := &identitySnapshotEngine{fakeEngine: raw}
				if err := c.Run(context.Background(), e); err != nil {
					t.Fatal(err)
				}
				var reads atomic.Int32
				e.afterRead = func() {
					if reads.Add(1) == boundary {
						if change == "engine" {
							raw.mu.Lock()
							raw.identity = "replacement"
							raw.mu.Unlock()
						} else {
							c.NetworkChanged()
							if err := c.release(); err != nil {
								t.Error(err)
							}
						}
					}
				}
				done := make(chan error, 1)
				go func() { _, err := c.ServerIdentityPinsJSON(); done <- err }()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("native callback invalidation published stale pins")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("identity snapshot held state locks across a native callback")
				}
			})
		}
	}
}
