package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"router-vpn/internal/multihoprelay"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func largeCapabilityFixture(c *Controller) multihoprelay.Capabilities {
	caps := multihoprelay.Capabilities{NodeID: c.meta.EntryNodeID, Execution: "server", Exits: []multihoprelay.Capability{}}
	for i := 0; i < 63; i++ {
		caps.Exits = append(caps.Exits, multihoprelay.Capability{ID: strings.Repeat("x", 120) + fmt.Sprintf("%03d", i), Mode: "wg-pq", NodeID: strings.Repeat("c", 64), PublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32))), PQIdentity: strings.Repeat("d", 64), Layer: "aes-256-gcm+xor-whitening"})
	}
	caps.Exits = append(caps.Exits, multihoprelay.Capability{ID: c.meta.ExitID, Mode: c.meta.ExitMode, NodeID: c.meta.ExitNodeID, Layer: c.meta.ExitStartLayer})
	return caps
}
func catalogController(t *testing.T, raw func(*Controller) []byte, oversizedPut bool) (*Controller, *atomic.Int32) {
	t.Helper()
	graph, meta := fixture(t, "server")
	c, err := New(graph, meta)
	if err != nil {
		t.Fatal(err)
	}
	e := makeEngine(t)
	c.engine = e
	c.engineID = e.Identity()
	body := raw(c)
	fallback := e.handler(c.meta.EntryTag)
	puts := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/multihop/lease" && r.Method == http.MethodGet {
			_, _ = w.Write(body)
			return
		}
		if r.Method == http.MethodPut {
			puts.Add(1)
			if oversizedPut {
				_, _ = w.Write([]byte(strings.Repeat(" ", multihoprelay.MaxControlResponseBytes+1)))
				return
			}
		}
		fallback(w, r)
	}))
	t.Cleanup(server.Close)
	e.servers[c.meta.EntryTag] = server
	return c, puts
}
func TestFullPublicCatalogCanAcquireAndReleaseMobileRelay(t *testing.T) {
	c, puts := catalogController(t, func(c *Controller) []byte {
		raw, _ := json.Marshal(largeCapabilityFixture(c))
		if len(raw) <= 8192 {
			t.Fatal("fixture does not cross old limit")
		}
		return raw
	}, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if puts.Load() != 1 || !c.ownsLease {
		t.Fatal("selected last entry was not leased")
	}
	if err := c.release(); err != nil {
		t.Fatal(err)
	}
	if c.ownsLease {
		t.Fatal("released lease retained ownership")
	}
}
func TestInvalidDiscoveryNeverCreatesALease(t *testing.T) {
	for _, kind := range []string{"oversized", "wrong-node", "too-many", "duplicate-exit", "duplicate-field", "unknown-field", "null"} {
		t.Run(kind, func(t *testing.T) {
			c, puts := catalogController(t, func(c *Controller) []byte {
				caps := largeCapabilityFixture(c)
				switch kind {
				case "wrong-node":
					caps.NodeID = strings.Repeat("f", 64)
				case "too-many":
					caps.Exits = append(caps.Exits, multihoprelay.Capability{ID: "extra", Mode: "shadowsocks", NodeID: strings.Repeat("c", 64)})
				case "duplicate-exit":
					caps.Exits[0] = caps.Exits[len(caps.Exits)-1]
				}
				raw, _ := json.Marshal(caps)
				switch kind {
				case "oversized":
					return append(raw, []byte(strings.Repeat(" ", multihoprelay.MaxCapabilitiesBytes))...)
				case "duplicate-field":
					return append([]byte(`{"node_id":"`+c.meta.EntryNodeID+`",`), raw[1:]...)
				case "unknown-field":
					return append([]byte(`{"secret":"never-trusted",`), raw[1:]...)
				case "null":
					return []byte(`null`)
				}
				return raw
			}, false)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := c.acquire(ctx); err == nil {
				t.Fatal("invalid discovery accepted")
			}
			if puts.Load() != 0 || c.ownsLease {
				t.Fatal("rejected catalog caused a mutation")
			}
		})
	}
}
func TestLargeDiscoveryDoesNotWidenMutationResponses(t *testing.T) {
	c, puts := catalogController(t, func(c *Controller) []byte { raw, _ := json.Marshal(largeCapabilityFixture(c)); return raw }, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.acquire(ctx); err == nil {
		t.Fatal("oversized PUT accepted")
	}
	if puts.Load() != 1 || !c.ownsLease {
		t.Fatal("ambiguous mutation lost cleanup ownership")
	}
	if err := c.release(); err != nil {
		t.Fatal(err)
	}
}
