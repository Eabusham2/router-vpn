package multihoprelay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestMaximumPQCatalogFitsPublicWireBound(t *testing.T) {
	cfg := config()
	cfg.Exits = nil
	for i := 0; i < MaxPairedExits; i++ {
		e := pqExit(t, "awg2-pq")
		e.ID = strings.Repeat("x", 125) + fmt.Sprintf("%03d", i)
		e.StartLayer = &StartLayer{Mode: "aes-256-gcm+xor-whitening", API: "http://10.88.0.1:8787", Transport: map[string]any{
			"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.2", "server_port": 8388,
			"method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))}}
		cfg.Exits = append(cfg.Exits, e)
	}
	node := req().EntryNodeID
	m, err := New(cfg, node, &runner{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"node_id": node, "execution": "server", "exits": m.Available()})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= MaxControlResponseBytes || len(raw) >= MaxCapabilitiesBytes {
		t.Fatal("maximum valid catalog does not exercise discovery bounds", len(raw))
	}
	var parsed Capabilities
	if err = json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if err = parsed.Validate(node); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private_key", "secret", "router_api", "amnezia", "listener_password"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("catalog exposed credential material", secret)
		}
	}
	cfg.Exits = append(cfg.Exits, cfg.Exits[0])
	if _, err = New(cfg, node, &runner{}); err == nil {
		t.Fatal("registry count limit was weakened")
	}
	t.Logf("maximum public catalog: %d bytes, %d entries", len(raw), len(parsed.Exits))
}

func capabilityFixture() Capabilities {
	return Capabilities{NodeID: strings.Repeat("a", 64), Execution: "server", Exits: []Capability{{ID: "exit", Mode: "shadowsocks", NodeID: strings.Repeat("b", 64)}}}
}
func TestCapabilitiesRejectWrongNodeAmbiguousAndOversizedCatalogs(t *testing.T) {
	for name, mutate := range map[string]func(*Capabilities){
		"wrong-node":      func(c *Capabilities) { c.NodeID = strings.Repeat("c", 64) },
		"wrong-execution": func(c *Capabilities) { c.Execution = "local" },
		"null-exits":      func(c *Capabilities) { c.Exits = nil },
		"duplicate":       func(c *Capabilities) { c.Exits = append(c.Exits, c.Exits[0]) },
		"too-many": func(c *Capabilities) {
			for i := 0; i < 64; i++ {
				e := c.Exits[0]
				e.ID = fmt.Sprint(i)
				c.Exits = append(c.Exits, e)
			}
		},
		"unbounded-id": func(c *Capabilities) { c.Exits[0].ID = strings.Repeat("x", 129) },
		"bad-mode":     func(c *Capabilities) { c.Exits[0].Mode = "wg\n" },
		"same-node":    func(c *Capabilities) { c.Exits[0].NodeID = c.NodeID },
		"bad-layer":    func(c *Capabilities) { c.Exits[0].Layer = "unowned" },
		"bad-public":   func(c *Capabilities) { c.Exits[0].PublicKey = "not-a-key" },
		"bad-pq":       func(c *Capabilities) { c.Exits[0].PQIdentity = "secret-sentinel" },
	} {
		t.Run(name, func(t *testing.T) {
			c := capabilityFixture()
			node := c.NodeID
			mutate(&c)
			if err := c.Validate(node); err == nil || strings.Contains(err.Error(), "sentinel") {
				t.Fatal("invalid catalog accepted or error leaked fields", err)
			}
		})
	}
	empty := capabilityFixture()
	empty.Exits = []Capability{}
	if err := empty.Validate(empty.NodeID); err != nil {
		t.Fatal("empty available catalog is valid", err)
	}
	c := capabilityFixture()
	e := c.Exits[0]
	e.Layer = "aes-256-gcm"
	c.Exits = append(c.Exits, e)
	if err := c.Validate(c.NodeID); err != nil {
		t.Fatal("different captured layers are distinct", err)
	}
}
func TestDiscoveryDoesNotWidenOtherResponseLimits(t *testing.T) {
	if LeaseResponseLimit(http.MethodGet) != MaxCapabilitiesBytes {
		t.Fatal("discovery remains undersized")
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPost, http.MethodHead, "get", ""} {
		if LeaseResponseLimit(method) != MaxControlResponseBytes {
			t.Fatal("non-discovery limit changed", method)
		}
	}
}
