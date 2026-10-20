package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"router-vpn/internal/hopmeasure"
)

func TestExternalMeasurementRequiresSuccessfulExactCapturedProof(t *testing.T) {
	for _, entry := range []string{"", "router-wg", "socks5"} {
		t.Run(entry, func(t *testing.T) {
			r, engine, _ := externalRequestFixture(t, entry)
			graph, capture := externalTestFixture(t, "shadowsocks", entry)
			source, selection := externalTestJSON(t, graph), externalTestJSON(t, capture)
			if _, err := r.NewHopMeasurement(source, selection, "session-old", engine); err == nil {
				t.Fatal("unproved native connection gained performance owner")
			}
			if _, err := r.Run(); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var tags []string
			engine.dial = func(_ context.Context, tag, address string) (net.Conn, error) {
				mu.Lock()
				tags = append(tags, tag)
				mu.Unlock()
				return nil, errors.New("fixture supplies no traffic")
			}
			service, err := r.NewHopMeasurement(source, selection, "session-old", engine)
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			id := strings.Repeat("a", 32)
			if err = service.Start(id, 65536); err != nil {
				t.Fatal(err)
			}
			if err = service.Drain(id); err != nil {
				t.Fatal(err)
			}
			var status hopmeasure.Status
			if json.Unmarshal([]byte(service.StatusJSON()), &status) != nil || !status.Drained {
				t.Fatal("captured request did not drain")
			}
			want := 1
			if entry != "" {
				want = 2
			}
			if len(status.Results) != want {
				t.Fatal("captured predecessor disappeared", status)
			}
			for i, result := range status.Results {
				if result.Ready || result.Download != nil || result.Upload != nil {
					t.Fatal("missing fixture traffic earned metrics")
				}
				kind := "public-path"
				if entry == "router-wg" && i == 0 {
					kind = "private-node"
				}
				if result.Kind != kind || result.Label == "" {
					t.Fatal("captured node/path measurement kind changed", result)
				}
			}
			mu.Lock()
			got := strings.Join(tags, ",")
			mu.Unlock()
			if !strings.HasSuffix(got, "custom-exit") || entry != "" && !strings.HasPrefix(got, r.meta.EntryTag+",") {
				t.Fatal("measurement escaped captured path order", got)
			}
			for _, secret := range []string{"private-entry-token", "api_token", "node_proof_id"} {
				if strings.Contains(service.StatusJSON(), secret) {
					t.Fatal("private metadata leaked into result")
				}
			}
			r.Cancel()
			if service.Start(strings.Repeat("b", 32), 65536) == nil {
				t.Fatal("canceled native proof retained measurement authority")
			}
		})
	}
}

func TestExternalMeasurementRejectsChangedSessionSourcePolicyAndNativeOwner(t *testing.T) {
	for _, mutation := range []string{"session", "source-bytes", "capture-ip", "capture-entry", "cancelled", "retired"} {
		t.Run(mutation, func(t *testing.T) {
			r, engine, _ := externalRequestFixture(t, "router-wg")
			if _, err := r.Run(); err != nil {
				t.Fatal(err)
			}
			graph, capture := externalTestFixture(t, "shadowsocks", "router-wg")
			source := externalTestJSON(t, graph)
			session := "session-old"
			switch mutation {
			case "session":
				session = "replacement-session"
			case "source-bytes":
				source += " "
			case "capture-ip":
				capture["expected_public_ip"] = "203.0.113.99"
				capture["profile"].(map[string]any)["external"].(map[string]any)["expected_public_ip"] = "203.0.113.99"
			case "capture-entry":
				capture["entry"].(map[string]any)["api_token"] = "another-entry-token"
			case "cancelled":
				r.Cancel()
			case "retired":
				engine.current.Store(false)
			}
			if _, err := r.NewHopMeasurement(source, externalTestJSON(t, capture), session, engine); err == nil {
				t.Fatal("changed capture gained measurement authority")
			}
		})
	}
}
