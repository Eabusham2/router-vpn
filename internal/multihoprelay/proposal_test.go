package multihoprelay

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestProposedListenerPreservesTunnelAcrossActivation(t *testing.T) {
	m, r := manager(t)
	q := req()
	q.Port = 26241
	q.Username = strings.Repeat("a", 48)
	q.Password = strings.Repeat("b", 48)
	peer := netip.MustParseAddr("10.77.0.2")
	lease, err := m.Create(context.Background(), peer, q)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Port != q.Port || lease.Username != q.Username || lease.Password != q.Password {
		t.Fatal("proposal changed")
	}
	var cfg map[string]any
	json.Unmarshal(r.configs[0], &cfg)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["listen_port"] != float64(q.Port) {
		t.Fatal("engine not bound to proposed port")
	}
	renewed, err := m.Create(context.Background(), peer, q)
	if err != nil || renewed.Password != lease.Password || r.starts != 1 {
		t.Fatal("renew restarted tunnel")
	}
	if err = m.Delete(context.Background(), peer, q); err != nil || r.processes[0].alive {
		t.Fatal("delete lost ownership")
	}
}
func TestInvalidListenerProposalStartsNothing(t *testing.T) {
	for _, change := range []func(*Request){func(q *Request) { q.Port = 80 }, func(q *Request) { q.Username = "bad" }, func(q *Request) { q.Password = q.Username }, func(q *Request) { q.Port = 0 }, func(q *Request) { q.Password = "" }} {
		m, r := manager(t)
		q := req()
		q.Port = 26240
		q.Username = strings.Repeat("a", 48)
		q.Password = strings.Repeat("b", 48)
		change(&q)
		if _, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); err == nil || r.starts != 0 {
			t.Fatal("unsafe proposal starts engine")
		}
	}
}
func TestListenerCollisionDoesNotEvictAnotherPeer(t *testing.T) {
	m, r := manager(t)
	q := req()
	q.Port = 26240
	q.Username = strings.Repeat("a", 48)
	q.Password = strings.Repeat("b", 48)
	if _, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), q); err != ErrBusy || r.starts != 1 || !r.processes[0].alive {
		t.Fatal("port ownership stolen")
	}
}
