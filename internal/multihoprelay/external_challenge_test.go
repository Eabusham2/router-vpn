package multihoprelay

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestEveryExternalProxyRequiresFreshAuthenticatedAcquisitionAndRejectsReplay(t *testing.T) {
	for _, protocol := range externalProtocols {
		t.Run(protocol, func(t *testing.T) {
			exit, prepared := externalProxyFixture(t, protocol, "")
			cfg := config()
			cfg.TTLSeconds = 90
			cfg.Exits = []Exit{exit}
			r := &runner{}
			m, err := New(cfg, prepared.EntryNodeID, r)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().Truncate(time.Second)
			m.now = func() time.Time { return now }
			peer := netip.MustParseAddr("10.77.0.2")
			if _, err := m.Create(context.Background(), peer, prepared); err == nil || !strings.Contains(err.Error(), "upgrade") || r.starts != 0 {
				t.Fatal("unsafe legacy unchallenged acquisition was not explicitly rejected")
			}
			cancelled := challengedExternalFixture(t, m, exit, prepared, peer)
			if err := m.Delete(context.Background(), peer, cancelled); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Create(context.Background(), peer, cancelled); err == nil || r.starts != 0 {
				t.Fatal("delayed PUT recreated an already cancelled external lease")
			}
			active := challengedExternalFixture(t, m, exit, prepared, peer)
			if active.ExternalAttempt == cancelled.ExternalAttempt || active.ExternalAuthentication == cancelled.ExternalAuthentication || active.ExternalFingerprint != prepared.ExternalFingerprint {
				t.Fatal("fresh attempt changed bundle identity or reused acquisition authority")
			}
			if _, err := m.Create(context.Background(), peer, active); err != nil {
				t.Fatal(err)
			}
			now = now.Add(61 * time.Second)
			if _, err := m.Create(context.Background(), peer, active); err != nil || r.starts != 1 {
				t.Fatal("live lease could not renew past its initial acquisition deadline", err)
			}
			if err := m.Delete(context.Background(), peer, active); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Create(context.Background(), peer, active); err == nil || r.starts != 1 {
				t.Fatal("expired/deleted acquisition restarted its provider session")
			}
			repeated := challengedExternalFixture(t, m, exit, prepared, peer)
			if _, err := m.Create(context.Background(), peer, repeated); err != nil || r.starts != 2 {
				t.Fatal("repeated winner proof could not acquire a fresh owner", err)
			}
			if err := m.Delete(context.Background(), peer, repeated); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Create(context.Background(), peer, repeated); err == nil {
				t.Fatal("deleted live attempt replayed before acquisition deadline")
			}
			beforeRestart := challengedExternalFixture(t, m, exit, prepared, peer)
			restarted, err := New(cfg, prepared.EntryNodeID, &runner{})
			if err != nil {
				t.Fatal(err)
			}
			restarted.now = m.now
			if _, err := restarted.Create(context.Background(), peer, beforeRestart); err == nil {
				t.Fatal("old entry epoch survived manager restart")
			}
			if _, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), beforeRestart); err == nil {
				t.Fatal("signed acquisition moved to another observed entry peer")
			}
			for _, field := range []string{"epoch", "peer", "expiry", "attempt"} {
				changed := beforeRestart
				switch field {
				case "epoch":
					changed.ExternalEpoch = strings.Repeat("e", 64)
				case "peer":
					changed.ExternalPeer = "10.77.0.3"
				case "expiry":
					changed.ExternalExpiresAt++
				case "attempt":
					changed.ExternalAttempt = strings.Repeat("e", 32)
				}
				if ValidateExternalRequest(exit, changed) == nil {
					t.Fatal("authenticator did not bind " + field)
				}
			}
			if err := m.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
