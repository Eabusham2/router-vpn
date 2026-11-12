package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func nodeChainExecutionDiscoveryFixture(p *NodeChainExecutionPolicy, now time.Time) NodeChainExecutionDiscovery {
	return NodeChainExecutionDiscovery{NodeID: p.source.Server.EntryNodeID,
		Challenge: multihoprelay.ExternalPacketChallenge{Epoch: strings.Repeat("c", 64), Peer: p.source.Request.Peer, ExpiresAt: now.Add(time.Minute).Unix()}, Sources: []multihoprelay.NodeChainDescriptor{p.Descriptor()}, FirstPort: p.source.FirstPort, LastPort: p.source.LastPort}
}

func TestNodeChainExecutionFreshAttemptsRetainOneOriginalNativeGraph(t *testing.T) {
	p, err := NewNodeChainExecutionPolicy(startJSON(t, nodeChainExecutionFixtureSource(t, 4, "", "auto")))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	discovery := nodeChainExecutionDiscoveryFixture(p, now)
	beforeSource, beforeConfig, beforeFront := p.Source(), p.Config(), p.Front()
	seen := map[string]bool{p.source.Request.SessionID: true}
	for i := 0; i < 8; i++ {
		request, err := p.newAttemptAt(startJSON(t, discovery), now)
		if err != nil {
			t.Fatal(err)
		}
		if seen[request.SessionID] || request.Epoch != discovery.Challenge.Epoch || request.AcquireExpiresAt != discovery.Challenge.ExpiresAt {
			t.Fatal("retired acquisition identity was reused or extended")
		}
		seen[request.SessionID] = true
		// Exactly these three acquisition fields may differ. Every credential,
		// key, selected DNS/source and proposed listener remains original.
		normalized := request.Clone()
		normalized.SessionID = p.source.Request.SessionID
		normalized.Epoch = p.source.Request.Epoch
		normalized.AcquireExpiresAt = p.source.Request.AcquireExpiresAt
		if !reflect.DeepEqual(normalized, p.Request()) || p.Source() != beforeSource || p.Config() != beforeConfig || !reflect.DeepEqual(p.Front(), beforeFront) {
			t.Fatal("fresh discovery silently replanned the original graph")
		}
		request.Users[0].Password = "changed"
		if p.source.Request.Users[0].Password == "changed" {
			t.Fatal("attempt aliases original proposal")
		}
	}
}

func TestNodeChainExecutionFreshAttemptRejectsReplanningOrExpiredDiscovery(t *testing.T) {
	p, err := NewNodeChainExecutionPolicy(startJSON(t, nodeChainExecutionFixtureSource(t, 4, "", "auto")))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for name, mutate := range map[string]func(*NodeChainExecutionDiscovery){
		"entry":   func(d *NodeChainExecutionDiscovery) { d.NodeID = strings.Repeat("a", 64) },
		"peer":    func(d *NodeChainExecutionDiscovery) { d.Challenge.Peer = "10.80.0.3" },
		"expired": func(d *NodeChainExecutionDiscovery) { d.Challenge.ExpiresAt = now.Unix() },
		"extended": func(d *NodeChainExecutionDiscovery) {
			d.Challenge.ExpiresAt = now.Add(time.Minute + time.Second).Unix()
		},
		"missing-epoch":    func(d *NodeChainExecutionDiscovery) { d.Challenge.Epoch = "" },
		"pool-start":       func(d *NodeChainExecutionDiscovery) { d.FirstPort++ },
		"pool-end":         func(d *NodeChainExecutionDiscovery) { d.LastPort++ },
		"missing-source":   func(d *NodeChainExecutionDiscovery) { d.Sources = nil },
		"duplicate-source": func(d *NodeChainExecutionDiscovery) { d.Sources = append(d.Sources, d.Sources[0].Clone()) },
		"replaced-source":  func(d *NodeChainExecutionDiscovery) { d.Sources[0].SourceSHA256 = strings.Repeat("a", 64) },
		"replaced-dns":     func(d *NodeChainExecutionDiscovery) { d.Sources[0].DNSPolicySHA256 = strings.Repeat("a", 64) },
		"changed-member":   func(d *NodeChainExecutionDiscovery) { d.Sources[0].Members[0].ProfileID = "new-member" },
		"changed-key": func(d *NodeChainExecutionDiscovery) {
			d.Sources[0].Members[0].ClientPublicKey = d.Sources[0].Members[0].ServerPublicKey
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := nodeChainExecutionDiscoveryFixture(p, now)
			mutate(&d)
			if _, err := p.newAttemptAt(startJSON(t, d), now); err == nil {
				t.Fatal("changed or expired fresh discovery acquired an attempt")
			}
		})
	}
	d := nodeChainExecutionDiscoveryFixture(p, now)
	raw := startJSON(t, d)
	for _, invalid := range []string{strings.Replace(raw, `"node_id":`, `"unknown":true,"node_id":`, 1), strings.Replace(raw, `"node_id":`, `"node_id":"duplicate","node_id":`, 1)} {
		if _, err := p.newAttemptAt(invalid, now); err == nil {
			t.Fatal("nonexact discovery JSON acquired an attempt")
		}
	}
}
