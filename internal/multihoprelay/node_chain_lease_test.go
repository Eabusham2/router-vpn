//go:build go1.25

package multihoprelay

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestNodeChainLeaseAbsentWorkerNeverFallsBack(t *testing.T) {
	r := &runner{}
	m := nodeChainFixtureManager(t, 3, r)
	defer nodeChainFixtureClose(t, m)
	peer := netip.MustParseAddr("10.77.0.2")
	if c, s, err := m.ChainAvailable(peer); !errors.Is(err, ErrUnavailable) || c != (ExternalPacketChallenge{}) || s != nil {
		t.Fatal("source reference advertised without an ordered worker", c, s, err)
	}
	q := nodeChainFixtureRequestFor(t, m, peer)
	if _, err := m.CreateChain(context.Background(), peer, q); !errors.Is(err, ErrUnavailable) || r.starts != 0 || len(m.leases) != 0 || len(m.chainAttempts) != 0 {
		t.Fatal("ordered acquisition fell back or reserved an unavailable worker", err)
	}
	legacy := req()
	legacy.ExitMode = "node-chain"
	legacy.ExitID = q.SourceSHA256
	if _, err := m.Create(context.Background(), peer, legacy); err == nil || r.starts != 0 {
		t.Fatal("ordinary API accepted an ordered label", err)
	}
	for _, row := range m.Available() {
		if row["exit_mode"] == "node-chain" {
			t.Fatal("ordinary discovery advertised unsupported ordered execution")
		}
	}
}

func TestNodeChainLeaseDiscoveryClonesCompleteSourcesAndPeer(t *testing.T) {
	r := &nodeChainFixtureRunner{}
	cfg := nodeChainFixtureConfig(t, 7)
	m, err := New(cfg, req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("10.77.0.2")
	want := cfg.NodeChains[0].Clone()
	cfg.NodeChains[0].Members[0].ProfileID = "caller-replacement"
	challenge, sources, err := m.ChainAvailable(peer)
	if err != nil || challenge.Validate() != nil || challenge.Peer != peer.String() || challenge.Epoch != m.packetEpoch || len(sources) != 1 || !reflect.DeepEqual(sources[0], want) || len(m.leases) != 0 || len(m.chainAttempts) != 0 || r.count() != 0 {
		t.Fatal("discovery changed source/peer or acquired a process", err)
	}
	sources[0].Members[0].ClientPublicKey = chainCapturePublic(t, 201)
	_, again, err := m.ChainAvailable(peer)
	if err != nil || !reflect.DeepEqual(again[0], want) {
		t.Fatal("discovery returned mutable registry storage", err)
	}
	for _, raw := range []string{"203.0.113.4", "127.0.0.1", "0.0.0.0", "ff02::1", "fd77::2%eth0"} {
		t.Run(raw, func(t *testing.T) {
			if c, s, err := m.ChainAvailable(netip.MustParseAddr(raw)); !errors.Is(err, ErrOwnership) || c != (ExternalPacketChallenge{}) || s != nil {
				t.Fatal("unowned peer received ordered capability", err)
			}
		})
	}
	// PeerKey normalizes the native TCP peer representation. The authenticated
	// wire request below must still carry its exact canonical IPv4 identity.
	mapped, _, err := m.ChainAvailable(netip.MustParseAddr("::ffff:10.77.0.2"))
	if err != nil || mapped.Peer != challenge.Peer || mapped.Epoch != challenge.Epoch {
		t.Fatal("native IPv4-mapped peer acquired a second owner identity", err)
	}
	other, _, err := m.ChainAvailable(peer.Next())
	if err != nil || other.Peer != peer.Next().String() || other.Epoch != challenge.Epoch {
		t.Fatal("discovery borrowed another peer's challenge", err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, s, err := m.ChainAvailable(peer); !errors.Is(err, ErrUnavailable) || c != (ExternalPacketChallenge{}) || s != nil {
		t.Fatal("closed manager advertised ordered runtime", err)
	}
}

func TestNodeChainLeaseCompleteMixedPathsRequireFreshReadyAdoption(t *testing.T) {
	for _, count := range []int{1, 2, 3, 7} {
		for _, entry := range []string{"wg", "awg2-fast", "awg2-strong"} {
			t.Run(fmt.Sprintf("%d/%s", count+1, entry), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					r := &nodeChainFixtureRunner{}
					cfg := nodeChainFixtureConfig(t, count)
					cfg.NodeChains[0].EntryMode = entry
					m, err := New(cfg, req().EntryNodeID, r)
					if err != nil {
						t.Fatal(err)
					}
					defer nodeChainFixtureClose(t, m)
					peer := netip.MustParseAddr("10.77.0.2")
					q := nodeChainFixtureRequestFor(t, m, peer)
					start := time.Now()
					caller, cancel := context.WithCancel(context.Background())
					lease, err := m.CreateChain(caller, peer, q)
					if err != nil {
						t.Fatal(err)
					}
					cancel()
					p := r.worker(t, 0)
					<-p.bootstrap
					if lease.Phase != NodeChainPending || lease.BootstrapDeadline.Sub(start) != 90*time.Second || !time.Now().Equal(start) || !reflect.DeepEqual(lease.Request, q) || !reflect.DeepEqual(lease.Users, q.Users) || lease.Port != q.Port {
						t.Fatal("pending admission waited, changed ownership or changed its 90s deadline")
					}
					status, err := m.ChainStatus(context.Background(), peer, q, strings.Repeat("b", 64))
					if err != nil || status.Receipt.Phase != NodeChainPending || status.Receipt.TrafficAllowed || status.Receipt.DNSProven || status.Receipt.PublicProven || len(status.Receipt.Prefixes) != 0 {
						t.Fatal("pending front was treated as a proved path", err)
					}
					p.ready.Store(true)
					if _, err := m.ChainStatus(context.Background(), peer, q, strings.Repeat("f", 64)); err == nil {
						t.Fatal("receipt bypassed unfinished original Bootstrap")
					}
					p.ready.Store(false)
					p.finish()
					synctest.Wait()
					m.mu.Lock()
					pre := m.chainLeaseLocked(m.leases[peer.String()])
					m.mu.Unlock()
					if pre.Phase != NodeChainPending {
						t.Fatal("bootstrap callback published Ready without current manager admission")
					}
					status, err = m.ChainStatus(context.Background(), peer, q, strings.Repeat("c", 64))
					if err != nil || status.Lease.Phase != NodeChainReady || !status.Receipt.DNSProven || !status.Receipt.PublicProven || len(status.Receipt.Prefixes) != count {
						t.Fatal("complete original proof was not adopted", err)
					}
					for i, row := range status.Receipt.Prefixes {
						member := p.capture.Source.Members[i]
						if row.Position != member.Position || row.ProfileID != member.ProfileID || row.NodeID != member.NodeID || row.Mode != member.Mode || !row.Proven {
							t.Fatal("Ready changed a captured ordered member")
						}
					}
					if status.Receipt.Prefixes[count-1].Mode != "shadowsocks" {
						t.Fatal("final identity or mode was substituted")
					}
					time.Sleep(time.Second)
					renewed, err := m.CreateChain(context.Background(), peer, q)
					if err != nil || renewed.OwnerID != lease.OwnerID || !renewed.BootstrapDeadline.Equal(lease.BootstrapDeadline) || !renewed.ExpiresAt.After(lease.ExpiresAt) || r.count() != 1 || r.ordinaryStarts.Load() != 0 {
						t.Fatal("renewal replaced the complete owner or fell back", err)
					}
					p.mu.Lock()
					owned := p.ctx
					p.mu.Unlock()
					if owned == nil || owned.Err() != nil {
						t.Fatal("HTTP completion canceled the native lease context")
					}
				})
			})
		}
	}
}

func TestNodeChainLeaseStartBootstrapAndStatusReleaseGlobalLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate, seen := make(chan struct{}), make(chan struct{})
		r := &nodeChainFixtureRunner{startGate: gate, startSeen: seen}
		m := nodeChainFixtureManager(t, 3, r)
		defer nodeChainFixtureClose(t, m)
		peer := netip.MustParseAddr("10.77.0.2")
		q := nodeChainFixtureRequestFor(t, m, peer)
		start := time.Now()
		created := make(chan error, 1)
		go func() { _, err := m.CreateChain(context.Background(), peer, q); created <- err }()
		<-seen
		if _, err := m.Create(context.Background(), peer.Next(), nodeChainFixtureOrdinaryRequest(m)); err != nil || !time.Now().Equal(start) {
			t.Fatal("native StartChain held the global lock", err)
		}
		close(gate)
		if err := <-created; err != nil {
			t.Fatal(err)
		}
		p := r.worker(t, 0)
		<-p.bootstrap
		if _, err := m.Create(context.Background(), peer.Next().Next(), nodeChainFixtureOrdinaryRequest(m)); err != nil || !time.Now().Equal(start) {
			t.Fatal("Bootstrap held the global lock", err)
		}
		p.finish()
		synctest.Wait()
		nonce := strings.Repeat("e", 64)
		entered, release := p.block(nonce, false)
		result := make(chan error, 1)
		go func() { _, err := m.ChainStatus(context.Background(), peer, q, nonce); result <- err }()
		<-entered
		if _, err := m.Create(context.Background(), peer.Next().Next().Next(), nodeChainFixtureOrdinaryRequest(m)); err != nil || !time.Now().Equal(start) {
			t.Fatal("Snapshot held the global lock", err)
		}
		close(release)
		if err := <-result; err != nil {
			t.Fatal("same-owner delayed status failed", err)
		}
	})
}

func TestNodeChainLeaseRetainsDetachedFullCapture(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &nodeChainFixtureRunner{mutateInput: true}
		m := nodeChainFixtureManager(t, 7, r)
		defer nodeChainFixtureClose(t, m)
		peer := netip.MustParseAddr("10.77.0.2")
		q := nodeChainFixtureRequestFor(t, m, peer)
		original := q.Clone()
		lease := nodeChainFixtureAcquire(t, m, peer, q)
		p := r.worker(t, 0)
		q.Users[0].Password = strings.Repeat("e", 48)
		q.LocalPacketPublicKeys[0] = chainCapturePublic(t, 201)
		lease.Request.Users[1].Username = strings.Repeat("f", 48)
		lease.Request.LocalPacketPublicKeys[1] = chainCapturePublic(t, 202)
		lease.Users[2].Password = strings.Repeat("d", 48)
		m.mu.Lock()
		active := m.leases[peer.String()]
		captured := active.chain.capture.Clone()
		attempt := m.chainAttempts[nodeChainAttemptKey(peer, original)].request.Clone()
		m.mu.Unlock()
		if !reflect.DeepEqual(captured.Request, original) || !reflect.DeepEqual(p.capture, captured) || !reflect.DeepEqual(attempt, original) {
			t.Fatal("caller, response or runner mutated retained original capture")
		}
		p.finish()
		synctest.Wait()
		status, err := m.ChainStatus(context.Background(), peer, original, strings.Repeat("c", 64))
		if err != nil {
			t.Fatal(err)
		}
		status.Receipt.Prefixes[0].ProfileID = "response-replacement"
		status.Lease.Request.Users[0].Password = "response-replacement"
		again, err := m.ChainStatus(context.Background(), peer, original, strings.Repeat("d", 64))
		if err != nil || again.Receipt.Prefixes[0].ProfileID != captured.Source.Members[0].ProfileID || !reflect.DeepEqual(again.Lease.Request, original) {
			t.Fatal("status response shared retained owner storage", err)
		}
	})
}

func TestNodeChainLeaseWrongCapturedRequestNeverStarts(t *testing.T) {
	for name, mutate := range map[string]func(*NodeChainRequest){
		"schema": func(q *NodeChainRequest) { q.Schema++ }, "session": func(q *NodeChainRequest) { q.SessionID = "old" }, "entry": func(q *NodeChainRequest) { q.EntryNodeID = strings.Repeat("e", 64) },
		"source": func(q *NodeChainRequest) { q.SourceSHA256 = strings.Repeat("e", 64) }, "registry": func(q *NodeChainRequest) { q.DescriptorSHA256 = strings.Repeat("e", 64) }, "dns": func(q *NodeChainRequest) { q.DNSPolicySHA256 = strings.Repeat("e", 64) },
		"epoch": func(q *NodeChainRequest) { q.Epoch = strings.Repeat("e", 64) }, "peer": func(q *NodeChainRequest) { q.Peer = "10.77.0.3" }, "peer-noncanonical": func(q *NodeChainRequest) { q.Peer = "::ffff:10.77.0.2" }, "port-low": func(q *NodeChainRequest) { q.Port = 1023 }, "port-pool": func(q *NodeChainRequest) { q.Port += 8 },
		"expired": func(q *NodeChainRequest) { q.AcquireExpiresAt = time.Now().Unix() }, "extended-window": func(q *NodeChainRequest) {
			q.AcquireExpiresAt = time.Now().Add(packetAcquireLifetime + time.Second).Unix()
		},
		"missing-users": func(q *NodeChainRequest) { q.Users = nil }, "extra-user": func(q *NodeChainRequest) { q.Users = append(q.Users, q.Users[0]) }, "user-position": func(q *NodeChainRequest) { q.Users[0].Position = 2 },
		"same-secrets": func(q *NodeChainRequest) { q.Users[1].Username = q.Users[0].Password }, "missing-local-key": func(q *NodeChainRequest) { q.LocalPacketPublicKeys = q.LocalPacketPublicKeys[1:] }, "duplicate-local-key": func(q *NodeChainRequest) { q.LocalPacketPublicKeys[1] = q.LocalPacketPublicKeys[0] },
		"local-reuses-middle": func(q *NodeChainRequest) { q.LocalPacketPublicKeys[0] = chainCapturePublic(t, 11) }, "local-reuses-server": func(q *NodeChainRequest) { q.LocalPacketPublicKeys[0] = chainCapturePublic(t, 41) },
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &nodeChainFixtureRunner{}
				m := nodeChainFixtureManager(t, 3, r)
				defer nodeChainFixtureClose(t, m)
				q := nodeChainFixtureRequestFor(t, m, netip.MustParseAddr("10.77.0.2"))
				mutate(&q)
				if _, err := m.CreateChain(context.Background(), netip.MustParseAddr("10.77.0.2"), q); err == nil || r.count() != 0 || r.ordinaryStarts.Load() != 0 || len(m.leases) != 0 || len(m.chainAttempts) != 0 {
					t.Fatal("unowned request reached or reserved a worker", err)
				}
			})
		})
	}
}

func TestNodeChainLeaseCannotReplaceAnActiveCapturedRequest(t *testing.T) {
	for name, mutate := range map[string]func(*NodeChainRequest){"session": func(q *NodeChainRequest) { q.SessionID = strings.Repeat("c", 32) }, "port": func(q *NodeChainRequest) { q.Port++ }, "username": func(q *NodeChainRequest) { q.Users[1].Username = strings.Repeat("c", 48) }, "password": func(q *NodeChainRequest) { q.Users[1].Password = strings.Repeat("d", 48) }, "local-key": func(q *NodeChainRequest) { q.LocalPacketPublicKeys[1] = chainCapturePublic(t, 201) }, "acquisition": func(q *NodeChainRequest) { q.AcquireExpiresAt-- }} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &nodeChainFixtureRunner{}
				m := nodeChainFixtureManager(t, 3, r)
				defer nodeChainFixtureClose(t, m)
				peer := netip.MustParseAddr("10.77.0.2")
				q := nodeChainFixtureRequestFor(t, m, peer)
				lease := nodeChainFixtureAcquire(t, m, peer, q)
				p := r.worker(t, 0)
				other := q.Clone()
				mutate(&other)
				if _, err := m.CreateChain(context.Background(), peer, other); !errors.Is(err, ErrBusy) || r.count() != 1 {
					t.Fatal("new request renewed the old owner", err)
				}
				if err := m.DeleteChain(context.Background(), peer, other); !errors.Is(err, ErrOwnership) || !p.Alive() {
					t.Fatal("new request deleted the old owner", err)
				}
				m.mu.Lock()
				same := m.leases[peer.String()].ExpiresAt.Equal(lease.ExpiresAt)
				m.mu.Unlock()
				if !same {
					t.Fatal("foreign request changed the original lease expiry")
				}
			})
		})
	}
}

func TestNodeChainLeaseReplayAndDeleteBeforePutCannotReacquire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &nodeChainFixtureRunner{}
		m := nodeChainFixtureManager(t, 3, r)
		defer nodeChainFixtureClose(t, m)
		peer := netip.MustParseAddr("10.77.0.2")
		q := nodeChainFixtureRequestFor(t, m, peer)
		if err := m.DeleteChain(context.Background(), peer, q); err != nil {
			t.Fatal(err)
		}
		if _, err := m.CreateChain(context.Background(), peer, q); !errors.Is(err, ErrOwnership) || r.count() != 0 {
			t.Fatal("late PUT overtook its retired DELETE", err)
		}
		changed := q.Clone()
		changed.Users[0].Password = strings.Repeat("e", 48)
		if _, err := m.CreateChain(context.Background(), peer, changed); !errors.Is(err, ErrOwnership) || r.count() != 0 {
			t.Fatal("same-session altered credentials bypassed tombstone", err)
		}
		time.Sleep(packetAcquireLifetime + time.Second)
		if _, err := m.CreateChain(context.Background(), peer, q); !errors.Is(err, ErrOwnership) || r.count() != 0 {
			t.Fatal("expired request revived after tombstone expiry", err)
		}
		fresh := nodeChainFixtureRequestFor(t, m, peer)
		fresh.SessionID = strings.Repeat("c", 32)
		if _, err := m.CreateChain(context.Background(), peer.Next(), fresh); !errors.Is(err, ErrOwnership) {
			t.Fatal("request crossed authenticated peers", err)
		}
		restarted := nodeChainFixtureManager(t, 3, r)
		defer nodeChainFixtureClose(t, restarted)
		if _, err := restarted.CreateChain(context.Background(), peer, fresh); !errors.Is(err, ErrOwnership) || r.count() != 0 {
			t.Fatal("old epoch survived manager restart", err)
		}
		lease := nodeChainFixtureAcquire(t, m, peer, fresh)
		if err := m.DeleteChain(context.Background(), peer, fresh); err != nil {
			t.Fatal(err)
		}
		if _, err := m.CreateChain(context.Background(), peer, fresh); !errors.Is(err, ErrOwnership) || r.count() != 1 {
			t.Fatal("joined owner was replayed", err)
		}
		fresh.SessionID = strings.Repeat("d", 32)
		next := nodeChainFixtureAcquire(t, m, peer, fresh)
		if next.OwnerID == lease.OwnerID || r.count() != 2 {
			t.Fatal("new attempt borrowed the retired owner")
		}
	})
}

func TestNodeChainLeaseCanceledLateStartRetainsUntilJoined(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate, seen := make(chan struct{}), make(chan struct{})
		r := &nodeChainFixtureRunner{startGate: gate, startSeen: seen, ignoreStart: true}
		cfg := nodeChainFixtureConfig(t, 3)
		cfg.LastPort = cfg.FirstPort
		m, err := New(cfg, req().EntryNodeID, r)
		if err != nil {
			t.Fatal(err)
		}
		defer nodeChainFixtureClose(t, m)
		peer := netip.MustParseAddr("10.77.0.2")
		q := nodeChainFixtureRequestFor(t, m, peer)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { _, err := m.CreateChain(ctx, peer, q); result <- err }()
		<-seen
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatal("canceled late start returned ownership", err)
		}
		m.mu.Lock()
		active := m.leases[peer.String()]
		retained := active != nil && active.retired && active.chain.Alive()
		m.mu.Unlock()
		if !retained {
			t.Fatal("unjoined late start released original ownership")
		}
		if _, err := m.Create(context.Background(), peer.Next(), nodeChainFixtureOrdinaryRequest(m)); err == nil || r.ordinaryStarts.Load() != 0 {
			t.Fatal("unjoined startup port was reused", err)
		}
		close(gate)
		synctest.Wait()
		p := r.worker(t, 0)
		if p.Alive() || p.stops.Load() == 0 {
			t.Fatal("late returned process escaped original cleanup")
		}
		if err := m.Sweep(context.Background()); err != nil || len(m.leases) != 0 {
			t.Fatal("joined late process did not release reservation", err)
		}
		if _, err := m.CreateChain(context.Background(), peer, q); !errors.Is(err, ErrOwnership) {
			t.Fatal("cancelled request replayed", err)
		}
	})
}

func TestNodeChainLeaseStartHasIndependentEightSecondLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate, seen := make(chan struct{}), make(chan struct{})
		r := &nodeChainFixtureRunner{startGate: gate, startSeen: seen, ignoreStart: true}
		m := nodeChainFixtureManager(t, 3, r)
		defer nodeChainFixtureClose(t, m)
		peer := netip.MustParseAddr("10.77.0.2")
		q := nodeChainFixtureRequestFor(t, m, peer)
		result := make(chan error, 1)
		go func() { _, err := m.CreateChain(context.Background(), peer, q); result <- err }()
		<-seen
		time.Sleep(8*time.Second + time.Millisecond)
		synctest.Wait()
		m.mu.Lock()
		owner := m.leases[peer.String()].chain
		m.mu.Unlock()
		if owner.ctx.Err() == nil {
			t.Fatal("start exceeded the unchanged eight-second bound")
		}
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("expired original StartChain returned usable ownership")
			}
		default:
			close(gate)
			t.Fatal("original startup cancellation did not bound the pending acquisition")
		}
		if !owner.Alive() || r.worker(t, 0).stops.Load() != 0 {
			t.Fatal("unjoined startup was prematurely released")
		}
		close(gate)
		synctest.Wait()
		if p := r.worker(t, 0); p.Alive() || p.stops.Load() == 0 {
			t.Fatal("expired StartChain escaped cleanup")
		}
	})
}

func TestNodeChainLeaseRenewalCannotExtendNinetySecondBootstrap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &nodeChainFixtureRunner{}
		m := nodeChainFixtureManager(t, 3, r)
		defer nodeChainFixtureClose(t, m)
		peer := netip.MustParseAddr("10.77.0.2")
		q := nodeChainFixtureRequestFor(t, m, peer)
		start := time.Now()
		lease := nodeChainFixtureAcquire(t, m, peer, q)
		p := r.worker(t, 0)
		<-p.bootstrap
		for range 2 {
			time.Sleep(30 * time.Second)
			renewed, err := m.CreateChain(context.Background(), peer, q)
			if err != nil || renewed.OwnerID != lease.OwnerID || !renewed.BootstrapDeadline.Equal(start.Add(90*time.Second)) || !renewed.ExpiresAt.After(lease.ExpiresAt) {
				t.Fatal("renewal changed owner or absolute deadline", err)
			}
		}
		time.Sleep(30*time.Second + time.Millisecond)
		synctest.Wait()
		if p.Alive() || p.stops.Load() == 0 {
			t.Fatal("absolute 90s bootstrap did not cancel and join")
		}
		if err := m.Sweep(context.Background()); err != nil || len(m.leases) != 0 {
			t.Fatal("confirmed drained bootstrap remained reserved", err)
		}
		if _, err := m.CreateChain(context.Background(), peer, q); !errors.Is(err, ErrOwnership) {
			t.Fatal("expired bootstrap replayed", err)
		}
	})
}

func TestNodeChainLeaseLateBootstrapCannotPassDelayedTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &nodeChainFixtureRunner{}
		m := nodeChainFixtureManager(t, 3, r)
		defer nodeChainFixtureClose(t, m)
		peer := netip.MustParseAddr("10.77.0.2")
		q := nodeChainFixtureRequestFor(t, m, peer)
		nodeChainFixtureAcquire(t, m, peer, q)
		p := r.worker(t, 0)
		<-p.bootstrap
		m.mu.Lock()
		owner := m.leases[peer.String()].chain
		m.mu.Unlock()
		owner.mu.Lock()
		owner.bootstrapTimer.Stop()
		owner.mu.Unlock()
		time.Sleep(90*time.Second + time.Millisecond)
		p.finish()
		synctest.Wait()
		if p.Alive() || p.stops.Load() == 0 {
			t.Fatal("late complete proof passed independent absolute deadline")
		}
		if _, err := m.ChainStatus(context.Background(), peer, q, strings.Repeat("e", 64)); err == nil {
			t.Fatal("expired proof became Ready")
		}
	})
}

func TestNodeChainLeaseReadyKeepsOriginalContextUntilStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &nodeChainFixtureRunner{}
		m := nodeChainFixtureManager(t, 3, r)
		defer nodeChainFixtureClose(t, m)
		peer := netip.MustParseAddr("10.77.0.2")
		q := nodeChainFixtureRequestFor(t, m, peer)
		nodeChainFixtureAcquire(t, m, peer, q)
		p := r.worker(t, 0)
		<-p.bootstrap
		p.finish()
		synctest.Wait()
		if _, err := m.ChainStatus(context.Background(), peer, q, strings.Repeat("e", 64)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(91 * time.Second)
		p.mu.Lock()
		owned := p.ctx
		p.mu.Unlock()
		if owned == nil || owned.Err() != nil || !p.Alive() {
			t.Fatal("successful admission kept a bootstrap cancellation timer")
		}
		if _, err := m.CreateChain(context.Background(), peer, q); err != nil {
			t.Fatal("ready original could not renew after acquisition window", err)
		}
		if err := m.DeleteChain(context.Background(), peer, q); err != nil || owned.Err() == nil || p.Alive() {
			t.Fatal("Stop did not revoke and join original context", err)
		}
	})
}

func TestNodeChainLeaseDelayedStatusRechecksCompleteRegistry(t *testing.T) {
	for _, fault := range []string{"dns", "entry-mode", "member-mode", "middle-key", "order", "final-proof", "removed"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &nodeChainFixtureRunner{}
				m := nodeChainFixtureManager(t, 3, r)
				defer nodeChainFixtureClose(t, m)
				peer := netip.MustParseAddr("10.77.0.2")
				q := nodeChainFixtureRequestFor(t, m, peer)
				lease := nodeChainFixtureAcquire(t, m, peer, q)
				p := r.worker(t, 0)
				p.finish()
				synctest.Wait()
				nonce := strings.Repeat("e", 64)
				entered, release := p.block(nonce, false)
				result := make(chan error, 1)
				go func() { _, err := m.chainStatus(context.Background(), peer, q, nonce, true); result <- err }()
				<-entered
				m.mu.Lock()
				s := &m.cfg.NodeChains[0]
				switch fault {
				case "dns":
					s.DNSPolicySHA256 = strings.Repeat("e", 64)
				case "entry-mode":
					s.EntryMode = "awg2-strong"
				case "member-mode":
					s.Members[0].Mode = "awg2-strong"
				case "middle-key":
					s.Members[0].ClientPublicKey = chainCapturePublic(t, 201)
				case "order":
					s.Members[0], s.Members[1] = s.Members[1], s.Members[0]
					s.Members[0].Position, s.Members[1].Position = 1, 2
				case "final-proof":
					s.Members[2].NodeID = strings.Repeat("e", 64)
				case "removed":
					m.cfg.NodeChains = nil
				}
				m.mu.Unlock()
				close(release)
				if err := <-result; !errors.Is(err, ErrOwnership) {
					t.Fatal("late proof adopted a changed full registry", err)
				}
				m.mu.Lock()
				same := m.leases[peer.String()].ExpiresAt.Equal(lease.ExpiresAt)
				m.mu.Unlock()
				if !same {
					t.Fatal("stale proof renewed expiry")
				}
				if err := m.DeleteChain(context.Background(), peer, q); err != nil || p.Alive() {
					t.Fatal("registry change prevented original-owner cleanup", err)
				}
			})
		})
	}
}

func TestNodeChainLeaseLateStatusCannotMutateReplacementOrNewerProof(t *testing.T) {
	for _, fault := range []string{"replacement", "newer-sequence", "canceled-caller"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &nodeChainFixtureRunner{}
				m := nodeChainFixtureManager(t, 3, r)
				defer nodeChainFixtureClose(t, m)
				peer := netip.MustParseAddr("10.77.0.2")
				q := nodeChainFixtureRequestFor(t, m, peer)
				lease := nodeChainFixtureAcquire(t, m, peer, q)
				p := r.worker(t, 0)
				p.finish()
				synctest.Wait()
				if _, err := m.ChainStatus(context.Background(), peer, q, strings.Repeat("d", 64)); err != nil {
					t.Fatal(err)
				}
				nonce := strings.Repeat("e", 64)
				entered, release := p.block(nonce, false)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				result := make(chan error, 1)
				go func() { _, err := m.chainStatus(ctx, peer, q, nonce, true); result <- err }()
				<-entered
				switch fault {
				case "replacement":
					if err := m.DeleteChain(context.Background(), peer, q); err != nil {
						t.Fatal(err)
					}
					q.SessionID = strings.Repeat("c", 32)
					lease = nodeChainFixtureAcquire(t, m, peer, q)
				case "newer-sequence":
					if _, err := m.ChainStatus(context.Background(), peer, q, strings.Repeat("f", 64)); err != nil {
						t.Fatal(err)
					}
				case "canceled-caller":
					cancel()
				}
				close(release)
				if err := <-result; err == nil {
					t.Fatal("late stale status adopted")
				}
				m.mu.Lock()
				active := m.leases[peer.String()]
				same := active != nil && active.chain.capture.OwnerID == lease.OwnerID && !active.retired && active.ExpiresAt.Equal(lease.ExpiresAt)
				m.mu.Unlock()
				if !same {
					t.Fatal("late callback changed current owner or expiry")
				}
				if fault == "replacement" {
					if !r.worker(t, 1).Alive() {
						t.Fatal("late callback stopped replacement")
					}
				} else if !p.Alive() {
					t.Fatal("discarding stale request retired healthy original")
				}
			})
		})
	}
}

func TestNodeChainLeaseProofLossRetiresOnlyOriginalWorker(t *testing.T) {
	for _, fault := range []string{"bootstrap-unproved", "dns", "public", "middle", "final", "capture", "sequence-replay", "status-timeout"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &nodeChainFixtureRunner{}
				m := nodeChainFixtureManager(t, 3, r)
				defer nodeChainFixtureClose(t, m)
				peer := netip.MustParseAddr("10.77.0.2")
				q := nodeChainFixtureRequestFor(t, m, peer)
				nodeChainFixtureAcquire(t, m, peer, q)
				p := r.worker(t, 0)
				if fault == "bootstrap-unproved" {
					p.mu.Lock()
					p.transform = func(r *NodeChainReceipt) {
						if r.Phase == NodeChainReady {
							r.Prefixes[1].Proven = false
						}
					}
					p.mu.Unlock()
				}
				p.finish()
				synctest.Wait()
				var sequence uint64
				if fault != "bootstrap-unproved" {
					status, err := m.ChainStatus(context.Background(), peer, q, strings.Repeat("d", 64))
					if err != nil {
						t.Fatal(err)
					}
					sequence = status.Receipt.Sequence
				}
				if _, err := m.Create(context.Background(), peer.Next(), nodeChainFixtureOrdinaryRequest(m)); err != nil {
					t.Fatal(err)
				}
				m.mu.Lock()
				other := m.leases[peer.Next().String()].p
				m.mu.Unlock()
				p.mu.Lock()
				switch fault {
				case "dns":
					p.transform = func(r *NodeChainReceipt) { r.DNSProven = false }
				case "public":
					p.transform = func(r *NodeChainReceipt) { r.PublicProven = false }
				case "middle":
					p.transform = func(r *NodeChainReceipt) { r.Prefixes[1].ProfileID = "replacement" }
				case "final":
					p.transform = func(r *NodeChainReceipt) { r.Prefixes[2].NodeID = strings.Repeat("e", 64) }
				case "capture":
					p.transform = func(r *NodeChainReceipt) { r.CaptureSHA256 = strings.Repeat("e", 64) }
				case "sequence-replay":
					p.transform = func(r *NodeChainReceipt) { r.Sequence = sequence }
				}
				p.mu.Unlock()
				nonce := strings.Repeat("e", 64)
				if fault == "status-timeout" {
					p.block(nonce, true)
				}
				start := time.Now()
				if _, err := m.ChainStatus(context.Background(), peer, q, nonce); err == nil {
					t.Fatal("incomplete or repeated proof was adopted")
				}
				if fault == "status-timeout" && time.Since(start) != time.Second {
					t.Fatal("status exceeded unchanged one-second limit")
				}
				synctest.Wait()
				if fault == "sequence-replay" {
					if !p.Alive() {
						t.Fatal("older sequence was treated as a new native failure")
					}
				} else if p.Alive() {
					t.Fatal("proof loss left original worker live")
				}
				if !other.Alive() {
					t.Fatal("ordered proof loss stopped an unrelated peer")
				}
			})
		})
	}
}

func TestNodeChainLeaseFailedStopRetainsFullOwnerAndPort(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &nodeChainFixtureRunner{}
		m := nodeChainFixtureManager(t, 3, r)
		defer nodeChainFixtureClose(t, m)
		peer := netip.MustParseAddr("10.77.0.2")
		q := nodeChainFixtureRequestFor(t, m, peer)
		nodeChainFixtureAcquire(t, m, peer, q)
		p := r.worker(t, 0)
		p.stopFail.Store(true)
		m.mu.Lock()
		before := m.leases[peer.String()]
		capture := before.chain.capture.Clone()
		pins := append([]string(nil), before.packetPins...)
		m.mu.Unlock()
		if err := m.DeleteChain(context.Background(), peer, q); err == nil {
			t.Fatal("failed native Stop was reported drained")
		}
		synctest.Wait()
		m.mu.Lock()
		after := m.leases[peer.String()]
		retained := after == before && after.retired && reflect.DeepEqual(after.chain.capture, capture) && reflect.DeepEqual(after.packetPins, pins) && after.chain.Alive()
		m.mu.Unlock()
		if !retained || !p.Alive() {
			t.Fatal("failed Stop lost its complete original ownership")
		}
		if _, err := m.CreateChain(context.Background(), peer, q); err == nil {
			t.Fatal("failed cleanup permitted exact renewal")
		}
		if _, err := m.Create(context.Background(), peer.Next(), nodeChainFixtureOrdinaryRequest(m)); err == nil || r.ordinaryStarts.Load() != 0 {
			t.Fatal("failed cleanup allowed another owner past retained inventory", err)
		}
		p.stopFail.Store(false)
		if err := m.DeleteChain(context.Background(), peer, q); err != nil || p.Alive() || len(m.leases) != 0 {
			t.Fatal("exact failed-cleanup retry did not release owner", err)
		}
	})
}

func TestNodeChainLeaseCanonicalPacketOwnershipAcrossFamilies(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "max-quic-wg", "max-quic-awg"} {
		for _, pin := range []string{"middle", "local"} {
			for _, direction := range []string{"ordered-first", "ordinary-first"} {
				t.Run(mode+"/"+pin+"/"+direction, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						seed := byte(11)
						if pin == "local" {
							seed = 71
						}
						exit := nodeChainFixturePacketExit(t, mode, seed, true)
						canonical, err := clientIdentity(relayPacketTransport(exit))
						if err != nil || canonical != chainCapturePublic(t, seed) {
							t.Fatal("fixture did not create an actual canonical private-key alias", err)
						}
						cfg := nodeChainFixtureConfig(t, 3)
						cfg.Exits = []Exit{exit}
						r := &nodeChainFixtureRunner{}
						m, err := New(cfg, req().EntryNodeID, r)
						if err != nil {
							t.Fatal(err)
						}
						defer nodeChainFixtureClose(t, m)
						peer, other := netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3")
						q := nodeChainFixtureRequestFor(t, m, peer)
						q.Port++
						ordinary := identityRequest(exit.ID, exit.Mode)
						if direction == "ordered-first" {
							nodeChainFixtureAcquire(t, m, peer, q)
							p := r.worker(t, 0)
							if _, err := m.Create(context.Background(), other, ordinary); err == nil || r.ordinaryStarts.Load() != 0 || !p.Alive() {
								t.Fatal("ordinary family stole an ordered canonical packet identity", err)
							}
							if err := m.DeleteChain(context.Background(), peer, q); err != nil {
								t.Fatal(err)
							}
							if _, err := m.Create(context.Background(), other, ordinary); err != nil {
								t.Fatal("confirmed ordered stop retained canonical packet key", err)
							}
						} else {
							if _, err := m.Create(context.Background(), other, ordinary); err != nil {
								t.Fatal(err)
							}
							if _, err := m.CreateChain(context.Background(), peer, q); err == nil || r.count() != 0 {
								t.Fatal("ordered path stole an ordinary canonical packet identity", err)
							}
							if err := m.Delete(context.Background(), other, ordinary); err != nil {
								t.Fatal(err)
							}
							nodeChainFixtureAcquire(t, m, peer, q)
						}
					})
				})
			}
		}
	}
}

func TestNodeChainLeasePacketPinsSurviveRegistryChangeAndFailedStop(t *testing.T) {
	for _, direction := range []string{"ordered-first", "ordinary-first"} {
		t.Run(direction, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				exit := nodeChainFixturePacketExit(t, "awg2-strong", 11, true)
				cfg := nodeChainFixtureConfig(t, 3)
				cfg.Exits = []Exit{exit}
				r := &nodeChainFixtureRunner{}
				m, err := New(cfg, req().EntryNodeID, r)
				if err != nil {
					t.Fatal(err)
				}
				defer nodeChainFixtureClose(t, m)
				peer, other := netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3")
				q := nodeChainFixtureRequestFor(t, m, peer)
				q.Port++
				ordinary := identityRequest(exit.ID, exit.Mode)
				if direction == "ordered-first" {
					nodeChainFixtureAcquire(t, m, peer, q)
					p := r.worker(t, 0)
					m.mu.Lock()
					m.cfg.NodeChains[0].Members[0].ClientPublicKey = chainCapturePublic(t, 201)
					m.mu.Unlock()
					if _, err := m.Create(context.Background(), other, ordinary); err == nil || r.ordinaryStarts.Load() != 0 {
						t.Fatal("changed registry erased captured ordered key", err)
					}
					p.stopFail.Store(true)
					if err := m.DeleteChain(context.Background(), peer, q); err == nil {
						t.Fatal("failed stop released original key")
					}
					if _, err := m.Create(context.Background(), other, ordinary); err == nil || r.ordinaryStarts.Load() != 0 {
						t.Fatal("failed stop erased captured ordered key", err)
					}
					p.stopFail.Store(false)
					if err := m.DeleteChain(context.Background(), peer, q); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := m.Create(context.Background(), other, ordinary); err != nil {
						t.Fatal(err)
					}
					m.mu.Lock()
					m.cfg.Exits[0] = nodeChainFixturePacketExit(t, "awg2-strong", 201, false)
					m.mu.Unlock()
					if _, err := m.CreateChain(context.Background(), peer, q); err == nil || r.count() != 0 {
						t.Fatal("changed registry erased captured ordinary key", err)
					}
					r.mu.Lock()
					p := r.ordinary[0]
					r.mu.Unlock()
					p.stopFail.Store(true)
					if err := m.Delete(context.Background(), other, ordinary); err == nil {
						t.Fatal("failed ordinary stop released captured key")
					}
					if _, err := m.CreateChain(context.Background(), peer, q); err == nil || r.count() != 0 {
						t.Fatal("failed ordinary close released captured key", err)
					}
					p.stopFail.Store(false)
					if err := m.Delete(context.Background(), other, ordinary); err != nil {
						t.Fatal(err)
					}
					nodeChainFixtureAcquire(t, m, peer, q)
				}
			})
		})
	}
}

func TestNodeChainLeasePortDiscoveryKeepsOriginalCustomBounds(t *testing.T) {
	for _, kind := range []string{"available", "absent-worker", "empty-registry", "closed"} {
		t.Run(kind, func(t *testing.T) {
			cfg := nodeChainFixtureConfig(t, 3)
			cfg.FirstPort, cfg.LastPort = 35110, 35113
			var r Runner = &nodeChainFixtureRunner{}
			if kind == "absent-worker" {
				r = &runner{}
			}
			if kind == "empty-registry" {
				cfg.NodeChains = nil
			}
			m, err := New(cfg, req().EntryNodeID, r)
			if err != nil {
				t.Fatal(err)
			}
			defer nodeChainFixtureClose(t, m)
			if kind == "closed" {
				if err := m.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			cfg.FirstPort, cfg.LastPort = 45110, 45113
			first, last, err := m.ChainPortRange(netip.MustParseAddr("10.77.0.2"))
			if kind == "available" {
				if err != nil || first != 35110 || last != 35113 {
					t.Fatal("port discovery lost original immutable configuration", first, last, err)
				}
			} else if !errors.Is(err, ErrUnavailable) || first != 0 || last != 0 {
				t.Fatal("unavailable owner exposed port capability", first, last, err)
			}
			if len(m.leases) != 0 || len(m.chainAttempts) != 0 {
				t.Fatal("port discovery reserved ownership")
			}
		})
	}
	for _, raw := range []string{"203.0.113.4", "127.0.0.1", "0.0.0.0", "ff02::1", "fd77::2%eth0"} {
		t.Run("peer/"+raw, func(t *testing.T) {
			m := nodeChainFixtureManager(t, 3, &nodeChainFixtureRunner{})
			defer nodeChainFixtureClose(t, m)
			if first, last, err := m.ChainPortRange(netip.MustParseAddr(raw)); !errors.Is(err, ErrOwnership) || first != 0 || last != 0 {
				t.Fatal("unowned peer learned usable ordered port range", first, last, err)
			}
		})
	}
	for _, port := range []int{35109, 35110, 35113, 35114} {
		t.Run(fmt.Sprintf("create/%d", port), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &nodeChainFixtureRunner{}
				cfg := nodeChainFixtureConfig(t, 3)
				cfg.FirstPort, cfg.LastPort = 35110, 35113
				m, err := New(cfg, req().EntryNodeID, r)
				if err != nil {
					t.Fatal(err)
				}
				defer nodeChainFixtureClose(t, m)
				peer := netip.MustParseAddr("10.77.0.2")
				q := nodeChainFixtureRequestFor(t, m, peer)
				q.Port = port
				lease, err := m.CreateChain(context.Background(), peer, q)
				if port < 35110 || port > 35113 {
					if !errors.Is(err, ErrOwnership) || r.count() != 0 || len(m.leases) != 0 {
						t.Fatal("request escaped configured port range", err)
					}
				} else if err != nil || lease.Port != port || r.count() != 1 {
					t.Fatal("exact boundary port was not retained", err)
				}
			})
		})
	}
}

func TestNodeChainLeaseInitialAdmissionRechecksOriginalSource(t *testing.T) {
	for _, fault := range []string{"dns", "middle-key", "removed", "caller-storage"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				gate, seen := make(chan struct{}), make(chan struct{})
				r := &nodeChainFixtureRunner{startGate: gate, startSeen: seen}
				m := nodeChainFixtureManager(t, 3, r)
				defer nodeChainFixtureClose(t, m)
				peer := netip.MustParseAddr("10.77.0.2")
				q := nodeChainFixtureRequestFor(t, m, peer)
				original := q.Clone()
				result := make(chan error, 1)
				go func() { _, err := m.CreateChain(context.Background(), peer, q); result <- err }()
				<-seen
				if fault == "caller-storage" {
					q.Users[0].Password = strings.Repeat("e", 48)
					q.LocalPacketPublicKeys[0] = chainCapturePublic(t, 201)
				} else {
					m.mu.Lock()
					switch fault {
					case "dns":
						m.cfg.NodeChains[0].DNSPolicySHA256 = strings.Repeat("e", 64)
					case "middle-key":
						m.cfg.NodeChains[0].Members[0].ClientPublicKey = chainCapturePublic(t, 201)
					case "removed":
						m.cfg.NodeChains = nil
					}
					m.mu.Unlock()
				}
				close(gate)
				err := <-result
				synctest.Wait()
				p := r.worker(t, 0)
				if fault == "caller-storage" {
					if err != nil || !p.Alive() || !reflect.DeepEqual(p.capture.Request, original) {
						t.Fatal("caller mutation changed pending capture", err)
					}
					if err := m.DeleteChain(context.Background(), peer, original); err != nil {
						t.Fatal(err)
					}
				} else if err == nil || p.Alive() {
					t.Fatal("initial admission published changed original source", err)
				}
				if r.ordinaryStarts.Load() != 0 {
					t.Fatal("initial source failure fell back")
				}
			})
		})
	}
}

func TestNodeChainLeaseSameSourceDoesNotSharePacketOwnership(t *testing.T) {
	for _, count := range []int{1, 3} {
		for _, independentLocal := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/local-independent-%t", count+1, independentLocal), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					r := &nodeChainFixtureRunner{}
					m := nodeChainFixtureManager(t, count, r)
					defer nodeChainFixtureClose(t, m)
					peer := netip.MustParseAddr("10.77.0.2")
					q := nodeChainFixtureRequestFor(t, m, peer)
					first := nodeChainFixtureAcquire(t, m, peer, q)
					other := nodeChainFixtureRequestFor(t, m, peer.Next())
					other.SessionID = strings.Repeat("c", 32)
					other.Port++
					for i := range other.Users {
						other.Users[i].Username = fmt.Sprintf("%048x", 500+i*2)
						other.Users[i].Password = fmt.Sprintf("%048x", 501+i*2)
						if independentLocal {
							other.LocalPacketPublicKeys[i] = chainCapturePublic(t, byte(201+i))
						}
					}
					second, err := m.CreateChain(context.Background(), peer.Next(), other)
					// A SS-only suffix may serve two independent entry packet owners. A
					// middle WG/AWG credential remains one roaming owner even if all local
					// keys and front credentials are independent.
					if count == 1 && independentLocal {
						if err != nil || second.OwnerID == first.OwnerID || second.Port == first.Port || reflect.DeepEqual(second.Users, first.Users) || r.count() != 2 {
							t.Fatal("independent owners were merged", err)
						}
					} else if err == nil || r.count() != 1 || !r.worker(t, 0).Alive() {
						t.Fatal("same source shared an original packet owner", err)
					}
				})
			})
		}
	}
}

func TestNodeChainLeaseOrdinaryEndpointsCannotRenewOrDeleteTypedOwner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &nodeChainFixtureRunner{}
		m := nodeChainFixtureManager(t, 3, r)
		defer nodeChainFixtureClose(t, m)
		peer := netip.MustParseAddr("10.77.0.2")
		q := nodeChainFixtureRequestFor(t, m, peer)
		lease := nodeChainFixtureAcquire(t, m, peer, q)
		p := r.worker(t, 0)
		m.mu.Lock()
		legacy := m.leases[peer.String()].Request
		m.mu.Unlock()
		if _, err := m.Create(context.Background(), peer, legacy); err == nil || r.ordinaryStarts.Load() != 0 {
			t.Fatal("ordinary API renewed a typed ordered owner", err)
		}
		if err := m.Delete(context.Background(), peer, legacy); err == nil || !p.Alive() {
			t.Fatal("ordinary API deleted a typed ordered owner", err)
		}
		m.mu.Lock()
		same := m.leases[peer.String()].chain.capture.OwnerID == lease.OwnerID && !m.leases[peer.String()].retired
		m.mu.Unlock()
		if !same {
			t.Fatal("ordinary endpoint changed the typed owner")
		}
	})
}

func TestNodeChainLeaseStartupFailureNeverFallsBackOrLosesPartialOwner(t *testing.T) {
	for _, fault := range []string{"start-error", "start-error-stop-fails", "front-unproved", "front-wrong-capture", "front-already-ready"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &nodeChainFixtureRunner{}
				switch fault {
				case "start-error", "start-error-stop-fails":
					r.startErr = errors.New("controlled private credential must not escape")
				case "front-unproved":
					r.configure = func(p *nodeChainFixtureProcess) { p.transform = func(r *NodeChainReceipt) { r.FrontReady = false } }
				case "front-wrong-capture":
					r.configure = func(p *nodeChainFixtureProcess) {
						p.transform = func(r *NodeChainReceipt) { r.CaptureSHA256 = strings.Repeat("e", 64) }
					}
				case "front-already-ready":
					r.configure = func(p *nodeChainFixtureProcess) { p.ready.Store(true) }
				}
				if fault == "start-error-stop-fails" {
					r.configure = func(p *nodeChainFixtureProcess) { p.stopFail.Store(true) }
				}
				m := nodeChainFixtureManager(t, 3, r)
				defer nodeChainFixtureClose(t, m)
				peer := netip.MustParseAddr("10.77.0.2")
				q := nodeChainFixtureRequestFor(t, m, peer)
				_, err := m.CreateChain(context.Background(), peer, q)
				if err == nil || strings.Contains(err.Error(), "private credential") || r.ordinaryStarts.Load() != 0 || r.count() != 1 {
					t.Fatal("failed startup returned usable ownership, leaked detail or fell back", err)
				}
				synctest.Wait()
				p := r.worker(t, 0)
				if fault == "start-error-stop-fails" {
					m.mu.Lock()
					active := m.leases[peer.String()]
					retained := active != nil && active.retired && active.chain.capture.Request.Port == q.Port && active.chain.Alive()
					m.mu.Unlock()
					if !retained || !p.Alive() {
						t.Fatal("partially started unjoined worker lost ownership")
					}
					if _, err := m.Create(context.Background(), peer.Next(), nodeChainFixtureOrdinaryRequest(m)); err == nil || r.ordinaryStarts.Load() != 0 {
						t.Fatal("partial cleanup failure permitted fallback/replacement", err)
					}
					p.stopFail.Store(false)
					if err := m.DeleteChain(context.Background(), peer, q); err != nil {
						t.Fatal(err)
					}
				} else if p.Alive() || len(m.leases) != 0 {
					t.Fatal("failed original startup was not joined")
				}
			})
		})
	}
}
