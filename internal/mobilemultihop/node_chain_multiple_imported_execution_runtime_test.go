package mobilemultihop

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
	"time"
)

// These are explicit native-owner/routing/DNS/worker doubles. Private HTTP,
// distinct original public TLS responses, Manager leases and routechoice run.
func (e *nodeChainExecutionRuntimeEngine) ObserveMultipleImportedExecutionContext(ctx context.Context, original *NodeChain) error {
	if ctx == nil || ctx.Err() != nil || e.projection == nil || e.projection.preparation.multiple == nil || original != e.projection.preparation.multiple.source {
		return nodeChainExecutionError
	}
	e.mu.Lock()
	alive := e.alive
	e.mu.Unlock()
	if !alive {
		return nodeChainExecutionError
	}
	return original.validateCapture()
}
func (e *nodeChainExecutionRuntimeEngine) MultipleImportedExecutionRetiredContext(ctx context.Context, original *NodeChain) error {
	if ctx == nil || ctx.Err() != nil || e.projection == nil || e.projection.preparation.multiple == nil || original != e.projection.preparation.multiple.source || original.validateCapture() != nil {
		return nodeChainExecutionError
	}
	e.mu.Lock()
	closed := !e.alive && !e.open
	e.mu.Unlock()
	if !closed {
		return errors.New("original native multiple-import fixture has not joined")
	}
	return ctx.Err()
}
func multipleImportedExecutionPublicFixtures(t *testing.T, f *nodeChainExecutionRuntimeFixture, local, server []NodeChainProof, trust *tls.Config) {
	t.Helper()
	for position, proof := range local {
		expected, public := f.engine.projection.policy.local.importedPublicIPAt(position)
		if !public {
			continue
		}
		endpoint, _ := nodeChainExecutionRuntimeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.Host != "1.1.1.1" || r.URL.Path != "/cdn-cgi/trace" || len(r.URL.Query().Get("routervpn_proof")) != 32 || r.Header.Get("Authorization") != "" {
				http.Error(w, "foreign public proof", 400)
				return
			}
			f.engine.mu.Lock()
			body := "ip=" + expected + "\n"
			if f.engine.wrongPrefix == position {
				body = "ip=198.51.100.251\n"
			}
			f.engine.publicCalls = append(f.engine.publicCalls, f.engine.selected+"/"+proof.ProfileID)
			f.engine.mu.Unlock()
			_, _ = w.Write([]byte(body))
		}))
		trust.RootCAs.AddCert(endpoint.Certificate())
		f.engine.peers[proof.Tag+"/1.1.1.1:443"] = endpoint.Listener.Addr().String()
		f.engine.peers[server[position].Tag+"/1.1.1.1:443"] = endpoint.Listener.Addr().String()
	}
}
func multipleImportedExecutionRuntimeFixture(t *testing.T, layout nodeChainImportedLayout, execution string) *nodeChainExecutionRuntimeFixture {
	t.Helper()
	_, prep, source := multipleImportedExecutionFixture(t, layout, "wg", "", execution, "")
	return newNodeChainExecutionRuntimeFixtureFromPreparation(t, source, prep)
}
func assertMultipleImportedExecutionProgress(t *testing.T, f *nodeChainExecutionRuntimeFixture) {
	t.Helper()
	p := f.runtime.Progress()
	if !p.Ready || !p.Complete || !p.DNSProven || !p.PublicProven || len(p.Prefixes) != len(f.runtime.projection.policy.local.nodes) {
		t.Fatal("incomplete selected proof", p)
	}
	for position, row := range p.Prefixes {
		if f.runtime.projection.policy.importedPublicAt(position) {
			if row.Kind != "public-path" || row.Label != nodeChainMultipleImportedExecutionPublicLabel {
				t.Fatal("imported proof falsely private", row)
			}
		} else if row.Kind == "public-path" {
			t.Fatal("private proof falsely public", row)
		}
	}
}
func TestNodeChainMultipleImportedExecutionRuntimeServer(t *testing.T) {
	for _, index := range []int{1, 2, 4, 5, 6, 7} {
		layout := multipleImportedServerLayouts[index]
		t.Run(layout.name, func(t *testing.T) {
			f := multipleImportedExecutionRuntimeFixture(t, layout, "server")
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			assertMultipleImportedExecutionProgress(t, f)
			if len(f.runtime.Progress().Comparison.Measurements) != 0 {
				t.Fatal("explicit Server compared")
			}
			if err := f.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			f.runner.mu.Lock()
			defer f.runner.mu.Unlock()
			if len(f.runner.workers) != 1 {
				t.Fatal("original Server lease inventory", len(f.runner.workers))
			}
			for _, worker := range f.runner.workers {
				if worker.Alive() {
					t.Fatal("joined stop left original worker alive")
				}
			}
		})
	}
}
func TestNodeChainMultipleImportedExecutionCompare(t *testing.T) {
	for _, index := range []int{1, 2, 5} {
		layout := multipleImportedServerLayouts[index]
		t.Run(layout.name, func(t *testing.T) {
			f := multipleImportedExecutionRuntimeFixture(t, layout, "auto")
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			assertMultipleImportedExecutionProgress(t, f)
			p := f.runtime.Progress()
			if len(p.Comparison.Measurements) != 2 || p.Comparison.Winner == nil || p.Comparison.Final == nil {
				t.Fatal("missing original comparison")
			}
			winner := p.Comparison.Measurements[0]
			for _, m := range p.Comparison.Measurements {
				if !m.Eligible || m.ScoreMS == nil || *m.ScoreMS != (m.LastNodeMS+m.ExternalMS)/2 {
					t.Fatal("original two-probe formula")
				}
				if *m.ScoreMS < *winner.ScoreMS {
					winner = m
				}
			}
			if *p.Comparison.Winner != winner.Candidate || p.Comparison.Final.Candidate != winner.Candidate || p.Execution != string(winner.Candidate.Execution) {
				t.Fatal("lowest eligible winner changed")
			}
			if err := f.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestNodeChainMultipleImportedExecutionRuntimeRefusals(t *testing.T) {
	for _, name := range []string{"first-public-IP", "later-public-IP", "final-private-proof", "selected-DNS", "remote-source-receipt", "swapped-public-routes", "missing-public-route", "foreign-original-owner"} {
		t.Run(name, func(t *testing.T) {
			f := multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[2], "server")
			originalOwners := f.runtime.projection.preparation.multiple.owners
			defer func() {
				f.engine.beforeObserve = nil
				f.runtime.projection.preparation.multiple.owners = originalOwners
			}()
			switch name {
			case "first-public-IP":
				f.engine.wrongPrefix = 1
			case "later-public-IP":
				f.engine.wrongPrefix = 3
			case "final-private-proof":
				f.engine.wrongPrefix = 4
			case "selected-DNS":
				f.engine.failDNS = true
			case "remote-source-receipt":
				f.mutateStatus = func(s *multihoprelay.NodeChainLeaseStatus) {
					if len(s.Receipt.Prefixes) > 0 {
						s.Receipt.Prefixes[0].SourceSHA256 = strings.Repeat("a", 64)
					}
				}
			case "swapped-public-routes":
				p := f.runtime.projection.policy.serverProofs
				a, b := p[1].Tag+"/1.1.1.1:443", p[3].Tag+"/1.1.1.1:443"
				f.engine.peers[a], f.engine.peers[b] = f.engine.peers[b], f.engine.peers[a]
			case "missing-public-route":
				delete(f.engine.peers, f.runtime.projection.policy.serverProofs[1].Tag+"/1.1.1.1:443")
			case "foreign-original-owner":
				f.engine.beforeObserve = func(context.Context) { f.runtime.projection.preparation.multiple.owners = nil }
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err == nil {
				t.Fatal("incomplete or substituted proof activated")
			}
			f.engine.mu.Lock()
			opened := f.engine.opens
			f.engine.mu.Unlock()
			if opened != 0 {
				t.Fatal("failed proof opened application")
			}
		})
	}
}
func TestNodeChainMultipleImportedExecutionRestoreKeepsChoice(t *testing.T) {
	testNodeChainExecutionRestoreKeepsWinner(t, multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[1], "auto"))
}
