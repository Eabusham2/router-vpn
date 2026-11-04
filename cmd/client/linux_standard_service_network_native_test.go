//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Engine/pidfd/source/flock ownership is actual. This explicit event-reader
// model is used only where the workspace cannot subscribe to native rtnetlink.
// The required namespace case separately exercises the production Tracker.
type standardNetworkModel struct {
	failure       error
	reads, closes int
	closeFailure  bool
	duringRead    func()
}

func (n *standardNetworkModel) CurrentContext(ctx context.Context) error {
	n.reads++
	if n.duringRead != nil {
		n.duringRead()
	}
	return errors.Join(n.failure, ctx.Err())
}
func (n *standardNetworkModel) Close() error {
	n.closes++
	if n.closeFailure {
		return errors.New("original reader did not join")
	}
	return nil
}

func standardNetworkSession(t *testing.T, policy string) (*linuxStandardService, *legacyExitFixture, *linuxStandardServicePeer, linuxStandardServiceRequest, context.Context) {
	return standardNetworkSessionWithDNS(t, policy, false)
}

func standardNetworkSessionWithDNS(t *testing.T, policy string, dns bool) (*linuxStandardService, *legacyExitFixture, *linuxStandardServicePeer, linuxStandardServiceRequest, context.Context) {
	t.Helper()
	s, f, _ := linuxStandardServiceRuntimeFixture(t, policy)
	if dns {
		installLegacyDNSEngine(t, f, "valid")
		script := strings.Replace(legacyDNSEngineFixture, "(root/'dns-query').write_bytes(q)", "(root/'dns-query').write_bytes(q)\n  with (root/'dns-queries').open('a') as out:out.write(q.hex()+'\\n')", 1)
		if err := os.WriteFile(filepath.Join(f.root, "bin", "sing-box"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	peer, _, _ := linuxStandardPeerFixture(t)
	request, dir := linuxStandardServiceRequestFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	if err := s.handle(ctx, peer, request, []*os.File{dir}); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	return s, f, peer, request, ctx
}

func TestLinuxStandardServiceNetworkShippingDNSRepeatsRealOriginalExchange(t *testing.T) {
	s, f, peer, request, ctx := standardNetworkSessionWithDNS(t, "on-connect", true)
	n := &standardNetworkModel{}
	opens := 0
	s.openNetwork = func(context.Context, context.Context) (linuxStandardNetworkObserver, error) { opens++; return n, nil }
	if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "prove-dns", false), nil); err != nil {
		t.Fatal("shipping original DNS readiness/epoch/proof failed", err)
	}
	queries, err := os.ReadFile(filepath.Join(f.root, "dns-queries"))
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Fields(string(queries))
	if len(rows) != 2 || rows[0] == rows[1] || opens != 1 || s.session.network == nil || s.session.owner.dns.proof == nil {
		t.Fatal("shipping proof bypassed original readiness or uncached epoch-protected exchange", len(rows), opens)
	}
	if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "dns-current", false), nil); err != nil {
		t.Fatal(err)
	}
	n.failure = errors.New("actual event-reader loss")
	if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "dns-current", false), nil); err == nil {
		t.Fatal("real original DNS receipt survived invalidated network epoch")
	}
}

func TestLinuxStandardServiceNetworkProofArmsOnceAndLatchesABA(t *testing.T) {
	for _, kind := range []string{"link", "address", "route", "rule", "overflow", "reader-failure"} {
		t.Run(kind, func(t *testing.T) {
			s, _, peer, request, ctx := standardNetworkSession(t, "on-connect")
			n := &standardNetworkModel{}
			opens, proofs := 0, 0
			open := func(operation, lifetime context.Context) (linuxStandardNetworkObserver, error) {
				opens++
				if operation != ctx || lifetime == operation {
					t.Fatal("epoch borrowed request lifetime")
				}
				return n, nil
			}
			prove := func(context.Context, *linuxLegacyStandardExitOwner) error { proofs++; return nil }
			if err := s.proveDNSWithNetworkObservers(ctx, open, prove); err != nil {
				t.Fatal(err)
			}
			original := s.session.network
			if opens != 1 || proofs != 2 || original == nil {
				t.Fatal("proof omitted original readiness, epoch or second measured exchange", opens, proofs)
			}
			// The topology snapshot remains the fixture's original constant. The
			// event epoch must keep an away-and-back or lost reader invalid.
			n.failure = errors.New("original " + kind + " event invalidated epoch")
			if err := s.networkCurrent(ctx, s.session, true); err == nil {
				t.Fatal("network event became current after identical final snapshot")
			}
			n.failure = nil
			for _, action := range []string{"current", "observe", "dns-current", "prove-dns"} {
				if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, action, false), nil); err == nil {
					t.Fatal("shipping proof returned success after latched network epoch", action)
				}
			}
			if err := s.proveDNSWithNetworkObservers(ctx, open, prove); err == nil || opens != 1 || s.session.network != original || proofs != 2 {
				t.Fatal("failed network epoch was reopened or proved again", err, opens, proofs)
			}
			if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
				t.Fatal(err)
			}
			if !s.session.joined || !original.closed || n.closes != 1 {
				t.Fatal("original observer/engine cleanup did not join")
			}
		})
	}
}

func TestLinuxStandardServiceNetworkInitializationAndProofFailuresStayRetained(t *testing.T) {
	for _, kind := range []string{"initialization", "missing-reader", "second-proof", "late-event", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _, _, ctx := standardNetworkSession(t, "always")
			n := &standardNetworkModel{}
			opens, proofs := 0, 0
			operation, cancel := context.WithCancel(ctx)
			defer cancel()
			open := func(context.Context, context.Context) (linuxStandardNetworkObserver, error) {
				opens++
				if kind == "initialization" {
					return n, errors.New("subscription lost initial event")
				}
				if kind == "missing-reader" {
					return nil, nil
				}
				return n, nil
			}
			prove := func(context.Context, *linuxLegacyStandardExitOwner) error {
				proofs++
				if proofs == 2 {
					switch kind {
					case "second-proof":
						return errors.New("selected DNS failed")
					case "late-event":
						n.failure = errors.New("original route changed before receipt")
					case "cancelled":
						cancel()
					}
				}
				return nil
			}
			if err := s.proveDNSWithNetworkObservers(operation, open, prove); err == nil {
				t.Fatal("failed armed proof became successful", kind)
			}
			original := s.session.network
			if original == nil {
				t.Fatal("partial observer capability was discarded")
			}
			if err := s.proveDNSWithNetworkObservers(ctx, open, prove); err == nil || opens != 1 || s.session.network != original {
				t.Fatal("failed proof refreshed its original epoch", err)
			}
		})
	}
}

func TestLinuxStandardServiceNetworkRetirementPreservesUnjoinedAndReplacement(t *testing.T) {
	s, _, peer, request, ctx := standardNetworkSession(t, "always")
	n := &standardNetworkModel{}
	if err := s.proveDNSWithNetworkObservers(ctx, func(context.Context, context.Context) (linuxStandardNetworkObserver, error) { return n, nil }, func(context.Context, *linuxLegacyStandardExitOwner) error { return nil }); err != nil {
		t.Fatal(err)
	}
	old := s.session
	original := old.network
	foreign := &standardNetworkModel{}
	replacement := &linuxStandardServiceSession{owner: old.owner}
	replacement.network = &linuxStandardServiceNetwork{session: replacement, owner: old.owner, observer: foreign}
	s.session = replacement
	if err := s.closeNetwork(ctx, old); err == nil || foreign.closes != 0 || n.closes != 0 {
		t.Fatal("stale cleanup closed another network owner", err)
	}
	s.session = old
	n.closeFailure = true
	if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err == nil || old.joined || original.closed || !old.cleanupPending {
		t.Fatal("unjoined reader fabricated engine cleanup", err)
	}
	if retired, err := legacyExitPIDFDState(old.owner.originalPIDFD); err != nil || retired {
		t.Fatal("unjoined network cleanup lost original engine", err)
	}
	n.closeFailure = false
	if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
		t.Fatal(err)
	}
	if !old.joined || !original.closed || foreign.closes != 0 {
		t.Fatal("original network retirement did not preserve replacement")
	}
	if _, present := legacyStandardProtectionOwners.Load(s.app); !present {
		t.Fatal("network retirement released original Always policy")
	}
}
