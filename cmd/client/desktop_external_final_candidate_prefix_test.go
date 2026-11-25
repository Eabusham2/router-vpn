//go:build linux || windows || (darwin && (amd64 || arm64))

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"router-vpn/internal/common"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func TestDesktopExternalFinalCandidatePrefixControl(t *testing.T) {
	for _, pair := range []struct {
		count  int
		target string
	}{{3, "linux"}, {4, "windows"}, {9, "darwin"}} {
		t.Run(fmt.Sprintf("%d/%s", pair.count, pair.target), func(t *testing.T) {
			a, nodes := desktopExternalFinalFixture(t, pair.count, "home")
			a.state.Connected, a.state.Mode, a.state.Phase = false, "off", "off"
			t.Setenv("HOMEVPN_ROOT", clientRoot(a))
			t.Setenv("HOMEVPN_PORTABLE", "0")
			marker := filepath.Join(clientRoot(a), "runtime", "native", "NATIVE-RUNTIME.json")
			if err := os.MkdirAll(filepath.Dir(marker), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(marker, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			candidate := desktopCandidateAddCustomSource(t, a, "2022-blake3-aes-256-gcm")
			ctx := t.Context()
			// The public handler always uses the host interface observer. Hold its
			// physical identity constant for this parent-only HTTP/source test.
			observe := func(ctx context.Context) (string, error) { return "original-physical-network", ctx.Err() }
			reply := httptest.NewRecorder()
			a.orderedCandidatePreparedCatalogWithNetwork(reply, httptest.NewRequest(http.MethodGet, "/api/multihop/saved-candidates/catalog?prefix_position=0&scope=saved-prefix-local", nil), observe)
			var view struct {
				Token      string                   `json:"view_token"`
				Candidates []orderedCandidateChoice `json:"candidates"`
			}
			if reply.Code != 200 || json.Unmarshal(reply.Body.Bytes(), &view) != nil || view.Token == "" {
				t.Fatalf("closed WG prefix catalog: %d %s", reply.Code, reply.Body.String())
			}
			found := false
			for _, c := range view.Candidates {
				if c.ID == candidate {
					found = true
					want := append([]common.MultihopNodeSelection(nil), nodes...)
					want[1] = common.MultihopNodeSelection{ID: candidate, Mode: "shadowsocks"}
					if c.SaveReason != "" || !reflect.DeepEqual(c.Proposal, want) {
						t.Fatal("saved candidate proposal lost original external exit, control or suffix", c.SaveReason, c.Proposal)
					}
				}
			}
			if !found {
				t.Fatal("original external candidate unavailable in closed WG prefix catalog")
			}
			q := orderedCandidatePreparationRequest{RequestID: strings.Repeat("a", 32), Position: 0, CandidateIDs: []string{candidate}, Samples: 50, Scope: orderedCandidateSavedPrefixScope}
			p, err := beginOrderedCandidatePreparationWithNetwork(ctx, a, q, observe)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.finish() })
			control := viaEntryControlFor(a)
			if control.preparedView == nil || control.preparedView.token != view.Token || !control.preparedView.matchesPreparation(p, time.Now()) {
				t.Fatal("public catalog and admitted preparation lost their original capture")
			}
			// Exercise both UI decisions against the same linked candidate. Saved
			// replacement keeps the suffix. Draft insertion also retains the
			// previous second member after the newly measured candidate.
			selected, ok := a.profileByIDLocked(candidate)
			if !ok {
				t.Fatal("missing original candidate")
			}
			linked := cloneRouterProfileStore(a.profiles).Profiles
			saved, rows, err := orderedCandidateProposal(p.selection.Nodes, 0, selected, linked)
			if err != nil || saved.ID != nodes[0].ID || rows[len(rows)-1] != nodes[len(nodes)-1] {
				t.Fatal("saved candidate lost control or public exit", err)
			}
			draft, inserted, err := orderedDraftProposal("local", p.selection.Nodes, 0, selected, linked)
			if err != nil || draft.ID != saved.ID || len(inserted) != len(nodes)+1 || inserted[1].ID != candidate || !reflect.DeepEqual(inserted[2:], nodes[1:]) {
				t.Fatal("candidate insertion lost original suffix", err)
			}
			for _, proposal := range []common.RouterProfile{saved, draft} {
				for i := range linked {
					if linked[i].ID == proposal.ID {
						linked[i] = proposal
					}
				}
				if _, err := captureOrderedCandidateProposal(ctx, clientRoot(a), proposal, linked, proposal.MultihopNodes); err != nil {
					t.Fatal("proposed original external-final source would not compile", err)
				}
				record, err := a.orderedCandidateProfileRecordLocked(proposal, "Measured original external exit")
				if err != nil || record.NodeID != nodes[0].ID || record.NodeChain[len(record.NodeChain)-1].ID != nodes[len(nodes)-1].ID {
					t.Fatal("separate saved profile lost original journal owner", err)
				}
			}
			private := cloneRouterProfile(p.selection.Control)
			private.ID = "independent-private"
			hostname := cloneRouterProfile(selected)
			hostname.External.Shadowsocks.Server = "other.example"
			for _, wrong := range []common.RouterProfile{private, hostname} {
				if _, _, err := orderedCandidateProposal(p.selection.Nodes, 0, wrong, linked); err == nil {
					t.Fatal("unsupported source substituted into external-final saved route")
				}
				if _, _, err := orderedDraftProposal("local", p.selection.Nodes, 0, wrong, linked); err == nil {
					t.Fatal("unsupported source inserted into external-final draft")
				}
			}
			launch, err := newDesktopNodeCandidatePrefixLaunchForPurpose(ctx, p.selection, strings.Repeat("b", 32), pair.target, p)
			if err != nil {
				t.Fatal("original closed WG candidate launch", err)
			}
			policy := launch.candidatePrefix.policy
			meta := policy.Metadata()
			if meta.PolicyProfileID != nodes[0].ID || meta.ProfileID != nodes[0].ID || launch.policyProfileID != nodes[0].ID || p.selection.Exit.ID != nodes[pair.count-1].ID || p.selection.Exit.ID == launch.policyProfileID ||
				len(meta.Prefixes) != 1 || meta.ApplicationOpen || meta.DNSOpen || !p.selection.Native.chain.chain.HasExternalFinal() || a.state.Connected {
				t.Fatal("closed prefix lost original paired policy or retained public exit")
			}
			if _, err := policy.ProtectionMembersSHA256(); err != nil {
				t.Fatal("full original device protection unavailable", err)
			}
			if pair.target == "darwin" {
				selection, err := newDesktopMacOSCandidatePrefixSelection(policy)
				if err != nil || selection.ProfileID != nodes[0].ID {
					t.Fatal("macOS candidate journal lost first control", err)
				}
			}
			launch.policyProfileID = p.selection.Exit.ID
			if validateDesktopNodeCandidatePrefixLaunch(ctx, launch) == nil {
				t.Fatal("public exit took the control journal")
			}
			launch.policyProfileID = nodes[0].ID
			input := launch.candidatePrefix.input
			launch.candidatePrefix.input = input + " "
			if validateDesktopNodeCandidatePrefixLaunch(ctx, launch) == nil {
				t.Fatal("changed launch source inherited its preparation")
			}
			launch.candidatePrefix.input = input
			original := p.prefixPreparation
			other, err := mobilemultihop.ParseNodeChainCandidatePreparationCapture(original.Source())
			if err != nil {
				t.Fatal(err)
			}
			p.prefixPreparation = other
			if p.sourceCurrent(ctx) == nil {
				t.Fatal("equal source from a second preparation replaced the owner")
			}
			p.prefixPreparation = original
		})
	}
}
