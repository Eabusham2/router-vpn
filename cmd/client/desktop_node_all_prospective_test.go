//go:build routervpn_node_all_prospective && go1.25

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"

	"router-vpn/internal/mobilemultihop"
)

// This explicit prospective application test requires a compiled capability
// overlay. The shipping predicate stays closed until the independent actual
// native MAX gate passes. Only the fixture's existing process/firewall and
// HTTP transport boundaries are modeled; selection, compilation, ownership,
// proof parsing and retirement are the shipping implementations.
func desktopNodeALLProspectiveFixture(t *testing.T, policy, layer string) *desktopNodeConnectionFixture {
	t.Helper()
	f := newDesktopNodeConnectionFixture(t, policy, layer)
	f.a.cfg.ModesFile = filepath.Join("..", "..", "configs", "client", "modes.json")
	f.a.cfg.StateFile = filepath.Join(f.data, "state.json")
	for _, candidate := range desktopNodeALLCandidates("wg") {
		if !mobilemultihop.DesktopNodePhysicalGraphSupported(candidate.RuntimeID, layer) {
			t.Fatal("prospective ALL requires its explicit compiled complete-MAX capability")
		}
		f.writeAssets(t, candidate.RuntimeID, nativeEntryMAXAssets(t, f.profile, candidate.RuntimeID))
	}
	return f
}

func TestDesktopNodeProspectiveALLProvesOrderedFallback(t *testing.T) {
	for _, policy := range []string{"always", "on-connect"} {
		for _, base := range []string{"wg", "awg"} {
			for winner := 0; winner < 4; winner++ {
				t.Run(policy+"/"+base+"/"+strconv.Itoa(winner), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						layer := []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"}[winner%3]
						f := desktopNodeALLProspectiveFixture(t, policy, layer)
						candidates := desktopNodeALLCandidates(base)
						for _, candidate := range candidates[:winner] {
							f.failedMode[candidate.RuntimeID] = true
						}
						response := httptest.NewRecorder()
						f.a.connectLogical(response, httptest.NewRequest(http.MethodPost, "/api/connect-logical", strings.NewReader(`{"mode":"all","base":"`+base+`"}`)))
						var result struct {
							OK       bool   `json:"ok"`
							Runtime  string `json:"runtime_mode"`
							Base     string `json:"base"`
							Fallback bool   `json:"fallback_used"`
						}
						selected := candidates[winner]
						if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.OK ||
							result.Runtime != selected.RuntimeID || result.Base != selected.Base || result.Fallback != (selected.Base != base) ||
							len(f.children) != winner+1 || !f.a.state.Connected || f.a.state.LogicalMode != "all" || f.a.state.RuntimeMode != selected.RuntimeID {
							t.Fatal("native ALL did not retain its first proved complete branch", response.Code, response.Body.String(), len(f.children))
						}
						for index, child := range f.children {
							if child.launch.mode != candidates[index].RuntimeID || (index < winner) != child.closed {
								t.Fatal("native ALL reordered a branch or failed to join its predecessor")
							}
							if index != 0 {
								prior := desktopNodeProtectionInstalled(f.children[index-1].launch.ownedNode.policy)
								if child.launch.ownedNode.attempt.transfer.Predecessor == nil || *child.launch.ownedNode.attempt.transfer.Predecessor != prior {
									t.Fatal("native ALL did not consume its exact joined predecessor")
								}
							}
						}
						current := f.children[winner]
						if current.Alive() != nil || f.kernel.releases != 0 || f.a.nodeProtection.active != current.launch.ownedNode.attempt ||
							logicalBaseStored(t, f.a) != base {
							t.Fatal("native ALL lost protection or rewrote its requested base preference")
						}
					})
				})
			}
		}
	}
}

func TestDesktopNodeProspectiveALLFailureRetainsSelectedProtection(t *testing.T) {
	for _, policy := range []string{"always", "on-connect"} {
		t.Run(policy, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := desktopNodeALLProspectiveFixture(t, policy, "off")
				for _, candidate := range desktopNodeALLCandidates("wg") {
					f.failedMode[candidate.RuntimeID] = true
				}
				response := httptest.NewRecorder()
				f.a.connectLogical(response, httptest.NewRequest(http.MethodPost, "/api/connect-logical", strings.NewReader(`{"mode":"all","base":"wg"}`)))
				if response.Code != http.StatusServiceUnavailable || len(f.children) != 4 || f.a.cmd != nil || f.a.state.Connected {
					t.Fatal("all failed native branches did not finish exact retirement", response.Code, response.Body.String(), len(f.children))
				}
				for _, child := range f.children {
					if !child.closed {
						t.Fatal("failed ALL left its owned child unjoined")
					}
				}
				expected := desktopNodeProtectionInstalled(f.children[len(f.children)-1].launch.ownedNode.policy)
				if f.kernel.locked || f.kernel.releases != 1 ||
					policy == "always" && (f.kernel.target == nil || *f.kernel.target != expected || f.a.nodeProtection == nil ||
						f.a.nodeProtection.active != nil || f.a.nodeProtection.target == nil || *f.a.nodeProtection.target != expected) ||
					policy == "on-connect" && f.kernel.target != nil {
					t.Fatal("failed ALL changed the selected protection policy", policy, f.kernel.releases)
				}
			})
		})
	}
}

func TestDesktopNodeProspectiveALLStopsAtUnjoinedAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := desktopNodeALLProspectiveFixture(t, "always", "off")
		f.failedMode["max-tls-wg"] = true
		captures := 0
		capture := f.a.nodeConnectionHost.capture
		f.a.nodeConnectionHost.capture = func(a *app) (desktopOwnedNodePreparation, error) {
			captures++
			return capture(a)
		}
		f.onStart = func(child *desktopNodeConnectionChild) {
			child.mu.Lock()
			child.closeErr = errors.New("captured native child refused its original join")
			child.mu.Unlock()
		}
		response := httptest.NewRecorder()
		f.a.connectLogical(response, httptest.NewRequest(http.MethodPost, "/api/connect-logical", strings.NewReader(`{"mode":"all","base":"wg"}`)))
		retained, retainedOK := desktopNodeOwners.Load(f.a)
		if response.Code != http.StatusServiceUnavailable || len(f.children) != 1 || captures != 2 ||
			!strings.Contains(response.Body.String(), "ALL cannot replace an unjoined native attempt") ||
			!retainedOK || retained != f.children[0].launch || f.a.cmd != nil && f.a.cmd != f.children[0].launch.command ||
			f.a.nodeProtection.active != f.children[0].launch.ownedNode.attempt || f.children[0].closed ||
			f.kernel.target == nil || !f.kernel.locked || f.kernel.releases != 0 {
			t.Fatal("ALL attempted a successor before its original child joined", response.Code, response.Body.String(), captures)
		}
	})
}
