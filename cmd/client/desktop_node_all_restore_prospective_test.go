//go:build routervpn_node_all_prospective && go1.25

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// The complete-MAX capability is the same explicit compiled test overlay as
// the ALL fallback suite. Actual native dataplane admission remains separate.
// The public Speed Lab transaction must restore the captured third candidate
// even after earlier candidates become usable and its generated input changes.
func TestDesktopNodeProspectiveALLTemporaryRestoreKeepsExactWinner(t *testing.T) {
	for _, policy := range []string{"always", "on-connect"} {
		for _, outcome := range []string{"cancel", "failed"} {
			t.Run(policy+"/"+outcome, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := desktopNodeALLProspectiveFixture(t, policy, "aes-256-gcm+xor-whitening")
					f.failedMode["max-tls-wg"], f.failedMode["max-tls-awg"] = true, true
					f.onHTTP = func(child *desktopNodeConnectionChild) {
						if child.launch.mode != "max-quic-wg" || child.launch.ownedNode.policy.Metadata().RestoredMTU != 0 {
							return
						}
						child.mu.Lock()
						child.live.Reader, child.live.Index, child.live.MTU = 2, 72, 1392
						child.live.Heartbeat = time.Now().UnixMilli()
						live := child.live
						child.mu.Unlock()
						if err := child.publish("node-mtu-status.json", live); err != nil {
							t.Error(err)
						}
					}
					connected := httptest.NewRecorder()
					f.a.connectLogical(connected, httptest.NewRequest(http.MethodPost, "/api/connect-logical", strings.NewReader(`{"mode":"all","base":"wg"}`)))
					if connected.Code != http.StatusOK || !f.a.state.Connected || f.a.state.RuntimeMode != "max-quic-wg" || len(f.children) != 3 {
						t.Fatal("could not establish the original third ALL candidate", connected.Code, connected.Body.String())
					}
					prior := f.children[2]
					for deadline := time.Now().Add(time.Second); ; {
						if _, _, err := captureSpeedLabIdentity(f.a); err == nil {
							break
						} else if !time.Now().Before(deadline) {
							t.Fatal("actual session observation did not capture the ALL winner", err)
						}
						time.Sleep(100 * time.Millisecond)
					}
					source := append([]byte(nil), prior.launch.ownedNode.source...)
					privateBefore, err := os.ReadFile(f.a.cfg.ProfilesFile)
					if err != nil {
						t.Fatal(err)
					}
					f.mu.Lock()
					for _, candidate := range desktopNodeALLCandidates("wg") {
						f.failedMode[candidate.RuntimeID] = outcome == "failed"
					}
					f.mu.Unlock()
					trials := 1
					if outcome == "failed" {
						trials = 4
					}
					ctx, cancelRequest := context.WithCancel(context.Background())
					defer cancelRequest()
					f.onStart = func(child *desktopNodeConnectionChild) {
						if child.launch.ownedNode.policy.Metadata().RestoredMTU != 0 {
							f.mu.Lock()
							f.failedMode[child.launch.mode] = false
							f.mu.Unlock()
						}
						if outcome == "cancel" && child.launch.mode == "max-tls-awg" ||
							outcome == "failed" && child.launch.mode == "max-quic-wg" && child.launch.ownedNode.policy.Metadata().RestoredMTU == 0 {
							path := filepath.Join(f.data, "generated", f.profile.ID, "max-quic-wg", "wg.conf")
							if err := os.WriteFile(path, []byte("replaced private input must not rebuild the captured winner\n"), 0600); err != nil {
								t.Fatal(err)
							}
						}
					}
					f.onHTTP = func(child *desktopNodeConnectionChild) {
						if outcome == "cancel" && child.launch.mode == "max-tls-awg" {
							cancelRequest()
						}
					}
					request := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", strings.NewReader(
						`{"scope":"temporary","topology":"router","node_id":"`+f.profile.ID+`","mode":"all","base":"awg","duration_mode":"custom","min_seconds":1,"max_seconds":1}`)).WithContext(ctx)
					response := httptest.NewRecorder()
					f.a.speedLabRun(response, request)
					if response.Code < 400 || (ctx.Err() != nil) != (outcome == "cancel") || !f.a.state.Connected || f.a.state.Phase != "connected" ||
						f.a.state.RuntimeMode != "max-quic-wg" || f.a.state.LogicalMode != "all" || f.a.state.Base != "wg" || len(f.children) != 4+trials {
						t.Fatal("temporary ALL did not restore its exact previously proved winner", response.Code, response.Body.String(), len(f.children), f.a.state)
					}
					trial, restored := f.children[2+trials], f.children[3+trials]
					expected := desktopNodeProtectionInstalled(trial.launch.ownedNode.policy)
					if !prior.closed || !trial.closed || restored.launch.mode != "max-quic-wg" ||
						restored.launch.ownedNode.policy.Metadata().RestoredMTU != 1392 || restored.launch.ownedNode.host != prior.launch.ownedNode.host ||
						!bytes.Equal(restored.launch.ownedNode.source, source) || restored.launch.ownedNode.attempt.transfer.Predecessor == nil ||
						*restored.launch.ownedNode.attempt.transfer.Predecessor != expected || restored.Alive() != nil || f.kernel.releases != 0 || f.requests.Load() != int32(4+trials) {
						t.Fatal("temporary ALL reran selection or lost captured source, MTU, host or joined predecessor")
					}
					privateAfter, err := os.ReadFile(f.a.cfg.ProfilesFile)
					if err != nil || !bytes.Equal(privateBefore, privateAfter) || f.a.connectionContext != nil || f.a.connectionCancel != nil {
						t.Fatal("temporary ALL changed saved profile state or retained its cancelled operation", err)
					}
					if _, exists := speedLabTemporaryOwners.Load(f.a); exists {
						t.Fatal("temporary ALL retained its completed transaction owner")
					}
				})
			})
		}
	}
}
