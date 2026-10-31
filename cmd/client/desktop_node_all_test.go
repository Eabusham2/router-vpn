package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"

	"router-vpn/internal/mobilemultihop"
)

func TestDesktopNodeALLKeepsCompleteTLSFirstOrder(t *testing.T) {
	for _, base := range []string{"wg", "awg"} {
		other := "awg"
		if base == "awg" {
			other = "wg"
		}
		want := []runtimeCandidate{{"max-tls-" + base, base}, {"max-tls-" + other, other},
			{"max-quic-" + base, base}, {"max-quic-" + other, other}}
		if got := desktopNodeALLCandidates(base); !reflect.DeepEqual(got, want) {
			t.Fatal("native ALL changed its complete TLS-first base preference", base, got)
		}
	}
}

// This is a deliberate closed-capability assertion. Positive complete-MAX
// application activation is a later unit with its own mandatory native proof.
// Dispatching ALL must already preserve a proved owner when all candidate
// preparations refuse, without invoking the legacy shell or its result file.
func TestDesktopNodePublicALLClosedGraphsKeepOriginalOwner(t *testing.T) {
	for _, policy := range []string{"always", "on-connect"} {
		t.Run(policy, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := logicalBasePublicFixture(t, policy)
				for _, candidate := range desktopNodeALLCandidates("wg") {
					if mobilemultihop.DesktopNodePhysicalGraphSupported(candidate.RuntimeID, "off") {
						t.Fatal("closed ALL fixture requires the separate complete-MAX admission unit")
					}
				}
				operation, finish, err := f.a.beginConnectionOperation()
				if err != nil {
					t.Fatal(err)
				}
				defer finish()
				if err := f.a.startMode("wg"); err != nil {
					t.Fatal(err)
				}
				original := f.children[0]
				attempt := f.a.nodeProtection.active
				target := *f.kernel.target
				catalog, _ := json.Marshal(f.a.modes)
				all, _ := f.a.mode("all")
				if ok, reason := f.a.checkMode(all); !ok {
					t.Fatal("native ALL catalog attempted a legacy command", reason)
				}
				_, err = f.a.startAllLogical("awg")
				if err == nil || !strings.Contains(err.Error(), "ALL native candidates unavailable:") {
					t.Fatal("closed native ALL did not use its actual captured candidate path", err)
				}
				previous := -1
				for _, candidate := range desktopNodeALLCandidates("awg") {
					index := strings.Index(err.Error(), candidate.RuntimeID+":")
					if index <= previous {
						t.Fatal("closed native ALL omitted or reordered a complete candidate", err)
					}
					previous = index
				}
				after, _ := json.Marshal(f.a.modes)
				if len(f.children) != 1 || original.Alive() != nil || original.closed || original.closes != 0 ||
					f.a.cmd != original.launch.command || !f.a.state.Connected || f.a.state.Mode != "wg" ||
					f.a.nodeProtection.active != attempt || f.kernel.target == nil || *f.kernel.target != target ||
					f.kernel.releases != 0 || !f.a.sameConnectionOperation(operation) || string(catalog) != string(after) {
					t.Fatal("native ALL preflight stopped or rewrote its original proved owner")
				}
			})
		})
	}
}

func TestDesktopNodePublicALLCancellationKeepsCapturedOperation(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		name := "cancel"
		if replacement {
			name = "replacement"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := logicalBasePublicFixture(t, "always")
				originalCapture := f.a.nodeConnectionHost.capture
				newOperation, cancelNew := context.WithCancel(context.Background())
				defer cancelNew()
				replacementCommand := exec.Command("captured-replacement-not-executed")
				entered := false
				f.a.nodeConnectionHost.capture = func(a *app) (desktopOwnedNodePreparation, error) {
					capture, err := originalCapture(a)
					if !entered {
						entered = true
						f.a.cancelConnectionOperation()
						if replacement {
							f.a.mu.Lock()
							f.a.connectionContext, f.a.connectionCancel = newOperation, cancelNew
							f.a.cmd = replacementCommand
							f.a.state.Connected, f.a.state.Phase, f.a.state.Mode = true, "connected", "captured-replacement"
							f.a.mu.Unlock()
						}
					}
					return capture, err
				}
				response := httptest.NewRecorder()
				f.a.connectLogical(response, httptest.NewRequest(http.MethodPost, "/api/connect-logical", strings.NewReader(`{"mode":"all","base":"wg"}`)))
				if !entered || response.Code != http.StatusConflict || len(f.children) != 0 || f.kernel.releases != 0 {
					t.Fatal("cancelled ALL left its original native operation", response.Code, response.Body.String())
				}
				if replacement && (f.a.connectionContext != newOperation || f.a.cmd != replacementCommand ||
					!f.a.state.Connected || f.a.state.Mode != "captured-replacement" || newOperation.Err() != nil) {
					t.Fatal("old ALL cancellation changed a replacement connection")
				}
			})
		})
	}
}
