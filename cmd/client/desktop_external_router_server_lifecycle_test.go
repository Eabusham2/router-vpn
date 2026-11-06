package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"

	"router-vpn/internal/common"
)

func desktopWindowsRouterServerHostFixture(t *testing.T, kill string, choices ...string) (*desktopWindowsExternalFixture, common.RouterProfile, common.RouterProfile) {
	t.Helper()
	f := newDesktopWindowsExternalFixture(t, kill)
	p := cloneRouterProfile(f.profiles["shadowsocks"])
	p.ID = "windows-paired-router-server"
	execution := "server"
	if len(choices) != 0 {
		execution = choices[0]
	}
	p.MultihopExecution, p.MultihopEntryMode = execution, "wg"
	p.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + p.Endpoint + "/node-response", ServerName: "exit.example.test"}
	f.base.a.profiles.Profiles = append(f.base.a.profiles.Profiles, p)
	f.base.a.profiles.SelectedID = p.ID
	if err := f.base.a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	// This models the already joined child's proof only. The separate native
	// acceptance suite must obtain it through actual WG, leased SOCKS and SS.
	f.proofFault = func(proof *desktopExternalProof) { proof.Execution = execution }
	return f, p, cloneRouterProfile(f.base.profile)
}

func desktopWindowsRouterServerConnect(f *desktopWindowsExternalFixture, p, e common.RouterProfile) *httptest.ResponseRecorder {
	direct := false
	body, _ := json.Marshal(externalProfileConnectRequest{ProfileID: p.ID, EntryID: e.ID, Direct: &direct, Execution: p.MultihopExecution, EntryMode: "wg"})
	response := httptest.NewRecorder()
	f.base.a.externalProfileConnect(response, httptest.NewRequest(http.MethodPost, "/api/external/connect", bytes.NewReader(body)))
	return response
}

func TestDesktopWindowsExternalRouterServerPublicLifecycle(t *testing.T) {
	testDesktopWindowsRouterPublicLifecycle(t, "server")
}
func TestDesktopWindowsExternalRouterLocalPublicLifecycle(t *testing.T) {
	testDesktopWindowsRouterPublicLifecycle(t, "local")
}
func testDesktopWindowsRouterPublicLifecycle(t *testing.T, execution string) {
	for _, kill := range []string{"on-connect", "always"} {
		t.Run(kill, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, p, e := desktopWindowsRouterServerHostFixture(t, kill, execution)
				response := desktopWindowsRouterServerConnect(f, p, e)
				if response.Code != http.StatusOK {
					t.Fatal("paired Server public connect", response.Code, response.Body.String())
				}
				raw, ok := desktopExternalRetainedLaunches.Load(f.base.a)
				if !ok {
					t.Fatal("original retained owner absent")
				}
				launch := raw.(*desktopNodeLaunch)
				if launch.profileID != e.ID || launch.policyProfileID != p.ID || launch.external.windows.entryToken != desktopOwnedNodeProfileToken(e) || launch.external.selection != execution {
					t.Fatal("Server owner relabeled original entry or final")
				}
				proof, err := f.base.a.readDesktopExternalProof(launch)
				if err != nil || proof.EntryNodeID != e.NodeProofID || proof.Execution != execution || !proof.EntryProven || !proof.DNSProven {
					t.Fatal("Server proof lost original paired identity", err)
				}
				if err := launch.external.windows.CurrentProof(context.Background(), proof); err != nil {
					t.Fatal(err)
				}
				changed := proof
				changed.Execution = "local"
				if execution == "local" {
					changed.Execution = "server"
				}
				if launch.external.windows.CurrentProof(context.Background(), changed) == nil {
					t.Fatal("Local proof admitted")
				}
				changed = proof
				changed.EntryNodeID = ""
				if launch.external.windows.CurrentProof(context.Background(), changed) == nil {
					t.Fatal("unpaired proof admitted")
				}
				synctest.Wait()
				if err := launch.external.windows.Close(context.Background()); err != nil {
					t.Fatal("original Server retirement", err)
				}
				if f.children[0].Alive() == nil {
					t.Fatal("unjoined Server child")
				}
			})
		})
	}
}
