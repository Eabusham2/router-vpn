package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConnectedOrderedCandidateHTTPViewRetainsLargeCatalog(t *testing.T) {
	f, initial, initialID := desktopCandidateTestCatalog(t, "2022-blake3-aes-256-gcm")
	base, ok := f.a.profileByIDLocked(initialID)
	if !ok {
		t.Fatal("connected reference candidate disappeared")
	}
	const count = 513
	linked := make([]string, count)
	for i := range linked {
		member := cloneRouterProfile(base)
		member.ID = fmt.Sprintf("connected-linked-%04d", i)
		member.Name = "Same candidate name"
		linked[i] = member.ID
		f.a.profiles.Profiles = append(f.a.profiles.Profiles, member)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/multihop/prefix-candidates/catalog?prefix_position=0", nil)
	start := time.Now()
	f.a.orderedCandidateCatalog(recorder, request)
	elapsed := time.Since(start)
	if recorder.Code != http.StatusOK {
		t.Fatalf("connected catalog GET after %s: HTTP %d %s", elapsed, recorder.Code, recorder.Body)
	}
	var response struct {
		Schema     int                      `json:"schema"`
		Token      string                   `json:"view_token"`
		Candidates []orderedCandidateChoice `json:"candidates"`
		Samples    int                      `json:"samples"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	control := viaEntryControlFor(f.a)
	control.mu.Lock()
	view := control.orderedView
	control.mu.Unlock()
	if view == nil || view.catalog == nil || view.catalog.plan == nil || view.identity.Ordered == nil || view.identity.Ordered.launch != initial.identity.Ordered.launch || view.token != response.Token || response.Schema != 1 || response.Samples != 50 || len(response.Candidates) != len(view.candidates) {
		t.Fatal("GET lost its original connected owner or whole inventory")
	}
	var metadata struct {
		Targets []struct {
			ID     string `json:"id"`
			Source string `json:"source_sha256"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(view.catalog.plan.Metadata()), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Targets) != len(response.Candidates) {
		t.Fatal("public and original candidate inventories differ")
	}
	positions := map[string]int{}
	for index, candidate := range response.Candidates {
		if _, duplicate := positions[candidate.ID]; duplicate || metadata.Targets[index].ID != candidate.ID || len(metadata.Targets[index].Source) != 64 {
			t.Fatal("duplicate or misbound candidate", index)
		}
		positions[candidate.ID] = index
	}
	for _, id := range linked {
		i, found := positions[id]
		if !found || response.Candidates[i].Name != "Same candidate name" {
			t.Fatal("missing captured original candidate", id)
		}
	}
	if len(view.identity.ProfileToken) != 64 || len(view.identity.EntryToken) != 64 {
		t.Fatal("connected GET failed to bind the active profile and entry")
	}
	last := linked[count-1]
	if positions[last] < count-1 {
		t.Fatal("later linked target lost complete original order")
	}
	borrow, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	selected, err := captureDesktopNodeChainCandidates(borrow, f.a, view.identity, view.position, []string{last})
	if err != nil {
		t.Fatal("selected candidate from later metadata frame not available", err)
	}
	var one struct {
		Targets []struct {
			ID     string `json:"id"`
			Source string `json:"source_sha256"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(selected.plan.Metadata()), &one); err != nil || len(one.Targets) != 1 || one.Targets[0].ID != last || one.Targets[0].Source != metadata.Targets[positions[last]].Source || selected.launch != view.catalog.launch {
		t.Fatal("selected the wrong original candidate or connected route", err)
	}
	for _, id := range []string{view.identity.RouterID, view.identity.Graph.EntryID} {
		for i := range f.a.profiles.Profiles {
			p := &f.a.profiles.Profiles[i]
			if p.ID != id {
				continue
			}
			original := p.APIToken
			p.APIToken += "changed"
			err := validateSpeedLabIdentityContext(t.Context(), f.a, view.identity)
			p.APIToken = original
			if err == nil {
				t.Fatal("connected selection retained changed original credentials", id)
			}
			break
		}
	}
	f.a.profiles.Profiles[len(f.a.profiles.Profiles)-1].External.Shadowsocks.Password += "changed"
	if err := view.catalog.pulseCurrent(t.Context()); err == nil {
		t.Fatal("late source change retained the old connected view")
	}
	t.Logf("connected HTTP GET returned %d original targets in %s; selected late identity %s", len(response.Candidates), elapsed, last)
}
