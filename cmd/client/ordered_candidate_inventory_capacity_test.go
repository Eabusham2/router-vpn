package main

import (
	"context"
	"encoding/json"
	"fmt"
	"router-vpn/internal/mobilemultihop"
	"testing"
	"time"
)

func TestDesktopCandidateCatalogRetainsBeyondSixtyFour(t *testing.T) {
	a, launch := desktopNodeChainLaunchFixture(t, 3, "windows")
	id := desktopCandidateAddCustomSource(t, a, "2022-blake3-aes-256-gcm")
	profile, found := a.profileByIDLocked(id)
	if !found {
		t.Fatal("original saved candidate missing")
	}
	ids := make([]string, 129)
	for i := range ids {
		original := cloneRouterProfile(profile)
		original.ID = fmt.Sprintf("linked-candidate-%04d", i)
		original.Name = "Same display name"
		ids[i] = original.ID
		a.profiles.Profiles = append(a.profiles.Profiles, original)
	}
	catalog, err := captureDesktopNodeChainCandidateSources(context.Background(), a, launch, 0, ids)
	if err != nil {
		t.Fatal("complete catalog was refused", err)
	}
	var metadata struct {
		Targets []struct {
			ID string `json:"id"`
		} `json:"targets"`
	}
	if json.Unmarshal([]byte(catalog.plan.Metadata()), &metadata) != nil || len(metadata.Targets) != len(ids) || len(catalog.profiles) != len(ids) {
		t.Fatal("linked candidate omitted after the old 64th position")
	}
	for i, target := range metadata.Targets {
		if target.ID != ids[i] {
			t.Fatal("original candidate identity replaced by display name or another row")
		}
	}
	// A source outside the old first 64 participates in the same full revision.
	a.profiles.Profiles[len(a.profiles.Profiles)-1].External.Shadowsocks.Password += "changed"
	if err := catalog.pulseCurrent(context.Background()); err == nil {
		t.Fatal("an off-page original source changed without revoking the catalog")
	}
}

func TestDesktopPreparedCandidateViewRetainsFullCatalogWithinAdmission(t *testing.T) {
	desktopPreparedFullCandidateInventory(t, 129)
}

func TestDesktopPreparedCandidateViewAcrossMetadataFrames(t *testing.T) {
	desktopPreparedFullCandidateInventory(t, 513)
}

func desktopPreparedFullCandidateInventory(t *testing.T, count int) {
	a, q := orderedPreparationFixture(t, "wg")
	original, ok := a.profileByIDLocked(q.CandidateIDs[0])
	if !ok {
		t.Fatal("saved candidate fixture missing")
	}
	want := map[string]bool{}
	for i := 0; i < count; i++ {
		profile := cloneRouterProfile(original)
		profile.ID = fmt.Sprintf("linked-candidate-%04d", i)
		profile.Name = "Same display name"
		a.profiles.Profiles = append(a.profiles.Profiles, profile)
		want[profile.ID] = true
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	view, err := captureOrderedCandidatePreparedView(ctx, a, 0, func(ctx context.Context) (string, error) { return "original-physical", ctx.Err() })
	if err != nil {
		t.Fatal("full view did not complete within the original admission budget", err)
	}
	for _, choice := range view.candidates {
		delete(want, choice.ID)
	}
	if len(want) != 0 {
		t.Fatal("linked candidates disappeared after the old 64-row boundary", len(want))
	}
	if a.candidatePreparation != nil || view.catalog.launch.command != nil {
		t.Fatal("catalog enumeration started or selected a trial")
	}
}

func TestDesktopCandidateLiteralSourceMatchesFullOriginalCompiler(t *testing.T) {
	a, launch := desktopNodeChainLaunchFixture(t, 3, "windows")
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		id := desktopCandidateAddCustomSource(t, a, cipher)
		profile := a.profiles.Profiles[len(a.profiles.Profiles)-1]
		profile.ID = id + "-" + cipher
		capture := &desktopNodeChainCapture{root: launch.root}
		total := 0
		original, err := capture.compileCandidateMember(t.Context(), profile, &total)
		if err != nil {
			t.Fatal(err)
		}
		input, parsed, err := compileDesktopOriginalImportedCandidate(t.Context(), profile)
		if err != nil || parsed == nil || input != original {
			t.Fatal("source-only compiler changed original candidate bytes", cipher, err)
		}
		inventory, err := json.Marshal(mobilemultihop.NodeChainCandidateInventory{Schema: 1, Revision: "original", Inputs: []string{original}})
		if err != nil {
			t.Fatal(err)
		}
		chain := launch.chain.policy.NodeChain()
		full, err := chain.NewCandidatePlan(0, string(inventory))
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := chain.NewCandidatePlanFromInputs(0, string(inventory), []*mobilemultihop.NodeChainCandidateInput{parsed})
		if err != nil || full.Metadata() != sealed.Metadata() || full.CaptureSHA256() != sealed.CaptureSHA256() {
			t.Fatal("parsed candidate changed original plan", err)
		}
	}
}
