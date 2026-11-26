package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testOldSHA = "1111111111111111111111111111111111111111"
const testNewSHA = "2222222222222222222222222222222222222222"

func testTemplate() string {
	return `name: router-vpn
services:
  init:
    image: ghcr.io/eabusham2/router-vpn-init:` + testOldSHA + `
  finalize-current:
    image: ghcr.io/eabusham2/router-vpn-init:` + testOldSHA + `
  bundle-web:
    image: ghcr.io/eabusham2/router-vpn-init:` + testOldSHA + `
    environment:
      ROUTER_VPN_GITHUB_SHA: ` + testOldSHA + `
  agent:
    image: ghcr.io/eabusham2/router-vpn-agent:` + testOldSHA + `
  wireguard:
    image: ghcr.io/eabusham2/router-vpn-wireguard:` + testOldSHA + `
  awg2:
    image: ghcr.io/eabusham2/router-vpn-awg2:` + testOldSHA + `
  rosenpass:
    image: ghcr.io/eabusham2/router-vpn-rosenpass:` + testOldSHA + `
  naive:
    image: ghcr.io/eabusham2/router-vpn-naive:` + testOldSHA + `
  ss-v2ray:
    image: ghcr.io/eabusham2/router-vpn-ss-v2ray:` + testOldSHA + `
  aux:
    image: ghcr.io/eabusham2/router-vpn-aux:` + testOldSHA + `
  updater:
    container_name: router-vpn-updater
    image: ghcr.io/eabusham2/router-vpn-updater:` + testOldSHA + `
`
}

func TestExactReleaseCompositionAndStagedUpdater(t *testing.T) {
	exact, err := validateAndMaterializeTemplate(testTemplate(), testNewSHA)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(exact, testOldSHA) || strings.Count(exact, testNewSHA) < 12 || composeSHA(exact) != testNewSHA {
		t.Fatal("materialized release is not bound to the complete source", exact)
	}
	if composeSHA(testTemplate()) != "unknown" {
		t.Fatal("raw template masqueraded as a deployed release")
	}
	phaseOne, err := preserveUpdater(exact, testTemplate())
	if err != nil || !strings.Contains(phaseOne, "router-vpn-updater:"+testOldSHA) ||
		!strings.Contains(phaseOne, "router-vpn-agent:"+testNewSHA) || composeSHA(phaseOne) != "unknown" {
		t.Fatal("mixed update phase lost the old updater or claimed completion", err)
	}
	withoutBroker := strings.Replace(exact, "ROUTER_VPN_GITHUB_SHA: "+testNewSHA, "ROUTER_VPN_GITHUB_SHA: missing", 1)
	if composeSHA(withoutBroker) != "unknown" {
		t.Fatal("unbound download broker accepted")
	}
	missing := strings.Replace(testTemplate(), "router-vpn-agent:"+testOldSHA, "router-vpn-init:"+testOldSHA, 1)
	if _, err := validateAndMaterializeTemplate(missing, testNewSHA); err == nil {
		t.Fatal("incomplete owned image set accepted")
	}
	if _, err := validateAndMaterializeTemplate(testTemplate()+"\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n", testNewSHA); err == nil {
		t.Fatal("host Docker socket admitted")
	}
}

func TestUpdateCredentialsRemainOnTheirOriginalOrigins(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "fixture-private-token")
	api, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/x/y", nil)
	githubAPIHeaders(api)
	raw, _ := http.NewRequest(http.MethodGet, "https://raw.githubusercontent.com/x/y/main/file", nil)
	githubBaseHeaders(raw)
	if api.Header.Get("Authorization") != "Bearer fixture-private-token" || raw.Header.Get("Authorization") != "" {
		t.Fatal("API and raw-source credentials were conflated")
	}
	client := githubClient("api.github.com")
	next, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/x/y?page=2", nil)
	if err := client.CheckRedirect(next, []*http.Request{api}); err != nil {
		t.Fatal("same-origin HTTPS redirect rejected", err)
	}
	for _, target := range []string{"https://objects.githubusercontent.com/archive", "http://api.github.com/repos/x/y"} {
		next, _ := http.NewRequest(http.MethodGet, target, nil)
		if err := client.CheckRedirect(next, []*http.Request{api}); err == nil {
			t.Fatal("authenticated redirect escaped its HTTPS origin")
		}
	}
	next, _ = http.NewRequest(http.MethodGet, raw.URL.String(), nil)
	next.Header.Set("Authorization", "Bearer fixture-private-token")
	next.Header.Set("Cookie", "private=fixture")
	if err := githubClient("raw.githubusercontent.com").CheckRedirect(next, []*http.Request{raw}); err != nil ||
		next.Header.Get("Authorization") != "" || next.Header.Get("Cookie") != "" {
		t.Fatal("raw-source redirect retained credentials", err)
	}
	dir := t.TempDir()
	keyPath, pinPath := filepath.Join(dir, "portainer.key"), filepath.Join(dir, "portainer.sha256")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(strings.Repeat("a", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &controller{portainerKeyFile: keyPath, portainerPinFile: pinPath}
	owned, key, err := c.portainerClient()
	if err != nil || key != "0123456789abcdef0123456789abcdef" {
		t.Fatal("original Portainer credential unavailable", err)
	}
	previous, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:9443/api/stacks", nil)
	if err := owned.CheckRedirect(api, []*http.Request{previous}); err == nil {
		t.Fatal("Portainer credential could follow a redirect")
	}
}

func TestReleaseSelectionRequiresFreshEvidenceAndStrictAncestry(t *testing.T) {
	runs := []workflowRun{
		{ID: 10, HeadSHA: testOldSHA, HeadBranch: "main", Status: "completed", Conclusion: "success"},
		{ID: 20, HeadSHA: testNewSHA, HeadBranch: "main", Status: "completed", Conclusion: "success"},
		{ID: 21, HeadSHA: testNewSHA, HeadBranch: "main", Status: "completed", Conclusion: "failure"},
	}
	candidates := latestSuccessfulWorkflowSHAs(runs, "main")
	if len(candidates) != 1 || candidates[0] != testOldSHA || newestMeaningfulWorkflowSuccess(runs, testNewSHA, "main") {
		t.Fatal("old green evidence overrode a newer failed run")
	}
	runs = append(runs, workflowRun{ID: 22, HeadSHA: testNewSHA, HeadBranch: "main", Status: "completed", Conclusion: "success"})
	if !newestMeaningfulWorkflowSuccess(runs, testNewSHA, "main") ||
		newestMeaningfulWorkflowSuccess(runs, testNewSHA, "other") {
		t.Fatal("release evidence lost exact source and branch")
	}
	runs = append(runs, workflowRun{ID: 23, HeadSHA: testNewSHA, HeadBranch: "main", Status: "in_progress"})
	if newestMeaningfulWorkflowSuccess(runs, testNewSHA, "main") {
		t.Fatal("unsettled newer run borrowed older green evidence")
	}
	comparison := githubCompare{Status: "ahead", AheadBy: 7, BehindBy: 0}
	comparison.BaseCommit.SHA, comparison.MergeBaseCommit.SHA = testOldSHA, testOldSHA
	if !compareProvesStrictUpgrade(testOldSHA, testNewSHA, comparison) {
		t.Fatal("strict descendant rejected")
	}
	comparison.MergeBaseCommit.SHA = testNewSHA
	if compareProvesStrictUpgrade(testOldSHA, testNewSHA, comparison) {
		t.Fatal("unproved ancestry admitted")
	}
	comparison.MergeBaseCommit.SHA = testOldSHA
	if compareProvesStrictUpgrade(testOldSHA, testOldSHA, comparison) {
		t.Fatal("same-source update admitted")
	}
}
