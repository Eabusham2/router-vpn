package main

import (
	"encoding/json"
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

func TestMaterializeExactSHAAndNoFloatingOldImages(t *testing.T) {
	got, err := validateAndMaterializeTemplate(testTemplate(), testNewSHA)
	if err != nil { t.Fatal(err) }
	if strings.Contains(got, testOldSHA) { t.Fatal("old custom image SHA survived materialization") }
	if strings.Count(got, testNewSHA) < 12 { t.Fatalf("target SHA did not replace complete image/provenance set: %d", strings.Count(got, testNewSHA)) }
	if composeSHA(got) != testNewSHA { t.Fatalf("composeSHA=%q", composeSHA(got)) }
}

func TestMaterializeRejectsDockerSocketBuildAndLatest(t *testing.T) {
	for name, extra := range map[string]string{
		"socket": "\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
		"build": "\n    build:\n      context: .\n",
		"latest": "\n    image: example.invalid/unsafe:latest\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateAndMaterializeTemplate(testTemplate()+extra, testNewSHA); err == nil { t.Fatal("unsafe compose was accepted") }
		})
	}
}

func TestMaterializeRequiresUpdaterService(t *testing.T) {
	bad := strings.ReplaceAll(testTemplate(), "router-vpn-updater:", "router-vpn-upgrade-missing:")
	if _, err := validateAndMaterializeTemplate(bad, testNewSHA); err == nil { t.Fatal("compose without update controller was accepted") }
}

func TestPreserveUpdaterKeepsOnlyOldUpdaterDuringPhaseOne(t *testing.T) {
	target, err := validateAndMaterializeTemplate(testTemplate(), testNewSHA)
	if err != nil { t.Fatal(err) }
	phaseOne, err := preserveUpdater(target, testTemplate())
	if err != nil { t.Fatal(err) }
	if !strings.Contains(phaseOne, "router-vpn-updater:"+testOldSHA) { t.Fatal("phase one did not preserve old updater") }
	if !strings.Contains(phaseOne, "router-vpn-agent:"+testNewSHA) { t.Fatal("phase one did not update core services") }
}

func TestStackEnvironmentFailsClosedWhenMissingOrInvalid(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, json.RawMessage("null"), json.RawMessage("   "), json.RawMessage(`{}`), json.RawMessage(`"bad"`)} {
		if _, err := stackEnvironment(raw); err == nil { t.Fatalf("invalid/missing Portainer environment was accepted: %q", string(raw)) }
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`[]`), json.RawMessage(`[ {"name":"WAN_INTERFACE","value":"eth0"} ]`)} {
		items, err := stackEnvironment(raw)
		if err != nil { t.Fatalf("valid Portainer environment rejected: %v", err) }
		if items == nil { t.Fatal("valid Portainer environment became nil") }
	}
}

func TestComposeSHARejectsMixedPhaseOneEvenWithGeneratedHeader(t *testing.T) {
	target, err := validateAndMaterializeTemplate(testTemplate(), testNewSHA)
	if err != nil { t.Fatal(err) }
	phaseOne, err := preserveUpdater(target, testTemplate())
	if err != nil { t.Fatal(err) }
	if got := composeSHA(phaseOne); got != "unknown" { t.Fatalf("mixed image set reported exact SHA %q despite generated target header", got) }
}

func TestComposeSHARequiresMaterializedHeaderAndBrokerProvenance(t *testing.T) {
	if got := composeSHA(testTemplate()); got != "unknown" {
		t.Fatalf("raw tracked baseline masqueraded as deployed exact SHA %q", got)
	}
	exact, err := validateAndMaterializeTemplate(testTemplate(), testNewSHA)
	if err != nil { t.Fatal(err) }
	header := "# GENERATED exact-SHA Router VPN production compose: " + testNewSHA + "\n"
	withoutHeader := strings.Replace(exact, header, "", 1)
	if got := composeSHA(withoutHeader); got != "unknown" {
		t.Fatalf("compose without generated provenance header resolved to %q", got)
	}
	broker := "ROUTER_VPN_GITHUB_SHA: " + testNewSHA
	withoutBroker := strings.Replace(exact, broker, "ROUTER_VPN_GITHUB_SHA: missing", 1)
	if got := composeSHA(withoutBroker); got != "unknown" {
		t.Fatalf("compose without broker provenance resolved to %q", got)
	}
	if got := composeSHA(header + exact); got != "unknown" {
		t.Fatalf("duplicate generated provenance headers resolved to %q", got)
	}
	duplicateBroker := strings.Replace(exact, broker, broker+"\n      "+broker, 1)
	if got := composeSHA(duplicateBroker); got != "unknown" {
		t.Fatalf("duplicate broker provenance resolved to %q", got)
	}
}


func TestGitHubRepositoryAndBranchValidationRejectsURLAndRefInjection(t *testing.T) {
	for _, good := range []string{
		"Eabusham2/router-vpn",
		"owner_name/repo.name",
		"owner-1/repo_2",
	} {
		if !validGitHubRepo(good) {
			t.Fatalf("valid GitHub repository rejected: %q", good)
		}
	}
	for _, bad := range []string{
		"",
		"Eabusham2",
		"Eabusham2/router/vpn",
		"../router-vpn",
		"Eabusham2/..",
		"Eabusham2/router?vpn",
		"Eabusham2/router#vpn",
		"Eabusham2/router vpn",
		"Eabusham2/router\\vpn",
	} {
		if validGitHubRepo(bad) {
			t.Fatalf("unsafe GitHub repository accepted: %q", bad)
		}
	}

	for _, good := range []string{"main", "release/2026-08", "feature.safe-1", "a_b/c-d"} {
		if !validGitHubBranch(good) {
			t.Fatalf("valid GitHub branch rejected: %q", good)
		}
	}
	for _, bad := range []string{
		"",
		"@",
		"/main",
		"main/",
		"feature//x",
		"feature/../main",
		"feature@{1",
		"feature.lock",
		".hidden/main",
		"feature?",
		"feature#bad",
		"feature bad",
		"feature\\bad",
	} {
		if validGitHubBranch(bad) {
			t.Fatalf("unsafe GitHub branch accepted: %q", bad)
		}
	}
}

func TestGitHubEndpointOriginsAndCredentialSeparation(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		host     string
		ok       bool
	}{
		{"https://api.github.com/repos/Eabusham2/router-vpn/actions/runs", "api.github.com", true},
		{"https://raw.githubusercontent.com/Eabusham2/router-vpn/" + testNewSHA + "/server/portainer-current.yaml", "raw.githubusercontent.com", true},
		{"http://api.github.com/repos/Eabusham2/router-vpn", "api.github.com", false},
		{"https://api.github.com.evil.invalid/repos/x/y", "api.github.com", false},
		{"https://user@api.github.com/repos/x/y", "api.github.com", false},
		{"https://api.github.com:443/repos/x/y", "api.github.com", false},
		{"https://raw.githubusercontent.com/Eabusham2/router-vpn/file#fragment", "raw.githubusercontent.com", false},
	} {
		_, err := validateGitHubEndpoint(tc.endpoint, tc.host)
		if tc.ok && err != nil {
			t.Fatalf("valid GitHub endpoint rejected: %s: %v", tc.endpoint, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("unsafe GitHub endpoint accepted: %s", tc.endpoint)
		}
	}

	t.Setenv("GITHUB_TOKEN", "top-secret")
	apiReq, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/x/y", nil)
	githubAPIHeaders(apiReq)
	if got := apiReq.Header.Get("Authorization"); got != "Bearer top-secret" {
		t.Fatalf("API request did not receive configured token: %q", got)
	}
	rawReq, _ := http.NewRequest(http.MethodGet, "https://raw.githubusercontent.com/x/y/main/file", nil)
	githubBaseHeaders(rawReq)
	if got := rawReq.Header.Get("Authorization"); got != "" {
		t.Fatalf("raw request unexpectedly received GitHub token: %q", got)
	}
}

func TestPortainerClientForbidsRedirectsBeforeCredentialReuse(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "portainer-api.key")
	pinPath := filepath.Join(dir, "portainer-tls.sha256")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &controller{portainerKeyFile: keyPath, portainerPinFile: pinPath}
	client, key, err := c.portainerClient()
	if err != nil {
		t.Fatal(err)
	}
	if key != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected Portainer key read: %q", key)
	}
	next, _ := http.NewRequest(http.MethodGet, "http://example.invalid/leak", nil)
	prev, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:9443/api/stacks", nil)
	if err := client.CheckRedirect(next, []*http.Request{prev}); err == nil ||
		!strings.Contains(err.Error(), "redirects are forbidden") {
		t.Fatalf("Portainer redirect was not refused: %v", err)
	}
}

func TestGitHubRedirectsStayOnExpectedHTTPSOrigin(t *testing.T) {
	apiClient := githubClient("api.github.com")
	prev, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/x/y", nil)
	same, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/x/y?page=2", nil)
	if err := apiClient.CheckRedirect(same, []*http.Request{prev}); err != nil {
		t.Fatalf("same-origin API redirect rejected: %v", err)
	}
	cross, _ := http.NewRequest(http.MethodGet, "https://objects.githubusercontent.com/archive", nil)
	if err := apiClient.CheckRedirect(cross, []*http.Request{prev}); err == nil {
		t.Fatal("cross-origin authenticated API redirect was accepted")
	}
	downgrade, _ := http.NewRequest(http.MethodGet, "http://api.github.com/repos/x/y", nil)
	if err := apiClient.CheckRedirect(downgrade, []*http.Request{prev}); err == nil {
		t.Fatal("GitHub API HTTPS downgrade redirect was accepted")
	}

	rawClient := githubClient("raw.githubusercontent.com")
	rawPrev, _ := http.NewRequest(http.MethodGet, "https://raw.githubusercontent.com/x/y/main/file", nil)
	rawSame, _ := http.NewRequest(http.MethodGet, "https://raw.githubusercontent.com/x/y/main/file2", nil)
	rawSame.Header.Set("Authorization", "Bearer should-be-removed")
	rawSame.Header.Set("Cookie", "secret=1")
	if err := rawClient.CheckRedirect(rawSame, []*http.Request{rawPrev}); err != nil {
		t.Fatalf("same-origin raw redirect rejected: %v", err)
	}
	if rawSame.Header.Get("Authorization") != "" || rawSame.Header.Get("Cookie") != "" {
		t.Fatal("raw redirect retained credentials")
	}
}

func TestUpdaterUsesBuildAllCallerAsAuthoritativeReleaseRun(t *testing.T) {
	want := []string{"build-all.yml"}
	if len(requiredReleaseWorkflows) != len(want) {
		t.Fatalf("required release workflow count=%d want=%d: %v", len(requiredReleaseWorkflows), len(want), requiredReleaseWorkflows)
	}
	for i := range want {
		if requiredReleaseWorkflows[i] != want[i] {
			t.Fatalf("required release workflow[%d]=%q want=%q", i, requiredReleaseWorkflows[i], want[i])
		}
	}
}

func TestReusableReleaseChildrenAreNotStandaloneRunRequirements(t *testing.T) {
	for _, forbidden := range []string{
		"source-snapshot.yml",
		"release-candidate.yml",
		"arm64-portainer-preflight.yml",
		"publish-arm64-images.yml",
		"production-release-compose.yml",
	} {
		for _, required := range requiredReleaseWorkflows {
			if required == forbidden {
				t.Fatalf("called reusable workflow %q was treated as a standalone run requirement", forbidden)
			}
		}
	}
}

func TestLatestSuccessfulWorkflowSHAsUsesNewestMeaningfulEvidencePerSHA(t *testing.T) {
	shaA := testNewSHA
	shaB := testOldSHA
	runs := []workflowRun{
		{ID: 100, HeadSHA: shaA, HeadBranch: "main", Status: "completed", Conclusion: "success"},
		{ID: 110, HeadSHA: shaA, HeadBranch: "main", Status: "completed", Conclusion: "failure"},
		{ID: 90, HeadSHA: shaB, HeadBranch: "main", Status: "completed", Conclusion: "success"},
	}
	got := latestSuccessfulWorkflowSHAs(runs, "main")
	if len(got) != 1 || got[0] != shaB {
		t.Fatalf("newer failed rerun did not block older green SHA evidence: %v", got)
	}

	runs = []workflowRun{
		{ID: 100, HeadSHA: shaA, HeadBranch: "main", Status: "completed", Conclusion: "success"},
		{ID: 111, HeadSHA: shaA, HeadBranch: "main", Status: "in_progress"},
		{ID: 90, HeadSHA: shaB, HeadBranch: "main", Status: "completed", Conclusion: "success"},
	}
	got = latestSuccessfulWorkflowSHAs(runs, "main")
	if len(got) != 1 || got[0] != shaB {
		t.Fatalf("newer pending rerun did not block older green SHA evidence: %v", got)
	}

	runs = []workflowRun{
		{ID: 100, HeadSHA: shaA, HeadBranch: "main", Status: "completed", Conclusion: "success"},
		{ID: 112, HeadSHA: shaA, HeadBranch: "main", Status: "completed", Conclusion: "cancelled"},
		{ID: 105, HeadSHA: shaB, HeadBranch: "main", Status: "completed", Conclusion: "success"},
	}
	got = latestSuccessfulWorkflowSHAs(runs, "main")
	if len(got) != 2 || got[0] != shaB || got[1] != shaA {
		t.Fatalf("neutral cancellation or candidate ordering wrong: %v", got)
	}

	runs = append(runs,
		workflowRun{ID: 200, HeadSHA: "not-a-sha", HeadBranch: "main", Status: "completed", Conclusion: "success"},
		workflowRun{ID: 201, HeadSHA: shaA, HeadBranch: "other", Status: "completed", Conclusion: "success"},
	)
	got = latestSuccessfulWorkflowSHAs(runs, "main")
	if len(got) != 2 || got[0] != shaB || got[1] != shaA {
		t.Fatalf("invalid/wrong-branch evidence affected candidates: %v", got)
	}
}

func TestNewestMeaningfulWorkflowEvidenceControlsVerification(t *testing.T) {
	base := []workflowRun{{ID: 10, HeadSHA: testNewSHA, HeadBranch: "main", Status: "completed", Conclusion: "success"}}
	if !newestMeaningfulWorkflowSuccess(base, testNewSHA, "main") {
		t.Fatal("single successful exact-SHA workflow was not accepted")
	}
	failedNewer := append(append([]workflowRun{}, base...), workflowRun{ID: 11, HeadSHA: testNewSHA, HeadBranch: "main", Status: "completed", Conclusion: "failure"})
	if newestMeaningfulWorkflowSuccess(failedNewer, testNewSHA, "main") {
		t.Fatal("older green workflow survived a newer failed rerun")
	}
	pendingNewer := append(append([]workflowRun{}, base...), workflowRun{ID: 12, HeadSHA: testNewSHA, HeadBranch: "main", Status: "in_progress", Conclusion: ""})
	if newestMeaningfulWorkflowSuccess(pendingNewer, testNewSHA, "main") {
		t.Fatal("older green workflow was accepted while a newer rerun was unsettled")
	}
	cancelledNewer := append(append([]workflowRun{}, base...), workflowRun{ID: 13, HeadSHA: testNewSHA, HeadBranch: "main", Status: "completed", Conclusion: "cancelled"})
	if !newestMeaningfulWorkflowSuccess(cancelledNewer, testNewSHA, "main") {
		t.Fatal("neutral cancelled duplicate erased prior successful evidence")
	}
	wrongIdentity := []workflowRun{
		{ID: 20, HeadSHA: testOldSHA, HeadBranch: "main", Status: "completed", Conclusion: "success"},
		{ID: 21, HeadSHA: testNewSHA, HeadBranch: "other", Status: "completed", Conclusion: "success"},
	}
	if newestMeaningfulWorkflowSuccess(wrongIdentity, testNewSHA, "main") {
		t.Fatal("wrong SHA/branch workflow evidence was accepted")
	}
}


func TestOwnedImageProofRejectsMissingDuplicatedAndUnknownRepos(t *testing.T) {
	missingAgent := strings.Replace(testTemplate(), "router-vpn-agent:"+testOldSHA, "router-vpn-init:"+testOldSHA, 1)
	if _, err := validateAndMaterializeTemplate(missingAgent, testNewSHA); err == nil || !strings.Contains(err.Error(), "router-vpn-agent") {
		t.Fatalf("missing required owned image was accepted: %v", err)
	}
	if got := composeSHA(missingAgent); got != "unknown" {
		t.Fatalf("missing required owned image resolved to exact SHA %q", got)
	}

	unknown := testTemplate() + "  future:\n    image: ghcr.io/eabusham2/router-vpn-future:" + testOldSHA + "\n"
	if _, err := validateAndMaterializeTemplate(unknown, testNewSHA); err == nil || !strings.Contains(err.Error(), "unrecognized") {
		t.Fatalf("unrecognized Router VPN image was accepted: %v", err)
	}
	if got := composeSHA(unknown); got != "unknown" {
		t.Fatalf("unrecognized Router VPN image resolved to exact SHA %q", got)
	}

	floating := testTemplate() + "  duplicate-agent:\n    image: ghcr.io/eabusham2/router-vpn-agent:edge\n"
	if _, err := validateAndMaterializeTemplate(floating, testNewSHA); err == nil || !strings.Contains(err.Error(), "full SHA") {
		t.Fatalf("floating Router VPN image tag was accepted: %v", err)
	}
	if got := composeSHA(floating); got != "unknown" {
		t.Fatalf("floating Router VPN image tag resolved to exact SHA %q", got)
	}
}

func TestRequiredOwnedImageRepositoriesAreClosedAndComplete(t *testing.T) {
	want := []string{
		"router-vpn-init",
		"router-vpn-agent",
		"router-vpn-wireguard",
		"router-vpn-awg2",
		"router-vpn-rosenpass",
		"router-vpn-naive",
		"router-vpn-ss-v2ray",
		"router-vpn-aux",
		"router-vpn-updater",
	}
	if len(requiredCustomImageRepos) != len(want) {
		t.Fatalf("owned image repository count=%d want=%d: %v", len(requiredCustomImageRepos), len(want), requiredCustomImageRepos)
	}
	for i := range want {
		if requiredCustomImageRepos[i] != want[i] {
			t.Fatalf("owned image repository[%d]=%q want=%q", i, requiredCustomImageRepos[i], want[i])
		}
	}
}
