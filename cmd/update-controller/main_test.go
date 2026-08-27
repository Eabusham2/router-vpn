package main

import (
	"encoding/json"
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


func TestUpdaterRequiresCompleteExactSHAReleaseWorkflowSet(t *testing.T) {
	want := []string{
		"release-candidate.yml",
		"arm64-portainer-preflight.yml",
		"publish-arm64-images.yml",
		"production-release-compose.yml",
	}
	if len(requiredReleaseWorkflows) != len(want) {
		t.Fatalf("required release workflow count=%d want=%d: %v", len(requiredReleaseWorkflows), len(want), requiredReleaseWorkflows)
	}
	for i := range want {
		if requiredReleaseWorkflows[i] != want[i] {
			t.Fatalf("required release workflow[%d]=%q want=%q", i, requiredReleaseWorkflows[i], want[i])
		}
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
