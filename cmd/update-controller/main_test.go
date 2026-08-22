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

func TestEnvPayloadNeverReturnsNilForPortainer(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, json.RawMessage("null"), json.RawMessage("   ")} {
		v := envPayload(raw)
		items, ok := v.([]any)
		if !ok || len(items) != 0 { t.Fatalf("null environment did not become empty array: %#v", v) }
	}
	input := json.RawMessage(`[ {"name":"WAN_INTERFACE","value":"eth0"} ]`)
	if got := envPayload(input); got == nil { t.Fatal("non-null Portainer env was dropped") }
}

func TestComposeSHAIsUnknownForMixedPhaseOneImages(t *testing.T) {
	target, err := validateAndMaterializeTemplate(testTemplate(), testNewSHA)
	if err != nil { t.Fatal(err) }
	phaseOne, err := preserveUpdater(target, testTemplate())
	if err != nil { t.Fatal(err) }
	// The generated header describes the target even while the updater is
	// deliberately old during rollback-protected phase one. Remove it to test
	// image-based inference does not lie about a mixed deployment.
	phaseOne = strings.Join(strings.Split(phaseOne, "\n")[2:], "\n")
	if got := composeSHA(phaseOne); got != "unknown" { t.Fatalf("mixed image set reported exact SHA %q", got) }
}
