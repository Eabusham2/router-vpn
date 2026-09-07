package common

import (
	"strings"
	"testing"
)

func TestIOSBundleDecodeNeverFallsBackAcrossNamedNodes(t *testing.T) {
	models := repoFile(t, "ios/RouterVPN/App/Models.swift")
	for _, required := range []string{
		"let requestedID = selectedRouterID.trimmingCharacters(in: .whitespacesAndNewlines)",
		"if requestedID.isEmpty {",
		"selected = routerProfiles.first",
		"if let selected { selectedRouterID = selected.id }",
		"guard let exact = routerProfiles.first(where: { $0.id == requestedID }) else {",
		"Selected Router VPN profile is not present in this bundle",
		"selected = exact",
		"selectedRouterID = requestedID",
	} {
		if !strings.Contains(models, required) {
			t.Fatalf("iOS ClientBundle selected-profile decode boundary missing %q", required)
		}
	}
	if strings.Contains(models, "let selected = routerProfiles.first(where: { $0.id == selectedRouterID }) ?? routerProfiles.first") {
		t.Fatal("iOS ClientBundle decode regained named-selection fallback to the first linked node")
	}

	profiles := repoFile(t, "ios/RouterVPN/App/IOSConnectionProfilesView.swift")
	for _, required := range []string{
		"let index = bundle.routerProfiles.firstIndex(where: { $0.id == saved.nodeID })",
		"bundle.selectedRouterID = saved.nodeID",
	} {
		if !strings.Contains(profiles, required) {
			t.Fatalf("iOS whole-connection profile load no longer proves the target node exists before selection: missing %q", required)
		}
	}

	external := repoFile(t, "ios/RouterVPN/App/RouterVPNModelExternal.swift")
	for _, required := range []string{
		"let selected = value.routerProfiles.first(where: { $0.id == id })",
		"value.selectedRouterID = selected.id",
	} {
		if !strings.Contains(external, required) {
			t.Fatalf("iOS node selection no longer proves the target profile exists before assigning selectedRouterID: missing %q", required)
		}
	}
}
