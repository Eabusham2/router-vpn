package common

import (
	"strings"
	"testing"
)

func TestAndroidSelectedProfileNeverFallsBackAcrossNodes(t *testing.T) {
	selector := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSelection.java")
	for _, required := range []string{
		`"selectedRouterID"`,
		`bundle.optString("selected_id", "")`,
		`if (!selected.isEmpty()) {`,
		`"Selected Router VPN profile '" + selected + "' is missing from this Android node bundle."`,
		`if (first == null) throw new IllegalStateException`,
	} {
		if !strings.Contains(selector, required) {
			t.Fatalf("Android strict selected-profile helper missing %q", required)
		}
	}

	store := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java")
	for _, required := range []string{
		"return AndroidProfileSelection.selectedRouterProfile(bundle);",
		"validateBundle(bundle);",
		"if (!id.equals(deriveId(bundle, bytes))) throw new IllegalStateException(\"Stored node identity check failed.\")",
		"Stored Router VPN node failed validation.",
	} {
		if !strings.Contains(store, required) {
			t.Fatalf("Android node-store selection/read boundary missing %q", required)
		}
	}
	if strings.Contains(store, "return profiles.length() > 0 ? profiles.optJSONObject(0) : null;") {
		t.Fatal("Android node store regained cross-node first-profile fallback")
	}

	proof := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidPathProbe.java")
	if !strings.Contains(proof, "AndroidProfileSelection.selectedRouterProfile(bundle)") {
		t.Fatal("Android selected-node proof no longer uses the strict profile selector")
	}
	forwarding := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidForwardingMaster.java")
	if !strings.Contains(forwarding, "AndroidProfileSelection.selectedRouterProfile(bundle)") {
		t.Fatal("Android forwarding master no longer uses the strict profile selector")
	}
}
