package common

import (
	"strings"
	"testing"
)

func TestAndroidHomeConnectedRequiresCurrentPathProof(t *testing.T) {
	home := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeSummary.java")
	for _, required := range []string{
		`home.connected&&"passed".equals(home.pathProof)`,
		`out.phase="engine-up-unproven"`,
		`Libbox engine is UP but no current selected-path proof is passed; Router VPN refuses to call this Connected.`,
		`Xray engine is UP but no current selected-path proof is passed; Router VPN refuses to call this Connected.`,
		`Stored Connected state has no current passed path proof; Router VPN refuses to adopt it.`,
		`if(!runtime.connected)throw new IllegalStateException("Router VPN runtime is not in a proven connected state.")`,
	} {
		if !strings.Contains(home, required) {
			t.Fatalf("Android Home Connected truth missing %q", required)
		}
	}
	for _, forbidden := range []string{
		`if("UP".equals(layered)){out.connected=true`,
		`if("UP".equals(xray)){out.connected=true`,
	} {
		if strings.Contains(home, forbidden) {
			t.Fatalf("Android Home regressed to treating raw engine UP as Connected: %q", forbidden)
		}
	}

	state := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeStateStore.java")
	for _, required := range []string{
		`putString("path_proof", "passed")`,
		`putBoolean("connected", true)`,
		`putString("path_proof", "pending")`,
		`putBoolean("connected", false)`,
	} {
		if !strings.Contains(state, required) {
			t.Fatalf("Android Home state proof lifecycle missing %q", required)
		}
	}
}
