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
		`if(!rawStops.await(4, TimeUnit.SECONDS))throw new IllegalStateException("Raw WireGuard/AmneziaWG teardown timed out; session ownership retained.")`,
		`if(!wgDown.get()||runtime.wireGuard.getState()!=com.wireguard.android.backend.Tunnel.State.DOWN)throw new IllegalStateException("WireGuard did not prove DOWN during Emergency Disconnect.")`,
		`if(!awgDown.get()||runtime.amneziaWG.getState()!=org.amnezia.awg.backend.Tunnel.State.DOWN)throw new IllegalStateException("AmneziaWG did not prove DOWN during Emergency Disconnect.")`,
		`Emergency Disconnect completed; all Router VPN engines proved terminal and no Router VPN-owned VPN network remains.`,
	} {
		if !strings.Contains(home, required) {
			t.Fatalf("Android Home Connected/emergency truth missing %q", required)
		}
	}
	for _, forbidden := range []string{
		`if("UP".equals(layered)){out.connected=true`,
		`if("UP".equals(xray)){out.connected=true`,
		`rawStops.await(4, TimeUnit.SECONDS);`,
	} {
		if strings.Contains(home, forbidden) {
			t.Fatalf("Android Home regressed to unproved Connected/teardown state: %q", forbidden)
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
