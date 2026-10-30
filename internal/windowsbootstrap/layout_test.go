package windowsbootstrap

import "testing"

func TestPortableLauncherNamesStayInsideTheirCapturedRoot(t *testing.T) {
	for _, name := range []string{"RouterVPNPortable.exe", "RouterVPNPortableCore.exe", "routervpnportable.EXE"} {
		if !IsPortableLauncherName(name) {
			t.Fatal("packaged Portable launcher was rejected", name)
		}
	}
	for _, name := range []string{"", "RouterVPN.exe", "Unrelated.exe", "RouterVPNPortable.exe.bak", "RouterVPNPortable.exe ", `..\RouterVPNPortable.exe`, `C:\RouterVPNPortableCore.exe`, "App/RouterVPN/RouterVPNPortable.exe"} {
		if IsPortableLauncherName(name) {
			t.Fatal("unselected Portable launcher name was admitted", name)
		}
	}
}
