package common

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func repositoryRoot() string {
	return filepath.Clean(filepath.Join("..", ".."))
}

func runRepositoryPythonPath(t *testing.T, scriptPath string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for the repository audits")
	}
	cmd := exec.Command(python, scriptPath)
	cmd.Dir = repositoryRoot()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("repository audit %s failed: %v\n%s", scriptPath, err, out)
	}
}

func TestAuthoritativeRepositoryPythonSafetyContracts(t *testing.T) {
	paths := []string{
		"deploy/full-audit-v4.py",
		"deploy/linux-full-profile-shipping-audit.py",
		"server/scripts/test_preserve_generated_state.py",
		"server/scripts/test_setup_center_update.py",
		"server/scripts/test_download_safety.py",
		"server/scripts/test_setup_center_release.py",
		"android/test_android_connection_profiles_contract.py",
		"android/test_android_via_entry_latency_contract.py",
		"modes/test_kill_switch.py",
		"modes/test_mtu_policy.py",
		"modes/test_multihop.py",
	}
	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) { runRepositoryPythonPath(t, path) })
	}
}

func TestASUSProtectedJFFSScriptsAreNeverTargeted(t *testing.T) {
	path := filepath.Join(repositoryRoot(), "router", "asus-merlin-router-vpn-forwards.sh")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, protected := range []string{"cod-na-block.sh", "rogue-dhcp-ra-guard.sh", "att-bgw-guard.sh"} {
		if strings.Contains(text, protected) {
			t.Fatalf("Router VPN forwarding helper must never target protected ASUS JFFS script %s", protected)
		}
	}
	for _, marker := range []string{
		`grep -Fqx "$LINE" "$FILE" 2>/dev/null || printf '%s\n' "$LINE" >> "$FILE"`,
		`write_hook "$NAT_START" "$RUNTIME apply-nat"`,
		`write_hook "$FIREWALL_START" "$RUNTIME apply-filter"`,
		`/jffs/scripts/router-vpn-forward.sh apply-nat`,
		`/jffs/scripts/router-vpn-forward.sh apply-filter`,
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("non-destructive ASUS JFFS hook marker missing: %s", marker)
		}
	}
	for _, forbidden := range []string{
		`cat > "$NAT_START"`, `cat > "$FIREWALL_START"`,
		`: > "$NAT_START"`, `: > "$FIREWALL_START"`,
		`rm -f "$NAT_START"`, `rm -f "$FIREWALL_START"`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("destructive Merlin hook behavior detected: %s", forbidden)
		}
	}
}
