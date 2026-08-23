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
		"deploy/router-forwarding-audit.py",
		"deploy/test_router_forwarding_fail_open.py",
		"deploy/linux-full-profile-shipping-audit.py",
		"deploy/linux-auto-requirements-audit.py",
		"deploy/docs-native-fallback-policy-audit.py",
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
		`grep -Fvx -- "$LINE" "$FILE" > "$TMP" || true`,
		`write_hook "$NAT_START" "$RUNTIME apply-nat"`,
		`write_hook "$FIREWALL_START" "$RUNTIME apply-filter"`,
		`TAG=ROUTER_VPN`,
		`-t nat -A PREROUTING -i "$WAN" -p "$PROTO" --dport "$EXT"`,
		`-A FORWARD -i "$WAN" -d "$DST" -p "$PROTO" --dport "$PORT" -m state --state NEW`,
		`apply) apply_all`,
		`verify) verify`,
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("non-destructive ASUS JFFS hook marker missing: %s", marker)
		}
	}
	for _, forbidden := range []string{
		`cat > "$NAT_START"`, `cat > "$FIREWALL_START"`,
		`: > "$NAT_START"`, `: > "$FIREWALL_START"`,
		`rm -f "$NAT_START"`, `rm -f "$FIREWALL_START"`,
		`ensure_jump nat PREROUTING -i "$WAN" -j`,
		`ensure_jump filter FORWARD -i "$WAN" -d "$DST" -j`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("destructive Merlin hook behavior detected: %s", forbidden)
		}
	}
}

func TestBuildInputsAndSourceSnapshotAreRepositoryConsistent(t *testing.T) {
	root := repositoryRoot()
	dockerPath := filepath.Join(root, "deploy", "update-controller.Dockerfile")
	dockerBody, err := os.ReadFile(dockerPath)
	if err != nil {
		t.Fatal(err)
	}
	dockerText := string(dockerBody)
	if strings.Contains(dockerText, "go.sum") {
		if _, err := os.Stat(filepath.Join(root, "go.sum")); err != nil {
			t.Fatalf("update-controller Dockerfile references go.sum but the repository does not ship it: %v", err)
		}
	}
	for _, marker := range []string{"COPY go.mod ./", "COPY cmd/update-controller ./cmd/update-controller", "go build -trimpath"} {
		if !strings.Contains(dockerText, marker) {
			t.Fatalf("update-controller image lost required deterministic build marker %q", marker)
		}
	}

	workflowPath := filepath.Join(root, ".github", "workflows", "source-snapshot.yml")
	workflowBody, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(workflowBody)
	for _, forbidden := range []string{`tar -tzf "$archive" | head`, `tar -tf "$archive" | head`} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("source snapshot uses a pipefail/SIGPIPE-prone archive preview: %s", forbidden)
		}
	}
	for _, marker := range []string{
		`(cd "$RUNNER_TEMP" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")`,
		`tar -tzf "$archive" > "$members"`,
		`test -s "$members"`,
		`head -n 5 "$members"`,
		`id: upload`,
		`description": "artifact:" + os.environ["ARTIFACT_ID"]`,
	} {
		if !strings.Contains(workflow, marker) {
			t.Fatalf("source snapshot lost exact-SHA local-audit handoff marker %q", marker)
		}
	}
}
