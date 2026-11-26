package common

import (
	"os"

	"path/filepath"

	"strings"
	"testing"
)

func repositoryRoot() string {
	return filepath.Clean(filepath.Join("..", ".."))
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
		`safe_jffs_file "$FILE"`,
		`new_jffs_tmp "$FILE"`,
		`grep -Fqx "$LINE" "$ACTIVE_TMP" 2>/dev/null || printf '%s\n' "$LINE" >> "$ACTIVE_TMP"`,
		`awk -v runtime="$RUNTIME"`,
		`commit_jffs_tmp "$FILE" 755`,
		`LINE="$2 || true"`,
		`write_hook "$NAT_START" "$RUNTIME apply"`,
		`write_hook "$FIREWALL_START" "$RUNTIME apply"`,
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

	workflowPath := filepath.Join(root, ".github", "workflows", "build-all.yml")
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
