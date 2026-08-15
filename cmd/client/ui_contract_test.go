package main

import (
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestDiagnosticsUIHasUniqueIDs(t *testing.T) {
	b, err := os.ReadFile("ui.html")
	if err != nil { t.Fatal(err) }
	html := string(b)
	idRe := regexp.MustCompile(`\bid=["']([^"']+)["']`)
	seen := map[string]int{}
	for _, m := range idRe.FindAllStringSubmatch(html, -1) { seen[m[1]]++ }
	var duplicates []string
	for id, count := range seen { if count > 1 { duplicates = append(duplicates, id) } }
	sort.Strings(duplicates)
	if len(duplicates) > 0 { t.Fatalf("duplicate HTML ids: %v", duplicates) }
	for _, required := range []string{"state", "node", "logical", "runtime", "proof", "exit", "dns", "rollback", "events", "refresh"} {
		if seen[required] != 1 { t.Fatalf("diagnostics UI missing unique id %q", required) }
	}
}

func TestLoopbackUIIsReadOnlyDiagnosticsNotDailyProduct(t *testing.T) {
	htmlBytes, err := os.ReadFile("ui.html")
	if err != nil { t.Fatal(err) }
	jsBytes, err := os.ReadFile("logical_ui.js")
	if err != nil { t.Fatal(err) }
	html, js := string(htmlBytes), string(jsBytes)

	for _, required := range []string{
		"Router VPN local controller", "Read-only loopback diagnostics", "native Router VPN app",
		"/api/status", "/api/session", "/api/session/events?after=0",
		"Selected-path proof", "Public exit", "DNS proof", "Rollback", "Recent typed events",
		"no connect, profile-edit, admin, forwarding or privileged mutation controls",
	} {
		if !strings.Contains(html, required) { t.Fatalf("diagnostics UI contract missing %q", required) }
	}
	for _, forbidden := range []string{
		"beforeinstallprompt", "serviceWorker.register", "manifest.webmanifest", "installPWA(",
		"/api/auto", "/api/connect-logical", "/api/profile/delete", "/api/forward", "/api/emergency-stop",
	} {
		if strings.Contains(html, forbidden) { t.Fatalf("loopback diagnostics UI regained retired/mutating contract %q", forbidden) }
	}

	for _, required := range []string{
		"Compatibility asset", "native apps own daily controls", "diagnostics only",
		"Connection validation", "/api/session", "Selected-node path proof", "DNS proof",
		"Cross-platform policy intent", "The Modes page shows the 16 logical modes",
		"/api/multihop/status", "/api/multihop/connect", "platform_supported",
		"Entry and exit nodes must be different",
		"exit public endpoint is not opened as a direct firewall exception",
		"forbiddenLoopbackMutations",
	} {
		if !strings.Contains(js, required) { t.Fatalf("logical UI compatibility boundary missing %q", required) }
	}
	for _, forbidden := range []string{
		"/api/logical-modes", "connectLogicalMode", "beforeinstallprompt", "serviceWorker.register", "installPWA(",
	} {
		if strings.Contains(js, forbidden) { t.Fatalf("logical UI compatibility asset regained retired product behavior %q", forbidden) }
	}
	if !strings.Contains(js, "forbiddenLoopbackMutations") || !strings.Contains(js, "/api/multihop/connect") {
		t.Fatal("retired multihop mutation endpoint is not explicitly classified as forbidden loopback behavior")
	}
}

func TestLogicalUISyntaxWhenNodeIsAvailable(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil { t.Skip("node is not installed on this test host") }
	cmd := exec.Command(node, "--check", "logical_ui.js")
	out, err := cmd.CombinedOutput()
	if err != nil { t.Fatalf("logical_ui.js syntax error: %v\n%s", err, out) }
}
