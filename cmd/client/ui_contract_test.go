package main

import (
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestUIHTMLHasUniqueIDsAndValidPageNavigation(t *testing.T) {
	b, err := os.ReadFile("ui.html")
	if err != nil { t.Fatal(err) }
	html := string(b)
	idRe := regexp.MustCompile(`\bid=["']([^"']+)["']`)
	seen := map[string]int{}
	for _, m := range idRe.FindAllStringSubmatch(html, -1) {
		seen[m[1]]++
	}
	var duplicates []string
	for id, count := range seen {
		if count > 1 { duplicates = append(duplicates, id) }
	}
	sort.Strings(duplicates)
	if len(duplicates) > 0 { t.Fatalf("duplicate HTML ids: %v", duplicates) }

	pageRe := regexp.MustCompile(`data-page=["']([^"']+)["']`)
	pages := map[string]bool{}
	for _, m := range pageRe.FindAllStringSubmatch(html, -1) { pages[m[1]] = true }
	navRe := regexp.MustCompile(`(?:showPage\(|data-target=["'])['"]?([a-zA-Z0-9_-]+)`)
	for _, m := range navRe.FindAllStringSubmatch(html, -1) {
		name := m[1]
		if name == "" { continue }
		if !pages[name] && strings.Contains(html, "showPage('"+name+"')") {
			t.Fatalf("navigation points at missing page %q", name)
		}
	}
	for _, required := range []string{"connect", "nodes", "modes"} {
		if !pages[required] { t.Fatalf("required UI page missing: %s", required) }
	}
}

func TestLogicalUIReferencesCoreDOMAndHasNoStaleModeClaim(t *testing.T) {
	htmlBytes, err := os.ReadFile("ui.html")
	if err != nil { t.Fatal(err) }
	jsBytes, err := os.ReadFile("logical_ui.js")
	if err != nil { t.Fatal(err) }
	html, js := string(htmlBytes), string(jsBytes)
	for _, id := range []string{"mode", "modes", "connChip", "routeInfo"} {
		if !strings.Contains(html, `id="`+id+`"`) && !strings.Contains(html, `id='`+id+`'`) {
			t.Fatalf("logical UI expects missing core DOM id %q", id)
		}
	}
	for _, stale := range []string{"always shows all 20 modes", "PortableApps 3.9"} {
		if strings.Contains(js, stale) { t.Fatalf("stale UI claim remains: %q", stale) }
	}
	for _, required := range []string{
		"Connection validation", "Selected-node path proof", "policy intent",
		"/api/session", "reloadModes", "connectLogicalMode",
	} {
		if !strings.Contains(js, required) { t.Fatalf("logical UI contract missing %q", required) }
	}
}

func TestLogicalUISyntaxWhenNodeIsAvailable(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil { t.Skip("node is not installed on this test host") }
	cmd := exec.Command(node, "--check", "logical_ui.js")
	out, err := cmd.CombinedOutput()
	if err != nil { t.Fatalf("logical_ui.js syntax error: %v\n%s", err, out) }
}
