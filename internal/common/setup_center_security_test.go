package common

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupCenterBrokerSecurityIntegration(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for Setup Center broker security tests")
	}
	script := filepath.Join("..", "..", "server", "scripts", "test_broker_security.py")
	cmd := exec.Command(python, script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("authenticated broker integration tests failed: %v\n%s", err, out)
	}
}

func TestSetupCenterSecretsAreNotStaticallyPublishedOrBundled(t *testing.T) {
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	publisher := read("server/scripts/publish-downloads.sh")
	for _, forbidden := range []string{
		`copy_static "$BUNDLE/router-vpn-bundle.json"`,
		`copy_static "$BUNDLE/CREDENTIALS.txt"`,
		`copy_public "$BUNDLE/router-vpn-bundle.json"`,
		`copy_public "$BUNDLE/CREDENTIALS.txt"`,
	} {
		if strings.Contains(publisher, forbidden) {
			t.Fatalf("private node material is statically published: %s", forbidden)
		}
	}
	if !strings.Contains(publisher, `"$OUT"/router-vpn-bundle.json`) || !strings.Contains(publisher, `"$OUT"/CREDENTIALS.txt`) {
		t.Fatal("upgrade cleanup does not remove legacy statically published node credentials")
	}
	initializer := read("server/init/noninteractive.sh")
	if !strings.Contains(initializer, `ensure-setup-auth.py "$BASE" >/dev/null`) {
		t.Fatal("init/upgrade path does not ensure router-local Setup Center auth")
	}
	if strings.Contains(initializer, "Setup Center access token:") {
		t.Fatal("initializer appears to print/embed Setup Center token")
	}
	broker := read("server/scripts/download-broker.py")
	for _, required := range []string{
		"setup-center.token", "hmac.compare_digest", "HttpOnly; SameSite=Strict",
		"/api/pairing/redeem", "apple_local_network_permission_required",
		`print("download broker:", self.command, urllib.parse.urlsplit(self.path).path`,
	} {
		if !strings.Contains(broker, required) {
			t.Fatalf("Setup Center security boundary missing %q", required)
		}
	}
}
