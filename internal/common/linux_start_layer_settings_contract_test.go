package common

import (
	"strings"
	"testing"
)

func TestLinuxStartLayerSettingsShipThroughExactTransform(t *testing.T) {
	transform := repoFile(t, "client/linux/apply-start-layer-settings.py")
	for _, required := range []string{
		`"aes-256-gcm"`,
		`"aes-256-gcm+xor-whitening"`,
		`"Start Layer"`,
		`"start_layer"`,
		"XOR is never counted as encryption",
		"Unsupported direct/multihop graphs fail closed",
		"expected one anchor",
	} {
		if !strings.Contains(transform, required) {
			t.Fatalf("Linux Start Layer settings transform missing %q", required)
		}
	}

	builder := repoFile(t, "client/linux/build-native-app.sh")
	for _, required := range []string{
		`START_LAYER_SETTINGS="$ROOT/client/linux/apply-start-layer-settings.py"`,
		`MUTATION_SETTINGS="$BUILD_DIR/routervpn-profile-settings-session.inc"`,
		`python3 "$START_LAYER_SETTINGS" "$MUTATION_SETTINGS" "$HARDENED_SETTINGS"`,
		`'Start Layer' 'start_layer' 'aes-256-gcm' 'aes-256-gcm+xor-whitening'`,
		"Start Layer settings are injected after session-mutation hardening",
	} {
		if !strings.Contains(builder, required) {
			t.Fatalf("Linux native builder no longer ships Start Layer settings: missing %q", required)
		}
	}

	settings := repoFile(t, "client/linux/routervpn-profile-settings-v1.inc")
	if !strings.Contains(settings, `/api/profile/settings`) || !strings.Contains(settings, `ADD_STR("base_tunnel"`) {
		t.Fatal("Linux Start Layer transform lost its canonical profile-settings target seam")
	}
}
