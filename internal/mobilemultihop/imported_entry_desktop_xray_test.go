package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

func importedSealedXrayFinals(t *testing.T, check func(*testing.T, []string)) {
	t.Helper()
	for _, final := range []struct {
		mode    string
		capture func(*testing.T, string, string, string) []string
	}{
		{"reality-pq-vision", importedPQFixture},
		{"reality-xhttp", importedXHTTPFixture},
	} {
		for _, kind := range []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"} {
			for _, first := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, last := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					t.Run(final.mode+"/"+kind+"/"+first+"/"+last, func(t *testing.T) {
						source := final.capture(t, kind, first, last)
						if len(source) != 7 || source[2] != final.mode {
							t.Fatal("sealed final fixture substituted another transport or lost an original input")
						}
						check(t, source)
					})
				}
			}
		}
	}
}

// A selected Start Layer has already been compiled into the private final
// before imported-entry composition. Compare its complete native Xray payload
// with that independently compiled final, preserving those exact adaptations.
func importedSealedXrayConfig(t *testing.T, source []string) string {
	t.Helper()
	original, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
	if err != nil {
		t.Fatal(err)
	}
	final := desktopNodeObject(t, externalTestRead(t, original.Config()), "outbounds", "proxy")
	configured, ok := final["config_json"].(string)
	if !ok || configured == "" || final["mode"] != source[2] {
		t.Fatal("independently compiled final lost its captured Xray payload")
	}
	return configured
}

func TestImportedLaunchInputRetainsPQAndXHTTPFinals(t *testing.T) {
	importedSealedXrayFinals(t, func(t *testing.T, source []string) {
		original := importedPacketXrayCompile(t, source)
		configured := importedSealedXrayConfig(t, source)
		final := desktopNodeObject(t, externalTestRead(t, original.Config()), "outbounds", LocalTag)
		if final["mode"] != source[2] || final["config_json"] != configured || original.Healthy() {
			t.Fatal("sealed constructor changed the captured Xray final or claimed live proof")
		}
		checkImportedLaunchRoundTrip(t, original, source)
	})
}

func TestDesktopImportedPolicyRetainsPQAndXHTTPFinals(t *testing.T) {
	importedSealedXrayFinals(t, func(t *testing.T, source []string) {
		original := desktopImportedOriginal(t, source, "always")
		before, metadata := original.Config(), original.Metadata()
		policy := desktopImportedPlan(t, original, desktopNodeTestSession, 0)
		config, meta, capture, err := policy.ReadValidated()
		if err != nil || meta.ExitMode != source[2] || meta.EntryID == meta.ExitID || meta.ProfileID != meta.ExitID ||
			meta.OriginalSourceSHA256 != original.SourceSHA256() || meta.OriginalConfigSHA256 != externalDigest([]byte(before)) ||
			meta.OriginalMetadataSHA256 != externalDigest([]byte(metadata)) || meta.KillSwitchPolicy != "always" ||
			meta.SOCKSUDPAssociationRequired || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "proxy" {
			t.Fatal("protected Xray final lost original authority, DNS, protection or its TCP-carried final")
		}
		configured := importedSealedXrayConfig(t, source)
		final := desktopNodeObject(t, externalTestRead(t, config), "outbounds", LocalTag)
		if final["mode"] != source[2] || final["config_json"] != configured {
			t.Fatal("protected final changed captured PQ encryption, XHTTP settings or native transport")
		}
		assertDesktopImportedExactDerivation(t, policy)
		_, shared, physical, err := ReadDesktopPhysicalPolicy(policy)
		if err != nil || shared.Kind != "imported" || shared.Mode != source[2] || shared.ProfileID != meta.ExitID ||
			shared.NodeID != meta.ExitNodeID || !reflect.DeepEqual(physical.PhysicalRoots, capture.PhysicalRoots) {
			t.Fatal("protected Xray final acquired another physical family or root")
		}
		if original.Config() != before || original.Metadata() != metadata || original.Healthy() {
			t.Fatal("native derivation changed the original final or fabricated live acceptance")
		}
	})
}

func TestDesktopImportedPolicyRestoresPQAndXHTTPFinals(t *testing.T) {
	for _, final := range []struct {
		mode    string
		capture func(*testing.T, string, string, string) []string
	}{
		{"reality-pq-vision", importedPQFixture},
		{"reality-xhttp", importedXHTTPFixture},
	} {
		t.Run(final.mode, func(t *testing.T) {
			source := final.capture(t, "openvpn-udp", "aes-256-gcm", "aes-256-gcm+xor-whitening")
			original := desktopImportedOriginal(t, source, "always")
			first := desktopImportedPlan(t, original, desktopNodeTestSession, 1392)
			_, meta, capture, err := first.ReadValidated()
			if err != nil || meta.ExitMode != final.mode || meta.RestoredMTU != 1392 {
				t.Fatal("protected Xray final lost its original restored MTU", err)
			}
			assertDesktopImportedExactDerivation(t, first)
			transfer := strings.Repeat("a", 64)
			// This is a serialization/ownership fixture, not a live DNS proof.
			record := DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID,
				SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: transfer,
				DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: "router-vpn", InterfaceIndex: 771,
				MTU: 1392, ProvedAt: 1793366400123, DNSMilliseconds: 1.25}
			raw, err := CanonicalDesktopNodeReadyRecord(record, first, transfer)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := original.ImportedLaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			rebuilt, err := ParseImportedLaunchInput(launch)
			if err != nil {
				t.Fatal(err)
			}
			defer rebuilt.Close()
			restored := desktopImportedPlan(t, rebuilt, strings.Repeat("b", 32), 1392)
			rm := restored.Metadata()
			if restored.OriginalController() == original || rm.ExitMode != final.mode || rm.RestoredMTU != 1392 ||
				rm.OriginalSourceSHA256 != meta.OriginalSourceSHA256 || rm.OriginalCaptureSHA256 != meta.OriginalCaptureSHA256 ||
				rm.SourceSHA256 == meta.SourceSHA256 || rm.ConfigSHA256 == meta.ConfigSHA256 {
				t.Fatal("Xray restoration changed its original inputs or reused the retired native owner")
			}
			assertDesktopImportedExactDerivation(t, restored)
			if _, err := ParseDesktopNodeReadyRecord(raw, restored, transfer); err == nil {
				t.Fatal("old Xray readiness became proof for the restored native session")
			}
			original.NetworkChanged()
			if first.Validate() == nil || restored.Validate() != nil || rebuilt.Healthy() {
				t.Fatal("retiring the original Xray source changed replacement authority or claimed live proof")
			}
		})
	}
}
