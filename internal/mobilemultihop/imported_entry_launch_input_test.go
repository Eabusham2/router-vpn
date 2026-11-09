package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func importedLaunchSource(t *testing.T, kind, first, last string) []string {
	t.Helper()
	switch kind {
	case "socks5":
		return importedSOCKSXrayFixture(t, first, last)
	case "shadowsocks", "hysteria2":
		return importedProxyXrayFixture(t, kind, first, last)
	case "http-connect", "https-connect":
		return importedCONNECTXrayFixture(t, kind, first, last)
	default:
		return importedPacketXrayFixture(t, kind, first, last)
	}
}

func TestImportedLaunchInputRecompilesOriginalProtocolsAndIndependentLayers(t *testing.T) {
	for _, kind := range []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"} {
		for _, first := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, last := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					source := importedLaunchSource(t, kind, first, last)
					original := importedPacketXrayCompile(t, source)
					checkImportedLaunchRoundTrip(t, original, source)
				})
			}
		}
	}
}

func checkImportedLaunchRoundTrip(t *testing.T, original *Controller, source []string) {
	t.Helper()
	before, metadata, selected := original.Config(), original.Metadata(), original.MTUProfile()
	raw, err := original.ImportedLaunchInput()
	if err != nil {
		t.Fatal("complete original constructor did not export its private input", err)
	}
	rebuilt, err := ParseImportedLaunchInput(raw)
	if err != nil || rebuilt == nil {
		t.Fatal("native child could not independently recompile original input", err)
	}
	defer rebuilt.Close()
	if rebuilt == original || rebuilt.Config() != before || rebuilt.Metadata() != metadata || rebuilt.MTUProfile() != selected ||
		rebuilt.SourceSHA256() != original.SourceSHA256() || rebuilt.imported.inputs != original.imported.inputs ||
		!reflect.DeepEqual(rebuilt.imported.openvpnTransport, original.imported.openvpnTransport) || rebuilt.imported.openvpnMTU != original.imported.openvpnMTU ||
		rebuilt.imported.publicIP != original.imported.publicIP {
		t.Fatal("native reconstruction changed original credentials, exact graph, final policy or OpenVPN authority")
	}
	inputs := rebuilt.imported.inputs
	if !reflect.DeepEqual(source, []string{inputs.EntryConfig, inputs.EntryCapture, inputs.ExitMode, inputs.ExitFiles, inputs.ExitProfile, inputs.ExitStart, inputs.DNSBootstrap}) {
		t.Fatal("private reconstruction substituted a constructor input")
	}
	again, err := rebuilt.ImportedLaunchInput()
	if err != nil || again != raw || original.Config() != before || original.Metadata() != metadata {
		t.Fatal("private recompile is not deterministic or changed the original owner", err)
	}
	if _, err := New(rebuilt.Config(), rebuilt.Metadata()); err == nil {
		t.Fatal("copied graph metadata replaced original imported authority")
	}
}

func TestImportedLaunchInputPreservesBoundedFinalModesAndSelectedDNS(t *testing.T) {
	for _, mode := range []string{"shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			source := importedOpenVPNFixture(t, "udp", mode, "aes-256-gcm", "aes-256-gcm+xor-whitening")
			checkImportedLaunchRoundTrip(t, importedPacketCompile(t, source), source)
		})
	}
	t.Run("selected-encrypted-dns", func(t *testing.T) {
		source := importedLaunchSource(t, "openvpn-tcp", "aes-256-gcm", "aes-256-gcm+xor-whitening")
		final := externalTestRead(t, source[4])
		final["dns_mode"], final["dns_protocol"], final["dns_host"] = "custom", "https", "selected.resolver.example"
		final["dns_port"], final["dns_server_name"], final["dns_path"] = 4443, "selected.resolver.example", "/captured/query"
		source[4] = externalTestJSON(t, final)
		source[6] = externalTestJSON(t, map[string]any{
			"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": "9.9.9.9", "server_port": 5353, "detour": "proxy"},
			"query":  map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "disable_cache": true, "rewrite_ttl": 17},
		})
		checkImportedLaunchRoundTrip(t, importedPacketXrayCompile(t, source), source)
	})
}

func TestImportedLaunchInputRejectsChangedOriginalAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*Controller){
		"config":            func(c *Controller) { c.config += " " },
		"metadata":          func(c *Controller) { c.imported.metadata += " " },
		"metadata-object":   func(c *Controller) { c.meta.EntryMode = "socks5" },
		"source":            func(c *Controller) { c.imported.source = strings.Repeat("f", 64) },
		"selected-policy":   func(c *Controller) { c.imported.profile += " " },
		"public-proof":      func(c *Controller) { c.imported.publicIP = "198.51.100.244" },
		"entry-config":      func(c *Controller) { c.imported.inputs.EntryConfig += " " },
		"entry-capture":     func(c *Controller) { c.imported.inputs.EntryCapture += " " },
		"final-mode":        func(c *Controller) { c.imported.inputs.ExitMode = "shadowsocks" },
		"final-files":       func(c *Controller) { c.imported.inputs.ExitFiles += " " },
		"final-profile":     func(c *Controller) { c.imported.inputs.ExitProfile += " " },
		"final-layer":       func(c *Controller) { c.imported.inputs.ExitStart = "" },
		"dns-bootstrap":     func(c *Controller) { c.imported.inputs.DNSBootstrap = `{}` },
		"openvpn-transport": func(c *Controller) { c.imported.openvpnTransport["password"] = "replacement secret" },
		"openvpn-mtu":       func(c *Controller) { c.imported.openvpnMTU++ },
		"seal":              func(c *Controller) { c.imported.desktopSeal = "" },
		"network-change":    func(c *Controller) { c.NetworkChanged() },
		"closed":            func(c *Controller) { _ = c.Close() },
	} {
		t.Run(name, func(t *testing.T) {
			original := importedPacketXrayCompile(t, importedLaunchSource(t, "openvpn-udp", "aes-256-gcm", "aes-256-gcm+xor-whitening"))
			mutate(original)
			if raw, err := original.ImportedLaunchInput(); err == nil || raw != "" || err.Error() != importedLaunchInputError.Error() {
				t.Fatal("changed imported source gained a private replay envelope or exposed credentials")
			}
		})
	}
	valid := importedPacketXrayCompile(t, importedLaunchSource(t, "wireguard", "", ""))
	copy := &Controller{meta: valid.meta, config: valid.config, imported: &importedEntry{
		source: valid.imported.source, metadata: valid.imported.metadata, profile: valid.imported.profile, publicIP: valid.imported.publicIP,
	}}
	copy.generation.Store(1)
	for _, candidate := range []*Controller{nil, {}, copy} {
		if raw, err := candidate.ImportedLaunchInput(); err == nil || raw != "" {
			t.Fatal("copied public output replaced original private constructor ownership")
		}
	}
}

func TestImportedLaunchInputRejectsIncompleteAmbiguousAndSubstitutedRecords(t *testing.T) {
	original := importedPacketXrayCompile(t, importedLaunchSource(t, "openvpn-udp", "aes-256-gcm", "aes-256-gcm+xor-whitening"))
	raw, err := original.ImportedLaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	reject := func(t *testing.T, candidate string) {
		t.Helper()
		compiled, err := ParseImportedLaunchInput(candidate)
		if err == nil || compiled != nil || err.Error() != importedLaunchInputError.Error() {
			t.Fatal("malformed imported envelope gained authority or exposed private compiler diagnostics")
		}
	}
	for _, fault := range []string{"source", "config", "metadata", "entry-config", "entry-capture", "final-mode", "final-files", "final-profile", "final-layer", "bootstrap", "fake-pairing"} {
		t.Run(fault, func(t *testing.T) {
			var record importedLaunchInputRecord
			if err := json.Unmarshal([]byte(raw), &record); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "source":
				record.SourceSHA256 = strings.Repeat("f", 64)
			case "config":
				record.ConfigSHA256 = strings.Repeat("f", 64)
			case "metadata":
				record.MetadataSHA256 = strings.Repeat("f", 64)
			case "entry-config":
				record.EntryConfig += " "
			case "entry-capture":
				record.EntryCapture += " "
			case "final-mode":
				record.ExitMode = "wg"
			case "final-files":
				record.ExitFiles += " "
			case "final-profile":
				record.ExitProfile += " "
			case "final-layer":
				record.ExitStart = ""
			case "bootstrap":
				record.DNSBootstrap = `{}`
			case "fake-pairing":
				capture := externalTestRead(t, record.EntryCapture)
				capture["profile"].(map[string]any)["node_proof_id"] = strings.Repeat("a", 64)
				record.EntryCapture = externalTestJSON(t, capture)
			}
			changed, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			reject(t, string(changed))
		})
	}
	for _, field := range []string{"entry_config", "entry_capture", "exit_mode", "exit_files", "exit_profile", "exit_start", "dns_bootstrap", "source_sha256", "config_sha256", "metadata_sha256"} {
		t.Run("missing-"+field, func(t *testing.T) {
			var record map[string]json.RawMessage
			if err := json.Unmarshal([]byte(raw), &record); err != nil {
				t.Fatal(err)
			}
			member, err := json.Marshal(field)
			if err != nil {
				t.Fatal(err)
			}
			member = append(append(member, ':'), record[field]...)
			missing := strings.Replace(raw, string(member)+",", "", 1)
			if missing == raw {
				missing = strings.Replace(raw, ","+string(member), "", 1)
			}
			if missing == raw {
				t.Fatal("missing-member negative did not alter canonical input")
			}
			reject(t, missing)
			reject(t, strings.Replace(raw, string(member), `"`+field+`":null`, 1))
		})
	}
	for name, candidate := range map[string]string{
		"empty": "", "null": "null", "trailing-whitespace": raw + "\n", "leading-whitespace": " " + raw, "two-records": raw + raw,
		"duplicate":     strings.Replace(raw, `"schema":1`, `"schema":1,"schema":1`, 1),
		"wrong-schema":  strings.Replace(raw, `"schema":1`, `"schema":2`, 1),
		"string-schema": strings.Replace(raw, `"schema":1`, `"schema":"1"`, 1),
		"case-alias":    strings.Replace(raw, `"schema":1`, `"Schema":1`, 1),
		"unknown-field": strings.Replace(raw, `"schema":1`, `"schema":1,"unknown":true`, 1),
		"wrong-family":  strings.Replace(raw, "routervpn-imported-launch-input", "routervpn-node-launch-input", 1),
	} {
		t.Run(name, func(t *testing.T) { reject(t, candidate) })
	}
	t.Run("oversized", func(t *testing.T) { reject(t, strings.Repeat(" ", ImportedLaunchInputLimit+1)) })
}
