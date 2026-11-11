package mobilemultihop

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func nodeChainIdentityFixture(t *testing.T) NodeChainSource {
	t.Helper()
	nodes := nodeChainModeFixtureNodes(t, []string{"awg2-fast", "awg2-strong", "wg", "shadowsocks"}, []string{"", "", "", ""})
	identities := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg", "wg"}, []string{"", "", "", ""})
	for i := 0; i < 2; i++ {
		input := nodes[i].inputs
		var files map[string]string
		if err := json.Unmarshal([]byte(input.Files), &files); err != nil {
			t.Fatal(err)
		}
		raw := string(mustDecodeChainAsset(t, files["awg.conf"]))
		endpoint := importedPQGraph(t, nodes[i].Config())["endpoints"].([]any)[0].(map[string]any)
		server, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{byte(211 + i)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		raw = strings.Replace(raw, endpoint["private_key"].(string), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(141 + i)}, 32)), 1)
		raw = strings.Replace(raw, endpoint["peers"].([]any)[0].(map[string]any)["public_key"].(string), base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()), 1)
		files["awg.conf"] = base64.StdEncoding.EncodeToString([]byte(raw))
		nodes[i], err = NewNodeProfile(input.Mode, startJSON(t, files), input.ProfileJSON, input.Start, input.DNSBootstrap)
		if err != nil {
			t.Fatal("independent AWG packet key must retain its original Router identity", err)
		}
	}
	source := nodeChainFixtureSource(t, nodes)
	for _, identity := range identities {
		source.IdentitySources = append(source.IdentitySources, identity.inputs.Files)
	}
	return source
}

func TestNodeChainIdentitySourcesBindOriginalWGWithoutChangingTransport(t *testing.T) {
	source := nodeChainIdentityFixture(t)
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	legacySource := source
	legacySource.IdentitySources = nil
	legacy, err := NewNodeChain(startJSON(t, legacySource))
	if err != nil || legacy.Config() != chain.Config() || legacy.SourceSHA256() == chain.SourceSHA256() {
		t.Fatal("identity inventory replaced the selected transport or lost its source binding", err)
	}
	legacyLaunch, err := legacy.LaunchInput()
	if err != nil || strings.Contains(legacyLaunch, `"identity_sources"`) {
		t.Fatal("optional inventory changed existing canonical legacy inputs", err)
	}
	if _, err := ParseNodeChainLaunchInput(legacyLaunch); err != nil {
		t.Fatal("legacy captures lost their existing validation", err)
	}
	for _, target := range []string{"", "android", "ios", "linux", "darwin", "windows"} {
		t.Run(target, func(t *testing.T) {
			projected := chain
			if target != "" {
				projected, err = ProjectNodeChain(chain, target, 1280)
				if err != nil {
					t.Fatal(err)
				}
			}
			launch, err := projected.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			var record nodeChainLaunchRecord
			if err := json.Unmarshal([]byte(launch), &record); err != nil || !reflect.DeepEqual(record.IdentitySources, source.IdentitySources) {
				t.Fatal("projection discarded or rewrote original identity assets", err)
			}
			opened, err := ParseNodeChainLaunchInput(launch)
			if err != nil || opened.Config() != projected.Config() || opened.Metadata() != projected.Metadata() {
				t.Fatal("native child could not reproduce complete original identity capture", err)
			}
		})
	}
}

func TestNodeChainIdentitySourcesRejectMissingReorderedAndForeignProof(t *testing.T) {
	source := nodeChainIdentityFixture(t)
	for _, fault := range []string{"missing-member", "extra-member", "empty-member", "reorder", "wrong-proof", "wrong-endpoint", "missing-full-source", "foreign-asset", "malformed", "duplicate-key", "wg-substitution", "aggregate-bound"} {
		t.Run(fault, func(t *testing.T) {
			changed := source
			changed.IdentitySources = append([]string(nil), source.IdentitySources...)
			switch fault {
			case "missing-member":
				changed.IdentitySources = changed.IdentitySources[:len(changed.IdentitySources)-1]
			case "extra-member":
				changed.IdentitySources = append(changed.IdentitySources, changed.IdentitySources[0])
			case "empty-member":
				changed.IdentitySources[1] = ""
			case "reorder":
				changed.IdentitySources[0], changed.IdentitySources[1] = changed.IdentitySources[1], changed.IdentitySources[0]
			case "aggregate-bound":
				changed.IdentitySources[1] = strings.Repeat(" ", NodeChainInputLimit)
			default:
				position := 1
				if fault == "wg-substitution" {
					position = 2
				}
				var files map[string]string
				if err := json.Unmarshal([]byte(changed.IdentitySources[position]), &files); err != nil {
					t.Fatal(err)
				}
				raw := string(mustDecodeChainAsset(t, files["wg.conf"]))
				switch fault {
				case "wrong-proof":
					server, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{231}, 32))
					if err != nil {
						t.Fatal(err)
					}
					for _, line := range strings.Split(raw, "\n") {
						if strings.HasPrefix(line, "PublicKey") {
							raw = strings.Replace(raw, line, "PublicKey = "+base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()), 1)
						}
					}
				case "wrong-endpoint":
					raw = strings.Replace(raw, "198.51.100.11", "198.51.100.91", 1)
				case "malformed":
					raw = "not a complete original WG identity"
				case "wg-substitution":
					raw += "\n# different original WG source\n"
				}
				files["wg.conf"] = base64.StdEncoding.EncodeToString([]byte(raw))
				if fault == "missing-full-source" {
					files = map[string]string{"wg-socks.conf": files["wg.conf"]}
				} else if fault == "foreign-asset" {
					files["identity-note.txt"] = base64.StdEncoding.EncodeToString([]byte("not a WG source"))
				}
				changed.IdentitySources[position] = startJSON(t, files)
				if fault == "duplicate-key" {
					changed.IdentitySources[position] = strings.Replace(changed.IdentitySources[position], `{"wg.conf":`, `{"wg.conf":"duplicate","wg.conf":`, 1)
				}
			}
			if _, err := NewNodeChain(startJSON(t, changed)); err == nil {
				t.Fatal("incomplete, reordered or foreign standard-WG identity source was accepted", fault)
			}
		})
	}
}

func TestNodeChainIdentitySourceChangeCannotReusePriorLaunch(t *testing.T) {
	source := nodeChainIdentityFixture(t)
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	launch, err := chain.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	var files map[string]string
	if err := json.Unmarshal([]byte(source.IdentitySources[1]), &files); err != nil {
		t.Fatal(err)
	}
	raw := string(mustDecodeChainAsset(t, files["wg.conf"])) + "\n# relinked original identity source\n"
	files["wg.conf"] = base64.StdEncoding.EncodeToString([]byte(raw))
	source.IdentitySources[1] = startJSON(t, files)
	next, err := NewNodeChain(startJSON(t, source))
	if err != nil || next.Config() != chain.Config() || next.SourceSHA256() == chain.SourceSHA256() || next.Metadata() == chain.Metadata() {
		t.Fatal("identity-only source change was discarded or altered the selected AWG transport", err)
	}
	for _, fault := range []string{"replace", "remove"} {
		var receipt nodeChainLaunchRecord
		if err := json.Unmarshal([]byte(launch), &receipt); err != nil {
			t.Fatal(err)
		}
		receipt.IdentitySources = source.IdentitySources
		if fault == "remove" {
			receipt.IdentitySources = nil
		}
		if _, err := ParseNodeChainLaunchInput(startJSON(t, receipt)); err == nil {
			t.Fatal("stale native launch accepted replaced or omitted identity inventory", fault)
		}
	}
}
