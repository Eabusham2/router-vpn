package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func encodeNodeBasePair(t *testing.T, assets map[string][]byte) string {
	t.Helper()
	encoded := map[string]string{}
	for name, value := range assets {
		encoded[name] = base64.StdEncoding.EncodeToString(value)
	}
	data, err := json.Marshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestNodeProfileRealGeneratedBasePairRetainsSourceAndCredentials(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			encoded, profile, start := nodeProfileFixture(t, mode, "aes-256-gcm+xor-whitening")
			assets, err := nodeProfileAssets(encoded)
			if err != nil {
				t.Fatal(err)
			}
			full, compat := "wg.conf", "wg-socks.conf"
			if mode != "wg" {
				full, compat = "awg.conf", "awg-socks.conf"
			}
			split := strings.ReplaceAll(string(assets[full]), "0.0.0.0/0, ::/0", "10.77.0.0/24, fd77:77::/64, 192.168.50.0/24")
			if split == string(assets[full]) {
				t.Fatal("fixture no longer models a generated split source")
			}
			original, err := NewNodeProfile(mode, encoded, startJSON(t, profile), start, "")
			if err != nil {
				t.Fatal(err)
			}
			assets[compat] = []byte(split)
			paired, err := NewNodeProfile(mode, encodeNodeBasePair(t, assets), startJSON(t, profile), start, "")
			if err != nil || paired.Config() != original.Config() || paired.SourceSHA256() == original.SourceSHA256() {
				t.Fatal("real base pair was rejected, changed credentials, or omitted split bytes from source identity", err)
			}
			assets[compat] = append(assets[compat], []byte("\n# saved compatible source revision\n")...)
			revised, err := NewNodeProfile(mode, encodeNodeBasePair(t, assets), startJSON(t, profile), start, "")
			if err != nil || revised.Config() != paired.Config() || revised.SourceSHA256() == paired.SourceSHA256() {
				t.Fatal("compatible source change escaped captured digest", err)
			}
			for _, change := range []func(string) string{
				func(value string) string { return strings.Replace(value, "Endpoint =", "UnownedEndpoint =", 1) },
				func(value string) string { return value + "\nPersistentKeepalive = 99\n" },
				func(value string) string { return strings.Replace(value, "PrivateKey =", "PrivateKey = unowned", 1) },
				func(value string) string { return value + "\n[Peer]\nPublicKey = unowned\n" },
			} {
				assets[compat] = []byte(change(split))
				if _, err := NewNodeProfile(mode, encodeNodeBasePair(t, assets), startJSON(t, profile), start, ""); err == nil {
					t.Fatal("conflicting split credentials/options were silently ignored")
				}
			}
		})
	}
}

func TestNodeBasePairAllowsOnlyGeneratedRoutingDifferences(t *testing.T) {
	raw, _ := wireGuardFixture()
	lines := strings.Split(raw, "\n")
	kept := []string{}
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "DNS =") {
			kept = append(kept, line)
		}
	}
	split := strings.ReplaceAll(strings.Join(kept, "\n"), "0.0.0.0/0, ::/0", "10.77.0.0/24")
	assets := map[string][]byte{"wg.conf": []byte(raw), "wg-socks.conf": []byte(split)}
	if got, err := NativeBaseSource("wg", assets); err != nil || string(got) != raw {
		t.Fatal("kernel split DNS/AllowedIPs difference rejected", err)
	}
	assets["unexpected.conf"] = []byte(raw)
	if _, err := NativeBaseSource("wg", assets); err == nil {
		t.Fatal("foreign native asset ignored")
	}
	delete(assets, "unexpected.conf")
	delete(assets, "wg.conf")
	if _, err := NativeBaseSource("wg", assets); err == nil {
		t.Fatal("split source substituted for a full native profile")
	}
}

func TestNativeNodeHostIdentityDoesNotUseDNSSubstitution(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want bool
	}{
		{"198.51.100.8", "198.51.100.8", true},
		{"2001:db8::8", "2001:0db8:0000:0:0:0:0:8", true},
		{"Node.Example.Test.", "node.example.test", true},
		{"198.51.100.8", "198.51.100.9", false},
		{"node.example.test", "198.51.100.8", false},
		{"198.51.100.8", "node.example.test", false},
		{"node.example.test", "old.example.test", false},
		{"::ffff:198.51.100.8", "198.51.100.8", false},
		{"fe80::1%eth0", "fe80::1%eth0", false},
		{"", "", false},
		{"node.example.test:51820", "node.example.test", false},
		{"node.example.test..", "node.example.test", false},
	} {
		if got := SameNativeNodeHost(test.a, test.b); got != test.want {
			t.Fatalf("host identity %q versus %q = %v, want %v", test.a, test.b, got, test.want)
		}
	}
}

func TestNodeProfileBaseBindsSavedEndpointAndPreservesSourcePort(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, paired := range []bool{false, true} {
			t.Run(mode+"/paired="+map[bool]string{false: "false", true: "true"}[paired], func(t *testing.T) {
				encoded, profile, _ := nodeProfileFixture(t, mode, "")
				assets, err := nodeProfileAssets(encoded)
				if err != nil {
					t.Fatal(err)
				}
				full, split := "wg.conf", "wg-socks.conf"
				if mode != "wg" {
					full, split = "awg.conf", "awg-socks.conf"
				}
				original := string(assets[full])
				for _, test := range []struct{ saved, captured string }{
					{"192.0.2.99", "192.0.2.1"},
					{"node.example.test", "192.0.2.1"},
					{"node.example.test", "old.example.test"},
				} {
					profile["endpoint"] = test.saved
					assets[full] = []byte(strings.Replace(original, "192.0.2.1:51820", net.JoinHostPort(test.captured, "52999"), 1))
					if paired {
						assets[split] = []byte(strings.ReplaceAll(string(assets[full]), "0.0.0.0/0, ::/0", "10.77.0.0/24"))
					}
					if _, err := NativeBaseSourceForEndpoint(mode, assets, test.saved); err == nil {
						t.Fatal("authentic base asset retained a stale endpoint", test)
					}
					if _, err := NewNodeProfile(mode, encodeNodeBasePair(t, assets), startJSON(t, profile), "", ""); err == nil {
						t.Fatal("shared compiler adopted an unowned outer endpoint", test)
					}
				}
				profile["endpoint"] = "2001:db8::8"
				assets[full] = []byte(strings.Replace(original, "192.0.2.1:51820", "[2001:0db8:0000:0:0:0:0:8]:52999", 1))
				if paired {
					assets[split] = []byte(strings.ReplaceAll(string(assets[full]), "0.0.0.0/0, ::/0", "10.77.0.0/24"))
				}
				before := encodeNodeBasePair(t, assets)
				compiled, err := NewNodeProfile(mode, before, startJSON(t, profile), "", "")
				if err != nil {
					t.Fatal("equivalent literal endpoint rejected", err)
				}
				graph := startObject(t, compiled.Config())
				peer := graph["endpoints"].([]any)[0].(map[string]any)["peers"].([]any)[0].(map[string]any)
				if peer["port"] != float64(52999) || peer["address"] != "2001:db8::8" || before != encodeNodeBasePair(t, assets) {
					t.Fatal("host binding replaced the port, address or saved source")
				}
			})
		}
	}
}
