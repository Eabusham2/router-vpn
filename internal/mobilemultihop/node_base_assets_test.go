package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
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
