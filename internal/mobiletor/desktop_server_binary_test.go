package mobiletor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerTorPackageBindsActualExecutableReceiptAndFileIdentity(t *testing.T) {
	prefix := os.Getenv("ROUTERVPN_SERVER_TOR_PACKAGE")
	if prefix == "" {
		t.Skip("requires built standalone Tor package")
	}
	if _, err := VerifyServerTorPackage(prefix); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(prefix, "share/router-vpn/tor/BUILD.json"))
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(filepath.Join(prefix, "bin/routervpn-tor"))
	if err != nil {
		t.Fatal(err)
	}
	copy := t.TempDir()
	bin := filepath.Join(copy, "bin/routervpn-tor")
	receipt := filepath.Join(copy, "share/router-vpn/tor/BUILD.json")
	if os.MkdirAll(filepath.Dir(bin), 0700) != nil || os.MkdirAll(filepath.Dir(receipt), 0700) != nil || os.WriteFile(bin, binary, 0755) != nil || os.WriteFile(receipt, raw, 0644) != nil {
		t.Fatal("package fixture")
	}
	owned, err := VerifyServerTorPackage(copy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(bin, bin+".old"); err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(bin, binary, 0755) != nil {
		t.Fatal("replacement")
	}
	if owned.Current() {
		t.Fatal("same-byte replacement borrowed the executable owner")
	}
	for _, field := range []string{"source_lock_sha256", "platform", "digest", "symlink", "writable"} {
		t.Run(field, func(t *testing.T) {
			var record map[string]any
			if json.Unmarshal(raw, &record) != nil {
				t.Fatal("record")
			}
			switch field {
			case "source_lock_sha256":
				record[field] = strings.Repeat("f", 64)
			case "platform":
				record[field] = "linux/other"
			case "digest":
				record["executable"].(map[string]any)["sha256"] = strings.Repeat("f", 64)
			case "symlink":
				if os.Remove(bin) != nil || os.Symlink(bin+".old", bin) != nil {
					t.Fatal("link")
				}
				defer func() { _ = os.Remove(bin); _ = os.WriteFile(bin, binary, 0755) }()
			case "writable":
				if os.Chmod(bin, 0777) != nil {
					t.Fatal("chmod")
				}
				defer os.Chmod(bin, 0755)
			}
			changed, _ := json.Marshal(record)
			if os.WriteFile(receipt, changed, 0644) != nil {
				t.Fatal("record write")
			}
			defer os.WriteFile(receipt, raw, 0644)
			if _, err := VerifyServerTorPackage(copy); err == nil {
				t.Fatal("invalid installed native package accepted")
			}
		})
	}
}
