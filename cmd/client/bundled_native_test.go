package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func nativeReceiptFixture() bundledNativeReceipt {
	digest := strings.Repeat("1", 64)
	r := bundledNativeReceipt{Schema: 1, Runtime: "sing-box-routervpn", Version: "1.14.1", Upstream: bundledAmneziaCore, Xray: bundledNativeXray, AmneziaVersion: bundledAmneziaVersion, AmneziaSum: bundledAmneziaSum, Rosenpass: bundledNativeRosenpass, Policy: digest, Target: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: bundledAmneziaGo, RustToolchain: "1.99.0", PQABI: 1, Size: 42, SHA256: digest, Files: map[string]bundledNativeFile{}}
	for _, name := range []string{nativeBinaryName(), "SING-BOX-LICENSE", "AMNEZIA-LICENSE", "XRAY-LICENSE", "ROSENPASS-LICENSE-MIT", "ROSENPASS-LICENSE-APACHE", "CRONET-LICENSE"} {
		r.Files[name] = bundledNativeFile{42, digest}
	}
	if runtime.GOOS == "linux" {
		r.Files["libcronet.so"] = bundledNativeFile{42, digest}
	}
	if runtime.GOOS == "windows" {
		r.Files["libcronet.dll"] = bundledNativeFile{42, digest}
	}
	return r
}

func TestNativeReceiptRequiresExactTargetsPinsAndPayload(t *testing.T) {
	encode := func(r bundledNativeReceipt) []byte {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := validateNativeReceipt(encode(nativeReceiptFixture())); err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*bundledNativeReceipt){
		"core":      func(r *bundledNativeReceipt) { r.Upstream = "latest" },
		"xray":      func(r *bundledNativeReceipt) { r.Xray = "latest" },
		"awg":       func(r *bundledNativeReceipt) { r.AmneziaSum = "wrong" },
		"pq":        func(r *bundledNativeReceipt) { r.PQABI = 0 },
		"pq-source": func(r *bundledNativeReceipt) { r.Rosenpass = "main" },
		"target":    func(r *bundledNativeReceipt) { r.Target = "another/target" },
		"go":        func(r *bundledNativeReceipt) { r.Toolchain = "go1.24.0" },
		"rust":      func(r *bundledNativeReceipt) { r.RustToolchain = "stable" },
		"policy":    func(r *bundledNativeReceipt) { r.Policy = "bad" },
		"oversized": func(r *bundledNativeReceipt) { r.Size = bundledNativeMaxBytes + 1 },
		"payload":   func(r *bundledNativeReceipt) { delete(r.Files, nativeBinaryName()) },
		"license":   func(r *bundledNativeReceipt) { delete(r.Files, "ROSENPASS-LICENSE-MIT") },
		"traversal": func(r *bundledNativeReceipt) {
			r.Files["../owned-LICENSE"] = bundledNativeFile{1, strings.Repeat("1", 64)}
		},
		"binary-alias": func(r *bundledNativeReceipt) { r.Files["another.exe"] = bundledNativeFile{1, strings.Repeat("1", 64)} },
		"payload-digest": func(r *bundledNativeReceipt) {
			r.Files[nativeBinaryName()] = bundledNativeFile{42, strings.Repeat("2", 64)}
		},
	}
	for label, change := range changes {
		t.Run(label, func(t *testing.T) {
			r := nativeReceiptFixture()
			change(&r)
			if _, err := validateNativeReceipt(encode(r)); err == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
	raw := encode(nativeReceiptFixture())
	for _, bad := range [][]byte{append(raw, raw...), append([]byte(`{"native_pq_abi":0,`), raw[1:]...)} {
		if _, err := validateNativeReceipt(bad); err == nil {
			t.Fatal("ambiguous receipt accepted")
		}
	}
}

func TestNativePayloadHashAndLinkRejection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload")
	data := []byte("owned executable bytes")
	sum := sha256.Sum256(data)
	expected := bundledNativeFile{int64(len(data)), hex.EncodeToString(sum[:])}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativeFile(path, expected); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", len(data))), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativeFile(path, expected); err == nil {
		t.Fatal("tampered same-size file accepted")
	}
	linked := filepath.Join(dir, "link")
	if os.Symlink(path, linked) == nil {
		if err := verifyNativeFile(linked, expected); err == nil {
			t.Fatal("linked payload accepted")
		}
	}
}

func TestNativeLibraryEnvironmentRejectsAmbientInjection(t *testing.T) {
	env := nativeLibraryEnvironment([]string{"OTHER=keep", "LD_LIBRARY_PATH=/unowned", "LD_PRELOAD=evil.so", "DYLD_INSERT_LIBRARIES=evil.dylib", "DYLD_LIBRARY_PATH=/unowned"}, "/owned/runtime/native")
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "unowned") || strings.Contains(joined, "evil") || !strings.Contains(joined, "OTHER=keep") {
		t.Fatal(env)
	}
	if runtime.GOOS == "linux" && !strings.Contains(joined, "LD_LIBRARY_PATH=/owned/runtime/native") {
		t.Fatal(env)
	}
}
