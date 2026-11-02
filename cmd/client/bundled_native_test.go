package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestNativeAmneziaBuildInfoRequiresExactTimerCorrection(t *testing.T) {
	// This is the actual debug/buildinfo.ReadFile shape of the pinned Go1.26.3
	// executable produced by prepare-amnezia-timers.py. Local replacements
	// carry no h1 sums; the unmodified bundle receipt still requires that sum.
	observed := `{"Path":"github.com/amnezia-vpn/amneziawg-go/v3","Version":"v3.1.20260814","Replace":{"Path":"./routervpn-patched-amnezia","Version":"(devel)"}}`
	decode := func() *debug.Module {
		t.Helper()
		var module debug.Module
		if err := json.Unmarshal([]byte(observed), &module); err != nil {
			t.Fatal(err)
		}
		return &module
	}
	unrelated := &debug.Module{Path: "example.com/unrelated", Version: "v1.0.0", Sum: "h1:unrelated"}
	if !bundledAmneziaBackend([]*debug.Module{unrelated, decode()}) {
		t.Fatal("actual pinned timer replacement was rejected")
	}
	changes := map[string]func(*debug.Module){
		"wrong-original-path":          func(m *debug.Module) { m.Path += "/alias" },
		"wrong-original-version":       func(m *debug.Module) { m.Version = "v3.1.20260815" },
		"original-version-alias":       func(m *debug.Module) { m.Version += "+incompatible" },
		"original-sum":                 func(m *debug.Module) { m.Sum = bundledAmneziaSum },
		"original-foreign-sum":         func(m *debug.Module) { m.Sum = "h1:changed" },
		"unpatched-backend":            func(m *debug.Module) { m.Replace, m.Sum = nil, bundledAmneziaSum },
		"missing-replacement":          func(m *debug.Module) { m.Replace = nil },
		"empty-replacement":            func(m *debug.Module) { m.Replace = new(debug.Module) },
		"absolute-replacement":         func(m *debug.Module) { m.Replace.Path = "/tmp/routervpn-patched-amnezia" },
		"relative-parent-replacement":  func(m *debug.Module) { m.Replace.Path = "../routervpn-patched-amnezia" },
		"normalized-replacement-alias": func(m *debug.Module) { m.Replace.Path = "./other/../routervpn-patched-amnezia" },
		"bare-replacement-alias":       func(m *debug.Module) { m.Replace.Path = "routervpn-patched-amnezia" },
		"backslash-replacement-alias":  func(m *debug.Module) { m.Replace.Path = `.\routervpn-patched-amnezia` },
		"case-replacement-alias":       func(m *debug.Module) { m.Replace.Path = "./RouterVPN-patched-amnezia" },
		"trailing-slash-alias":         func(m *debug.Module) { m.Replace.Path += "/" },
		"remote-replacement":           func(m *debug.Module) { m.Replace.Path = bundledAmneziaModule },
		"empty-replacement-version":    func(m *debug.Module) { m.Replace.Version = "" },
		"pinned-replacement-version":   func(m *debug.Module) { m.Replace.Version = bundledAmneziaVersion },
		"replacement-sum":              func(m *debug.Module) { m.Replace.Sum = bundledAmneziaSum },
		"nested-replacement":           func(m *debug.Module) { m.Replace.Replace = &debug.Module{Path: "./unowned"} },
	}
	for label, change := range changes {
		t.Run(label, func(t *testing.T) {
			module := decode()
			change(module)
			if bundledAmneziaBackend([]*debug.Module{unrelated, module}) {
				t.Fatal("unowned backend build metadata was accepted")
			}
		})
	}
	for label, modules := range map[string][]*debug.Module{
		"missing": nil, "unrelated-only": {unrelated}, "nil-dependency": {nil, decode()},
		"duplicate":          {decode(), decode()},
		"invalid-then-valid": {{Path: bundledAmneziaModule, Version: "wrong"}, decode()},
		"valid-then-invalid": {decode(), {Path: bundledAmneziaModule, Version: "wrong"}},
	} {
		t.Run(label, func(t *testing.T) {
			if bundledAmneziaBackend(modules) {
				t.Fatal("missing, duplicate or malformed backend identity was accepted")
			}
		})
	}
}

func nativeReceiptFixture() bundledNativeReceipt {
	digest := strings.Repeat("1", 64)
	r := bundledNativeReceipt{Schema: 1, Runtime: "sing-box-routervpn", Version: "1.14.1", Upstream: bundledAmneziaCore, Xray: bundledNativeXray, AmneziaVersion: bundledAmneziaVersion, AmneziaSum: bundledAmneziaSum, Rosenpass: bundledNativeRosenpass, Policy: digest, Target: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: bundledAmneziaGo, RustToolchain: "1.99.0", PQABI: 1, Size: 42, SHA256: digest, Files: map[string]bundledNativeFile{}}
	for _, name := range []string{nativeBinaryName(), "SING-BOX-LICENSE", "AMNEZIA-LICENSE", "XRAY-LICENSE", "ROSENPASS-LICENSE-MIT", "ROSENPASS-LICENSE-APACHE", "CRONET-LICENSE", "TOR-PT-NOTICES.json"} {
		r.Files[name] = bundledNativeFile{42, digest}
	}
	for _, name := range append(append([]string{}, bundledTorRecords...), bundledTorBinaryName(r.Target)) {
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
		"core":               func(r *bundledNativeReceipt) { r.Upstream = "latest" },
		"xray":               func(r *bundledNativeReceipt) { r.Xray = "latest" },
		"awg":                func(r *bundledNativeReceipt) { r.AmneziaSum = "wrong" },
		"pq":                 func(r *bundledNativeReceipt) { r.PQABI = 0 },
		"pq-source":          func(r *bundledNativeReceipt) { r.Rosenpass = "main" },
		"target":             func(r *bundledNativeReceipt) { r.Target = "another/target" },
		"go":                 func(r *bundledNativeReceipt) { r.Toolchain = "go1.24.0" },
		"rust":               func(r *bundledNativeReceipt) { r.RustToolchain = "stable" },
		"policy":             func(r *bundledNativeReceipt) { r.Policy = "bad" },
		"oversized":          func(r *bundledNativeReceipt) { r.Size = bundledNativeMaxBytes + 1 },
		"payload":            func(r *bundledNativeReceipt) { delete(r.Files, nativeBinaryName()) },
		"license":            func(r *bundledNativeReceipt) { delete(r.Files, "ROSENPASS-LICENSE-MIT") },
		"missing-pt-notices": func(r *bundledNativeReceipt) { delete(r.Files, bundledNativePTNoticesName) },
		"oversized-pt-notices": func(r *bundledNativeReceipt) {
			r.Files[bundledNativePTNoticesName] = bundledNativeFile{2<<20 + 1, strings.Repeat("1", 64)}
		},
		"ordinary-license-bound": func(r *bundledNativeReceipt) {
			r.Files["XRAY-LICENSE"] = bundledNativeFile{256<<10 + 1, strings.Repeat("1", 64)}
		},
		"misnamed-pt-notices": func(r *bundledNativeReceipt) {
			r.Files["TOR-PT-NOTICE.json"] = r.Files[bundledNativePTNoticesName]
			delete(r.Files, bundledNativePTNoticesName)
		},
		"unowned-license-alias": func(r *bundledNativeReceipt) {
			r.Files["TOR-PT-NOTICES-LICENSE"] = bundledNativeFile{42, strings.Repeat("1", 64)}
		},
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

func TestNativePTNoticesExactBoundAndPayloadIntegrity(t *testing.T) {
	for _, size := range []int64{256<<10 + 1, 302744, 2 << 20} {
		r := nativeReceiptFixture()
		r.Files[bundledNativePTNoticesName] = bundledNativeFile{size, strings.Repeat("1", 64)}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validateNativeReceipt(raw); err != nil {
			t.Fatalf("bounded notices rejected: size=%d: %v", size, err)
		}
	}
	directory := t.TempDir()
	r := nativeReceiptFixture()
	for name := range r.Files {
		body := []byte("owned native fixture " + name)
		if name == bundledNativePTNoticesName {
			body = []byte(`{"notice":"` + strings.Repeat("x", 300<<10) + `"}`)
		}
		sum := sha256.Sum256(body)
		r.Files[name] = bundledNativeFile{int64(len(body)), hex.EncodeToString(sum[:])}
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	r.Size, r.SHA256 = r.Files[nativeBinaryName()].Size, r.Files[nativeBinaryName()].SHA256
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateNativeReceipt(raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "NATIVE-RUNTIME.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativePayload(directory, r); err != nil {
		t.Fatal(err)
	}
	notices := filepath.Join(directory, bundledNativePTNoticesName)
	original, err := os.ReadFile(notices)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(notices); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativePayload(directory, r); err == nil {
		t.Fatal("missing PT notices accepted")
	}
	changed := append([]byte(nil), original...)
	changed[len(changed)/2] ^= 1
	if err := os.WriteFile(notices, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativePayload(directory, r); err == nil {
		t.Fatal("changed same-size PT notices accepted")
	}
	if err := os.WriteFile(notices, original, 0600); err != nil {
		t.Fatal(err)
	}
	misnamed := filepath.Join(directory, "TOR-PT-NOTICE.json")
	if err := os.Rename(notices, misnamed); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativePayload(directory, r); err == nil {
		t.Fatal("misnamed PT notices accepted")
	}
	if err := os.Rename(misnamed, notices); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(misnamed, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativePayload(directory, r); err == nil {
		t.Fatal("unowned extra notice payload accepted")
	}
	if err := os.Remove(misnamed); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativePayload(directory, r); err != nil {
		t.Fatal(err)
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
