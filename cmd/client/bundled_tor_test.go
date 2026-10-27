package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// Independently assembled object headers, without executable instructions.
// The optional real-package gate below is mandatory in desktop packaging CI.
var bundledTorHeaderFixtures = map[string]string{
	"darwin/amd64":  "z/rt/gcAAAEDAAAAAgAAAAEAAAA4AAAAAAAgAAAAAAAMAAAAOAAAABgAAAAAAAAAAAAAAAAAAAAvdXNyL2xpYi9saWJTeXN0ZW0uQi5keWxpYgAAAAAAAA==",
	"darwin/arm64":  "z/rt/gwAAAEDAAAAAgAAAAEAAAA4AAAAAAAgAAAAAAAMAAAAOAAAABgAAAAAAAAAAAAAAAAAAAAvdXNyL2xpYi9saWJTeXN0ZW0uQi5keWxpYgAAAAAAAA==",
	"linux/amd64":   "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAAABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAADAAAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAA6AAAAAAAAADoAAAAAAAAAAAQAAAAAAAAUuV0ZAQAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAADoAAAAAAAAAOgAAAAAAAAAABAAAAAAAABR5XRkBgAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAOgAAAAAAAAA6AAAAAAAAAAAEAAAAAAAAA==",
	"linux/arm64":   "f0VMRgIBAQAAAAAAAAAAAAIAtwABAAAAAABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAADAAAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAA6AAAAAAAAADoAAAAAAAAAAAQAAAAAAAAUuV0ZAQAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAADoAAAAAAAAAOgAAAAAAAAAABAAAAAAAABR5XRkBgAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAOgAAAAAAAAA6AAAAAAAAAAAEAAAAAAAAA==",
	"windows/amd64": "TVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQRQAAZIYBAAAAAAAAAAAAAAAAAPAAIgALAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAEAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAuaWRhdGEAAAACAAAAEAAAAAIAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAS0VSTkVMMzIuZGxsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
	"windows/arm64": "TVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQRQAAZIYBAAAAAAAAAAAAAAAAAPAAIgALAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAEAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAuaWRhdGEAAAACAAAAEAAAAAIAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAS0VSTkVMMzIuZGxsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
}

func bundledTorFixture(t *testing.T, target string) (string, bundledTorReceipt) {
	t.Helper()
	directory := t.TempDir()
	root := filepath.Join("..", "..")
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	executable, execution, err := bundledTorExecution(target)
	if err != nil {
		t.Fatal(err)
	}
	r := bundledTorReceipt{Schema: 1, Runtime: "tor-routervpn", Version: bundledTorVersion, Revision: bundledTorRevision,
		Target: target, Executable: executable, Execution: execution, SourceSHA: bundledTorSourceSHA, PaddingSHA: bundledTorPaddingSHA,
		PaddingVersion: 1, Inputs: map[string]string{}, Dependencies: map[string]string{}, Process: map[string]string{},
		Offline: bundledTorOfflineReceipt(), Files: map[string]bundledNativeFile{}}
	names := append([]string{}, bundledTorInputs...)
	sort.Strings(names)
	var combined []byte
	for _, name := range names {
		r.Inputs[name] = bundledTorDigest(read(name))
		combined = append(combined, []byte(name+"\x00"+r.Inputs[name]+"\x00")...)
	}
	r.InputsSHA = bundledTorDigest(combined)
	for _, name := range []string{"libssl.a", "libcrypto.a", "libevent.a", "libz.a"} {
		r.Dependencies[name] = strings.Repeat("1", 64)
	}
	r.Compiler.Version, r.Compiler.Target = "metadata fixture only", executable
	r.NativeTests.Passed = true
	r.NativeTests.Selectors = []string{"routervpn_padding/..", "relaycrypt/..", "cellqueue/.."}
	r.NativeTests.SHA256 = strings.Repeat("2", 64)
	var lock struct {
		Process map[string]struct {
			Original string `json:"original"`
		} `json:"embedded_process_sha256"`
	}
	source := read("mobile/torpack/sources.json")
	if err := json.Unmarshal(source, &lock); err != nil {
		t.Fatal(err)
	}
	for name, entry := range lock.Process {
		r.Process[name] = entry.Original
	}
	image, err := base64.StdEncoding.DecodeString(bundledTorHeaderFixtures[target])
	if err != nil {
		t.Fatal(err)
	}
	r.Identity, err = bundledTorExecutableIdentity(image, target)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{bundledTorBinaryName(target): image, "TOR-SOURCE-LOCK.json": source,
		"TOR-PADDING-SOURCE-LOCK.json": read("mobile/tor/padding-source-lock.json"), "TOR-LICENSES.json": read("deploy/testfixtures/desktop-tor-licenses.json")}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		r.Files[name] = bundledNativeFile{Size: int64(len(raw)), SHA256: bundledTorDigest(raw)}
	}
	writeBundledTorFixture(t, directory, r)
	return directory, r
}

func writeBundledTorFixture(t *testing.T, directory string, r bundledTorReceipt) {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "TOR-RUNTIME.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestBundledTorCapturedPlatformReceipts(t *testing.T) {
	for target := range bundledTorHeaderFixtures {
		t.Run(target, func(t *testing.T) {
			directory, r := bundledTorFixture(t, target)
			if path, err := verifyBundledTorPayload(directory, target); err != nil || path != filepath.Join(directory, bundledTorBinaryName(target)) {
				t.Fatalf("complete captured Tor package rejected: %v %q", err, path)
			}
			mutations := map[string]func(*bundledTorReceipt){
				"source":         func(v *bundledTorReceipt) { v.SourceSHA = strings.Repeat("0", 64) },
				"padding":        func(v *bundledTorReceipt) { v.PaddingVersion = 0 },
				"stock-process":  func(v *bundledTorReceipt) { v.Runtime = "tor" },
				"foreign-target": func(v *bundledTorReceipt) { v.Target = "linux/riscv64" },
				"execution":      func(v *bundledTorReceipt) { v.Execution = "unknown" },
				"native-tests":   func(v *bundledTorReceipt) { v.NativeTests.Passed = false },
				"input-closure":  func(v *bundledTorReceipt) { v.InputsSHA = strings.Repeat("0", 64) },
				"compiler":       func(v *bundledTorReceipt) { v.Compiler.Target = "" },
				"library":        func(v *bundledTorReceipt) { v.Identity.Libraries = []string{"ambient.dll"} },
			}
			for name, change := range mutations {
				altered := r
				change(&altered)
				writeBundledTorFixture(t, directory, altered)
				if _, err := verifyBundledTorPayload(directory, target); err == nil {
					t.Fatal("invalid Tor metadata accepted: " + name)
				}
			}
			writeBundledTorFixture(t, directory, r)
			if target == "windows/arm64" && (r.Executable != "windows/amd64" || r.Execution != "windows11-amd64-emulation") {
				t.Fatal("qualified x64 Tor helper was falsely represented as native ARM64")
			}
		})
	}
}

func TestBundledTorIndependentSemanticAndExecutableRejection(t *testing.T) {
	for target := range bundledTorHeaderFixtures {
		t.Run(target, func(t *testing.T) {
			directory, r := bundledTorFixture(t, target)
			name := bundledTorBinaryName(target)
			raw, _ := os.ReadFile(filepath.Join(directory, name))
			changed := append([]byte{}, raw...)
			switch {
			case strings.HasPrefix(target, "linux/"):
				binary.LittleEndian.PutUint16(changed[18:], 0)
			case strings.HasPrefix(target, "darwin/"):
				binary.LittleEndian.PutUint32(changed[4:], 0)
			default:
				copy(changed[576:], []byte("UNOWNED1.dll\x00"))
			}
			if err := os.WriteFile(filepath.Join(directory, name), changed, 0600); err != nil {
				t.Fatal(err)
			}
			r.Files[name] = bundledNativeFile{Size: int64(len(changed)), SHA256: bundledTorDigest(changed)}
			writeBundledTorFixture(t, directory, r)
			if _, err := verifyBundledTorPayload(directory, target); err == nil {
				t.Fatal("rehashing a foreign or DLL-dependent Tor executable bypassed semantic admission")
			}
		})
	}
	directory, r := bundledTorFixture(t, "linux/amd64")
	r.Offline["owned_padding_capability"] = float64(1)
	writeBundledTorFixture(t, directory, r)
	if _, err := verifyBundledTorPayload(directory, "linux/amd64"); err == nil {
		t.Fatal("integer masquerading as an actual offline boolean was accepted")
	}
	r.Offline = bundledTorOfflineReceipt()
	delete(r.Inputs, "mobile/tor/routervpn_padding.c")
	writeBundledTorFixture(t, directory, r)
	if _, err := verifyBundledTorPayload(directory, "linux/amd64"); err == nil {
		t.Fatal("missing native padding source was accepted")
	}
}

func TestBundledTorRejectsRehashedSourceLock(t *testing.T) {
	directory, r := bundledTorFixture(t, "linux/amd64")
	path := filepath.Join(directory, "TOR-SOURCE-LOCK.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	if err := json.Unmarshal(raw, &source); err != nil {
		t.Fatal(err)
	}
	source["native_version"] = "tor unpinned"
	raw, err = json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	r.Files["TOR-SOURCE-LOCK.json"] = bundledNativeFile{Size: int64(len(raw)), SHA256: bundledTorDigest(raw)}
	writeBundledTorFixture(t, directory, r)
	if _, err := verifyBundledTorPayload(directory, "linux/amd64"); err == nil {
		t.Fatal("rehashing an unpinned Tor source lock bypassed captured source admission")
	}
}

func TestBundledTorActualPackage(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_DESKTOP_TOR_PACKAGE")
	if directory == "" {
		t.Skip("actual source-built Tor package is required by desktop delivery CI")
	}
	target := runtime.GOOS + "/" + runtime.GOARCH
	binary, err := verifyBundledTorPayload(directory, target)
	if err != nil {
		t.Fatal(err)
	}
	if binary != filepath.Join(directory, bundledTorBinaryName(target)) {
		t.Fatal("actual Tor verification selected another executable")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := bundledTorExecutableIdentity(raw, target)
	if err != nil || identity.Format == "" {
		t.Fatalf("actual executable identity failed: %v", err)
	}
	var record bundledTorReceipt
	receipt, _ := os.ReadFile(filepath.Join(directory, "TOR-RUNTIME.json"))
	if json.Unmarshal(receipt, &record) != nil || !reflect.DeepEqual(record.Identity, identity) {
		t.Fatal("actual C executable differs from native receipt identity")
	}
}

func TestNativeReceiptRequiresEveryBundledTorFile(t *testing.T) {
	for _, name := range append(append([]string{}, bundledTorRecords...), bundledTorBinaryName(runtime.GOOS+"/"+runtime.GOARCH)) {
		r := nativeReceiptFixture()
		delete(r.Files, name)
		raw, _ := json.Marshal(r)
		if _, err := validateNativeReceipt(raw); err == nil {
			t.Fatal("incomplete native runtime accepted missing " + name)
		}
	}
}
