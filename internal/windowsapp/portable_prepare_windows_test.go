//go:build windows

package windowsapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"router-vpn/internal/windowscontroller"
)

func portableNativeFixture(t *testing.T) (root, packageRoot, dataRoot, desktop string) {
	t.Helper()
	identity, err := windowscontroller.CurrentIdentity()
	if err != nil || !identity.Primary || identity.SID == "" {
		t.Fatal("native Portable test has no captured desktop", err)
	}
	root = filepath.Join(t.TempDir(), "Portable original")
	packageRoot, dataRoot = filepath.Join(root, "App", "RouterVPN"), filepath.Join(root, "Data")
	if err := os.MkdirAll(filepath.Join(packageRoot, "modes"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"client.json":  "{\"health_url\":\"http://10.77.0.1:8787/health\",\"package_preference\":{\"keep\":true}}",
		"routers.json": "{\"schema_version\":4,\"selected_id\":\"\",\"profiles\":[]}\n",
		"modes.json":   "[]\n", "logical-modes.json": "[]\n",
	} {
		path := filepath.Join(packageRoot, name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		api, err := portableNative()
		if err != nil {
			t.Fatal(err)
		}
		file, err := portableOpenExisting(path, false, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)
		if err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(portableHardenCaptured(api, file, identity.SID, false), file.Close()); err != nil {
			t.Fatal(err)
		}
	}
	return root, packageRoot, dataRoot, identity.SID
}

func assertPortablePrivateNative(t *testing.T, path, desktop string, directory bool) {
	t.Helper()
	api, err := portableNative()
	if err != nil {
		t.Fatal(err)
	}
	file, err := portableOpenExisting(path, directory, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	security, err := portableInspectSecurity(api, file)
	if err != nil {
		t.Fatal(err)
	}
	defer security.close()
	owner, _, grants, err := security.inspect()
	if err != nil || security.control&0x1000 == 0 || !portableTrustedPrincipal(owner, desktop) {
		t.Fatal("actual Portable object lost its protected original-user boundary", err)
	}
	effective := false
	for _, grant := range grants {
		if grant.allow && grant.mask != 0 {
			if grant.principal != desktop && grant.principal != "S-1-5-18" && grant.principal != "S-1-5-32-544" {
				t.Fatal("actual private bytes have an unrelated Windows reader/writer")
			}
			effective = effective || grant.flags&8 == 0
		}
	}
	if !effective {
		t.Fatal("actual Portable object has no effective private grant")
	}
}

func TestWindowsPortableRequiresCapturedCore(t *testing.T) {
	image, err := windowscontroller.PinCurrentImage()
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	self, err := windowscontroller.OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	if strings.EqualFold(filepath.Base(image.Path()), "RouterVPNPortableCore.exe") {
		t.Fatal("the independent Portable API rejection test was placed in a shipping Core layout")
	}
	for _, invoke := range []func() error{
		func() error { return PreparePortableData(context.Background(), image, self) },
		func() error { return PreparePortableData(nil, image, self) },
		func() error { return PreparePortableData(context.Background(), nil, self) },
		func() error { return PreparePortableData(context.Background(), image, nil) },
	} {
		if err := invoke(); err == nil {
			t.Fatal("Portable preparation accepted an unproved current Core owner")
		}
	}
}

func TestWindowsPortableInitializationAndRelocation(t *testing.T) {
	root, packageRoot, dataRoot, desktop := portableNativeFixture(t)
	owned := func() error { return nil }
	if err := preparePortableCaptured(context.Background(), packageRoot, dataRoot, desktop, owned); err != nil {
		t.Fatal("fresh generic Portable data did not initialize", err)
	}
	for _, name := range []string{"", "generated"} {
		assertPortablePrivateNative(t, filepath.Join(dataRoot, name), desktop, true)
	}
	for _, name := range []string{"client.json", "routers.json"} {
		assertPortablePrivateNative(t, filepath.Join(dataRoot, name), desktop, false)
	}
	routerBytes := []byte("{\"schema_version\":4,\"selected_id\":\"home\",\"profiles\":[{\"id\":\"home\",\"name\":\"Saved private node\",\"endpoint\":\"198.51.100.7\",\"api_token\":\"private-fixture-sentinel\"}],\"future_store_field\":{\"keep\":true}}\n")
	configBytes, err := os.ReadFile(filepath.Join(dataRoot, "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := portableJSONObject(configBytes)
	if err != nil {
		t.Fatal(err)
	}
	config["future_exact_number"] = json.RawMessage("9007199254740993")
	config["saved_dns"] = json.RawMessage("\"home-adguard\"")
	configBytes, _ = json.Marshal(config)
	for name, body := range map[string][]byte{
		"routers.json": routerBytes, "client.json": configBytes,
		"modes.windows.json":       []byte("preserved legacy catalog; never command authority"),
		"windows-runtime.json":     []byte("preserved runtime receipt"),
		"connection-profiles.json": []byte("preserved complete private profiles"),
	} {
		if err := os.WriteFile(filepath.Join(dataRoot, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	relocated := filepath.Join(filepath.Dir(root), "Portable relocated")
	if err := os.Rename(root, relocated); err != nil {
		t.Fatal("preparation retained a file/ancestor owner after completion", err)
	}
	packageRoot, dataRoot = filepath.Join(relocated, "App", "RouterVPN"), filepath.Join(relocated, "Data")
	if err := preparePortableCaptured(context.Background(), packageRoot, dataRoot, desktop, owned); err != nil {
		t.Fatal("existing private Portable data did not relocate", err)
	}
	current, err := os.ReadFile(filepath.Join(dataRoot, "routers.json"))
	if err != nil || !bytes.Equal(current, routerBytes) {
		t.Fatal("Portable relocation reset or reserialized selected private nodes", err)
	}
	current, err = os.ReadFile(filepath.Join(dataRoot, "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	moved, err := portableJSONObject(current)
	if err != nil || string(moved["future_exact_number"]) != "9007199254740993" || string(moved["saved_dns"]) != "\"home-adguard\"" {
		t.Fatal("Portable relocation replaced saved or unknown preferences", err)
	}
	for field, expected := range map[string]string{
		"modes_file": filepath.Join(packageRoot, "modes.json"), "scripts_dir": filepath.Join(packageRoot, "modes"),
		"profiles_file": filepath.Join(dataRoot, "routers.json"), "state_file": filepath.Join(dataRoot, "state.json"),
	} {
		var actual string
		if json.Unmarshal(moved[field], &actual) != nil || actual != expected {
			t.Fatalf("Portable relocation did not rebase owned field %s", field)
		}
	}
	for name, expected := range map[string]string{
		"modes.windows.json":   "preserved legacy catalog; never command authority",
		"windows-runtime.json": "preserved runtime receipt", "connection-profiles.json": "preserved complete private profiles",
	} {
		body, err := os.ReadFile(filepath.Join(dataRoot, name))
		if err != nil || string(body) != expected {
			t.Fatalf("Portable preparation replaced unrelated saved file %s", name)
		}
	}
	before, err := os.Stat(filepath.Join(dataRoot, "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := preparePortableCaptured(context.Background(), packageRoot, dataRoot, desktop, owned); err != nil {
		t.Fatal("repeated Portable preparation failed", err)
	}
	after, err := os.Stat(filepath.Join(dataRoot, "client.json"))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("unchanged Portable config was replaced during repeated launch", err)
	}
	if _, err := os.Lstat(filepath.Join(dataRoot, ".routervpn-prepare.lock")); !os.IsNotExist(err) {
		t.Fatal("Portable completion retained its private preparation lock", err)
	}
}

func TestWindowsPortableRejectsUnsafeAndInvalidState(t *testing.T) {
	for _, scenario := range []string{"private-hardlink", "data-link", "generated-link", "source-hardlink", "invalid-config", "invalid-routers", "existing-lock"} {
		t.Run(scenario, func(t *testing.T) {
			root, packageRoot, dataRoot, desktop := portableNativeFixture(t)
			outside := filepath.Join(root, "outside")
			if err := os.Mkdir(outside, 0700); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(outside, "sentinel.json")
			content := []byte("{\"private\":\"owned-negative-fixture\"}")
			if err := os.WriteFile(sentinel, content, 0600); err != nil {
				t.Fatal(err)
			}
			if scenario == "data-link" {
				if err := os.Symlink(outside, dataRoot); err != nil {
					t.Fatal("actual Data-link negative could not be created", err)
				}
			} else if err := os.Mkdir(dataRoot, 0700); err != nil {
				t.Fatal(err)
			}
			var unchanged string
			switch scenario {
			case "private-hardlink":
				if err := os.Link(sentinel, filepath.Join(dataRoot, "client.json")); err != nil {
					t.Fatal(err)
				}
			case "generated-link":
				if err := os.Symlink(outside, filepath.Join(dataRoot, "generated")); err != nil {
					t.Fatal("actual generated-link negative could not be created", err)
				}
			case "source-hardlink":
				if err := os.Link(filepath.Join(packageRoot, "client.json"), filepath.Join(outside, "package-alias.json")); err != nil {
					t.Fatal(err)
				}
			case "invalid-config":
				unchanged = filepath.Join(dataRoot, "client.json")
			case "invalid-routers":
				unchanged = filepath.Join(dataRoot, "routers.json")
			case "existing-lock":
				unchanged = filepath.Join(dataRoot, ".routervpn-prepare.lock")
			}
			if unchanged != "" {
				if err := os.WriteFile(unchanged, []byte("retain invalid or foreign bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := preparePortableCaptured(context.Background(), packageRoot, dataRoot, desktop, func() error { return nil }); err == nil {
				t.Fatal("unsafe/invalid existing Portable state was admitted")
			}
			actual, err := os.ReadFile(sentinel)
			if err != nil || !bytes.Equal(actual, content) {
				t.Fatal("rejected Portable state changed another retained file", err)
			}
			if unchanged != "" {
				actual, err := os.ReadFile(unchanged)
				if err != nil || string(actual) != "retain invalid or foreign bytes" {
					t.Fatal("Portable rejection reset or deleted existing bytes", err)
				}
			}
			entries, err := os.ReadDir(outside)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "sentinel.json" && entry.Name() != "package-alias.json" {
					t.Fatal("Portable preparation created state through a rejected directory link")
				}
			}
		})
	}
}

func TestWindowsPortableCancellationAndPublicationOwnership(t *testing.T) {
	_, packageRoot, dataRoot, desktop := portableNativeFixture(t)
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := preparePortableCaptured(cancelled, packageRoot, dataRoot, desktop, func() error { return nil }); err == nil {
		t.Fatal("cancelled Portable preparation proceeded")
	}
	if _, err := os.Lstat(dataRoot); !os.IsNotExist(err) {
		t.Fatal("cancelled Portable preparation created Data", err)
	}
	api, err := portableNative()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := portablePrivateDirectory(api, dataRoot, desktop)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	path := filepath.Join(dataRoot, "client.json")
	owned := func() error { return nil }
	if err := portablePublishPrivate(api, path, desktop, nil, []byte("{\"saved\":1}"), owned); err != nil {
		t.Fatal(err)
	}
	before, err := portableReadPrivate(api, path, desktop)
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte("{\"replacement\":true}")
	if err := os.WriteFile(path, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if err := portablePublishPrivate(api, path, desktop, before, []byte("{\"stale\":true}"), owned); err == nil {
		t.Fatal("stale Portable publication replaced a newer private value")
	}
	if err := portablePublishPrivate(api, filepath.Join(dataRoot, "cancelled.json"), desktop, nil, []byte("{}"), func() error { return context.Canceled }); err == nil {
		t.Fatal("revoked Portable publication became authoritative")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, replacement) {
		t.Fatal("failed Portable publication changed its replacement owner", err)
	}
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".routervpn-prepare-") || entry.Name() == "cancelled.json" {
			t.Fatal("failed Portable publication leaked or adopted temporary state")
		}
	}
}
