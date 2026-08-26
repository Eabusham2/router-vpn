package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPortablePrivateStoreRoundTrip(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Data", "client.json")
	if err := atomicWritePortablePrivate(path, []byte("{\"listen\":\"127.0.0.1:8788\"}\n")); err != nil {
		t.Fatal(err)
	}
	body, err := readPortablePrivate(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "{\"listen\":\"127.0.0.1:8788\"}\n" {
		t.Fatalf("body=%q", body)
	}
	if info, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".client.json.tmp-*")); err != nil {
		t.Fatal(err)
	} else if len(matches) != 0 {
		t.Fatalf("temporary files survived commit: %v", matches)
	}
}

func TestPortablePrivateStoreRejectsSymlinkDataDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	data := filepath.Join(root, "Data")
	if err := os.Symlink(outside, data); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := atomicWritePortablePrivate(filepath.Join(data, "routers.json"), []byte("{}\n")); err == nil {
		t.Fatal("Portable private writer accepted symlink Data directory")
	}
	if entries, err := os.ReadDir(outside); err != nil {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Fatalf("private state escaped through Data symlink: %v", entries)
	}
}

func TestPortablePrivateStoreRejectsNestedSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	nested := filepath.Join(root, "portable")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	redirect := filepath.Join(nested, "redirect")
	if err := os.Symlink(outside, redirect); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	path := filepath.Join(redirect, "Data", "client.json")
	if err := atomicWritePortablePrivate(path, []byte("{}\n")); err == nil {
		t.Fatal("Portable private writer accepted nested symlink ancestor")
	}
}

func TestPortableCopyDefaultRejectsPoisonedExistingTarget(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "default.json")
	real := filepath.Join(root, "real.json")
	dst := filepath.Join(root, "Data", "routers.json")
	if err := os.WriteFile(src, []byte("{\"profiles\":[]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, dst); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := copyPortablePrivate(src, dst, false); err == nil {
		t.Fatal("Portable default copy accepted a symlink existing target")
	}
	if body, err := os.ReadFile(real); err != nil {
		t.Fatal(err)
	} else if string(body) != "secret\n" {
		t.Fatalf("symlink target changed: %q", body)
	}
}

func TestPortablePackageSourceRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real.json")
	link := filepath.Join(root, "source.json")
	if err := os.WriteFile(real, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readPortablePackageFile(link, 1024); err == nil {
		t.Fatal("Portable launcher accepted a symlinked package source")
	}
}

func TestPortablePackageSourceRejectsSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "modes.json"), []byte("[]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(root, "App")
	if err := os.Mkdir(app, 0o700); err != nil {
		t.Fatal(err)
	}
	redirect := filepath.Join(app, "RouterVPN")
	if err := os.Symlink(outside, redirect); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readPortablePackageFile(filepath.Join(redirect, "modes.json"), 1024); err == nil {
		t.Fatal("Portable launcher accepted a package source through a symlink ancestor")
	}
}

func TestPortableRegularExistsRejectsRuntimeSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "Data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	windows := filepath.Join(outside, "windows")
	if err := os.Mkdir(windows, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(windows, "sing-box.exe"), []byte("fake\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(data, "runtime")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if portableRegularExists(filepath.Join(data, "runtime", "windows", "sing-box.exe")) {
		t.Fatal("Portable runtime readiness accepted a binary through a symlink ancestor")
	}
}
