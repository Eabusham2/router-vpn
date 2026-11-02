package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func privateStoreTestRoot(t *testing.T) string {
	t.Helper()
	// Canonicalize only the new fixture directory. A system temporary-root
	// alias must not mask the explicit file, parent or replacement defect
	// each test creates below it; shipping path validation remains unchanged.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestPrivateStoreHardensAndPublishesPrivateRegularFile(t *testing.T) {
	dir := privateStoreTestRoot(t)
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readPrivateRegular(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old\n" {
		t.Fatalf("read=%q", string(got))
	}
	if mode := mustPrivateMode(t, path); mode != 0o600 {
		t.Fatalf("hardened mode=%#o", mode)
	}
	if err := atomicWritePrivate(path, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new\n" {
		t.Fatalf("published=%q", string(got))
	}
	if mode := mustPrivateMode(t, path); mode != 0o600 {
		t.Fatalf("published mode=%#o", mode)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".client.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files survived commit: %v", matches)
	}
}

func TestPrivateStoreRejectsSymlinkTargets(t *testing.T) {
	dir := privateStoreTestRoot(t)
	realPath := filepath.Join(dir, "real.json")
	linkPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(realPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	if _, err := readPrivateRegular(linkPath, 1024); err == nil {
		t.Fatal("symlink private store was accepted for read")
	}
	if err := atomicWritePrivate(linkPath, []byte("replacement\n")); err == nil {
		t.Fatal("symlink private store was accepted for write")
	}
	got, err := os.ReadFile(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret\n" {
		t.Fatalf("symlink target changed: %q", string(got))
	}
}

func TestPrivateStoreRejectsSymlinkParent(t *testing.T) {
	root := privateStoreTestRoot(t)
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	path := filepath.Join(linkedDir, "routers.json")
	if err := atomicWritePrivate(path, []byte("secret\n")); err == nil {
		t.Fatal("symlink parent was accepted for private store write")
	}
	if _, err := os.Stat(filepath.Join(realDir, "routers.json")); !os.IsNotExist(err) {
		t.Fatalf("symlink-parent write escaped into real directory: %v", err)
	}
}

func TestPrivateStoreRejectsNestedSymlinkAncestor(t *testing.T) {
	root := privateStoreTestRoot(t)
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(realDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	path := filepath.Join(linkedDir, "nested", "state", "routers.json")
	if err := atomicWritePrivate(path, []byte("secret\n")); err == nil {
		t.Fatal("nested symlink ancestor was accepted for private store write")
	}
	if _, err := os.Stat(filepath.Join(realDir, "nested", "state")); !os.IsNotExist(err) {
		t.Fatalf("nested symlink-ancestor write created redirected state: %v", err)
	}
}

func TestPrivateStoreRejectsOversizedRead(t *testing.T) {
	path := filepath.Join(privateStoreTestRoot(t), "routers.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateRegular(path, 4); err == nil {
		t.Fatal("oversized private store was accepted")
	}
}

func mustPrivateMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestPrivateStoreRejectsTargetReplacementBeforeAdoption(t *testing.T) {
	dir := privateStoreTestRoot(t)
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, []byte("owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows loads the native file ID lazily. This fixture must capture the
	// original object before it replaces the pathname under test.
	if !os.SameFile(before, before) {
		t.Fatal("original private file identity was not captured")
	}
	replacement := filepath.Join(dir, "foreign-replacement")
	if err := os.WriteFile(replacement, []byte("foreign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := atomicWritePrivateTargetUnchanged(path, before); err == nil {
		t.Fatal("foreign regular-file replacement was accepted before private adoption")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "foreign\n" {
		t.Fatalf("foreign replacement was modified: %q", string(got))
	}
}

// The ownership callback can observe a replacement writer before it returns.
// The private store must compare its original target after that last callback,
// even when the replacement has the same contents and timestamps.
func TestPrivateStoreCheckedWriteRetainsOriginalTarget(t *testing.T) {
	for _, scenario := range []string{"unchanged", "same-content", "different-content", "appeared", "removed", "refused"} {
		t.Run(scenario, func(t *testing.T) {
			root := privateStoreTestRoot(t)
			path := filepath.Join(root, "profiles.json")
			original, next, foreign := []byte("original private record\n"), []byte("new private record\n"), []byte("foreign private record\n")
			var before os.FileInfo
			if scenario != "appeared" {
				if err := atomicWritePrivate(path, original); err != nil {
					t.Fatal(err)
				}
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				before, err = file.Stat()
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
				// Keep the original object alive without retaining a Windows
				// handle that would itself prevent the replacement operation.
				if err := os.Link(path, filepath.Join(root, "original-retained.json")); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			refused := errors.New("captured ownership was revoked")
			published, err := atomicWritePrivateChecked(path, next, func() error {
				calls++
				if calls == 1 {
					return nil
				}
				if calls != 2 {
					return errors.New("private transaction repeated its final callback")
				}
				switch scenario {
				case "same-content", "different-content", "appeared":
					value := foreign
					if scenario == "same-content" {
						value = original
					}
					if err := atomicWritePrivate(path, value); err != nil {
						return err
					}
					if before != nil {
						return os.Chtimes(path, before.ModTime(), before.ModTime())
					}
				case "removed":
					return os.Remove(path)
				case "refused":
					return refused
				}
				return nil
			})
			if calls != 2 || (err == nil) != (scenario == "unchanged") || (published != nil) != (scenario == "unchanged") {
				t.Fatalf("private target changed during final ownership callback: scenario=%s calls=%d published=%t err=%v", scenario, calls, published != nil, err)
			}
			if scenario == "refused" && !errors.Is(err, refused) {
				t.Fatal("private callback failure identity was lost", err)
			}
			got, readErr := os.ReadFile(path)
			if scenario == "removed" {
				if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatal("private publication recreated a removed target", readErr)
				}
			} else {
				want := foreign
				switch scenario {
				case "unchanged":
					want = next
				case "same-content", "refused":
					want = original
				}
				if readErr != nil || !bytes.Equal(got, want) {
					t.Fatal("private transaction changed the replacement writer's bytes", readErr)
				}
			}
			if before != nil {
				kept, keepErr := os.ReadFile(filepath.Join(root, "original-retained.json"))
				if keepErr != nil || !bytes.Equal(kept, original) {
					t.Fatal("private publication overwrote the retained original object", keepErr)
				}
			}
			matches, globErr := filepath.Glob(filepath.Join(root, ".profiles.json.tmp-*"))
			if globErr != nil || len(matches) != 0 {
				t.Fatal("private publication retained an abandoned temporary file", matches, globErr)
			}
		})
	}
}
