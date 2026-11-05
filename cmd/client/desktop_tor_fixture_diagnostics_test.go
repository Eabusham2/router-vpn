package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

const desktopTorFixtureDiagnosticEntries = 48
const desktopTorFixtureDiagnosticDepth = 4
const desktopTorFixtureDiagnosticNameBytes = 160
const desktopTorFixtureDiagnosticStackBytes = 32 << 10

type desktopTorFixtureDiagnosticTest interface {
	Cleanup(func())
	TempDir() string
	Failed() bool
	Logf(string, ...any)
}

// Register before the FIRST TempDir: testing runs cleanups in reverse order.
// This observer therefore runs after the original RemoveAll and preserves its
// failure. It neither removes anything nor gives a late writer another chance.
func desktopTorFixtureDiagnosticTempRoot(t desktopTorFixtureDiagnosticTest) (string, error) {
	var root string
	t.Cleanup(func() {
		if !t.Failed() || root == "" {
			return
		}
		if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
			return
		}
		t.Logf("Tor fixture retained root after failed cleanup (metadata only):\n%s", desktopTorFixtureDirectoryDiagnostic(root))
		stack := make([]byte, desktopTorFixtureDiagnosticStackBytes)
		n := runtime.Stack(stack, true)
		t.Logf("Tor fixture goroutines after failed cleanup (at most %d bytes, possibly truncated):\n%s", len(stack), stack[:n])
	})
	directory := t.TempDir()
	var err error
	root, err = filepath.EvalSymlinks(directory)
	return root, err
}

func desktopTorFixtureDiagnosticError(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, os.ErrNotExist):
		return "absent"
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, os.ErrClosed):
		return "closed"
	default:
		return "other"
	}
}

// Directory entries only: no file content, environment, configuration or key
// reads. One retained os.Root confines traversal; symlinks are never traversed.
func desktopTorFixtureDirectoryDiagnostic(path string) string {
	identity, err := os.Lstat(path)
	if err != nil {
		return "root error=" + desktopTorFixtureDiagnosticError(err) + "\n"
	}
	if !identity.IsDir() || identity.Mode()&os.ModeSymlink != 0 {
		return "root type changed\n"
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return "root error=" + desktopTorFixtureDiagnosticError(err) + "\n"
	}
	defer root.Close()
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(identity, current) {
		return "root identity changed\n"
	}
	var out strings.Builder
	remaining := desktopTorFixtureDiagnosticEntries
	var visit func(string, int)
	visit = func(path string, depth int) {
		if remaining == 0 {
			return
		}
		identity, err := root.Lstat(path)
		if err != nil || !identity.IsDir() || identity.Mode()&os.ModeSymlink != 0 {
			fmt.Fprintf(&out, "depth=%d directory-identity-unavailable=%s\n", depth, desktopTorFixtureDiagnosticError(err))
			return
		}
		file, err := root.Open(path)
		if err != nil {
			fmt.Fprintf(&out, "depth=%d directory-error=%s\n", depth, desktopTorFixtureDiagnosticError(err))
			return
		}
		current, statErr := file.Stat()
		if statErr != nil || !os.SameFile(identity, current) {
			_ = file.Close()
			out.WriteString("directory identity changed\n")
			return
		}
		entries, readErr := file.ReadDir(remaining + 1)
		_ = file.Close()
		for _, entry := range entries {
			if remaining == 0 {
				out.WriteString("entry limit reached\n")
				return
			}
			remaining--
			name := entry.Name()
			shown := name
			if len(shown) > desktopTorFixtureDiagnosticNameBytes {
				shown = shown[:desktopTorFixtureDiagnosticNameBytes] + "[truncated]"
			}
			kind := "file"
			if entry.Type()&os.ModeSymlink != 0 {
				kind = "symlink"
			} else if entry.IsDir() {
				kind = "directory"
			} else if entry.Type() != 0 {
				kind = "special"
			}
			fmt.Fprintf(&out, "depth=%d name=%q type=%s\n", depth, shown, kind)
			if kind == "directory" && depth < desktopTorFixtureDiagnosticDepth {
				visit(filepath.Join(path, name), depth+1)
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			fmt.Fprintf(&out, "directory-error=%s\n", desktopTorFixtureDiagnosticError(readErr))
		}
	}
	visit(".", 0)
	return out.String()
}

func TestDesktopTorFixtureDiagnosticIsBoundedAndReadOnly(t *testing.T) {
	root := t.TempDir()
	secret := []byte("PRIVATE CONTENT MUST NOT APPEAR")
	for i := 0; i < desktopTorFixtureDiagnosticEntries+8; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("entry-%03d", i)), secret, 0600); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	original := make(map[string]os.FileInfo, len(before))
	for _, entry := range before {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		original[entry.Name()] = info
	}
	output := desktopTorFixtureDirectoryDiagnostic(root)
	if strings.Contains(output, string(secret)) || strings.Count(output, "type=") != desktopTorFixtureDiagnosticEntries || !strings.Contains(output, "entry limit reached") || len(output) > 48*240 {
		t.Fatal("diagnostic disclosed contents or exceeded its entry/output bound", output)
	}
	after, err := os.ReadDir(root)
	if err != nil || len(after) != len(before) {
		t.Fatal("diagnostic mutated directory", err)
	}
	for _, entry := range after {
		raw, err := os.ReadFile(filepath.Join(root, entry.Name()))
		info, statErr := entry.Info()
		prior := original[entry.Name()]
		if err != nil || statErr != nil || prior == nil || string(raw) != string(secret) || info.Mode() != prior.Mode() || !os.SameFile(prior, info) {
			t.Fatal("diagnostic changed original file", err, statErr)
		}
	}
}

func TestDesktopTorFixtureDiagnosticDoesNotFollowSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "outside-secret-name"), []byte("outside-secret-body"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314)) { // ERROR_PRIVILEGE_NOT_HELD
			t.Skip("native symlink creation unavailable: " + desktopTorFixtureDiagnosticError(err))
		}
		t.Fatal(err)
	}
	output := desktopTorFixtureDirectoryDiagnostic(root)
	if !strings.Contains(output, "type=symlink") || strings.Contains(output, "outside-secret") {
		t.Fatal("diagnostic followed symlink", output)
	}
	if output := desktopTorFixtureDirectoryDiagnostic(filepath.Join(root, "link")); output != "root type changed\n" {
		t.Fatal("diagnostic followed replaced root symlink", output)
	}
}

func TestDesktopTorFixtureDiagnosticBoundsDepthNamesAndErrors(t *testing.T) {
	root := t.TempDir()
	path := root
	for i := 0; i < desktopTorFixtureDiagnosticDepth+3; i++ {
		path = filepath.Join(path, fmt.Sprintf("level-%d", i))
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, strings.Repeat("n", 200)), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	output := desktopTorFixtureDirectoryDiagnostic(root)
	if strings.Contains(output, "level-5") || strings.Contains(output, strings.Repeat("n", 161)) || !strings.Contains(output, "[truncated]") {
		t.Fatal("diagnostic exceeded depth or name bound", output)
	}
	if got := desktopTorFixtureDiagnosticError(errors.New("PRIVATE ERROR CONTENT")); got != "other" {
		t.Fatal("diagnostic disclosed raw error", got)
	}
}

type desktopTorFixtureCleanupOrder struct {
	root      string
	callbacks []func()
	failed    bool
	events    []string
	logs      []string
}

func (f *desktopTorFixtureCleanupOrder) Cleanup(fn func()) { f.callbacks = append(f.callbacks, fn) }
func (f *desktopTorFixtureCleanupOrder) TempDir() string {
	f.Cleanup(func() { f.events = append(f.events, "original-cleanup-failure"); f.failed = true })
	return f.root
}
func (f *desktopTorFixtureCleanupOrder) Failed() bool { return f.failed }
func (f *desktopTorFixtureCleanupOrder) Logf(format string, args ...any) {
	f.events = append(f.events, "diagnostic")
	f.logs = append(f.logs, fmt.Sprintf(format, args...))
}

func TestDesktopTorFixtureDiagnosticRunsAfterOriginalCleanup(t *testing.T) {
	f := &desktopTorFixtureCleanupOrder{root: t.TempDir()}
	if _, err := desktopTorFixtureDiagnosticTempRoot(f); err != nil {
		t.Fatal(err)
	}
	if len(f.callbacks) != 2 {
		t.Fatal("diagnostic did not precede first TempDir registration")
	}
	for i := len(f.callbacks) - 1; i >= 0; i-- {
		f.callbacks[i]()
	}
	if !f.failed || strings.Join(f.events, ",") != "original-cleanup-failure,diagnostic,diagnostic" {
		t.Fatal("diagnostic changed failure or ran before original cleanup", f.events)
	}
	if _, err := os.Stat(f.root); err != nil {
		t.Fatal("diagnostic retried removal", err)
	}
	if len(f.logs) != 2 || len(f.logs[1]) > desktopTorFixtureDiagnosticStackBytes+160 {
		t.Fatal("diagnostic exceeded stack output bound")
	}
}

func TestDesktopTorEntryFixtureRegistersDiagnosticBeforeFirstTempDir(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "desktop_tor_predecessor_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var helper, nextFixture token.Pos
	count := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "desktopTorEntryFixture" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if selected, ok := call.Fun.(*ast.SelectorExpr); ok && selected.Sel.Name == "TempDir" {
				t.Error("entry fixture registered an unobserved TempDir cleanup")
			}
			if name, ok := call.Fun.(*ast.Ident); ok {
				switch name.Name {
				case "desktopTorFixtureDiagnosticTempRoot":
					helper = call.Pos()
					count++
				case "desktopNodeFixture":
					nextFixture = call.Pos()
				}
			}
			return true
		})
	}
	if count != 1 || helper == token.NoPos || nextFixture <= helper {
		t.Fatal("actual entry fixture did not register diagnostics before its first TempDir and nested fixture")
	}
}
