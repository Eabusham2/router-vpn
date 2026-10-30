//go:build windows && routervpn_windows_app_native

package windowsapp

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// This invokes the production Main composition in a real installed/Portable
// layout. The separately built shipping controller and actual App/Tray scripts
// must start, complete their owned-channel self-tests and retire before Main
// can return. The ordinary Session cases independently inspect those channels,
// the authenticated receipt and process joins in greater detail.
func TestWindowsAppEntry(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) != 2 {
		t.Fatal("the native Windows application entry requires its owned layout and case")
	}
	root, scenario := arguments[0], arguments[1]
	portable := scenario == "portable-outer-entry-selftest"
	if scenario != "installed-entry-selftest" && !portable {
		t.Fatal("unknown native Windows application entry scenario")
	}
	packageRoot, dataRoot := root, root
	if portable {
		packageRoot, dataRoot = filepath.Join(root, "App", "RouterVPN"), filepath.Join(root, "Data")
		for _, name := range []string{"client.json", "routers.json"} {
			if _, err := os.Lstat(filepath.Join(dataRoot, name)); !os.IsNotExist(err) {
				t.Fatal("the native Portable entry must exercise actual first-launch private preparation")
			}
		}
	}
	preferences := capturedSessionPreferences(t, packageRoot, dataRoot)
	original := os.Args
	os.Args = []string{original[0], "--self-test"}
	t.Cleanup(func() { os.Args = original })
	if code := Main(portable); code != 0 {
		t.Fatalf("the actual Windows application entry failed: %d", code)
	}
	for path, captured := range preferences {
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, captured) {
			t.Fatalf("application entry changed an existing saved preference: %s: %v", filepath.Base(path), err)
		}
	}
	// A live controller retains this exact packaged input independently of the
	// launcher. A Main that simply omits retirement cannot pass this check even
	// though both GUI self-tests already returned successfully.
	file, err := os.OpenFile(filepath.Join(packageRoot, "client", "RouterVPN-Windows-ControllerTransport.cs"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("application entry returned with its controller code still retained: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("actual installed/Portable entry completed its shipping UI and checked Session retirement")
}
