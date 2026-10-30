package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Windows can report different short/long spellings of the same temporary
// path. Require the selected absolute path to identify the generated file;
// identical bytes in another file are not evidence of catalog selection.
func runtimeUtilitySelectedCatalog(catalog string, selected any) error {
	path, ok := selected.(string)
	if !ok || !filepath.IsAbs(path) {
		return errors.New("selected catalog is not an absolute path")
	}
	expected, err := os.Stat(catalog)
	if err != nil {
		return err
	}
	actual, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !expected.Mode().IsRegular() || !actual.Mode().IsRegular() || !os.SameFile(expected, actual) {
		return errors.New("selected catalog does not identify the generated file")
	}
	return nil
}

// Execute the complete controller, including package initialization. Calling
// the utility helpers directly would miss the startup bug seen by the real
// Windows installer, where an unrelated catalog wrote to stderr before main.
func TestRuntimeUtilityStartup(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "router-vpn-client")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual controller: %v\n%s", err, output)
	}
	helper, err := os.ReadFile(filepath.Join("..", "..", "client", "Prepare-Windows-Mode-Catalog-v2.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, body []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func(root string) map[string]string {
		t.Helper()
		result := map[string]string{}
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if entry.IsDir() {
				result[relative+"/"] = ""
				return nil
			}
			body, err := os.ReadFile(path)
			result[relative] = string(body)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	run := func(directory, config string, args ...string) (string, string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, args...)
		command.Dir = directory
		for _, value := range os.Environ() {
			name, _, _ := strings.Cut(value, "=")
			if !strings.EqualFold(name, "HOMEVPN_CLIENT_CONFIG") && !strings.EqualFold(name, "HOMEVPN_ROOT") && !strings.EqualFold(name, "HOMEVPN_PORTABLE") {
				command.Env = append(command.Env, value)
			}
		}
		if config != "" {
			command.Env = append(command.Env, "HOMEVPN_CLIENT_CONFIG="+config)
		}
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		if ctx.Err() != nil {
			t.Fatalf("controller did not finish: %v\n%s", ctx.Err(), stderr.String())
		}
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		return stdout.String(), stderr.String(), code
	}

	t.Run("catalog-file-identity-controls", func(t *testing.T) {
		root := t.TempDir()
		catalog := filepath.Join(root, "modes.windows.json")
		other := filepath.Join(root, "other-catalog.json")
		write(catalog, []byte("[]\n"))
		write(other, []byte("[]\n"))
		// Keep the dot component uncleaned: this is a distinct spelling of the
		// actual file on every host, so literal string equality would fail.
		alias := root + string(os.PathSeparator) + "." + string(os.PathSeparator) + "modes.windows.json"
		if alias == catalog {
			t.Fatal("catalog identity control has no path alias")
		}
		for _, selected := range []string{catalog, alias} {
			if err := runtimeUtilitySelectedCatalog(catalog, selected); err != nil {
				t.Fatalf("same catalog rejected for %q: %v", selected, err)
			}
		}
		for _, selected := range []any{other, filepath.Join(root, "missing.json"), root, "modes.windows.json", "", 42} {
			if err := runtimeUtilitySelectedCatalog(catalog, selected); err == nil {
				t.Fatalf("wrong or missing selected catalog accepted: %v", selected)
			}
		}
		if err := runtimeUtilitySelectedCatalog(filepath.Join(root, "missing-generated.json"), catalog); err == nil {
			t.Fatal("missing generated catalog accepted")
		}
	})

	missing := t.TempDir()
	invalid := t.TempDir()
	write(filepath.Join(invalid, "runtime", "native", "NATIVE-RUNTIME.json"), []byte("{invalid-receipt"))
	write(filepath.Join(invalid, "runtime", "amnezia", "AMNEZIA-RUNTIME.json"), []byte("{invalid-receipt"))
	for _, input := range []struct{ name, config string }{
		{"missing", ""},
		{"malformed", "{unrelated-invalid-config"},
		{"unsafe-public-probe", `{"health_url":"` + legacyPublicHealthURL + `","custom":"preserve"}`},
		{"safe-private-probe", `{"health_url":"http://10.77.0.1:8787/health","custom":"preserve"}`},
	} {
		for _, explicit := range []bool{false, true} {
			label := input.name + "/ambient-cwd"
			if explicit {
				label = input.name + "/explicit-unrelated-config"
			}
			t.Run(label, func(t *testing.T) {
				root := t.TempDir()
				write(filepath.Join(root, "client", "Prepare-Windows-Mode-Catalog-v2.ps1"), helper)
				if input.config != "" {
					write(filepath.Join(root, "client.json"), []byte(input.config))
				}
				before := snapshot(root)
				cwd, config := root, ""
				if explicit {
					cwd, config = t.TempDir(), filepath.Join(root, "client.json")
				}
				cwdBefore := snapshot(cwd)
				for _, utility := range []struct{ flag, missing, invalid string }{
					{"--verify-native-runtime", "native engine directory: native AmneziaWG package directory is missing or linked", "native runtime receipt differs from the required source, target or payload"},
					{"--verify-amnezia-runtime", "native AmneziaWG package directory is missing or linked", "native AmneziaWG receipt must be exact unambiguous JSON"},
				} {
					for _, request := range []struct {
						args []string
						want string
					}{
						{[]string{utility.flag}, utility.flag + " requires one application root"},
						{[]string{utility.flag, missing, "extra-root"}, utility.flag + " requires one application root"},
						{[]string{utility.flag, missing}, utility.missing},
						{[]string{utility.flag, invalid}, utility.invalid},
					} {
						stdout, stderr, code := run(cwd, config, request.args...)
						if code != 1 || stdout != "" || stderr != request.want+"\n" {
							t.Fatalf("utility %v must return only its own verification error, got exit=%d stdout=%q stderr=%q", request.args, code, stdout, stderr)
						}
						if !reflect.DeepEqual(snapshot(root), before) || !reflect.DeepEqual(snapshot(cwd), cwdBefore) {
							t.Fatalf("utility %v changed unrelated application data", request.args)
						}
					}
				}
			})
		}
	}

	t.Run("physical-protection-admission-before-configuration", func(t *testing.T) {
		root := t.TempDir()
		write(filepath.Join(root, "client", "Prepare-Windows-Mode-Catalog-v2.ps1"), helper)
		write(filepath.Join(root, "client.json"), []byte("{unrelated-invalid-config"))
		before := snapshot(root)
		for _, args := range [][]string{
			{windowsProtectionUtilityFlag},
			{windowsProtectionUtilityFlag, "unknown"},
			{windowsProtectionUtilityFlag, "release", "foreign-owner"},
			{windowsProtectionUtilityFlag, "force-off", "foreign-path"},
			{windowsProtectionUtilityFlag, "status", "foreign-object"},
			{windowsProtectionUtilityFlag, "--help"},
		} {
			stdout, stderr, code := run(root, filepath.Join(root, "client.json"), args...)
			if code != 1 || stdout != "" || stderr != "--windows-physical-protection requires exactly probe, status, release or force-off\n" {
				t.Fatalf("physical protection utility admitted arbitrary input or ordinary startup: args=%v code=%d out=%q err=%q", args, code, stdout, stderr)
			}
			if !reflect.DeepEqual(snapshot(root), before) {
				t.Fatal("rejected protection utility changed unrelated application data")
			}
		}
		if runtime.GOOS != "windows" {
			for _, operation := range []string{"probe", "status", "release", "force-off"} {
				stdout, stderr, code := run(root, filepath.Join(root, "client.json"), windowsProtectionUtilityFlag, operation)
				if code != 1 || stdout != "" || stderr != "owned Windows physical protection requires Windows\n" || !reflect.DeepEqual(snapshot(root), before) {
					t.Fatalf("foreign platform fell through to ordinary startup: operation=%s code=%d out=%q err=%q", operation, code, stdout, stderr)
				}
			}
		}
	})

	t.Run("darwin-pf-before-configuration", func(t *testing.T) {
		root := t.TempDir()
		write(filepath.Join(root, "client.json"), []byte("{unrelated-invalid-config"))
		before := snapshot(root)
		for _, args := range [][]string{{darwinOwnedPFArgument}, {darwinOwnedPFArgument, "clear"}, {darwinOwnedPFArgument, "apply", "foreign-owner"}} {
			stdout, stderr, code := run(root, filepath.Join(root, "client.json"), args...)
			if code != 1 || stdout != "" || stderr != "the fixed Darwin PF utility requires exactly plan or apply\n" || !reflect.DeepEqual(snapshot(root), before) {
				t.Fatalf("Darwin PF utility admitted ordinary startup or arbitrary authority: args=%v code=%d out=%q err=%q", args, code, stdout, stderr)
			}
		}
		if runtime.GOOS != "darwin" {
			for _, phase := range []string{"plan", "apply"} {
				stdout, stderr, code := run(root, filepath.Join(root, "client.json"), darwinOwnedPFArgument, phase)
				if code != 1 || stdout != "" || stderr != "the installed Darwin PF utility requires macOS\n" || !reflect.DeepEqual(snapshot(root), before) {
					t.Fatalf("Darwin PF utility fell through to ordinary startup on another platform: phase=%s code=%d out=%q err=%q", phase, code, stdout, stderr)
				}
			}
		}
	})

	t.Run("normal-startup-migrates-trust-and-prepares-catalog", func(t *testing.T) {
		root := t.TempDir()
		write(filepath.Join(root, "client", "Prepare-Windows-Mode-Catalog-v2.ps1"), helper)
		write(filepath.Join(root, "client.json"), []byte(`{"health_url":"`+legacyPublicHealthURL+`","modes_file":"modes.json","scripts_dir":"modes","state_file":"state.json","profiles_file":"routers.json","custom":"preserve"}`))
		write(filepath.Join(root, "modes.json"), []byte(`[{"id":"first","command":[],"check_command":[],"stop_command":[]},{"id":"second","command":[],"check_command":[],"stop_command":[]}]`))
		// Stop normal startup after configuration/catalog processing and before
		// opening any listener or attempting a connection.
		write(filepath.Join(root, "routers.json"), []byte("{invalid-profiles"))
		stdout, stderr, code := run(root, "")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "read router profiles:") || strings.Contains(stderr, "catalog preparation failed") {
			t.Fatalf("normal startup did not reach the profile boundary: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		var config map[string]any
		body, err := os.ReadFile(filepath.Join(root, "client.json"))
		if err != nil || json.Unmarshal(body, &config) != nil || config["health_url"] != defaultPrivatePathProbeURL || config["custom"] != "preserve" {
			t.Fatalf("normal startup lost trust migration or existing config: %s (%v)", body, err)
		}
		if runtime.GOOS == "windows" {
			catalog := filepath.Join(root, "modes.windows.json")
			if err := runtimeUtilitySelectedCatalog(catalog, config["modes_file"]); err != nil {
				t.Fatalf("normal Windows startup did not prepare/select its native catalog: expected=%q selected=%q: %v", catalog, config["modes_file"], err)
			}
			t.Logf("Windows selected catalog identifies generated file: expected=%q selected=%q", catalog, config["modes_file"])
		}
	})
	t.Run("normal-startup-rejects-malformed-trust-before-catalog", func(t *testing.T) {
		root := t.TempDir()
		write(filepath.Join(root, "client", "Prepare-Windows-Mode-Catalog-v2.ps1"), helper)
		write(filepath.Join(root, "client.json"), []byte("{invalid-config"))
		write(filepath.Join(root, "modes.json"), []byte(`[{"id":"first"},{"id":"second"}]`))
		before := snapshot(root)
		stdout, stderr, code := run(root, "")
		if code == 0 || stdout != "" || !strings.Contains(stderr, "cannot establish a safe path-proof configuration:") || strings.Contains(stderr, "catalog preparation failed") || !reflect.DeepEqual(snapshot(root), before) {
			t.Fatalf("normal startup bypassed trust validation or ran the catalog first: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
}
