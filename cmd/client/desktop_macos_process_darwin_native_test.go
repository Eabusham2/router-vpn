//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/macosprocess"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "routervpn-external" {
		// This role exists only in the explicitly tagged disposable-host fixture.
		if err := macOSRuntimeFixtureChild(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(123)
		}
		os.Exit(0)
	}
}
func macOSRuntimeFixtureChild() error {
	if os.Getuid() != 0 || len(os.Args) != 12 {
		return errors.New("runtime fixture lacks its exact privileged invocation")
	}
	keys := []string{"--runtime-dir", "--session", "--physical-source-sha256", "--config-sha256", "--darwin-control"}
	for i, key := range keys {
		if os.Args[2+i*2] != key {
			return errors.New("runtime fixture received another command")
		}
	}
	if os.Args[11] != "inherited-v1" {
		return errors.New("runtime fixture lacks its fixed inherited protocol")
	}
	scope := macosprocess.Scope{Workspace: os.Args[3], Session: os.Args[5], Source: os.Args[7], Config: os.Args[9]}
	body, err := os.ReadFile(filepath.Join(macOSOwnedControllerRoot, "fixture-native-authority"))
	if err != nil || string(body) != "explicit disposable macOS controller fixture\n" {
		return errors.New("runtime fixture has no explicit disposable authority")
	}
	body, err = os.ReadFile(filepath.Join(scope.Workspace, "capture.json"))
	if err != nil {
		return err
	}
	var options struct {
		Case string `json:"case"`
	}
	if json.Unmarshal(body, &options) != nil {
		return errors.New("runtime fixture has no original case")
	}
	if options.Case == "foreign-exec" {
		for fd := 3; fd <= 10; fd++ {
			syscall.CloseOnExec(fd)
		}
		return syscall.Exec("/bin/sleep", []string{"sleep", "15"}, []string{"PATH=/usr/bin:/bin"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	capture, err := macosprocess.InheritCapture(ctx, scope)
	if err != nil {
		return err
	}
	defer capture.Close()
	bootstrap, err := macosprocess.BindInherited(ctx, capture)
	if err != nil {
		return err
	}
	defer bootstrap.Close()
	return bootstrap.WaitStop(ctx, func(context.Context) error {
		if options.Case == "cleanup-failure" {
			return errors.New("fixture retained native cleanup")
		}
		marker, err := macOSRuntimeFixtureCleanedPath(macOSOwnedControllerRoot, scope.Workspace)
		if err != nil {
			return err
		}
		return os.WriteFile(marker, []byte("original native cleanup\n"), 0600)
	})
}

func macOSRuntimeFixtureInstall(t *testing.T) {
	t.Helper()
	directory := filepath.Dir(macosprocess.EnginePath)
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(macOSOwnedExecutable())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(macosprocess.EnginePath, binary, 0755); err != nil {
		t.Fatal(err)
	}
	// Distinct signed CodeDirectories make controller/runtime interchange a
	// native negative even though this fixture shares a compiled test program.
	signed := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", "--identifier", "routervpn.fixture.captured.engine", macosprocess.EnginePath)
	if output, err := signed.CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	binary, err = os.ReadFile(macosprocess.EnginePath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	digest := hex.EncodeToString(sum[:])
	catalog, _ := json.Marshal(map[string]any{"Runtime": "sing-box-routervpn", "Target": "darwin/" + runtime.GOARCH, "Size": len(binary), "SHA256": digest, "Files": map[string]any{"sing-box-routervpn": map[string]any{"Size": len(binary), "SHA256": digest}}})
	if err = os.WriteFile(macosprocess.CatalogPath, catalog, 0644); err != nil {
		t.Fatal(err)
	}
}

// Called within the actual inherited installed controller, so both image and
// GUI/socket/lock evidence originate from the real supervisor lifecycle.
func macOSRuntimeFixtureCases(ctx context.Context, parent *desktopMacOSSessionCapture) error {
	verify := func(ctx context.Context, root string) (string, error) {
		if root != macOSOwnedControllerRoot {
			return "", errors.New("foreign fixture root")
		}
		return macosprocess.EnginePath, ctx.Err()
	}
	for _, scenario := range []string{"joined-cleanup", "workspace-growth", "workspace-replaced", "input-hard-linked", "input-replaced", "catalog-replaced", "runtime-replaced", "foreign-exec", "cleanup-failure", "canceled"} {
		if err := func() error {
			directory, err := newPrivateRuntimeDir(macOSOwnedControllerRoot, "native-node")
			if err != nil {
				return err
			}
			defer os.RemoveAll(directory)
			config := []byte(`{"fixture":"captured native graph"}`)
			sum := sha256.Sum256(config)
			scope := macosprocess.Scope{Workspace: directory, Session: strings.Repeat("1", 32), Source: strings.Repeat("2", 64), Config: hex.EncodeToString(sum[:])}
			for name, body := range map[string][]byte{"source.json": []byte(`{"fixture":"original source"}`), "capture.json": []byte(`{"case":"` + scenario + `"}`), "sing-box.json": config} {
				if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
					return err
				}
			}
			call := ctx
			cancel := func() {}
			if scenario == "canceled" {
				call, cancel = context.WithCancel(ctx)
				cancel()
			}
			defer cancel()
			process, startErr := startDesktopMacOSProcessWithVerifier(call, parent, scope, verify)
			if process != nil {
				defer func() {
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					_ = parent.session.Release(cleanup, process)
				}()
			}
			if scenario == "canceled" {
				if !errors.Is(startErr, context.Canceled) || process != nil || parent.Current(ctx) != nil {
					return errors.New("canceled child start changed the shared parent")
				}
				return nil
			}
			if scenario == "foreign-exec" {
				if startErr == nil || process == nil {
					return errors.New("native runtime admitted another actual main image")
				}
				if err := parent.session.Release(ctx, process); err != nil {
					return err
				}
				if process.NativeCleanup(ctx) == nil {
					return errors.New("foreign exec exit impersonated native cleanup")
				}
				return nil
			}
			if startErr != nil {
				return startErr
			}
			if err := process.Current(ctx); err != nil {
				return err
			}
			if scenario == "workspace-growth" {
				// APFS reports ordinary child entries in the directory's link
				// count. A private result file must preserve the original pin.
				if err := os.WriteFile(filepath.Join(directory, "fixture-owned-growth"), []byte("owned result\n"), 0600); err != nil {
					return err
				}
				if err := process.Current(ctx); err != nil {
					return errors.Join(err, errors.New("owned workspace growth retired its original inode"))
				}
			}
			if scenario == "workspace-replaced" || scenario == "input-hard-linked" {
				if scenario == "workspace-replaced" {
					if err := os.Rename(directory, directory+".original-fixture"); err != nil {
						return err
					}
					defer os.Rename(directory+".original-fixture", directory)
					if err := os.Mkdir(directory, 0700); err != nil {
						return err
					}
					defer os.RemoveAll(directory)
				} else {
					linked := filepath.Join(directory, "fixture-linked-input")
					if err := os.Link(filepath.Join(directory, "source.json"), linked); err != nil {
						return err
					}
					defer os.Remove(linked)
				}
				if process.Current(ctx) == nil {
					return errors.New("native child accepted replaced directory or hard-linked regular input")
				}
				if err := parent.session.Release(ctx, process); err != nil {
					return err
				}
				if process.NativeCleanup(ctx) == nil {
					return errors.New("invalid directory/input ownership produced native cleanup authority")
				}
				return nil
			}
			var path string
			switch scenario {
			case "input-replaced":
				path = filepath.Join(directory, "source.json")
			case "catalog-replaced":
				path = macosprocess.CatalogPath
			case "runtime-replaced":
				path = macosprocess.EnginePath
			}
			if path != "" {
				if err := os.Rename(path, path+".original-fixture"); err != nil {
					return err
				}
				defer os.Rename(path+".original-fixture", path)
				body, err := os.ReadFile(path + ".original-fixture")
				if err != nil {
					return err
				}
				info, err := os.Stat(path + ".original-fixture")
				if err != nil {
					return err
				}
				if err = os.WriteFile(path, body, info.Mode().Perm()); err != nil {
					return err
				}
				defer os.Remove(path)
				if process.Current(ctx) == nil {
					return errors.New("native child accepted a replaced captured pathname")
				}
				if err = parent.session.Release(ctx, process); err != nil {
					return err
				}
				if process.NativeCleanup(ctx) == nil {
					return errors.New("replaced native input produced a cleanup receipt")
				}
				return nil
			}
			err = process.StopAndJoin(ctx)
			if scenario == "cleanup-failure" {
				if err == nil {
					return errors.New("native cleanup failure produced a stopped acknowledgment")
				}
			} else {
				if err != nil {
					return err
				}
				marker, err := macOSRuntimeFixtureCleanedPath(macOSOwnedControllerRoot, directory)
				if err != nil {
					return err
				}
				body, err := os.ReadFile(marker)
				if err != nil || string(body) != "original native cleanup\n" {
					return errors.New("native child exited without original cleanup")
				}
				if process.Current(ctx) == nil {
					return errors.New("joined native child still admitted work")
				}
			}
			if err = parent.session.Release(ctx, process); err != nil {
				return err
			}
			if scenario == "cleanup-failure" {
				if process.NativeCleanup(ctx) == nil {
					return errors.New("forced child join impersonated acknowledged native cleanup")
				}
			} else if err := process.NativeCleanup(ctx); err != nil {
				return err
			}
			select {
			case <-process.joined:
			default:
				return errors.New("native child release preceded its original waiter")
			}
			return parent.Current(ctx)
		}(); err != nil {
			return fmt.Errorf("captured runtime %s: %w", scenario, err)
		}
	}
	// Keep one actual runtime alive until the original GUI/controller ends.
	// Parent shutdown must acknowledge native cleanup and join this exact
	// command before lock release, regardless of dependent iteration order.
	directory, err := newPrivateRuntimeDir(macOSOwnedControllerRoot, "native-node")
	if err != nil {
		return err
	}
	config := []byte(`{"fixture":"parent retirement"}`)
	sum := sha256.Sum256(config)
	scope := macosprocess.Scope{Workspace: directory, Session: strings.Repeat("3", 32), Source: strings.Repeat("4", 64), Config: hex.EncodeToString(sum[:])}
	for name, body := range map[string][]byte{"source.json": []byte(`{}`), "capture.json": []byte(`{"case":"parent-close"}`), "sing-box.json": config} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			return err
		}
	}
	process, err := startDesktopMacOSProcessWithVerifier(ctx, parent, scope, verify)
	if err != nil {
		return err
	}
	if err = process.Current(ctx); err != nil {
		return err
	}
	return parent.session.Retain(ctx, &macOSRuntimeFixtureDependent{process: process, directory: directory})
}

type macOSRuntimeFixtureDependent struct {
	process   *desktopMacOSProcess
	directory string
}

func (d *macOSRuntimeFixtureDependent) Close(ctx context.Context) (failure error) {
	phase := "runtime-close"
	defer func() {
		if failure != nil {
			// Controller teardown retains a failed dependent but has no error
			// return. Preserve the actual native cause before its later missing
			// marker assertion, within the runner's existing bounded log tail.
			fmt.Fprintf(os.Stderr, "captured runtime parent retirement phase=%s: %.4096s\n", phase, failure.Error())
		}
	}()
	if err := d.process.Close(ctx); err != nil {
		return err
	}
	phase = "native-cleanup-proof"
	if err := d.process.NativeCleanup(ctx); err != nil {
		return err
	}
	phase = "original-waiter"
	select {
	case <-d.process.joined:
	default:
		return errors.New("original parent released an unjoined runtime")
	}
	phase = "original-controller-locks"
	for _, file := range []*os.File{d.process.parent.parent.input, d.process.parent.parent.installLock, d.process.parent.parent.processLock} {
		if _, err := file.Stat(); err != nil {
			return errors.New("runtime join followed original lock release")
		}
	}
	phase = "original-workspace"
	if err := os.RemoveAll(d.directory); err != nil {
		return err
	}
	phase = "joined-marker"
	return os.WriteFile(macOSControllerFixtureEventPath(macOSOwnedControllerRoot, "fixture-runtime-joined"), []byte("original runtime joined before locks\n"), 0600)
}

func TestMacOSOwnedControllerNativeCapturedRuntimeChild(t *testing.T) {
	fixture := macOSControllerNativeInstall(t)
	macOSRuntimeFixtureInstall(t)
	fixture.start()
	connection := fixture.connection(fixture.uid)
	defer connection.Close()
	if _, err := connection.Write(macOSControllerNativeFrame()); err != nil {
		t.Fatal(err)
	}
	started := macOSControllerNativeReceipt(t, connection, "started", 0)
	client := macOSControllerNativeHTTP(t)
	client.Timeout = 70 * time.Second
	macOSControllerNativeAwait(t, func() bool {
		request, _ := http.NewRequest("GET", "http://"+linuxOwnedControllerAddress+"/api/status", nil)
		request.Header.Set("Authorization", "Bearer "+testLocalControllerAccess)
		response, err := client.Do(request)
		if err != nil {
			return false
		}
		response.Body.Close()
		return response.StatusCode == 200
	}, "captured runtime controller did not start")
	request, _ := http.NewRequest("POST", "http://"+linuxOwnedControllerAddress+"/api/native-runtime-fixture", nil)
	request.Header.Set("Authorization", "Bearer "+testLocalControllerAccess)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8192))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "captured native runtime cases passed\n" {
		t.Fatal("actual controller/runtime bootstrap failed", response.StatusCode, string(body), err)
	}
	originalRoot, rootBefore, err := macOSFixtureDirectoryMetadata(macOSOwnedControllerRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(macOSControllerFixtureEventPath(macOSOwnedControllerRoot, "fixture-release"), []byte("release original operation\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	joined := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
	if joined.ExitCode != 0 {
		t.Fatal("captured runtime controller did not join successfully", joined.ExitCode)
	}
	currentRoot, rootAfter, err := macOSFixtureDirectoryMetadata(macOSOwnedControllerRoot)
	if err != nil || !os.SameFile(originalRoot, currentRoot) || rootBefore != rootAfter {
		t.Fatal("actual controller teardown observation changed captured root ACL metadata", err)
	}
	if body, err := os.ReadFile(macOSControllerFixtureEventPath(macOSOwnedControllerRoot, "fixture-runtime-joined")); err != nil || string(body) != "original runtime joined before locks\n" {
		t.Fatal("actual runtime was not joined before original locks", string(body), err)
	}
}
