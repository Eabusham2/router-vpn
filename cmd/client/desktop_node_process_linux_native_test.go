//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/linuxprotection"
)

const linuxNodeLauncherMarker = "ROUTERVPN_NODE_LINUX_PROCESS_FIXTURE"

func init() {
	if os.Getenv(linuxNodeLauncherMarker) != "1" {
		return
	}
	if err := linuxNodeLauncherEngineFixture(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(121)
	}
	os.Exit(0)
}

// Only the child fixture protocol is modeled. It runs from the actual pinned
// installed image with the same inherited descriptors and native bootstrap.
func linuxNodeLauncherEngineFixture() error {
	if os.Getuid() != 0 || len(os.Args) != 18 || os.Args[1] != "routervpn-node" {
		return errors.New("native engine fixture has the wrong invocation")
	}
	values := make(map[string]string)
	for i := 2; i < len(os.Args); i += 2 {
		values[os.Args[i]] = os.Args[i+1]
	}
	if values["--linux-parent-channel"] != "3" || values["--linux-parent-directory"] != "4" {
		return errors.New("native engine fixture lost its original inherited descriptors")
	}
	for _, fd := range []int{3, 4, 5} {
		syscall.CloseOnExec(fd)
	}
	image := os.NewFile(5, "original-pinned-engine")
	defer image.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	channel, err := linuxprocess.CaptureChannel(os.NewFile(3, "original-controller-channel"))
	if err != nil {
		if channel != nil {
			_ = channel.Close(ctx)
		}
		return err
	}
	capture, err := linuxprotection.NodeCommandCaptureSHA256(values["--session"], values["--physical-source-sha256"], values["--config-sha256"])
	if err != nil || capture != values["--linux-parent-capture"] {
		_ = channel.Close(ctx)
		return errors.New("native engine fixture changed its command capture")
	}
	bootstrap, err := linuxprocess.BindInheritedParent(ctx, channel, os.NewFile(4, "original-controller-task"), capture)
	if bootstrap != nil {
		defer bootstrap.Close(context.Background())
	}
	if err != nil {
		return err
	}
	if err := bootstrap.CheckCapture(ctx, capture); err != nil {
		return err
	}
	if cwd, err := os.Getwd(); err != nil || cwd != values["--runtime-dir"] {
		return errors.Join(err, errors.New("native engine fixture lost its captured working directory"))
	}
	if err := bootstrap.Send(ctx, []byte("native-engine-ready")); err != nil {
		return err
	}
	for {
		body, err := bootstrap.Receive(ctx)
		if err != nil {
			return nil
		}
		switch string(body) {
		case "ping":
			if err := bootstrap.Send(ctx, []byte("pong")); err != nil {
				return err
			}
		case "exit":
			return nil
		default:
			return errors.New("native engine fixture received an unrelated message")
		}
	}
}

func linuxNodeLauncherPackage() error {
	directory := filepath.Join(linuxOwnedControllerRoot, "runtime", "native")
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	image, err := os.ReadFile(filepath.Join(linuxOwnedControllerRoot, "router-vpn-client"))
	if err != nil {
		return err
	}
	receipt := nativeReceiptFixture()
	for name := range receipt.Files {
		body := []byte("owned native launcher fixture; not a protocol receipt")
		if name == nativeBinaryName() {
			body = image
		}
		if err := os.WriteFile(filepath.Join(directory, name), body, 0755); err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		receipt.Files[name] = bundledNativeFile{Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
	}
	receipt.Size, receipt.SHA256 = receipt.Files[nativeBinaryName()].Size, receipt.Files[nativeBinaryName()].SHA256
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "NATIVE-RUNTIME.json"), raw, 0600)
}

func linuxNodeLauncherFixture(controller *ownedDesktopController, scenario string) error {
	a := &app{localController: controller, cfg: common.ClientConfig{
		ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"),
		ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"), StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json"),
	}}
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "launcher-fixture-rendezvous")
	defer gate.Close()
	var signal [1]byte
	if _, err := io.ReadFull(gate, signal[:]); err != nil || signal[0] != 1 {
		return errors.Join(err, errors.New("launcher fixture lost its rendezvous"))
	}
	if err := linuxNodeLauncherPackage(); err != nil {
		return err
	}
	directory := filepath.Join(linuxOwnedControllerRoot, "runtime", "owned-node-fixture")
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	session, source, config := strings.Repeat("1", 32), strings.Repeat("2", 64), strings.Repeat("3", 64)
	capture, err := linuxprotection.NodeCommandCaptureSHA256(session, source, config)
	if err != nil {
		return err
	}
	arguments := []string{"routervpn-node", "--runtime-dir", directory, "--session", session, "--config-sha256", config, "--physical-source-sha256", source, "--physical-transfer-sha256", strings.Repeat("4", 64)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if scenario == "wrong-capture" {
		capture = strings.Repeat("a", 64)
	}
	if scenario == "cancelled" {
		cancel()
	}
	verifier := func(context.Context, string) (string, error) {
		return filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()), nil
	}
	if scenario == "wrong-verifier" {
		verifier = func(context.Context, string) (string, error) {
			return filepath.Join(linuxOwnedControllerRoot, "router-vpn-client"), nil
		}
	}
	process, launchErr := startDesktopLinuxNodeProcessWithVerifier(ctx, parent, arguments, []string{linuxNodeLauncherMarker + "=1", "GORACE=atexit_sleep_ms=0"}, directory, capture, verifier)
	if process != nil {
		defer process.Close(context.Background())
	}
	if scenario == "wrong-capture" || scenario == "cancelled" || scenario == "wrong-verifier" {
		if launchErr == nil || process != nil && process.Started() {
			return errors.New("unaccepted launcher input created an authenticated engine")
		}
		if process != nil {
			if err := process.Close(context.Background()); err != nil {
				return err
			}
			if !process.closed || !process.released {
				return errors.New("partial launcher did not join retained pins")
			}
		}
	} else {
		if launchErr != nil || process == nil || !process.Started() {
			return errors.Join(launchErr, errors.New("actual pinned Linux engine did not authenticate"))
		}
		bootstrap, err := process.Bootstrap(ctx)
		if err != nil {
			return err
		}
		body, err := bootstrap.Receive(ctx)
		if err != nil || string(body) != "native-engine-ready" {
			return errors.Join(err, errors.New("actual pinned Linux engine omitted readiness"))
		}
		observed, engine, err := bootstrap.Observations(ctx)
		if err != nil || observed.ProcessID != os.Getpid() || engine.ProcessID != process.command.Process.Pid || engine.ProcParentID != observed.ProcProcessID {
			return errors.Join(err, errors.New("launcher replaced its original parent or clone identity"))
		}
		if err := bootstrap.Send(ctx, []byte("ping")); err != nil {
			return err
		}
		body, err = bootstrap.Receive(ctx)
		if err != nil || string(body) != "pong" {
			return errors.Join(err, errors.New("launcher lost its actual authenticated channel"))
		}
		switch scenario {
		case "live":
		case "engine-exit":
			if err := bootstrap.Send(ctx, []byte("exit")); err != nil {
				return err
			}
			if _, err := process.Wait(ctx); err != nil {
				return err
			}
			if process.Alive() == nil {
				return errors.New("retired original engine retained live launcher authority")
			}
		case "parent-retirement":
			if err := parent.parent.Close(ctx); err != nil {
				return err
			}
			if !process.closed || !process.released || process.Alive() == nil {
				return errors.New("controller retirement released borrowed witnesses before its child joined")
			}
		case "image-replacement":
			path := filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName())
			if err := os.Rename(path, path+".old"); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte("replacement is never executable authority"), 0755); err != nil {
				return err
			}
			if process.Alive() == nil {
				return errors.New("changed native package pathname retained launcher authority")
			}
		case "workspace-replacement":
			if err := os.Rename(directory, directory+".old"); err != nil {
				return err
			}
			if err := os.Mkdir(directory, 0700); err != nil {
				return err
			}
			if process.Alive() == nil {
				return errors.New("changed private workspace retained launcher authority")
			}
			if err := os.Remove(directory); err != nil {
				return err
			}
			if err := os.Rename(directory+".old", directory); err != nil {
				return err
			}
			if process.Alive() == nil {
				return errors.New("restoring a replaced workspace revived the retired launcher")
			}
		default:
			return errors.New("launcher fixture has an unknown native scenario")
		}
		if err := process.Close(ctx); err != nil {
			return err
		}
		if !process.closed || !process.released || process.bootstrap != nil || process.root != nil {
			return errors.New("launcher retained original handles after acknowledged join")
		}
		for _, pin := range process.pins {
			if pin.file != nil {
				return errors.New("launcher retained a pinned payload after child join")
			}
		}
		select {
		case <-process.joined:
		default:
			return errors.New("launcher fabricated its original child join")
		}
		if scenario != "parent-retirement" && parent.Current(ctx) != nil {
			return errors.New("child retirement closed its borrowed original controller")
		}
	}
	if len(parent.parent.dependents) != 0 {
		return errors.New("joined launcher remained in parent ownership")
	}
	for _, file := range []*os.File{controller.input, controller.installLock, controller.processLock} {
		if _, err := file.Stat(); err != nil {
			return errors.Join(err, errors.New("launcher closed borrowed controller locks or input"))
		}
	}
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

func TestLinuxOwnedControllerNamespaceNodeEngineLauncher(t *testing.T) {
	for _, scenario := range []string{"live", "engine-exit", "parent-retirement", "image-replacement", "workspace-replacement", "wrong-capture", "cancelled", "wrong-verifier"} {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			child := startLinuxNodeParentProcess(t, installed, "launcher/"+scenario)
			child.retire(t, "")
		})
	}
}
