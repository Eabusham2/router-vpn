//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

var linuxNodeHostCases = []string{"complete", "restored-mtu", "wrong-package", "request-replaced", "profile-replaced",
	"options-replaced", "network-replaced", "source-replaced", "workspace-replaced", "cancelled-retirement", "entered-command"}

// The actual installed controller, private asset compiler and workspace run in
// the same isolated namespace as the shipping parent. Only package metadata
// verification is modeled; this stage starts no engine and proves no traffic.
func linuxNodeHostFixture(controller *ownedDesktopController, scenario string) error {
	profile, _, err := linuxTransactionProfile("always")
	if err != nil {
		return err
	}
	profile.EffectiveMTU = 9000 // Historical readback must not become the new path MTU.
	operation, endOperation := context.WithCancel(context.Background())
	defer endOperation()
	a := &app{localController: controller, connectionContext: operation, connectionCancel: endOperation,
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
			ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"),
			StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")},
		profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}},
		cmd:      &exec.Cmd{}, state: state{Connected: true, Mode: "previous", RuntimeMode: "previous", Phase: "connected", RouterID: "previous"}}
	beforeCommand, beforeState := a.cmd, a.state
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "host-parent-rendezvous")
	defer gate.Close()
	var one [1]byte
	if _, err := io.ReadFull(gate, one[:]); err != nil || one[0] != 1 {
		return errors.Join(err, errors.New("host fixture lost its original rendezvous"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	directory := filepath.Join(linuxOwnedControllerRoot, "generated", profile.ID, "shadowsocks")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	graph, err := json.Marshal(map[string]any{
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": profile.Endpoint, "server_port": 8388,
			"method": mobilemultihop.NativeStartLayerMethod, "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{43}, 32))}},
		"route": map[string]any{"final": "proxy", "rules": []any{}},
	})
	if err != nil {
		return err
	}
	asset := filepath.Join(directory, "sing-box.json")
	if err := os.WriteFile(asset, graph, 0600); err != nil {
		return err
	}
	originalInfo, err := os.Stat(asset)
	if err != nil {
		return err
	}
	verifies := 0
	verify := func(context.Context, string) (string, error) {
		verifies++
		if scenario == "wrong-package" {
			return "/another/runtime/native/" + nativeBinaryName(), nil
		}
		if scenario == "request-replaced" {
			a.mu.Lock()
			a.connectionContext = context.Background()
			a.mu.Unlock()
		}
		return filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()), nil
	}
	for _, mode := range []string{"wg", "awg2-fast", "hysteria2", "max", "openvpn"} {
		if host, err := prepareDesktopLinuxNodeHostWith(operation, a, profile, mode, 0, verify, nil); host != nil || err == nil || verifies != 0 {
			return errors.New("private Linux host admitted an unproved graph family")
		}
	}
	restored := 0
	if scenario == "restored-mtu" {
		restored = 1392
	}
	host, prepareErr := prepareDesktopLinuxNodeHostWith(operation, a, profile, "shadowsocks", restored, verify, nil)
	if scenario == "wrong-package" || scenario == "request-replaced" {
		if host != nil || prepareErr == nil || verifies != 1 {
			return errors.Join(prepareErr, errors.New("Linux host accepted a replacement package or request"))
		}
	} else {
		if prepareErr != nil || host == nil || verifies != 1 {
			return errors.Join(prepareErr, errors.New("Linux host did not retain its original native parent"))
		}
		defer host.Close(context.Background())
		if !sameDesktopLinuxParentCapture(parent, host.parent) || host.launch.directory != "" ||
			host.policy.Metadata().TargetOS != "linux" || host.policy.Metadata().RestoredMTU != restored ||
			host.selection.Policy != "always" || host.selection.HomeLAN || host.launch.command != nil {
			return errors.New("Linux host substituted its original parent or sealed policy")
		}
		switch scenario {
		case "profile-replaced":
			a.profiles.Profiles[0].APIToken = "replacement-private-token"
		case "options-replaced":
			a.profiles.Profiles[0].DAITAEnabled = !profile.DAITAEnabled
		case "network-replaced":
			if output, err := exec.Command("ip", "link", "set", "dev", "rvpn-test", "name", "rvpn-changed").CombinedOutput(); err != nil {
				return fmt.Errorf("isolated native link rename failed: %w: %s", err, output)
			}
		}
		stageErr := host.Stage(ctx)
		if scenario == "network-replaced" {
			if output, err := exec.Command("ip", "link", "set", "dev", "rvpn-changed", "name", "rvpn-test").CombinedOutput(); err != nil {
				return fmt.Errorf("isolated native link restoration failed: %w: %s", err, output)
			}
		}
		if scenario == "profile-replaced" || scenario == "options-replaced" || scenario == "network-replaced" {
			if stageErr == nil || host.launch.directory != "" || host.staged {
				return errors.New("Linux host staged a replaced private source, options or network")
			}
		} else {
			if stageErr != nil {
				return stageErr
			}
			workspace := host.launch.directory
			if err := host.Stage(ctx); err == nil {
				return errors.New("Linux host reused an already entered staging workspace")
			}
			arguments, capture, err := host.Arguments(ctx)
			if err != nil {
				return err
			}
			control, _ := host.selection.ControlSHA256()
			wantedCapture, _ := host.selection.CaptureSHA256()
			if len(arguments) != 11 && restored == 0 || len(arguments) != 13 && restored != 0 ||
				arguments[0] != "routervpn-node" || arguments[10] != control || capture != wantedCapture ||
				strings.Contains(strings.Join(arguments, " "), profile.APIToken) || restored != 0 && arguments[12] != "1392" {
				return errors.New("Linux host argv changed its sealed control capture or disclosed credentials")
			}
			arguments[10] = strings.Repeat("e", 64)
			fresh, _, err := host.Arguments(ctx)
			if err != nil || fresh[10] != control {
				return errors.New("returned argv mutated its retained Linux host")
			}
			if original, err := readDesktopRuntimeFile(host.launch, "node-source.json", mobilemultihop.NodeLaunchInputLimit); err != nil || !bytes.Equal(original, host.source) {
				clear(original)
				return errors.Join(err, errors.New("Linux host did not preserve complete original private source"))
			} else {
				clear(original)
			}
			switch scenario {
			case "source-replaced":
				if err := os.WriteFile(filepath.Join(workspace, "node-source.json"), []byte("another private node\n"), 0600); err != nil {
					return err
				}
				if _, _, err := host.Arguments(ctx); err == nil {
					return errors.New("Linux host admitted replaced private launch input")
				}
			case "workspace-replaced":
				retained := workspace + ".original"
				if err := os.Rename(workspace, retained); err != nil {
					return err
				}
				if err := os.Mkdir(workspace, 0700); err != nil {
					return err
				}
				marker := filepath.Join(workspace, "other-owner")
				if err := os.WriteFile(marker, []byte("keep\n"), 0600); err != nil {
					return err
				}
				if _, _, err := host.Arguments(ctx); err == nil {
					return errors.New("Linux host accepted a substituted private workspace")
				}
				if err := host.Close(ctx); err == nil {
					return errors.New("Linux host deleted a replacement workspace")
				}
				if raw, err := os.ReadFile(marker); err != nil || string(raw) != "keep\n" {
					return errors.New("Linux host touched replacement-owner contents")
				}
				if err := os.Remove(marker); err != nil {
					return err
				}
				if err := os.Remove(workspace); err != nil {
					return err
				}
				if err := os.Rename(retained, workspace); err != nil {
					return err
				}
			case "cancelled-retirement":
				endOperation()
				if _, _, err := host.Arguments(ctx); err == nil {
					return errors.New("Linux host admitted a cancelled original request")
				}
			case "entered-command":
				host.launch.command = &exec.Cmd{}
				if err := host.Close(ctx); err == nil {
					return errors.New("prepared Linux host discarded an entered command")
				}
				if _, err := os.Stat(filepath.Join(workspace, "node-source.json")); err != nil {
					return errors.New("prepared Linux host removed entered command inputs")
				}
				host.launch.command = nil // This fixture never starts that synthetic command.
			}
			if err := host.Close(ctx); err != nil {
				return err
			}
			if _, err := os.Lstat(workspace); !errors.Is(err, os.ErrNotExist) {
				return errors.Join(err, errors.New("Linux prepared host retained its never-executed workspace"))
			}
		}
		if err := host.Close(ctx); err != nil {
			return err
		}
		if !host.closed || !host.released || host.source != nil || host.policy != nil {
			return errors.New("Linux prepared host did not retire its original private capture")
		}
	}
	a.mu.Lock()
	unchanged := a.cmd == beforeCommand && reflect.DeepEqual(a.state, beforeState)
	a.mu.Unlock()
	after, err := os.Stat(asset)
	actual, readErr := os.ReadFile(asset)
	if err != nil || readErr != nil || !os.SameFile(originalInfo, after) || !bytes.Equal(actual, graph) || !unchanged {
		return errors.New("Linux host preparation changed prior connection state or original generated assets")
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	controller.close()
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

func TestDesktopLinuxGuardianKernelNodeHost(t *testing.T) {
	physical, err := net.InterfaceByName("rvpn-test")
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || err != nil || physical.Index < 1 {
		t.Fatal("Node host requires its actual isolated guardian namespace", err)
	}
	t.Setenv(linuxControllerNamespaceMarker, "1")
	for _, scenario := range linuxNodeHostCases {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			child := startLinuxNodeParentProcess(t, installed, "host/"+scenario)
			child.retire(t, "")
		})
	}
}
