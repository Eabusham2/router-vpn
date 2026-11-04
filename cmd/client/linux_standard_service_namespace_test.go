//go:build linux && routervpn_controller_privileged && routervpn_standard_service_native

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
)

type linuxStandardServiceDiagnostic struct {
	mu   sync.Mutex
	body bytes.Buffer
}

func (d *linuxStandardServiceDiagnostic) Write(body []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.body.Write(body)
}
func (d *linuxStandardServiceDiagnostic) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.body.String()
}

func init() {
	if os.Getenv(linuxControllerNamespaceMarker) == "1" && len(os.Args) == 2 &&
		(os.Args[1] == linuxStandardServiceArgument || os.Args[1] == linuxStandardServiceUpgradeArgument) {
		main()
		os.Exit(0)
	}
}

// This gate requires real root-private /opt and /run mounts, native nft/netlink,
// named Unix listeners, kernel peer pidfds, actual installed service/helper
// processes, readiness and process join. Missing capabilities fail the gate.
func TestLinuxStandardServiceNamespaceInstalledIdleUpgradeAndAlwaysRetention(t *testing.T) {
	for _, scenario := range []string{"off", "on-connect", "on-connect-failure", "always-off", "always"} {
		t.Run(scenario, func(t *testing.T) {
			policy := scenario
			if scenario == "always-off" {
				policy = "always"
			}
			if scenario == "on-connect-failure" {
				policy = "on-connect"
			}
			executable := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(linuxStandardServiceDirectory); err != nil {
				t.Fatal(err)
			}
			profile := common.RouterProfile{ID: "control", Name: "Control", KillSwitch: policy != "off", KillSwitchPolicy: policy, Endpoint: "203.0.113.77",
				DNSMode: "custom", DNSProtocol: "udp", DNSHost: "1.1.1.1", DNSPort: 53}
			applyProfileDefaults(&profile)
			body, _ := json.Marshal(common.RouterProfileStore{SchemaVersion: 4, SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}})
			if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"), body, 0600); err != nil {
				t.Fatal(err)
			}
			// Previous-boot metadata selects this standard-policy branch only.
			// It supplies no creator authority: the service must prove complete
			// native absence and obtain a new original kernel acknowledgment.
			linuxStandardServicePreviousBootState(t, linuxOwnedControllerRoot, profile.ID, profile.Endpoint)
			if policy == "on-connect" {
				legacyStopBoundaryFiles(t, linuxOwnedControllerRoot)
				// Keep the actual original-child DNS listener and uncached
				// exchange in this installed lifecycle case. Its downstream
				// resolver remains the explicit existing router fixture.
				engine := strings.Replace(legacyDNSEngineFixture,
					"signal.signal(signal.SIGINT,lambda *_:sys.exit(0))\nsignal.signal(signal.SIGTERM,lambda *_:sys.exit(0))",
					"def done(*_):\n (root/'engine-stopped').write_text('closed');sys.exit(0)\nsignal.signal(signal.SIGINT,done)\nsignal.signal(signal.SIGTERM,done)", 1)
				if scenario == "on-connect-failure" {
					// Only this private generated engine cooperatively exits. The
					// service still creates, observes and joins its actual child.
					loop := "\nwhile True:\n if (root/'close-listener').exists():"
					if strings.Count(engine, loop) != 1 {
						t.Fatal("original generated DNS engine loop changed")
					}
					engine = strings.Replace(engine, loop, "\nwhile True:\n if (root/'run/standard-service-fixture-exit').exists():done()\n if (root/'close-listener').exists():", 1)
				}
				if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "bin", "sing-box"), []byte(engine), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "dns-mode"), []byte("valid"), 0600); err != nil {
					t.Fatal(err)
				}
				catalog, _ := json.Marshal(legacyStopShippingCatalog(t))
				if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "modes.json"), catalog, 0600); err != nil {
					t.Fatal(err)
				}
				if err := persistStandardExitStore(standardExitStore{SchemaVersion: standardExitStoreVersion, Exits: []standardExit{validTestStandardExit("socks5")}}); err != nil {
					t.Fatal(err)
				}
			}
			notifyPath := filepath.Join("/run", "standard-service-ready-"+scenario)
			notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyPath, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			defer notify.Close()
			service := exec.Command(executable, linuxStandardServiceArgument)
			service.Env = []string{linuxControllerNamespaceMarker + "=1", "NOTIFY_SOCKET=" + notifyPath, "GORACE=atexit_sleep_ms=0"}
			var diagnostic linuxStandardServiceDiagnostic
			service.Stderr = &diagnostic
			if err = service.Start(); err != nil {
				t.Fatal(err)
			}
			joined := make(chan error, 1)
			go func() { joined <- service.Wait() }()
			retired := false
			defer func() {
				if !retired {
					_ = service.Process.Kill()
					<-joined
				}
			}()
			_ = notify.SetReadDeadline(time.Now().Add(15 * time.Second))
			packet := make([]byte, 4096)
			n, _, err := notify.ReadFromUnix(packet)
			if err != nil || !strings.Contains(string(packet[:n]), "READY=1") {
				t.Fatal("installed service did not prove native readiness", err, string(packet[:n]), diagnostic.String())
			}
			if policy == "on-connect" || scenario == "always-off" {
				reader, writer := linuxControllerUserPipe(t, executable)
				controller := linuxControllerBootstrapCommand(executable, reader)
				action := "1"
				if scenario == "always-off" {
					action = "off"
				}
				if scenario == "on-connect-failure" {
					action = "failure"
				}
				controller.Env = append(controller.Env, "ROUTERVPN_CONTROLLER_STANDARD_SERVICE_FIXTURE="+action)
				var output bytes.Buffer
				controller.Stdout = &output
				controller.Stderr = &output
				if err = controller.Start(); err != nil {
					t.Fatal(err)
				}
				if _, err = writer.Write(testLinuxOwnedHandshake()); err != nil {
					t.Fatal(err)
				}
				if err = controller.Wait(); err != nil || !strings.Contains(output.String(), "standard-service-route-joined") {
					t.Fatal("actual controller service route did not complete", err, output.String())
				}
				_ = writer.Close()
				_ = reader.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			helper := exec.CommandContext(ctx, executable, linuxStandardServiceUpgradeArgument)
			helper.Env = []string{linuxControllerNamespaceMarker + "=1", "GORACE=atexit_sleep_ms=0"}
			output, err := helper.CombinedOutput()
			if policy != "always" || scenario == "always-off" {
				if err != nil {
					t.Fatal("actual idle upgrade helper failed", err, string(output), diagnostic.String())
				}
				select {
				case err = <-joined:
					retired = true
					if err != nil {
						t.Fatal("original idle service did not join cleanly", err, diagnostic.String())
					}
				case <-ctx.Done():
					t.Fatal("helper claimed completion before original service joined")
				}
				if _, err = os.Lstat(linuxStandardServiceSocket); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("original listener not removed", err)
				}
				lock, err := ownedDesktopLock(linuxOwnedInstallLock, true)
				if err != nil {
					t.Fatal("joined original service retained shared source lock", err)
				}
				_ = lock.Close()
			} else {
				if err == nil || !strings.Contains(string(output), "original Always protection") {
					t.Fatal("idle helper falsely retired actual boot Always", err, string(output))
				}
				if err = service.Process.Signal(syscall.Signal(0)); err != nil {
					t.Fatal("rejected upgrade lost actual original service", err)
				}
				stateBytes, err := os.ReadFile(filepath.Join(linuxOwnedControllerRoot, "run", "kill-switch.json"))
				if err != nil {
					t.Fatal(err)
				}
				var saved legacyExitProtectionState
				if err = json.Unmarshal(stateBytes, &saved); err != nil || saved.Policy != "always" || saved.Owner.Receipt.TableHandle == 0 || !strings.HasPrefix(saved.Owner.Receipt.Table, "router_vpn_standard_") {
					t.Fatal("boot readiness lacked actual acknowledged creator", err, string(stateBytes))
				}
				// Only this isolated namespace fixture is killed during teardown;
				// the rejected upgrade never claims policy release or live handoff.
			}
		})
	}
}
