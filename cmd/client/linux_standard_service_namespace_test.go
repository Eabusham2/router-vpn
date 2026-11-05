//go:build linux && routervpn_controller_privileged && routervpn_standard_service_native

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
		if os.Args[1] == linuxStandardServiceArgument && os.Getenv("ROUTERVPN_STANDARD_SERVICE_NATIVE_TRIGGER") == "1" {
			_, err := runLinuxStandardServiceUtility(os.Args[1:], linuxStandardNativeExitObserver)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
		main()
		os.Exit(0)
	}
}

// This gate requires real root-private /opt and /run mounts, native nft/netlink,
// named Unix listeners, kernel peer pidfds, actual installed service/helper
// processes, readiness and process join. Missing capabilities fail the gate.
func TestLinuxStandardServiceNamespaceInstalledIdleUpgradeAndAlwaysRetention(t *testing.T) {
	for _, scenario := range []string{"off", "on-connect", "on-connect-mtu", "on-connect-public", "on-connect-public-restore", "on-connect-failure", "on-connect-network-failure", "on-connect-route-change", "on-connect-pre-rpc-network-failure", "always-off", "always"} {
		t.Run(scenario, func(t *testing.T) {
			policy := scenario
			if scenario == "always-off" {
				policy = "always"
			}
			if scenario == "on-connect-mtu" || scenario == "on-connect-public" || scenario == "on-connect-public-restore" || scenario == "on-connect-route-change" || scenario == "on-connect-network-failure" || scenario == "on-connect-failure" || scenario == "on-connect-pre-rpc-network-failure" {
				policy = "on-connect"
			}
			executable := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(linuxStandardServiceDirectory); err != nil {
				t.Fatal(err)
			}
			profile := common.RouterProfile{ID: "control", Name: "Control", KillSwitch: policy != "off", KillSwitchPolicy: policy, Endpoint: "203.0.113.77",
				DNSMode: "custom", DNSProtocol: "udp", DNSHost: "1.1.1.1", DNSPort: 53}
			if scenario == "on-connect-mtu" || scenario == "on-connect-public" || scenario == "on-connect-public-restore" {
				profile.MTUPolicy = "auto"
			}
			applyProfileDefaults(&profile)
			body, _ := json.Marshal(common.RouterProfileStore{SchemaVersion: 4, SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}})
			if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"), body, 0600); err != nil {
				t.Fatal(err)
			}
			// Previous-boot metadata selects this standard-policy branch only.
			// It supplies no creator authority: the service must prove complete
			// native absence and obtain a new original kernel acknowledgment.
			linuxStandardServicePreviousBootState(t, linuxOwnedControllerRoot, profile.ID, profile.Endpoint)
			var nativeQueries *atomic.Int64
			if policy == "on-connect" {
				legacyStopBoundaryFiles(t, linuxOwnedControllerRoot)
				if err := os.Remove(filepath.Join(linuxOwnedControllerRoot, "bin", "sing-box")); err != nil {
					t.Fatal(err)
				}
				// No stock script exists in this installed fixture. The controller
				// captures a request; the service selects the real verified bundle.
				linuxStandardInstallRuntimeFixture(t)
				if scenario == "on-connect-public" || scenario == "on-connect-public-restore" {
					peer := installStandardPublicPeer(t)
					nativeQueries = linuxStandardNativePeerFixture(t, peer.serve)
				} else {
					nativeQueries = linuxStandardNativePeerFixture(t)
				}
				profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "tcp", "203.0.113.53", 5353
				body, _ = json.Marshal(common.RouterProfileStore{SchemaVersion: 4, SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}})
				if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"), body, 0600); err != nil {
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
			if scenario == "on-connect-failure" {
				service.Env = append(service.Env, "ROUTERVPN_STANDARD_SERVICE_NATIVE_TRIGGER=1")
			}
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
				if scenario == "on-connect-mtu" {
					action = "mtu"
				}
				if scenario == "on-connect-public" {
					action = "public-mtu"
				}
				if scenario == "on-connect-public-restore" {
					action = "public-restore"
				}
				if scenario == "always-off" {
					action = "off"
				}
				if scenario == "on-connect-network-failure" {
					action = "network-failure"
				}
				if scenario == "on-connect-route-change" {
					action = "route-change"
				}
				if scenario == "on-connect-failure" {
					action = "failure"
				}
				if scenario == "on-connect-pre-rpc-network-failure" {
					action = "pre-rpc-network-failure"
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
				if scenario == "on-connect-public" && !strings.Contains(output.String(), "standard-service-public-retest-cancel-speedlab-joined") {
					t.Fatal("public native pipeline omitted joined results", output.String())
				}
				if scenario == "on-connect-public-restore" && !strings.Contains(output.String(), "standard-service-public-cancelled-speedlab-restored") {
					t.Fatal("cancelled temporary Speed Lab did not restore original", output.String())
				}
				if scenario == "on-connect-pre-rpc-network-failure" && nativeQueries != nil && nativeQueries.Load() != 0 {
					t.Fatal("rejected pre-RPC epoch still executed selected DNS")
				}
				if scenario != "on-connect-pre-rpc-network-failure" && nativeQueries != nil && nativeQueries.Load() < 1 {
					t.Fatal("actual standard engine did not route uncached selected DNS through the original SOCKS peer")
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
