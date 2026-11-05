//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() {
	if os.Getenv("ROUTERVPN_NODE_TRANSFER_NATIVE") == "1" && os.Getenv(linuxControllerNamespaceMarker) == "1" && len(os.Args) == 2 && (os.Args[1] == linuxStandardServiceArgument || os.Args[1] == linuxStandardServiceUpgradeArgument) {
		main()
		os.Exit(0)
	}
}

// The existing installed Node namespace supplies its real encrypted peer,
// selected DNS, controller bootstrap and generated bundle. Add the actual
// installed service, using that same peer for the original standard tunnel.
func linuxHostTUNTransferService(t *testing.T, installed string, peer *linuxHostTUNPeer) {
	t.Helper()
	root := linuxOwnedControllerRoot
	for _, name := range []string{"native-standard-exit-linux.sh", "cleanup-private-runtime.py", "native-wrapper-owner.py", "runtime-pids.py", "select-standard-engine.sh", "run-multihop.sh", "multihop.py", "profile_id.py", "private_profile_store.py", "dns-policy.py", "kill-switch-platform.py", "kill-switch.py"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "modes", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, "modes", name), raw, 0700); err != nil {
			t.Fatal(err)
		}
	}
	exit := validTestStandardExit("shadowsocks")
	exit.ID = "service-transfer-original"
	exit.Server = peer.address.Addr().String()
	exit.ServerPort = int(peer.address.Port())
	exit.Secret = peer.password
	if err := persistStandardExitStore(standardExitStore{SchemaVersion: standardExitStoreVersion, Exits: []standardExit{exit}}); err != nil {
		t.Fatal(err)
	}
	notifyPath := "/run/routervpn-transfer-ready"
	notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer notify.Close()
	defer os.Remove(notifyPath)
	service := exec.Command(installed, linuxStandardServiceArgument)
	service.Env = []string{linuxControllerNamespaceMarker + "=1", "ROUTERVPN_NODE_TRANSFER_NATIVE=1", "NOTIFY_SOCKET=" + notifyPath, "GORACE=atexit_sleep_ms=0"}
	var diagnostic bytes.Buffer
	service.Stderr = &diagnostic
	if err = service.Start(); err != nil {
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() { joined <- service.Wait() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		helper := exec.CommandContext(ctx, installed, linuxStandardServiceUpgradeArgument)
		helper.Env = []string{linuxControllerNamespaceMarker + "=1", "ROUTERVPN_NODE_TRANSFER_NATIVE=1", "GORACE=atexit_sleep_ms=0"}
		output, err := helper.CombinedOutput()
		if err != nil {
			_ = service.Process.Kill()
			<-joined
			t.Errorf("original transfer service idle cleanup: %v %s %s", err, output, diagnostic.String())
			return
		}
		select {
		case err := <-joined:
			if err != nil {
				t.Error("original transfer service join", err, diagnostic.String())
			}
		case <-ctx.Done():
			_ = service.Process.Kill()
			<-joined
			t.Error("transfer service retirement omitted original join")
		}
	})
	if err = notify.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 4096)
	n, _, err := notify.ReadFromUnix(body)
	if err != nil || !strings.Contains(string(body[:n]), "READY=1") {
		t.Fatal("original transfer service not ready", err, string(body[:n]))
	}
}

func linuxHostTUNStartStandardTransferSource(ctx context.Context, a *app) (*linuxStandardServiceLaunch, error) {
	request, _ := json.Marshal(standardExitConnectRequest{StandardExitID: "service-transfer-original", Direct: true})
	response := httptest.NewRecorder()
	a.platformStandardExitConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/standard-exit/connect", bytes.NewReader(request)).WithContext(ctx), platformStandardExitRuntime{
		prepareLegacy: prepareLegacyStandardExitOwner,
		prove:         func(*app, string) error { return nil }, // Public Internet reachability only; native DNS/TUN and all owners are real.
		proveDNS: func(ctx context.Context, owner legacyStandardExitLaunch) error {
			return owner.(*linuxStandardServiceLaunch).ProveSelectedDNS(ctx)
		},
		current: func(owner legacyStandardExitLaunch, ctx context.Context) error { return owner.Current(ctx) },
	})
	if response.Code != http.StatusOK {
		return nil, fmt.Errorf("actual standard source Connect: %d %s", response.Code, response.Body.String())
	}
	raw, present := linuxStandardServiceOwners.Load(a)
	owner, ok := raw.(*linuxStandardServiceLaunch)
	if !present || !ok || owner.Command().Process != nil || !a.state.Connected {
		return nil, errors.New("transfer source did not retain actual service ownership")
	}
	return owner, nil
}

func linuxHostTUNTransferredSource(owner *linuxStandardServiceLaunch, host *desktopLinuxNodeHost) error {
	if owner == nil || !owner.joined || owner.transfer == nil || !owner.transfer.resolved.Load() || !owner.transfer.committed.Load() || owner.transfer.host.transaction == nil || owner.transfer.host.transaction.standardTransfer != owner.transfer || owner.transfer.host.transaction.head.Record.Transfer == nil || *owner.transfer.host.transaction.head.Record.Transfer != *owner.transfer.intent.Load() {
		return errors.New("actual Node admission omitted original durable service succession")
	}
	if _, present := linuxStandardServiceOwners.Load(owner.app); present {
		return errors.New("committed transfer retained stale service runtime selection")
	}
	if _, err := os.Stat(filepath.Join(linuxOwnedControllerRoot, "run", "kill-switch.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("committed transfer did not retire original standard saved owner")
	}
	return nil
}

func linuxHostTUNTransferCase(scenario string) bool {
	return scenario == "service-transfer" || scenario == "service-transfer-lost-reply" || scenario == "service-transfer-longer-deadline"
}

// Only the transport delivery/immutable request comparison is faulted. The
// original installed service and actual native creators perform every effect.
func linuxHostTUNTransferFault(owner *linuxStandardServiceLaunch, scenario string) *bool {
	fired := new(bool)
	owner.exchange = func(ctx context.Context, q linuxStandardServiceRequest, directory *os.File, before func()) (linuxStandardServiceResponse, error) {
		inject := !*fired && q.Action == "transfer-commit"
		if inject {
			*fired = true
		}
		if inject && scenario == "service-transfer-longer-deadline" {
			copy := *q.Transfer
			copy.DeadlineNS += int64(time.Minute)
			q.Transfer = &copy
		}
		response, err := linuxStandardServiceRPC(ctx, owner.image, owner.prepared.namespaceInfo, &owner.peer, q, directory, before)
		if inject && scenario == "service-transfer-lost-reply" && err == nil {
			return linuxStandardServiceResponse{}, io.ErrUnexpectedEOF
		}
		return response, err
	}
	return fired
}
