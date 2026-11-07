package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/nativeopenvpn"
)

// These peers exercise the actual private host mailbox. Actual authenticated
// OpenVPN endpoint/status/packet-reader execution is a separate native gate.
func desktopImportedOpenVPNObservationFixture(t *testing.T) (*desktopNodeMTUFixture, nativeopenvpn.PacketObservation) {
	t.Helper()
	f := importedDesktopDNSFixture(t)
	state := nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{Remote: nativeopenvpn.Remote{Host: "203.0.113.24", Port: 1194, Network: "tcp"}, Generation: 3, ConnectedAt: time.Now().UnixMilli()}, MTU: 1500}
	f.launch.importedOpenVPN = &desktopImportedOpenVPNRuntime{spec: desktopImportedOpenVPNSpec{Remote: state.Remote.Remote, Minimum: 1500}, notBefore: state.Remote.ConnectedAt}
	return f, state
}

func desktopImportedOpenVPNReply(launch *desktopNodeLaunch, request desktopImportedDNSRequest, status string, live desktopNodeMTURecord, state *nativeopenvpn.PacketObservation) error {
	result := desktopImportedDNSResult{OpenVPN: state, desktopImportedDNSRequest: request, Status: status, Interface: live.Interface, Index: live.Index, ProvedAt: time.Now().UnixMilli(), Milliseconds: 1}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(launch.directory, ".node-dns-result.json.pending"), raw, 0600); err != nil {
		return err
	}
	if err := launch.directoryRoot.Rename(".node-dns-result.json.pending", "node-dns-result.json"); err != nil {
		return err
	}
	return launch.directoryRoot.Remove("node-dns-request.json")
}

func TestDesktopImportedOpenVPNReceiptAdmission(t *testing.T) {
	for _, fault := range []string{"success", "failed", "remote", "port", "network", "capacity", "missing-state", "operation", "reader", "source", "owner", "old-connection", "future-connection"} {
		t.Run(fault, func(t *testing.T) {
			f, original := desktopImportedOpenVPNObservationFixture(t)
			var current atomic.Bool
			current.Store(true)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				request, err := importedDesktopDNSReadRequest(ctx, f.launch)
				if err != nil {
					done <- err
					return
				}
				if request.Operation != "openvpn-observe" {
					done <- errors.New("observation called DNS operation")
					return
				}
				state, live, status := original, f.base, "passed"
				observed := &state
				switch fault {
				case "failed":
					status = "failed"
				case "remote":
					state.Remote.Host = "203.0.113.25"
				case "port":
					state.Remote.Port++
				case "network":
					state.Remote.Network = "udp"
				case "capacity":
					state.MTU--
				case "missing-state":
					observed = nil
				case "operation":
					request.Operation = ""
				case "reader":
					request.Reader++
					live.Reader++
				case "source":
					f.launch.workspaceMu.Lock()
					err = os.WriteFile(filepath.Join(f.launch.directory, "sing-box.json"), []byte(`{"replacement":true}`), 0600)
					f.launch.workspaceMu.Unlock()
				case "owner":
					current.Store(false)
				case "old-connection":
					state.Remote.ConnectedAt--
				case "future-connection":
					state.Remote.ConnectedAt = time.Now().Add(time.Hour).UnixMilli()
				}
				if err == nil {
					err = desktopImportedOpenVPNReply(f.launch, request, status, live, observed)
				}
				if fault == "missing-state" || fault == "operation" || fault == "reader" {
					stopped, _ := json.Marshal(map[string]any{"schema": 1, "session_id": f.launch.mtuSession, "source_sha256": f.launch.configSHA256, "closed": true})
					err = errors.Join(err, writeDesktopRuntimeFile(f.launch, "stopped.json", stopped, false))
				}
				done <- err
			}()
			err := exchangeDesktopImportedOpenVPN(ctx, f.launch, func(ctx context.Context) error {
				if !current.Load() {
					return errors.New("original native owner replaced")
				}
				return ctx.Err()
			})
			if peer := <-done; peer != nil {
				t.Fatal(peer)
			}
			if fault == "success" && (err != nil || f.launch.importedOpenVPN.original == nil || *f.launch.importedOpenVPN.original != original) || fault != "success" && err == nil {
				t.Fatal("unowned native OpenVPN observation admitted", fault, err)
			}
		})
	}
}

func TestDesktopImportedOpenVPNOriginalConnectionCannotRelatch(t *testing.T) {
	for _, fault := range []string{"generation", "connected-at", "capacity"} {
		t.Run(fault, func(t *testing.T) {
			f, state := desktopImportedOpenVPNObservationFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			for round := 0; round < 2; round++ {
				if round == 1 {
					switch fault {
					case "generation":
						state.Remote.Generation++
					case "connected-at":
						state.Remote.ConnectedAt++
					case "capacity":
						state.MTU++
					}
				}
				captured := state
				done := make(chan error, 1)
				go func() {
					request, err := importedDesktopDNSReadRequest(ctx, f.launch)
					if err == nil {
						err = desktopImportedOpenVPNReply(f.launch, request, "passed", f.base, &captured)
					}
					done <- err
				}()
				err := exchangeDesktopImportedOpenVPN(ctx, f.launch, func(ctx context.Context) error { return ctx.Err() })
				if peer := <-done; peer != nil {
					t.Fatal(peer)
				}
				if (round == 0) != (err == nil) {
					t.Fatal("replacement connection generation/capacity admitted", fault, err)
				}
			}
			before := f.launch.importedDNSGeneration
			if err := exchangeDesktopImportedOpenVPN(ctx, f.launch, func(ctx context.Context) error { return ctx.Err() }); err == nil || f.launch.importedDNSGeneration != before || !f.launch.importedOpenVPN.retired.Load() {
				t.Fatal("retired native connection relatched another sample")
			}
		})
	}
}

func TestDesktopImportedOpenVPNCancellationJoinsNativeObservation(t *testing.T) {
	f, _ := desktopImportedOpenVPNObservationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, draining, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	peer := make(chan error, 1)
	go func() {
		wait, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		request, err := importedDesktopDNSReadRequest(wait, f.launch)
		if err != nil {
			peer <- err
			return
		}
		close(entered)
		for {
			raw, err := readDesktopRuntimeFileContext(wait, f.launch, "node-dns-cancel.json", 4096)
			if err == nil {
				var actual desktopImportedDNSRequest
				if decodeRelayControlJSON(raw, &actual) != nil || actual != request {
					peer <- errors.New("foreign operation cancelled native worker")
					return
				}
				break
			}
			if wait.Err() != nil {
				peer <- wait.Err()
				return
			}
			time.Sleep(time.Millisecond)
		}
		close(draining)
		<-release
		peer <- desktopImportedOpenVPNReply(f.launch, request, "cancelled", f.base, nil)
	}()
	done := make(chan error, 1)
	go func() {
		done <- exchangeDesktopImportedOpenVPN(ctx, f.launch, func(ctx context.Context) error { return ctx.Err() })
	}()
	<-entered
	cancel()
	<-draining
	select {
	case err := <-done:
		t.Fatal("host detached from native observation", err)
	default:
	}
	close(release)
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || f.launch.importedOpenVPN.original != nil || f.launch.importedOpenVPN.retired.Load() {
		t.Fatal("cancelled pending query created or retired connected identity", err)
	}
	if _, err := f.launch.directoryRoot.Lstat("node-dns-cancel.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancel record survived its joined worker", err)
	}
}

func TestDesktopImportedOpenVPNContextOwnedLocks(t *testing.T) {
	for _, lock := range []string{"observation", "mailbox", "workspace"} {
		t.Run(lock, func(t *testing.T) {
			f, _ := desktopImportedOpenVPNObservationFixture(t)
			mutex := &f.launch.importedOpenVPN.mu
			if lock == "mailbox" {
				mutex = &f.launch.importedDNSMu
			} else if lock == "workspace" {
				mutex = &f.launch.workspaceMu
			}
			mutex.Lock()
			defer mutex.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if err := exchangeDesktopImportedOpenVPN(ctx, f.launch, func(ctx context.Context) error { return ctx.Err() }); err == nil || ctx.Err() == nil {
				t.Fatal("native observation waited beyond original caller", lock, err)
			}
			if f.launch.importedDNSGeneration != 0 || f.launch.importedOpenVPN.original != nil {
				t.Fatal("cancelled lock waiter published operation")
			}
		})
	}
}

func TestDesktopImportedOpenVPNDNSOperationCannotBorrowObservation(t *testing.T) {
	f, state := desktopImportedOpenVPNObservationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	peer := make(chan error, 1)
	go func() {
		request, err := importedDesktopDNSReadRequest(ctx, f.launch)
		if err == nil {
			err = desktopImportedOpenVPNReply(f.launch, request, "passed", f.base, &state)
		}
		stopped := []byte(`{"schema":1,"session_id":"` + f.launch.mtuSession + `","source_sha256":"` + f.launch.configSHA256 + `","closed":true}`)
		peer <- errors.Join(err, writeDesktopRuntimeFile(f.launch, "stopped.json", stopped, false))
	}()
	if _, err := exchangeDesktopImportedDNS(ctx, f.launch, func(ctx context.Context) error { return ctx.Err() }); err == nil {
		t.Fatal("OpenVPN remote observation substituted for selected DNS response")
	}
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
	if f.launch.importedOpenVPN.original != nil || f.launch.importedDNSGeneration != 1 {
		t.Fatal("DNS request acquired native connected authority")
	}
}
