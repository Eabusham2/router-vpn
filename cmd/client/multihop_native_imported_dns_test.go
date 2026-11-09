package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func importedDesktopDNSFixture(t *testing.T) *desktopNodeMTUFixture {
	t.Helper()
	f := newDesktopNodeMTUFixture(t)
	f.launch.importedEntry = true
	graph := []byte(`{"captured":"final resolver and transport"}`)
	digest := sha256.Sum256(graph)
	f.launch.configSHA256, f.base.Config = hex.EncodeToString(digest[:]), hex.EncodeToString(digest[:])
	if err := writeDesktopRuntimeFile(f.launch, "sing-box.json", graph, false); err != nil {
		t.Fatal(err)
	}
	if err := f.publish(f.base, false); err != nil {
		t.Fatal(err)
	}
	return f
}

func importedDesktopDNSReadRequest(ctx context.Context, launch *desktopNodeLaunch) (desktopImportedDNSRequest, error) {
	for {
		raw, err := readDesktopRuntimeFileContext(ctx, launch, "node-dns-request.json", 4096)
		if err == nil {
			var request desktopImportedDNSRequest
			err = decodeRelayControlJSON(raw, &request)
			return request, err
		}
		if !errors.Is(err, os.ErrNotExist) {
			return desktopImportedDNSRequest{}, err
		}
		select {
		case <-ctx.Done():
			return desktopImportedDNSRequest{}, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

func importedDesktopDNSReply(launch *desktopNodeLaunch, request desktopImportedDNSRequest, status string, live desktopNodeMTURecord) error {
	result := desktopImportedDNSResult{desktopImportedDNSRequest: request, Status: status, Interface: live.Interface, Index: live.Index, ProvedAt: time.Now().UnixMilli(), Milliseconds: 1}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	path := filepath.Join(launch.directory, ".node-dns-result.json.pending")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return err
	}
	if err := launch.directoryRoot.Rename(".node-dns-result.json.pending", "node-dns-result.json"); err != nil {
		return err
	}
	if err := launch.directoryRoot.Remove("node-dns-request.json"); err != nil {
		return err
	}
	return nil
}

func TestDesktopImportedDNSReceiptAdmission(t *testing.T) {
	for _, fault := range []string{"success", "dns-failed", "reader", "source", "owner", "old-receipt"} {
		t.Run(fault, func(t *testing.T) {
			f := importedDesktopDNSFixture(t)
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
				status := "passed"
				live := f.base
				switch fault {
				case "dns-failed":
					status = "failed"
				case "reader":
					live.Reader++
					request.Reader++
				case "source":
					f.launch.workspaceMu.Lock()
					err = os.WriteFile(filepath.Join(f.launch.directory, "sing-box.json"), []byte(`{"foreign":true}`), 0600)
					f.launch.workspaceMu.Unlock()
				case "owner":
					current.Store(false)
				case "old-receipt":
					request.Request = strings.Repeat("f", 32)
				}
				if err == nil {
					err = importedDesktopDNSReply(f.launch, request, status, live)
				}
				if fault == "reader" || fault == "old-receipt" {
					stopped, _ := json.Marshal(map[string]any{"schema": 1, "session_id": f.launch.mtuSession, "source_sha256": f.launch.configSHA256, "closed": true})
					err = errors.Join(err, writeDesktopRuntimeFile(f.launch, "stopped.json", stopped, false))
				}
				done <- err
			}()
			elapsed, err := exchangeDesktopImportedDNS(ctx, f.launch, func(ctx context.Context) error {
				if !current.Load() {
					return errors.New("original source replaced")
				}
				return ctx.Err()
			})
			if peerErr := <-done; peerErr != nil {
				t.Fatal(peerErr)
			}
			if fault == "success" && (err != nil || elapsed <= 0) || fault != "success" && err == nil {
				t.Fatal("unproved final DNS admitted", fault, elapsed, err)
			}
		})
	}
}

func TestDesktopImportedDNSCancellationWaitsForNativeJoin(t *testing.T) {
	f := importedDesktopDNSFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, retiring, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
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
			_, err = readDesktopRuntimeFileContext(wait, f.launch, "node-dns-cancel.json", 4096)
			if err == nil {
				break
			}
			if wait.Err() != nil {
				peer <- wait.Err()
				return
			}
			time.Sleep(time.Millisecond)
		}
		close(retiring)
		<-release
		peer <- importedDesktopDNSReply(f.launch, request, "cancelled", f.base)
	}()
	done := make(chan error, 1)
	go func() {
		_, err := exchangeDesktopImportedDNS(ctx, f.launch, func(ctx context.Context) error { return ctx.Err() })
		done <- err
	}()
	<-entered
	cancel()
	<-retiring
	select {
	case err := <-done:
		t.Fatal("parent abandoned entered DNS worker", err)
	default:
	}
	close(release)
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("cancelled query was admitted")
	}
	if _, err := f.launch.directoryRoot.Lstat("node-dns-cancel.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("late owned cancellation survived drain", err)
	}
}

func TestDesktopImportedDNSCannotUseSuccessfulOSLookup(t *testing.T) {
	for _, source := range []string{"launch", "retained-missing", "retained-replaced", "graph-only", "registered-only", "observed-only"} {
		a := &app{}
		launch := &desktopNodeLaunch{importedEntry: true, profileID: "paired-final", mode: "shadowsocks"}
		observed := observedConnection{Profile: common.RouterProfile{ID: "paired-final", DNSMode: "home", AdGuardIPv4: "192.168.50.133"}, RouterID: "paired-final", Connected: true, Phase: "connected"}
		switch source {
		case "launch":
			desktopNodeOwners.Store(a, launch)
		case "retained-missing", "retained-replaced":
			nativeMultihopOwners.Store(a, &nativeMultihopRuntime{launch: launch, selection: multihopSelection{Native: &nativeMultihopCapture{imported: true}}})
			if source == "retained-replaced" {
				desktopNodeOwners.Store(a, &desktopNodeLaunch{profileID: "paired-final", mode: "shadowsocks"})
			}
		case "graph-only":
			activeMultihopGraphs.Store(a, activeMultihopGraph{EntryID: "imported-entry", ExitID: "paired-final", ImportedEntry: true})
		case "registered-only":
			activeDNSRuntimeIdentities.Store(a, activeDNSRuntimeIdentity{ProfileID: "paired-final", RuntimeID: "shadowsocks", ImportedEntry: true})
		case "observed-only":
			observed.Mode, observed.Profile.MultihopEnabled, observed.Profile.MultihopEntryID = "multihop", true, "imported-entry"
			a.profiles.Profiles = []common.RouterProfile{{ID: "imported-entry", NodeKind: "external"}}
		}
		called := false
		result := proveSelectedDNSWithLookup(context.Background(), a, observed, "shadowsocks", func(context.Context, string) ([]string, error) { called = true; return []string{"93.184.216.34"}, nil })
		desktopNodeOwners.Delete(a)
		nativeMultihopOwners.Delete(a)
		activeMultihopGraphs.Delete(a)
		activeDNSRuntimeIdentities.Delete(a)
		if result.Status == "passed" || called || !strings.Contains(result.Reason, "imported") {
			t.Fatal("ordinary OS resolver blessed an unproved imported final", source, result, called)
		}
	}
}

func TestDesktopImportedDNSAtomicPublicationAndFreshHeartbeat(t *testing.T) {
	// Complete the native exchange before the publisher resumes after Link.
	// The receipt's lower time bound must precede visibility, not this return.
	delayed := importedDesktopDNSFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	elapsed, err := exchangeDesktopImportedDNSWithPublisher(ctx, delayed.launch, func(ctx context.Context) error { return ctx.Err() },
		func(ctx context.Context, launch *desktopNodeLaunch, name string, raw []byte) error {
			if err := publishDesktopImportedDNSMessage(ctx, launch, name, raw); err != nil {
				return err
			}
			if name == "node-dns-request.json" {
				var request desktopImportedDNSRequest
				if err := decodeRelayControlJSON(raw, &request); err != nil {
					return err
				}
				if err := importedDesktopDNSReply(launch, request, "passed", delayed.base); err != nil {
					return err
				}
				time.Sleep(25 * time.Millisecond)
			}
			return nil
		})
	cancel()
	if err != nil || elapsed <= 0 {
		t.Fatal("native completion before publisher resume was rejected", elapsed, err)
	}
	for _, name := range []string{"node-dns-request.json", "node-dns-cancel.json"} {
		f := importedDesktopDNSFixture(t)
		body := []byte(`{"session_id":"complete-before-visible"}`)
		entered, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- publishDesktopImportedDNSWithWriter(context.Background(), f.launch, name, body, func(file *os.File, raw []byte) error {
				if _, err := file.Write(raw[:len(raw)/2]); err != nil {
					return err
				}
				close(entered)
				<-release
				_, err := file.Write(raw[len(raw)/2:])
				return err
			})
		}()
		<-entered
		_, premature := f.launch.directoryRoot.Lstat(name)
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !errors.Is(premature, os.ErrNotExist) {
			t.Fatal("native reader could consume a partially published message", name, premature)
		}
		actual, err := readDesktopRuntimeFile(f.launch, name, 4096)
		if err != nil || string(actual) != string(body) {
			t.Fatal("published message differs from its complete private inode", name, string(actual), err)
		}
		if err := publishDesktopImportedDNSMessage(context.Background(), f.launch, name, []byte(`{"replacement":true}`)); err == nil {
			t.Fatal("publication overwrote an already owned message", name)
		}
	}
	for _, swapped := range []bool{false, true} {
		f := importedDesktopDNSFixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		done := make(chan error, 1)
		go func() {
			_, err := exchangeDesktopImportedDNS(ctx, f.launch, func(ctx context.Context) error { return ctx.Err() })
			done <- err
		}()
		request, err := importedDesktopDNSReadRequest(ctx, f.launch)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		stale := f.base
		stale.Heartbeat = time.Now().Add(-3 * time.Second).UnixMilli()
		publishHeartbeat := func(record desktopNodeMTURecord) error {
			raw, err := json.Marshal(record)
			if err != nil {
				return err
			}
			f.launch.workspaceMu.Lock()
			defer f.launch.workspaceMu.Unlock()
			if err := os.WriteFile(filepath.Join(f.launch.directory, ".node-mtu-status.json.pending"), raw, 0600); err != nil {
				return err
			}
			return f.launch.directoryRoot.Rename(".node-mtu-status.json.pending", "node-mtu-status.json")
		}
		if err := publishHeartbeat(stale); err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := importedDesktopDNSReply(f.launch, request, "passed", f.base); err != nil {
			cancel()
			t.Fatal(err)
		}
		select {
		case err := <-done:
			cancel()
			t.Fatal("joined DNS receipt did not wait for the same reader's fresh heartbeat", err)
		case <-time.After(30 * time.Millisecond):
		}
		fresh := f.base
		fresh.Heartbeat = time.Now().UnixMilli()
		if swapped {
			fresh.Reader++
		}
		if err := publishHeartbeat(fresh); err != nil {
			cancel()
			t.Fatal(err)
		}
		err = <-done
		cancel()
		if swapped && err == nil || !swapped && err != nil {
			t.Fatal("post-query heartbeat admitted the wrong reader", swapped, err)
		}
	}
}

// Exercise the actual request publication and receipt reader. These finite
// private-file peers model native completion only; authenticated OpenVPN and
// selected DNS execution remain in their separate native gates.
func TestDesktopImportedDNSOperationDuration(t *testing.T) {
	for _, operation := range []string{"dns", "observe"} {
		for _, fault := range []string{"positive", "zero", "failed-zero", "cancelled-zero", "negative", "nan", "infinite", "oversized", "reader", "foreign-operation"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f, original := desktopImportedOpenVPNObservationFixture(t)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				op := ""
				if operation == "observe" {
					op = "openvpn-observe"
				}
				status, duration := "passed", "0"
				switch fault {
				case "positive":
					duration = "1"
				case "failed-zero":
					status = "failed"
				case "cancelled-zero":
					status = "cancelled"
				case "negative":
					duration = "-1"
				case "nan":
					duration = "NaN"
				case "infinite":
					duration = "1e999"
				case "oversized":
					duration = "7000.1"
				}
				validReceipt := fault == "positive" || fault == "zero" && operation == "observe" || fault == "failed-zero" || fault == "cancelled-zero"
				requests, cancels := 0, 0
				var captured desktopImportedDNSRequest
				publish := func(call context.Context, launch *desktopNodeLaunch, name string, raw []byte) error {
					if err := publishDesktopImportedDNSMessage(call, launch, name, raw); err != nil {
						return err
					}
					if name == "node-dns-cancel.json" {
						cancels++
						// Invalid evidence still uses the original explicit native
						// close acknowledgement to finish its cleanup; it cannot
						// manufacture a passing or joined measurement receipt.
						stopped, _ := json.Marshal(map[string]any{"schema": 1, "session_id": launch.mtuSession, "source_sha256": launch.configSHA256, "closed": true})
						return writeDesktopRuntimeFile(launch, "stopped.json", stopped, false)
					}
					if name != "node-dns-request.json" || decodeRelayControlJSON(raw, &captured) != nil || captured.Operation != op {
						return errors.New("duration fixture lost the actual original request")
					}
					requests++
					result := desktopImportedDNSResult{desktopImportedDNSRequest: captured, Status: status,
						Interface: f.base.Interface, Index: f.base.Index, ProvedAt: time.Now().UnixMilli(), Milliseconds: 1}
					if op == "openvpn-observe" && status == "passed" {
						result.OpenVPN = &original
					}
					if fault == "reader" {
						result.Reader++
					} else if fault == "foreign-operation" {
						result.Operation = "foreign"
					}
					body, err := json.Marshal(result)
					if err != nil {
						return err
					}
					// Invalid JSON/nonfinite controls enter the real decoder;
					// ordinary finite values use the same wire field.
					marker := []byte(`"milliseconds":1`)
					if bytes.Count(body, marker) != 1 {
						return errors.New("duration fixture lost its exact wire field")
					}
					body = bytes.Replace(body, marker, []byte(`"milliseconds":`+duration), 1)
					if err := writeDesktopRuntimeFile(launch, "node-dns-result.json", body, false); err != nil {
						return err
					}
					return launch.directoryRoot.Remove("node-dns-request.json")
				}
				result, err := exchangeDesktopImportedNativeWithPublisher(ctx, f.launch, func(call context.Context) error {
					return call.Err()
				}, op, publish)
				if requests != 1 || f.launch.importedDNSGeneration != captured.Generation {
					t.Fatal("duration case did not use the exact actual request", requests)
				}
				if validReceipt {
					if cancels != 0 || f.launch.importedDNSLast != captured.Request {
						t.Fatal("valid same-tick completion did not join its original request", fault, cancels, err)
					}
				} else if cancels != 1 || f.launch.importedDNSLast == captured.Request {
					t.Fatal("invalid measurement or foreign receipt acquired completion authority", fault, cancels, err)
				}
				if validReceipt && status == "passed" {
					if err != nil || result == nil || result.desktopImportedDNSRequest != captured || result.Milliseconds != map[string]float64{"positive": 1, "zero": 0}[fault] ||
						op == "openvpn-observe" && (result.OpenVPN == nil || *result.OpenVPN != original) || op == "" && result.OpenVPN != nil {
						t.Fatal("actual reader lost current operation or exact measured duration", result, err)
					}
				} else if err == nil || result != nil {
					t.Fatal("failed/cancelled/invalid DNS result became a successful measurement", fault, result, err)
				}
			})
		}
	}
}
