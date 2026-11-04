//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/standardengine"
)

// Both service RPC endpoints use real original Unix channels, SO_PEERPIDFD,
// task/image/namespace witnesses and framed bytes. The service then creates
// the existing actual sealed child/bootstrap fixture. Only native network and
// nft/TUN observations use the explicit event/creator models here.
func linuxStandardControllerEpochFixture(t *testing.T) (*linuxStandardService, *legacyExitFixture, *linuxStandardServiceLaunch, *linuxStandardStartupObserverFixture, context.Context) {
	t.Helper()
	s, f, _ := linuxStandardStartupFixture(t, "complete")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	f.a.localController = &linuxOwnedController{}
	f.a.connectionContext = ctx
	command, err := nativeStandardExitCommand(f.a, f.a.profiles.Profiles[0], common.RouterProfile{}, f.exit, true)
	if err != nil {
		t.Fatal(err)
	}
	observer := &linuxStandardStartupObserverFixture{}
	prepared, err := prepareLegacyStandardExitOwnerWithRequestObserver(f.a, command, "standard-"+f.exit.Protocol, "external", "standard:"+f.exit.ID, func() error { return nil }, func() string { return "captured-test-network" }, false, true,
		func(context.Context, context.Context) (linuxStandardStartupObserver, error) { return observer, nil })
	if err != nil {
		t.Fatal(err)
	}
	local := prepared.(*linuxLegacyStandardExitOwner)
	digest, err := linuxStandardProfileDigest(f.a.profiles.Profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	o := &linuxStandardServiceLaunch{app: f.a, prepared: local, image: s.image, request: linuxStandardServiceRequest{Schema: 1, Action: "start", Session: local.session, Directory: local.launch.directory, ConfigSHA256: local.digest, ProfileID: local.protectionProfileID, ProfileSHA256: digest, Endpoint: local.protectionEndpoint, RuntimeMode: local.runtimeMode, Base: local.base, RouterID: local.routerID, NetworkID: local.dns.networkID}}
	o.exchange = func(operation context.Context, request linuxStandardServiceRequest, directory *os.File, beforeWrite func()) (linuxStandardServiceResponse, error) {
		pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return linuxStandardServiceResponse{}, err
		}
		client := standardServiceTestConnection(t, os.NewFile(uintptr(pair[0]), "original-controller-epoch-channel"))
		server := standardServiceTestConnection(t, os.NewFile(uintptr(pair[1]), "original-service-epoch-channel"))
		defer client.Close()
		s.workers.Add(1)
		go s.connectionWithArguments(server, os.Args)
		deadline, ok := operation.Deadline()
		if !ok {
			t.Fatal("fixture request omitted original deadline")
		}
		// This fixture originally owns 20 seconds; its absolute transmitted
		// deadline remains earlier than that per-request maximum on every call.
		request.DeadlineNS, request.BudgetMS = deadline.UnixNano(), 20000
		response, err := linuxStandardServiceExchange(operation, client, s.image, s.namespace, &o.peer, request, directory, os.Args, beforeWrite)
		s.workers.Wait()
		return response, err
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		observer.closeFailure = nil
		_ = local.requestEpoch.close(cleanup)
		_ = s.retire(cleanup, true)
		_ = o.closeCopies()
		if o.peer != nil {
			_ = o.peer.Close()
		}
		linuxStandardServiceOwners.Delete(f.a)
	})
	return s, f, o, observer, ctx
}

func TestLinuxStandardServiceControllerEpochUsesOriginalWireAndChild(t *testing.T) {
	s, _, o, observer, ctx := linuxStandardControllerEpochFixture(t)
	if err := o.Start(ctx); err != nil {
		t.Fatal("actual authenticated controller Start", err)
	}
	n := o.prepared.requestEpoch
	if !o.attempted || !n.ready || !observer.began || !observer.recorded || !observer.ended || s.session == nil || s.session.owner.native == nil || s.session.owner.originalPIDFD == nil {
		t.Fatal("controller did not retain actual service child startup ownership")
	}
	native := s.session.owner.native
	capture, err := standardengine.ReadSealed(native.capture, 2048)
	if err != nil || !bytes.Equal(capture, n.startup.Capture) || !bytes.Equal(native.readyBody, n.startup.Ready) {
		t.Fatal("response reconstructed original child bytes", err)
	}
	if err := o.Current(ctx); err != nil {
		t.Fatal("original epoch not current", err)
	}
	observer.failure = errors.New("original physical link moved away and back")
	if err := o.Current(ctx); err == nil || n.failure == nil {
		t.Fatal("current proof erased original controller ABA")
	}
	stop := &linuxStandardServiceStop{owner: o, command: o.Command(), operation: ctx}
	if err := stop.Retire(ctx, o.Command(), true); err != nil {
		t.Fatal("original invalidation prevented joined cleanup", err)
	}
	if !observer.closed || !n.closed || !o.joined || !o.copiesClosed || !s.session.joined {
		t.Fatal("original readers/child/copies did not join")
	}
}

func TestLinuxStandardServiceControllerEpochRejectsChangedStartup(t *testing.T) {
	for _, scenario := range []string{"pre-rpc-aba", "during-rpc-aba", "late-end", "session", "configuration", "mode", "deadline", "expired", "ready-source", "missing", "source-replaced", "profile-replaced", "operation-replaced", "peer-replaced", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			s, f, o, observer, original := linuxStandardControllerEpochFixture(t)
			ctx, cancelOperation := context.WithCancel(original)
			defer cancelOperation()
			f.a.connectionContext = ctx
			originalExchange := o.exchange
			if scenario == "pre-rpc-aba" {
				observer.failure = errors.New("original pre-RPC physical ABA")
			}
			o.exchange = func(operation context.Context, request linuxStandardServiceRequest, directory *os.File, beforeWrite func()) (linuxStandardServiceResponse, error) {
				response, err := originalExchange(operation, request, directory, beforeWrite)
				if err != nil || request.Action != "start" {
					return response, err
				}
				switch scenario {
				case "during-rpc-aba":
					observer.failure = errors.New("original in-flight physical ABA")
				case "late-end":
					observer.invalidateAtRecord = true
				case "missing":
					response.Startup = nil
				case "source-replaced":
					path := filepath.Join(o.prepared.launch.directory, "sing-box.json")
					body, readErr := os.ReadFile(path)
					if readErr != nil {
						t.Fatal(readErr)
					}
					if err := os.Rename(path, path+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, body, 0600); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Remove(path); _ = os.Rename(path+".original", path) })
				case "profile-replaced":
					f.a.profiles.Profiles[0].Name += " replacement"
				case "operation-replaced":
					f.a.connectionContext = context.Background()
				case "peer-replaced":
					old := o.peer
					o.peer, _, _ = linuxStandardPeerFixture(t)
					t.Cleanup(func() { _ = o.peer.Close(); o.peer = old })
				case "cancelled":
					cancelOperation()
				default:
					capture, decodeErr := standardengine.DecodeCapture(response.Startup.Capture, standardengine.SHA256(response.Startup.Capture))
					if decodeErr != nil {
						t.Fatal(decodeErr)
					}
					switch scenario {
					case "session":
						capture.Session = strings.Repeat("a", 32)
					case "configuration":
						capture.ConfigSHA256 = strings.Repeat("a", 64)
					case "mode":
						capture.Mode = "standard-wireguard"
					case "deadline":
						capture.DeadlineNS = response.transmittedDeadline + 1
					case "expired":
						capture.DeadlineNS = time.Now().Add(-time.Second).UnixNano()
					}
					ready, _ := standardengine.DecodeReady(response.Startup.Ready, standardengine.SHA256(response.Startup.Capture))
					response.Startup.Capture, _ = capture.Canonical()
					ready.CaptureSHA256 = standardengine.SHA256(response.Startup.Capture)
					if scenario == "ready-source" {
						ready.CaptureSHA256 = strings.Repeat("b", 64)
					}
					response.Startup.Ready, _ = ready.Canonical()
				}
				return response, nil
			}
			err := o.Start(ctx)
			if err == nil {
				t.Fatal("controller accepted changed original startup", scenario)
			}
			witness := map[string]string{"pre-rpc-aba": "pre-RPC physical ABA", "during-rpc-aba": "in-flight physical ABA", "late-end": "invalidated during ledger adoption", "session": "another source or deadline", "configuration": "another source or deadline", "mode": "another source or deadline", "deadline": "another source or deadline", "expired": "another source or deadline", "ready-source": "belongs to another source", "missing": "no original child startup response", "source-replaced": "source was replaced", "profile-replaced": "source policy changed", "operation-replaced": "replaced controller operation", "peer-replaced": "original authenticated peer", "cancelled": "context canceled"}[scenario]
			if !strings.Contains(err.Error(), witness) {
				t.Fatal("negative missed its intended original boundary", scenario, err)
			}
			if observer.ended || o.prepared.requestEpoch.ready {
				t.Fatal("rejected startup published a ready controller epoch")
			}
			if scenario == "pre-rpc-aba" {
				if o.attempted || s.session != nil {
					t.Fatal("pre-RPC ABA executed the service")
				}
			} else if !o.attempted || s.session == nil || s.session.owner.originalPIDFD == nil {
				t.Fatal("negative did not pass actual original child/RPC boundary")
			}
		})
	}
}

func TestLinuxStandardServiceControllerEpochCloseRetryPrecedesStop(t *testing.T) {
	s, _, o, observer, ctx := linuxStandardControllerEpochFixture(t)
	if err := o.Start(ctx); err != nil {
		t.Fatal(err)
	}
	stop := &linuxStandardServiceStop{owner: o, command: o.Command(), operation: ctx}
	observer.closeFailure = errors.New("original observer join still pending")
	if err := stop.Retire(ctx, o.Command(), true); err == nil {
		t.Fatal("Stop bypassed original reader join")
	}
	if o.copiesClosed || o.joined || s.session.joined || o.prepared.namespace == nil || o.prepared.requestEpoch.closed {
		t.Fatal("failed join lost original cleanup authority")
	}
	observer.closeFailure = nil
	if err := stop.Retire(ctx, o.Command(), true); err != nil {
		t.Fatal("same original Stop retry", err)
	}
	if !observer.closed || !o.joined || !s.session.joined {
		t.Fatal("retry did not join exact original owners")
	}
}

func TestLinuxStandardServiceControllerEpochPreparationPrecedesSources(t *testing.T) {
	for _, scenario := range []string{"before-source-event", "source-failure", "partial-open"} {
		t.Run(scenario, func(t *testing.T) {
			_, f, _ := linuxStandardServiceRuntimeFixture(t, "on-connect")
			f.a.localController = &linuxOwnedController{}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			f.a.connectionContext = ctx
			command, err := nativeStandardExitCommand(f.a, f.a.profiles.Profiles[0], common.RouterProfile{}, f.exit, true)
			if err != nil {
				t.Fatal(err)
			}
			observer := &linuxStandardStartupObserverFixture{closeFailure: errors.New("retain original observer join")}
			opened := false
			prepared, err := prepareLegacyStandardExitOwnerWithRequestObserver(f.a, command, "standard-"+f.exit.Protocol, "external", "standard:"+f.exit.ID, func() error {
				if !opened {
					t.Fatal("source/TUN validation preceded original network observer")
				}
				if scenario == "before-source-event" {
					observer.failure = errors.New("physical ABA before source capture")
				}
				if scenario == "source-failure" {
					return os.Remove(filepath.Join(command.Args[3], "sing-box.json"))
				}
				return nil
			}, func() string { return "captured-test-network" }, false, true, func(context.Context, context.Context) (linuxStandardStartupObserver, error) {
				opened = true
				if scenario == "partial-open" {
					return observer, errors.New("original native initialization failed")
				}
				return observer, nil
			})
			owner, ok := prepared.(*linuxLegacyStandardExitOwner)
			if err == nil || !ok || owner.requestEpoch == nil || owner.requestEpoch.observer != observer {
				t.Fatal("preparation lost original failed observer", err)
			}
			_, err = finishLegacyStandardExitPreparation(f.a, ctx, owner, err)
			if err == nil {
				t.Fatal("failed original close became successful preparation")
			}
			if actual, present := legacyStandardExitPreparations.Load(owner); !present || actual != f.a {
				t.Fatal("original observer not retained in preparation registry")
			}
			observer.closeFailure = nil
			if err := retireLegacyStandardPreparations(f.a, ctx); err != nil {
				t.Fatal("original preparation retry", err)
			}
			if !observer.closed || !owner.requestEpoch.closed {
				t.Fatal("preparation retry did not join original observer")
			}
		})
	}
}

func TestLinuxStandardServiceControllerEpochWireRejectsUnrelatedLedger(t *testing.T) {
	for _, scenario := range []string{"current", "stop", "failed-start", "missing-start", "foreign-session", "wire-deadline"} {
		t.Run(scenario, func(t *testing.T) {
			pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			client := standardServiceTestConnection(t, os.NewFile(uintptr(pair[0]), "original-negative-controller"))
			server := standardServiceTestConnection(t, os.NewFile(uintptr(pair[1]), "original-negative-service"))
			defer client.Close()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			request := linuxStandardServiceRequest{Schema: 1, Action: "start", Session: strings.Repeat("c", 32), BudgetMS: 3000, DeadlineNS: deadline.UnixNano()}
			if scenario == "current" || scenario == "stop" {
				request.Action = scenario
			}
			joined := make(chan error, 1)
			go func() {
				body, files, err := linuxStandardServiceRead(server)
				for _, file := range files {
					_ = file.Close()
				}
				if err != nil {
					joined <- err
					return
				}
				var received linuxStandardServiceRequest
				if err = linuxStandardServiceDecode(body, &received); err != nil {
					joined <- err
					return
				}
				response := linuxStandardServiceResponse{Schema: 1, Action: received.Action, Session: received.Session, Complete: true, Startup: &linuxStandardServiceStartup{Capture: []byte("explicit rejected payload"), Ready: []byte("explicit rejected payload")}}
				if scenario == "failed-start" {
					response.Complete = false
					response.Error = "original failed start"
				}
				if scenario == "missing-start" {
					response.Startup = nil
				}
				if scenario == "foreign-session" {
					response.Session = strings.Repeat("d", 32)
				}
				if scenario == "wire-deadline" {
					raw, _ := json.Marshal(response)
					raw = append(raw[:len(raw)-1], []byte(`,"transmittedDeadline":9223372036854775807}`)...)
					err = linuxStandardServiceWrite(server, json.RawMessage(raw), nil)
				} else {
					err = linuxStandardServiceWrite(server, response, nil)
				}
				joined <- err
			}()
			image, _ := os.Stat("/proc/self/exe")
			namespace, _ := os.Stat("/proc/thread-self/ns/net")
			var peer *linuxStandardServicePeer
			_, err = linuxStandardServiceExchange(ctx, client, image, namespace, &peer, request, nil, os.Args, nil)
			if peer != nil {
				defer peer.Close()
			}
			if err == nil {
				t.Fatal("wire accepted unrelated startup authority", scenario)
			}
			if err := <-joined; err != nil {
				t.Fatal("negative did not send original wire packet", err)
			}
			witness := "startup ledger scope"
			if scenario == "foreign-session" {
				witness = "another request's completion"
			}
			if scenario == "wire-deadline" {
				witness = "unknown field"
			}
			if !strings.Contains(err.Error(), witness) {
				t.Fatal("wire negative missed intended boundary", err)
			}
		})
	}
}
