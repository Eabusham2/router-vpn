//go:build go1.25

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/routechoice"
)

func (f *desktopImportedOwnedFixture) temporary(t *testing.T, caller context.Context, cancel context.CancelFunc) (*speedLabMultihopPreparation, multihopSelection) {
	t.Helper()
	if err := retireUnstartedNativeMultihop(f.launch); err != nil {
		t.Fatal(err)
	}
	prepared, q, owner := f.prepareTemporary(t, caller, cancel, f.selection.ExitMode)
	// With no previous runtime this still executes the same captured suspend
	// admission. The separate succession test supplies an actual joined A.
	if err := f.a.speedLabSuspendPreviousWith(speedLabTemporarySnapshot{Owner: owner}, false, func(hold bool) error {
		if !hold || f.a.cmd != nil || owner.runtime != nil {
			return errors.New("temporary suspension changed its original protection choice")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	selection, err := prepared.apply(caller, f.a, q)
	if err != nil {
		t.Fatal(err)
	}
	f.launch, f.selection = prepared.launch, selection
	return prepared, selection
}

func (f *desktopImportedOwnedFixture) prepareTemporary(t *testing.T, caller context.Context, cancel context.CancelFunc, finalMode string) (*speedLabMultihopPreparation, speedLabRequest, *speedLabTemporaryOwner) {
	t.Helper()
	owner := &speedLabTemporaryOwner{intent: f.operation, test: f.operation, current: f.operation,
		network: f.network.Load().(string), cancelIntent: f.cancel, cancelTest: cancel, runtime: f.a.cmd}
	speedLabTemporaryOwners.Store(f.a, owner)
	q := speedLabRequest{Scope: "temporary", Topology: "multihop", EntryID: f.selection.Entry.ID, ExitID: f.selection.Exit.ID,
		EntryMode: f.selection.EntryMode, ExitMode: finalMode, Execution: "local", Base: "auto"}
	prepared, err := f.a.prepareSpeedLabImportedMultihopWithRuntime(caller, q, speedLabMultihopPreparationRuntime{
		capture: captureNativeMultihopForAppContext,
		network: f.readNetwork,
		preflight: func(ctx context.Context, a *app, selection multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
			if descriptor != nil {
				return nil, errors.New("imported temporary path acquired a server proposal")
			}
			launch, err := prepareDesktopOwnedImportedLaunchWith(ctx, a, selection, f.readNetwork)
			if err != nil {
				return nil, err
			}
			// The installed CLI is the modeled boundary; the private graph
			// file, bounded check invocation and cleanup are production code.
			err = preflightRetainedNativeMultihop(ctx, filepath.Join(launch.ownedNode.host.capture.packageRoot, "runtime", "native", nativeBinaryName()), launch,
				func(ctx context.Context, _ string, arguments, _ []string, directory string) error {
					if len(arguments) > 0 && arguments[0] == "check" {
						body, err := osReadImportedPreflight(directory)
						if err != nil || string(body) != string(launch.config) {
							return errors.Join(err, errors.New("preflight read a different private graph"))
						}
					}
					return ctx.Err()
				})
			return launch, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prepared.releaseUnused() })
	return prepared, q, owner
}

func TestDesktopImportedOwnedSpeedLabProtectedPreSuspendAdmission(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			f := newDesktopImportedOwnedFixture(t, "shadowsocks", "reality-vision", policy)
			f.stage(t)
			f.publish(t)
			if err := startDesktopOwnedImportedLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			original, child := f.launch, f.processes[0]
			graph, _ := getActiveMultihopGraph(f.a)
			restore, err := captureNativeMultihopRestoreContext(f.operation, f.a, original.command, graph,
				f.selection.Control, f.selection.Entry, f.selection.Exit)
			if err != nil {
				t.Fatal("protected predecessor could not capture its actual restore source", err)
			}
			profiles, state := cloneRouterProfileStore(f.a.profiles), f.a.state
			attempt, target := f.a.nodeProtection.active, *f.kernel.target
			caller, cancel := context.WithCancel(f.operation)
			defer cancel()
			// B has a different actual final graph; preparation must leave A's
			// live native child, complete profiles and protection untouched.
			prepared, request, owner := f.prepareTemporary(t, caller, cancel, "hysteria2")
			snapshot := speedLabTemporarySnapshot{Owner: owner, Runtime: original.command,
				Plan: speedLabRestorePlan{multihop: &restore}}
			if prepared.selection.Native == f.selection.Native || prepared.selection.Native.source == f.selection.Native.source ||
				prepared.launch.ownedNode.imported.policy.Metadata().SessionID == original.mtuSession {
				t.Fatal("temporary successor reused the predecessor graph or native session")
			}
			if err := f.a.guardDesktopOwnedNodeTemporary(request, snapshot); err == nil {
				t.Fatal("unprepared temporary path gained the protected predecessor's permission")
			}
			request.preparedMultihop = prepared
			if err := f.a.guardDesktopOwnedNodeTemporary(request, snapshot); err != nil {
				t.Fatal("checked imported successor remained unreachable before prior suspension", err)
			}
			registered, found := desktopNodeOwners.Load(f.a)
			if !found || registered != original || f.a.cmd != original.command || f.starts != 1 || child.closes != 0 ||
				f.a.nodeProtection.active != attempt || *f.kernel.target != target || !f.kernel.locked ||
				!reflect.DeepEqual(f.a.profiles, profiles) || f.a.state != state || prepared.launch.directory != "" ||
				original.ownedNode.imported.policy.Validate() != nil {
				t.Fatal("pre-suspend admission changed the protected original or prematurely started its successor")
			}
			if err := f.a.retireDesktopOwnedNode(context.Background(), original); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Keep this read explicit: the preflight runner models the external binary,
// not its producer-side source capture or the file the binary receives.
func osReadImportedPreflight(directory string) ([]byte, error) {
	return os.ReadFile(filepath.Join(directory, "sing-box.json"))
}

type importedOwnedProofCounts struct {
	entry, final, bypass atomic.Int32
}

func (f *desktopImportedOwnedFixture) installProofLanes(t *testing.T, fault string) *importedOwnedProofCounts {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"api64.ipify.org", "api.ipify.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	prior := http.DefaultTransport
	transport := prior.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	transport.DialTLS, transport.DialTLSContext = nil, nil
	counts := &importedOwnedProofCounts{}
	var workers sync.WaitGroup
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if network != "tcp" || address != "127.0.0.1:1098" && address != "127.0.0.1:1099" {
			counts.bypass.Add(1)
			return nil, errors.New("proof bypassed the two captured native lanes")
		}
		client, server := net.Pipe()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(server)
			request, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			if address == "127.0.0.1:1098" {
				if request.Method != http.MethodConnect || request.Host != "api64.ipify.org:443" && request.Host != "api.ipify.org:443" || request.Header.Get("Authorization") != "" {
					t.Error("public entry proof changed its exact HTTPS target or borrowed private authorization", request.Host)
					return
				}
				_ = request.Body.Close()
				if _, err := io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
					return
				}
				secure := tls.Server(server, serverTLS)
				if err := secure.Handshake(); err != nil {
					return
				}
				request, err = http.ReadRequest(bufio.NewReader(secure))
				if err != nil {
					return
				}
				defer request.Body.Close()
				if request.Header.Get("Authorization") != "" || request.Method != http.MethodGet {
					t.Error("public entry request acquired private authorization")
					return
				}
				counts.entry.Add(1)
				if fault == "entry-replaced" {
					f.a.mu.Lock()
					f.a.profiles.Profiles[0].External.ExpectedPublicIP = "203.0.113.237"
					f.a.mu.Unlock()
				}
				body := f.selection.Entry.External.ExpectedPublicIP
				if fault == "wrong-entry" {
					body = "203.0.113.236"
				}
				response := http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Close: true}
				_ = response.Write(secure)
				return
			}
			defer request.Body.Close()
			if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer "+f.selection.Exit.APIToken || request.URL.Path != "/health" {
				t.Error("paired final proof lost its own private request", request.URL)
				return
			}
			counts.final.Add(1)
			node := f.selection.Exit.NodeProofID
			if fault == "wrong-final" {
				node = strings.Repeat("f", 64)
			}
			body, _ := json.Marshal(map[string]any{"ok": true, "node_id": node, "proof": desktopNodeProofKind})
			response := http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Close: true}
			_ = response.Write(server)
		}()
		return client, nil
	}
	http.DefaultTransport = transport
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		workers.Wait()
		http.DefaultTransport = prior
	})
	return counts
}

func TestDesktopImportedOwnedSpeedLabActualOpenAndProofs(t *testing.T) {
	for _, fault := range []string{"success", "wrong-entry", "entry-replaced", "wrong-final", "failed-DNS", "caller-after-create"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopImportedOwnedFixture(t, "shadowsocks", "reality-vision", "always")
			caller, cancel := context.WithCancel(f.operation)
			defer cancel()
			prepared, selection := f.temporary(t, caller, cancel)
			counts := f.installProofLanes(t, fault)
			if fault == "caller-after-create" {
				f.onStart = func(context.Context, *desktopImportedOwnedProcess) { cancel() }
			}
			driver := &desktopExecutionDriver{a: f.a, selection: selection, network: f.network.Load().(string), prepared: prepared}
			ctx, stop := context.WithTimeout(caller, 2*time.Second)
			candidate := routechoice.Candidate{Execution: routechoice.Local, Transport: selection.ExitMode, EntryID: selection.Entry.ID, ExitID: selection.Exit.ID}
			session, err := driver.Open(ctx, candidate)
			stop()
			shouldOpen := fault == "success" || fault == "failed-DNS"
			if (err == nil) != shouldOpen || session == nil || f.starts != 1 || f.launch.command.Process != nil ||
				f.launch.ownedNode.process != f.processes[0] || f.a.state.Connected || counts.bypass.Load() != 0 {
				t.Fatal("actual execution driver lost typed creation, negative proof, or original cleanup", fault, err, f.starts, counts.entry.Load(), counts.final.Load())
			}
			if !shouldOpen {
				if fault != "wrong-final" && counts.final.Load() != 0 || fault == "caller-after-create" && counts.entry.Load() != 0 {
					t.Fatal("failed entry/caller advanced to another proof lane")
				}
			} else {
				identity, identityErr := session.(*desktopExecutionSession).IdentityContext(caller)
				if identityErr != nil || identity == "" || f.launch.ownedNode.operation != f.operation {
					t.Fatal("completed startup timeout became the connection lifetime")
				}
				verify, stopVerify := context.WithTimeout(caller, 2*time.Second)
				done := make(chan error, 1)
				go func() {
					request, err := importedDesktopDNSReadRequest(verify, f.launch)
					if err != nil {
						done <- err
						return
					}
					live, err := readDesktopNodeMTUContext(verify, f.launch)
					if err == nil {
						status := "passed"
						if fault == "failed-DNS" {
							status = "failed"
						}
						err = importedDesktopDNSReply(f.launch, request, status, live)
					}
					done <- err
				}()
				err = session.Verify(verify)
				peerErr := <-done
				stopVerify()
				if peerErr != nil || (err == nil) != (fault == "success") || counts.entry.Load() < 2 || counts.final.Load() < 2 || f.launch.importedDNSGeneration != 1 {
					t.Fatal("actual Verify bypassed distinct entry/final proofs or fresh native DNS", fault, err, peerErr, counts.entry.Load(), counts.final.Load())
				}
			}
			if err := f.a.retireDesktopOwnedNode(context.Background(), f.launch); err != nil || !f.processes[0].closed || f.a.nodeProtection.active != nil {
				t.Fatal("actual execution driver lost original imported retirement", err)
			}
		})
	}
}
