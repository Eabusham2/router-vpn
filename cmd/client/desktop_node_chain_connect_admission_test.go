package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestDesktopCONNECTPublicAdmissionRequiresOriginalHost(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin", "android", "freebsd", ""} {
		for _, arch := range []string{"amd64", "arm64", "386", "arm", "riscv64", ""} {
			for _, retained := range []bool{false, true} {
				for _, orderedHost := range []bool{false, true} {
					want := retained && orderedHost && (target == "linux" || target == "windows") && (arch == "amd64" || arch == "arm64")
					if got := desktopNodeChainCONNECTAdmissionSupported(target, arch, retained, orderedHost); got != want {
						t.Fatalf("public CONNECT target %s/%s retained=%v ordered=%v: %v", target, arch, retained, orderedHost, got)
					}
				}
			}
		}
	}
	if got, want := nativeNodeChainCONNECTPlatformSupported(), desktopNodeChainCONNECTAdmissionSupported(runtime.GOOS, runtime.GOARCH, retainedNativeMultihopSelected(), nativeNodeChainPlatformSupported()); got != want {
		t.Fatal("public CONNECT bypassed its actual retained ordered host")
	}
}

func desktopCONNECTExpectedPublicHost() bool {
	return retainedNativeMultihopSelected() && nativeNodeChainPlatformSupported() &&
		(runtime.GOOS == "linux" || runtime.GOOS == "windows") &&
		(runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
}

func desktopCONNECTSelectPublicHandler(t *testing.T, a *app) {
	t.Helper()
	// Select only the existing dispatcher. This is not a native installation,
	// kernel, child, tunnel, or physical traffic acceptance fixture.
	directory := filepath.Join(clientRoot(a), "runtime", "native")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "NATIVE-RUNTIME.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_PORTABLE", "0")
}

func desktopCONNECTPublicHandlerFixture(t *testing.T, mode, protocol, authentication string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopCONNECTCaptureFixture(t, mode, authentication, "off")
	if protocol == "http-connect" {
		middle := &a.profiles.Profiles[1]
		proxy := *middle.External.HTTPSConnect
		proxy.TLSServerName = ""
		middle.External.Protocol, middle.External.HTTPSConnect, middle.External.HTTPConnect = protocol, nil, &proxy
		nodes[1].Mode = protocol
		a.profiles.Profiles[2].MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
	} else if protocol != "https-connect" {
		t.Fatal("unknown CONNECT fixture protocol")
	}
	desktopCONNECTSelectPublicHandler(t, a)
	return a, nodes
}

func TestDesktopCONNECTPublicCapabilityRetainsExactProtocolAndSecrets(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			for _, fault := range []string{"original", "anonymous", "hostname", "wrong-endpoint", "layer", "paired-token", "paired-proof", "paired-api", "missing-source", "opposite-source", "partial-auth", "oversized-auth", "bad-port", "bad-sni", "socks5"} {
				t.Run(fault, func(t *testing.T) {
					a, _ := desktopCONNECTPublicHandlerFixture(t, "wg", protocol, "password")
					p := common.CloneRouterProfile(a.profiles.Profiles[1])
					originalToken := publicProfileToken(p)
					proxy := p.External.HTTPConnect
					if protocol == "https-connect" {
						proxy = p.External.HTTPSConnect
					}
					username, password := proxy.Username, proxy.Password
					switch fault {
					case "anonymous":
						proxy.Username, proxy.Password = "", ""
					case "hostname":
						p.Endpoint, proxy.Host = "middle.example.test", "middle.example.test"
					case "wrong-endpoint":
						p.Endpoint = "203.0.113.199"
					case "layer":
						p.StartLayer = "aes-256-gcm"
					case "paired-token":
						p.APIToken = "unrelated-paired-token"
					case "paired-proof":
						p.NodeProofID = strings.Repeat("b", 64)
					case "paired-api":
						p.RouterAPI = "https://192.0.2.1"
					case "missing-source":
						p.External.HTTPConnect, p.External.HTTPSConnect = nil, nil
					case "opposite-source":
						p.External.HTTPConnect, p.External.HTTPSConnect = proxy, proxy
					case "partial-auth":
						proxy.Username = ""
					case "oversized-auth":
						proxy.Password = strings.Repeat("x", 4097)
					case "bad-port":
						proxy.Port = 65536
					case "bad-sni":
						proxy.TLSServerName = "not a server name"
					case "socks5":
						p.External.Protocol = "socks5"
					}
					before := common.CloneRouterProfile(p)
					view := publicProfileFor(p)
					want := (fault == "original" || fault == "anonymous") && desktopCONNECTExpectedPublicHost()
					if view.External == nil || view.External.OrderedMiddle != want || !reflect.DeepEqual(before, p) {
						t.Fatal("public CONNECT capability changed the original source or widened protocol admission", fault)
					}
					raw, err := json.Marshal(view)
					if err != nil {
						t.Fatal(err)
					}
					for _, secret := range []string{username, password, "unrelated-paired-token"} {
						if secret != "" && strings.Contains(string(raw), secret) {
							t.Fatal("public CONNECT capability disclosed a private credential")
						}
					}
					if fault == "anonymous" && publicProfileToken(p) == originalToken {
						t.Fatal("public source token lost the original authentication identity")
					}
				})
			}
		})
	}
}

func desktopCONNECTPublicCaptureBoundary(t *testing.T, a *app, nodes []common.MultihopNodeSelection, q multihopConnectRequest) {
	t.Helper()
	before := cloneRouterProfileStore(a.profiles)
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	captures, preflights := 0, 0
	stop := errors.New("component boundary: no installed CONNECT native launch was attempted")
	driver := nativeMultihopConnectRuntime{
		capture: func(owner *app, selection multihopSelection, modes []string) (multihopSelection, error) {
			captures++
			return captureNativeNodeChainSelection(owner.connectionOperationContextOrBackground(), clientRoot(owner), selection, modes, nil)
		},
		preflight: func(owner *app, selection multihopSelection, _ *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
			preflights++
			if owner != a || selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.connect == nil || selection.Native.chain.chain != nil || selection.Native.chain.socks != nil || !reflect.DeepEqual(nodeChainSelectedReferences(selection.Nodes), nodes) {
				t.Fatal("public CONNECT handler substituted the original typed source")
			}
			if err := selection.Native.chain.currentContext(context.Background(), a); err != nil {
				t.Fatal("public CONNECT source is no longer current", err)
			}
			_, meta, err := selection.Native.chain.connect.source.ReadValidated()
			if err != nil || meta.NativeAdmission != "closed" || len(meta.Proofs) != len(nodes) {
				t.Fatal("public source compilation invented a native proof", err)
			}
			for i, proof := range meta.Proofs {
				if proof.Mode != nodes[i].Mode {
					t.Fatal("public capture changed an original protocol")
				}
			}
			return nil, stop
		},
		stage: func(*app, multihopSelection, *desktopNodeLaunch) error {
			t.Error("source component entered native CONNECT staging")
			return stop
		},
		proof: func(*app, multihopSelection, *exec.Cmd) error {
			t.Error("source component invented native CONNECT proof")
			return stop
		},
	}
	response := httptest.NewRecorder()
	a.nativeMultihopConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/multihop/connect", bytes.NewReader(raw)), driver)
	if !desktopCONNECTExpectedPublicHost() {
		if response.Code != http.StatusNotImplemented || captures != 0 || preflights != 0 || a.cmd != nil || a.state.Connected || !reflect.DeepEqual(before, a.profiles) {
			t.Fatal("unavailable original ordered host gained CONNECT admission", response.Code, response.Body.String())
		}
		return
	}
	// The real physical-network snapshot remains mandatory before capture. An
	// environment that denies that OS query must fail this hosted component;
	// no test-only interface or successful network observation is substituted.
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), stop.Error()) || captures != 1 || preflights != 1 || a.cmd != nil || a.state.Connected || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("public CONNECT did not reach exactly its original source boundary", response.Code, response.Body.String(), captures, preflights)
	}
}

func TestDesktopCONNECTPublicHandlerReachesOriginalTypedCapture(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			for _, protocol := range []string{"http-connect", "https-connect"} {
				t.Run(protocol, func(t *testing.T) {
					a, nodes := desktopCONNECTPublicHandlerFixture(t, mode, protocol, "password")
					desktopCONNECTPublicCaptureBoundary(t, a, nodes, orderedPublicRequest(t, a, nodes))
				})
			}
		})
	}
}

func TestDesktopCONNECTRegisteredRouteRefusesChangedSourceAndGraph(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			for _, fault := range []string{"stale-middle", "stale-final", "partial-capture", "cancelled", "server", "auto", "layer", "hostname", "first", "final", "wrong-protocol"} {
				t.Run(fault, func(t *testing.T) {
					a, nodes := desktopCONNECTPublicHandlerFixture(t, "wg", protocol, "password")
					proxy := a.profiles.Profiles[1].External.HTTPConnect
					if protocol == "https-connect" {
						proxy = a.profiles.Profiles[1].External.HTTPSConnect
					}
					if fault == "layer" {
						a.profiles.Profiles[1].StartLayer = "aes-256-gcm"
					}
					if fault == "hostname" {
						a.profiles.Profiles[1].Endpoint, proxy.Host = "middle.example.test", "middle.example.test"
					}
					q := orderedPublicRequest(t, a, nodes)
					status := http.StatusBadRequest
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					switch fault {
					case "stale-middle":
						proxy.Password += "-replacement"
						status = http.StatusConflict
					case "stale-final":
						a.profiles.Profiles[2].APIToken += "-replacement"
						status = http.StatusConflict
					case "partial-capture":
						q.ExpectedProfileTokens = nil
					case "cancelled":
						cancel()
						status = http.StatusConflict
					case "server", "auto":
						q.Execution = fault
					case "first":
						q.Nodes[0], q.Nodes[1] = q.Nodes[1], q.Nodes[0]
					case "final":
						q.Nodes[2].Mode = "hysteria2"
					case "wrong-protocol":
						if protocol == "https-connect" {
							q.Nodes[1].Mode = "http-connect"
						} else {
							q.Nodes[1].Mode = "https-connect"
						}
					}
					if !desktopCONNECTExpectedPublicHost() && fault != "cancelled" && fault != "partial-capture" && fault != "server" && fault != "auto" {
						status = http.StatusNotImplemented
					}
					before := cloneRouterProfileStore(a.profiles)
					raw, err := json.Marshal(q)
					if err != nil {
						t.Fatal(err)
					}
					mux := http.NewServeMux()
					registerDesktopMultihopRoutes(mux, a)
					response := httptest.NewRecorder()
					mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/multihop/connect", bytes.NewReader(raw)).WithContext(ctx))
					_, graph := getActiveMultihopGraph(a)
					if response.Code != status || a.cmd != nil || a.state.Connected || graph || !reflect.DeepEqual(before, a.profiles) {
						t.Fatal("registered CONNECT route crossed the source, protocol or lifecycle guard", fault, response.Code, response.Body.String())
					}
				})
			}
		})
	}
}

func TestDesktopCONNECTCandidateProfileLoadReachesPublicCapture(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			a, members, candidate := orderedCONNECTCandidateProposalFixture(t, "awg2-strong", protocol, "off")
			desktopCONNECTSelectPublicHandler(t, a)
			control, profiles, nodes, compiled := orderedCONNECTCandidateCompile(t, a, members, candidate)
			record, err := a.orderedCandidateProfileRecordLocked(control, "Original CONNECT candidate")
			if err != nil {
				t.Fatal(err)
			}
			publication, err := appendOrderedCandidateProfile(a, record, func() error { return compiled.validate(context.Background(), control, profiles) })
			if err != nil || publication == nil {
				t.Fatal("source-checked CONNECT candidate publication", err)
			}
			mux := http.NewServeMux()
			registerConnectionProfileSetupRoutes(mux, a)
			raw, err := json.Marshal(map[string]string{"id": record.ID})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/connection-profile/setup/load", bytes.NewReader(raw)))
			if response.Code != http.StatusOK {
				t.Fatal("registered candidate Load refused original references", response.Code, response.Body.String())
			}
			var loaded struct {
				Selected string            `json:"selected_node_id"`
				Tokens   map[string]string `json:"profile_tokens"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &loaded); err != nil {
				t.Fatal(err)
			}
			q := orderedPublicRequest(t, a, nodes)
			if loaded.Selected != control.ID || !reflect.DeepEqual(loaded.Tokens, q.ExpectedProfileTokens) {
				t.Fatal("registered Load did not return the exact restored public source identities")
			}
			middle, found := a.profileByIDLocked(candidate.ID)
			if !found || !reflect.DeepEqual(middle, candidate) {
				t.Fatal("candidate Load changed its original private CONNECT source")
			}
			q.ExpectedSelectedNodeID, q.ExpectedProfileTokens = &loaded.Selected, loaded.Tokens
			desktopCONNECTPublicCaptureBoundary(t, a, nodes, q)
		})
	}
}
