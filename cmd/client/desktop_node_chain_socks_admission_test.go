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

func TestDesktopSOCKSPublicAdmissionTargetBounds(t *testing.T) {
	connectBefore := nativeNodeChainCONNECTPlatformSupported()
	for _, target := range []string{"linux", "windows", "darwin", "android", "freebsd"} {
		for _, arch := range []string{"amd64", "arm64", "386", "arm", "riscv64", ""} {
			for _, retained := range []bool{false, true} {
				want := retained && (target == "linux" || target == "windows" || target == "darwin") && (arch == "amd64" || arch == "arm64")
				if got := desktopNodeChainSOCKSAdmissionSupported(target, arch, retained); got != want {
					t.Fatalf("public SOCKS target %s/%s retained=%v: %v", target, arch, retained, got)
				}
			}
		}
	}
	if nativeNodeChainCONNECTPlatformSupported() != connectBefore {
		t.Fatal("SOCKS target checks changed the separately owned CONNECT admission")
	}
}

func desktopSOCKSPublicHandlerFixture(t *testing.T, mode, authentication string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopSOCKSCaptureFixture(t, mode, authentication, "off")
	// Select the real dispatcher only. This marker is not an installed bundle,
	// native child, privileged kernel, proof, or physical-traffic receipt.
	directory := filepath.Join(clientRoot(a), "runtime", "native")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "NATIVE-RUNTIME.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_PORTABLE", "0")
	return a, nodes
}

func TestDesktopSOCKSPublicCapabilityRetainsStrictSourceAndSecrets(t *testing.T) {
	for _, fault := range []string{"original", "anonymous", "hostname", "wrong-endpoint", "layer", "paired-token", "paired-proof", "paired-api", "missing-source", "partial-auth", "oversized-auth", "bad-port", "http-connect", "https-connect"} {
		t.Run(fault, func(t *testing.T) {
			a, _ := desktopSOCKSPublicHandlerFixture(t, "wg", "password")
			p := common.CloneRouterProfile(a.profiles.Profiles[1])
			originalToken := publicProfileToken(p)
			switch fault {
			case "anonymous":
				p.External.SOCKS5.Username, p.External.SOCKS5.Password = "", ""
			case "hostname":
				p.Endpoint, p.External.SOCKS5.Host = "middle.example.test", "middle.example.test"
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
				p.External.SOCKS5 = nil
			case "partial-auth":
				p.External.SOCKS5.Username = ""
			case "oversized-auth":
				p.External.SOCKS5.Password = strings.Repeat("x", 256)
			case "bad-port":
				p.External.SOCKS5.Port = 0
			case "http-connect", "https-connect":
				p.External.Protocol = fault
			}
			before := common.CloneRouterProfile(p)
			view := publicProfileFor(p)
			want := (fault == "original" || fault == "anonymous") && desktopNodeChainSOCKSAdmissionSupported(runtime.GOOS, runtime.GOARCH, true)
			if view.External == nil || view.External.OrderedMiddle != want || !reflect.DeepEqual(p, before) {
				t.Fatal("public capability changed its source or admitted an unsupported middle", fault)
			}
			raw, err := json.Marshal(view)
			if err != nil {
				t.Fatal(err)
			}
			credentials := a.profiles.Profiles[1].External.SOCKS5
			for _, secret := range []string{credentials.Username, credentials.Password, "unrelated-paired-token"} {
				if secret != "" && strings.Contains(string(raw), secret) {
					t.Fatal("public ordered capability disclosed a private credential")
				}
			}
			if fault == "anonymous" && publicProfileToken(p) == originalToken {
				t.Fatal("public source token lost original authentication identity")
			}
		})
	}
}

func TestDesktopSOCKSPublicPhysicalBoundaryAndSourceContract(t *testing.T) {
	if !desktopNodeChainSOCKSAdmissionSupported(runtime.GOOS, runtime.GOARCH, true) {
		t.Skip("installed SOCKS public target is not enabled on this platform")
	}
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, authentication := range []string{"password", "none"} {
			t.Run(mode+"/"+authentication, func(t *testing.T) {
				a, nodes := desktopSOCKSPublicHandlerFixture(t, mode, authentication)
				before := cloneRouterProfileStore(a.profiles)
				q := orderedPublicRequest(t, a, nodes)
				raw, err := json.Marshal(q)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				request := httptest.NewRequest(http.MethodPost, "/api/multihop/connect", bytes.NewReader(raw)).WithContext(ctx)
				// Observe the same shipping physical function without replacing it.
				// Some component environments deny the actual interface inventory.
				physicalBefore := physicalNetworkIdentity()
				captures, preflights, sourceChecks := 0, 0, 0
				checkSource := func(selection multihopSelection) {
					sourceChecks++
					if selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.socks == nil || selection.Native.chain.chain != nil || selection.Native.chain.connect != nil || !reflect.DeepEqual(nodeChainSelectedReferences(selection.Nodes), nodes) {
						t.Fatal("original public request substituted its typed source")
					}
					if err := selection.Native.chain.currentContext(ctx, a); err != nil {
						t.Fatal("public source is not current", err)
					}
					_, meta, err := selection.Native.chain.socks.source.ReadValidated()
					if err != nil || meta.NativeAdmission != "closed" || len(meta.Proofs) != 3 || meta.Proofs[0].Mode != mode || meta.Proofs[1].Mode != "socks5" || meta.Proofs[2].Mode != "shadowsocks" {
						t.Fatal("public source compilation invented native proof", err)
					}
				}
				stop := errors.New("component boundary: no installed native launch was attempted")
				driver := nativeMultihopConnectRuntime{
					capture: func(owner *app, selection multihopSelection, modes []string) (multihopSelection, error) {
						captures++
						// This is the real source compiler at the public capture seam;
						// installed bundle/host verification remains a native gate.
						return captureNativeNodeChainSelection(owner.connectionOperationContextOrBackground(), clientRoot(owner), selection, modes, nil)
					},
					preflight: func(owner *app, selection multihopSelection, _ *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
						preflights++
						if owner != a {
							t.Fatal("public handler replaced its original owner")
						}
						checkSource(selection)
						return nil, stop
					},
					stage: func(*app, multihopSelection, *desktopNodeLaunch) error {
						t.Error("component test entered native staging")
						return stop
					},
					proof: func(*app, multihopSelection, *exec.Cmd) error {
						t.Error("component test invented native proof")
						return stop
					},
				}
				response := httptest.NewRecorder()
				a.nativeMultihopConnectOwned(response, request, driver)
				if request.Context() != ctx || ctx.Err() != nil || request.Method != http.MethodPost || request.URL.Path != "/api/multihop/connect" {
					t.Fatal("public physical boundary changed the original request/context")
				}
				if physicalBefore == "" {
					if physicalNetworkIdentity() != "" || response.Code != http.StatusConflict || strings.TrimSpace(response.Body.String()) != "could not capture the physical multihop network" || captures != 0 || preflights != 0 || sourceChecks != 0 {
						t.Fatal("public handler did not preserve the exact Local admission boundary", response.Code, response.Body.String(), captures, preflights)
					}
					// This separate compiler check is component-only. It does not
					// replace the unavailable public physical path or native proof.
					a.mu.Lock()
					selection, err := a.resolveNativeMultihopRequestLocked(q)
					a.mu.Unlock()
					if err != nil {
						t.Fatal("original public source no longer resolves", err)
					}
					captured, err := captureNativeNodeChainSelection(ctx, clientRoot(a), selection, []string{selection.ExitMode}, nil)
					if err != nil {
						t.Fatal("original public source compiler refused", err)
					}
					checkSource(captured)
					t.Log("component-only: public physical inventory refused; original request source compiled independently")
				} else if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), stop.Error()) || captures != 1 || preflights != 1 {
					t.Fatal("public handler did not preserve the exact Local admission boundary", response.Code, response.Body.String(), captures, preflights)
				}
				_, nativeOwner := nativeMultihopOwners.Load(a)
				_, childOwner := desktopNodeOwners.Load(a)
				_, graph := getActiveMultihopGraph(a)
				if sourceChecks != 1 || nativeOwner || childOwner || graph || a.cmd != nil || a.state.Connected || !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("component source check acquired native authority or changed original profiles")
				}
			})
		}
	}
}

func TestDesktopSOCKSRegisteredPublicRouteRefusesStaleAndUnsupportedGraphs(t *testing.T) {
	if !desktopNodeChainSOCKSAdmissionSupported(runtime.GOOS, runtime.GOARCH, true) {
		t.Skip("installed SOCKS public target is not enabled on this platform")
	}
	for _, fault := range []string{"stale-middle", "partial-capture", "cancelled", "server", "auto", "layer", "hostname", "first", "final", "connect"} {
		t.Run(fault, func(t *testing.T) {
			a, nodes := desktopSOCKSPublicHandlerFixture(t, "wg", "password")
			status := http.StatusBadRequest
			if fault == "layer" {
				a.profiles.Profiles[1].StartLayer = "aes-256-gcm"
			}
			if fault == "hostname" {
				a.profiles.Profiles[1].Endpoint, a.profiles.Profiles[1].External.SOCKS5.Host = "middle.example.test", "middle.example.test"
			}
			q := orderedPublicRequest(t, a, nodes)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "stale-middle":
				a.profiles.Profiles[1].External.SOCKS5.Password += "-replaced"
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
			case "connect":
				// CONNECT is admitted on this same retained Windows/Linux host,
				// but a SOCKS source cannot acquire its distinct typed authority.
				q.Nodes[1].Mode = "http-connect"
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
				t.Fatal("registered public route crossed original source or shape guard", fault, response.Code, response.Body.String())
			}
		})
	}
}
