package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

type desktopImportedExecutionFixture func(*testing.T, int, string, string, int, ...string) (*app, *desktopNodeLaunch)

// This uses the real saved Custom TCP compiler. Native process/proof/lease
// behavior is modeled only by the existing explicitly scoped product fixture.
func desktopHostnameExecutionLaunchFixture(t *testing.T, count int, target, method string, keyBytes int, modes ...string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, count)
	if len(modes) != 0 {
		installOrderedAWGAssets(t, a, nodes, modes, "off")
	}
	installDesktopOrderedHostname(t, a, nodes)
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
	}
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	lookups := 0
	selection, err = captureNativeMultihopSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, func(context.Context, string) ([]netip.Addr, error) {
		lookups++
		return nil, errors.New("ambient hostname resolution forbidden")
	})
	if lookups != 0 {
		t.Fatal("hostname execution acquired an ordinary-network resolver")
	}
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
	if err != nil {
		t.Fatal(err)
	}
	// This marker selects only the public capability dispatcher, matching the
	// existing SOCKS source fixture. It is not an installed/native receipt.
	directory := filepath.Join(clientRoot(a), "runtime", "native")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "NATIVE-RUNTIME.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_PORTABLE", "0")
	return a, launch
}

func TestDesktopHostnameExecutionOriginalPreparation(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, target := range []string{"linux", "windows", "darwin"} {
			for _, requested := range []string{"server", "auto"} {
				t.Run(fmt.Sprintf("%d/%s/%s", count, target, requested), func(t *testing.T) {
					a, launch := desktopHostnameExecutionLaunchFixture(t, count, target, "", 0)
					original := cloneRouterProfileStore(a.profiles)
					members := launch.chain.selection.Nodes
					if err := desktopOrderedExecutionMembers(members, requested); err != nil {
						t.Fatal("saved hostname prefix refused", err)
					}
					view := publicProfileFor(members[count-2].Profile)
					if view.External == nil || view.External.OrderedExecutionMiddle || !view.External.OrderedHostnameExecutionMiddle {
						t.Fatal("hostname capability borrowed literal admission")
					}
					owner, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
					if err != nil {
						t.Fatal("saved hostname preparation refused", err)
					}
					var source mobilemultihop.NodeChainSource
					if json.Unmarshal([]byte(owner.preparation.LocalSource()), &source) != nil || source.Schema != 2 || len(source.Nodes) != count || source.IdentitySources[count-2] != "" {
						t.Fatal("hostname preparation lost original source")
					}
					wanted, err := desktopNodeChainImportedHostnameInput(members[count-2].Profile)
					if err != nil || source.Nodes[count-2] != wanted {
						t.Fatal("hostname preparation replaced saved resolver or original import", err)
					}
					policy, err := owner.physical.OriginalDesktopPolicy()
					if err != nil || policy != launch.chain.policy || policy.OriginalChain() != launch.chain.selection.Native.chain.chain {
						t.Fatal("hostname preparation replaced original policy", err)
					}
					request := orderedPublicRequest(t, a, nodeChainSelectedReferences(members))
					request.Execution = requested
					a.mu.Lock()
					_, currentErr := a.resolveNativeMultihopRequestLocked(request)
					a.mu.Unlock()
					if currentErr != nil {
						t.Fatal("original hostname tokens refused", currentErr)
					}
					a.profiles.Profiles[count-2].DNSPort++
					a.mu.Lock()
					_, staleErr := a.resolveNativeMultihopRequestLocked(request)
					a.mu.Unlock()
					a.profiles = cloneRouterProfileStore(original)
					if staleErr == nil {
						t.Fatal("hostname request borrowed a changed saved resolver")
					}
					if !reflect.DeepEqual(original, a.profiles) {
						t.Fatal("hostname preparation rewrote saved credentials or resolver")
					}
					for _, fault := range []string{"dns-mode", "dns-protocol", "dns-host", "dns-port", "layer", "paired-id", "endpoint", "key", "duplicate-proof", "wrong-position"} {
						changed := cloneDesktopNodeChainMembers(members)
						p := &changed[count-2].Profile
						switch fault {
						case "dns-mode":
							p.DNSMode = "default"
						case "dns-protocol":
							p.DNSProtocol = "udp"
						case "dns-host":
							p.DNSHost = "resolver.example.test"
						case "dns-port":
							p.DNSPort = 0
						case "layer":
							p.StartLayer = "aes-256-gcm"
						case "paired-id":
							p.NodeProofID = changed[0].Profile.NodeProofID
						case "endpoint":
							p.Endpoint = "foreign.example.test"
						case "key":
							p.External.Shadowsocks.Password = "invalid"
						case "duplicate-proof":
							changed[count-3].Profile.NodeProofID = changed[0].Profile.NodeProofID
						case "wrong-position":
							changed[count-3], changed[count-2] = changed[count-2], changed[count-3]
						}
						if desktopOrderedExecutionMembers(changed, requested) == nil {
							t.Fatal("hostname execution admitted changed original policy", fault)
						}
					}
					if err := owner.attach(launch); err != nil {
						t.Fatal(err)
					}
					replacement, err := mobilemultihop.NewDesktopNodeChainExecutionPreparation(policy, requested)
					if err != nil {
						t.Fatal(err)
					}
					owner.preparation = replacement
					if owner.validateSource() == nil {
						t.Fatal("equal hostname preparation replaced original owner")
					}
				})
			}
		}
	}
}

func TestDesktopHostnameExecutionTrioRefused(t *testing.T) {
	_, launch := desktopHostnameExecutionLaunchFixture(t, 3, "linux", "", 0)
	for _, requested := range []string{"server", "auto"} {
		if desktopOrderedExecutionMembers(launch.chain.selection.Nodes, requested) == nil {
			t.Fatal("hostname trio acquired suffix packet authority")
		}
		if _, err := newDesktopNodeChainExecutionSource(launch.chain, requested); err == nil {
			t.Fatal("hostname trio acquired native preparation")
		}
	}
}

func TestDesktopHostnameExecutionPublic4Server(t *testing.T) {
	testDesktopImportedExecutionPublicConnectWith(t, []int{4}, desktopHostnameExecutionLaunchFixture, desktopImportedExecutionChoice{"server", "server"})
}
func TestDesktopHostnameExecutionPublic4CompareLocal(t *testing.T) {
	testDesktopImportedExecutionPublicConnectWith(t, []int{4}, desktopHostnameExecutionLaunchFixture, desktopImportedExecutionChoice{"auto", "local"})
}
func TestDesktopHostnameExecutionPublic4CompareServer(t *testing.T) {
	testDesktopImportedExecutionPublicConnectWith(t, []int{4}, desktopHostnameExecutionLaunchFixture, desktopImportedExecutionChoice{"auto", "server"})
}
func TestDesktopHostnameExecutionPublic8Server(t *testing.T) {
	testDesktopImportedExecutionPublicConnectWith(t, []int{8}, desktopHostnameExecutionLaunchFixture, desktopImportedExecutionChoice{"server", "server"})
}
func TestDesktopHostnameExecutionPublic8CompareLocal(t *testing.T) {
	testDesktopImportedExecutionPublicConnectWith(t, []int{8}, desktopHostnameExecutionLaunchFixture, desktopImportedExecutionChoice{"auto", "local"})
}
func TestDesktopHostnameExecutionPublic8CompareServer(t *testing.T) {
	testDesktopImportedExecutionPublicConnectWith(t, []int{8}, desktopHostnameExecutionLaunchFixture, desktopImportedExecutionChoice{"auto", "server"})
}
func TestDesktopHostnameExecutionRestore4(t *testing.T) {
	testDesktopImportedExecutionRestoreWith(t, 4, desktopHostnameExecutionLaunchFixture)
}
func TestDesktopHostnameExecutionRestore8(t *testing.T) {
	testDesktopImportedExecutionRestoreWith(t, 8, desktopHostnameExecutionLaunchFixture)
}
func TestDesktopHostnameExecutionSavedProfile(t *testing.T) {
	for _, count := range []int{4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) { testDesktopImportedExecutionSavedProfileWith(t, count, true) })
	}
}

func TestDesktopHostnameExecutionRefusesForeignNativeResolver(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, fault := range []string{"omitted", "foreign-resolver"} {
			t.Run(fmt.Sprintf("%d/%s", count, fault), func(t *testing.T) {
				f, s := prepareDesktopImportedExecutionModelWith(t, count, "server", "server", desktopHostnameExecutionLaunchFixture)
				replacement := ""
				if fault == "foreign-resolver" {
					p := cloneDesktopNodeChainMembers(f.selection.Nodes)[count-2].Profile
					p.DNSPort++
					var err error
					replacement, err = desktopNodeChainImportedHostnameInput(p)
					if err != nil {
						t.Fatal(err)
					}
				}
				f.executionModel.importedSourceOverride = &replacement
				if err := s.startContext(f.operation); err == nil {
					t.Fatal("hostname execution acquired foreign native resolver source")
				}
				if f.starts != 0 || desktopOwnedNodeProcess(s.launch) != nil || f.a.state.Connected {
					t.Fatal("foreign hostname source created process or Connected")
				}
				if err := s.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
