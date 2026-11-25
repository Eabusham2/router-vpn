package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func desktopSelectedPrivateStreamFixture(t *testing.T, count, private int) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	return desktopPrivateStreamFixtureWithEntry(t, count, private, "wg")
}

func desktopPrivateStreamFixtureWithEntry(t *testing.T, count, private int, entry string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	var imports []int
	for position := 1; position < count-1; position++ {
		if position != private {
			imports = append(imports, position)
		}
	}
	a, refs := desktopIndependentImportedFixture(t, desktopIndependentImportedLayout{"selected-private-stream", count, imports}, entry, "off")
	refs[private].Mode = "shadowsocks"
	path := filepath.Join(clientRoot(a), "generated", refs[private].ID, "shadowsocks", "sing-box.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'s'}, 32))
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(160 + private)}, 32))
	if strings.Count(string(raw), oldKey) != 1 {
		t.Fatal("private fixture lost its original cipher")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), oldKey, newKey, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	a.profiles.Profiles[count-1].MultihopNodes = refs
	return a, refs
}

func TestDesktopSelectedPrivateStreamCaptureAndNamedRestore(t *testing.T) {
	testSelectedPrivateStreamCaptureAndNamedRestore(t, "wg")
}

func TestDesktopAWGPrivateStreamCaptureAndNamedRestore(t *testing.T) {
	for _, entry := range []string{"awg2-fast", "awg2-strong"} {
		t.Run(entry, func(t *testing.T) { testSelectedPrivateStreamCaptureAndNamedRestore(t, entry) })
	}
}

func testSelectedPrivateStreamCaptureAndNamedRestore(t *testing.T, entry string) {
	for _, count := range []int{4, 9, 16} {
		for _, execution := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, execution), func(t *testing.T) {
				private := count - 2
				a, refs := desktopPrivateStreamFixtureWithEntry(t, count, private, entry)
				selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[count-1], a.profiles.Profiles, refs, execution)
				if err != nil {
					t.Fatal("qualified selected private route refused", err)
				}
				selection, err = captureNativeNodeChainSelection(t.Context(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
				if err != nil {
					t.Fatal("complete original private source refused", err)
				}
				if execution == "auto" {
					for i := 1; i < count-1; i++ {
						rows := orderedCandidateResponseSourceNodes(selection, execution, i)
						if len(rows) != count || rows[0].Mode != entry || rows[i].Mode != "shadowsocks" {
							t.Fatal("chooser lost original packet mode or measured stop", i)
						}
					}
				}
				launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "darwin")
				if err != nil {
					t.Fatal(err)
				}
				launch.chain.execution, err = newDesktopNodeChainExecutionSource(launch.chain, execution)
				if err != nil {
					t.Fatal("original selected private preparation", err)
				}
				capture, err := newDesktopMacOSNodeChainSelection(launch.chain)
				if err != nil || !capture.validMembers() {
					t.Fatal("macOS lost its exact private member policy", err)
				}
				response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{
					"name": "Private route " + execution, "mode": "shadowsocks", "multihop_enabled": true,
					"multihop_execution": execution, "multihop_nodes": refs,
				})
				var saved struct {
					Profile connectionProfileRecord `json:"profile"`
				}
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &saved) != nil ||
					len(saved.Profile.NodeChain) != count || !savedPairedStreamPath(saved.Profile) {
					t.Fatal("named private route save", response.Code, response.Body.String())
				}
				original := cloneRouterProfileStore(a.profiles)
				a.profiles.Profiles[private].DNSPort = 5301
				response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.Profile.ID})
				if response.Code != http.StatusOK || a.profiles.Profiles[private].DNSPort != original.Profiles[private].DNSPort ||
					a.profiles.Profiles[count-1].MultihopExecution != execution || !reflect.DeepEqual(a.profiles.Profiles[count-1].MultihopNodes, refs) || a.state.Connected {
					t.Fatal("named Load changed the private role or connected implicitly", response.Code, response.Body.String())
				}
				for _, fault := range []string{"entry", "first-private", "second-private", "layer"} {
					members := append([]desktopNodeChainMember(nil), selection.Nodes...)
					switch fault {
					case "entry":
						members[0].Mode = "awg2-pq"
					case "first-private":
						members[1], members[private] = members[private], members[1]
					case "second-private":
						members[1].Profile = members[private].Profile
						members[1].Profile.ID += "-other"
					case "layer":
						members[private].Profile.StartLayer = "aes-256-gcm"
					}
					if desktopNodeChainMultipleImportedExecutionShape(members) {
						t.Fatal("different route borrowed private selected admission", fault)
					}
				}
			})
		}
	}
}
