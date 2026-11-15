package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// These tests execute the actual catalog/compiler and bounded admission
// predicate. Installed Darwin execution, PF/utun, selected proofs and joined
// relay retirement remain the separate privileged native fixture's evidence.
func TestDesktopDarwinImportedTrioExecutionAdmission(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
			for _, requested := range []string{"server", "auto"} {
				t.Run(mode+"/"+method+"/"+requested, func(t *testing.T) {
					a, nodes := desktopNodeChainCaptureFixture(t, 3)
					installOrderedAWGAssets(t, a, nodes, []string{mode, "wg", "shadowsocks"}, "off")
					keyBytes := 32
					if method == "2022-blake3-aes-128-gcm" {
						keyBytes = 16
					}
					installDesktopOrderedImportedCipher(t, a, nodes, method, keyBytes)
					for i := range a.profiles.Profiles {
						a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
					}
					control, _ := a.profileByIDLocked(a.profiles.SelectedID)
					selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
					if err != nil {
						t.Fatal(err)
					}
					selection, err = captureNativeMultihopSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
					if err != nil || !desktopDarwinImportedTrioExecutionMembers(selection.Nodes, requested) {
						t.Fatal("original literal Darwin trio lost bounded admission", err)
					}
					launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("b", 32), "darwin")
					if err != nil {
						t.Fatal(err)
					}
					owner, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
					if err != nil {
						t.Fatal("original Darwin execution preparation failed", err)
					}
					_, meta, capture, err := owner.readPolicy()
					if err != nil || meta.TargetOS != "darwin" || len(meta.Prefixes) != 3 || meta.Prefixes[0].Mode != mode || meta.Prefixes[1].NodeKind != "external" || meta.Prefixes[1].NodeID != "" || capture.SelectedDNS.Physical || owner.preparation.Execution() != requested {
						t.Fatal("Darwin admission replaced captured protocol, imported identity or DNS", err)
					}
					original, err := owner.physical.OriginalDesktopPolicy()
					if err != nil || original != launch.chain.policy || original.OriginalChain() != selection.Native.chain.chain {
						t.Fatal("Darwin preparation replaced original source authority", err)
					}
				})
			}
		}
	}
}

func TestDesktopDarwinImportedTrioExecutionBoundedSource(t *testing.T) {
	_, launch := desktopImportedExecutionLaunchFixture(t, "darwin", "2022-blake3-aes-256-gcm", 32)
	original := launch.chain.selection.Nodes
	if !desktopDarwinImportedTrioExecutionMembers(original, "server") {
		t.Fatal("original source fixture did not qualify")
	}
	for _, fault := range []string{"local", "missing-choice", "foreign-choice", "empty", "two", "four", "paired-only", "entry-layer", "entry-whitening", "entry-unknown-layer", "exit-layer", "exit-whitening", "exit-unknown-layer", "middle-layer", "hostname", "changed-endpoint", "noncanonical-key", "duplicate-proof", "foreign-final"} {
		t.Run(fault, func(t *testing.T) {
			members := cloneDesktopNodeChainMembers(original)
			requested := "server"
			switch fault {
			case "local":
				requested = "local"
			case "missing-choice":
				requested = ""
			case "foreign-choice":
				requested = "compare"
			case "empty":
				members = nil
			case "two":
				members = members[:2]
			case "four":
				members = append(members, members[2])
			case "paired-only":
				members[1].Profile = cloneRouterProfile(members[0].Profile)
				members[1].Profile.ID = "independent-paired-middle"
			case "entry-layer", "entry-whitening", "entry-unknown-layer":
				members[0].Profile.StartLayer = map[string]string{"entry-layer": "aes-256-gcm", "entry-whitening": "aes-256-gcm+xor-whitening", "entry-unknown-layer": "unknown"}[fault]
			case "exit-layer", "exit-whitening", "exit-unknown-layer":
				members[2].Profile.StartLayer = map[string]string{"exit-layer": "aes-256-gcm", "exit-whitening": "aes-256-gcm+xor-whitening", "exit-unknown-layer": "unknown"}[fault]
			case "middle-layer":
				members[1].Profile.StartLayer = "aes-256-gcm"
			case "hostname":
				members[1].Profile.External.Shadowsocks.Server, members[1].Profile.Endpoint = "middle.example.test", "middle.example.test"
			case "changed-endpoint":
				members[1].Profile.Endpoint = "203.0.113.199"
			case "noncanonical-key":
				members[1].Profile.External.Shadowsocks.Password += "\n"
			case "duplicate-proof":
				members[2].Profile.NodeProofID = members[0].Profile.NodeProofID
			case "foreign-final":
				members[2].Mode = "hysteria2"
			}
			if desktopDarwinImportedTrioExecutionMembers(members, requested) {
				t.Fatal("bounded Darwin execution adopted an unrelated or changed source", fault)
			}
		})
	}
}

func TestDesktopImportedTrioStatusKeepsSeparateCapability(t *testing.T) {
	a, _ := desktopNodeChainCaptureFixture(t, 3)
	response := httptest.NewRecorder()
	a.nativeMultihopStatus(response, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil))
	var actual struct {
		Ordinary []string `json:"ordered_executions"`
		Imported []string `json:"ordered_imported_trio_executions"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &actual) != nil {
		t.Fatal("actual public capability response failed", response.Code)
	}
	ordinary, imported := []string{"local"}, []string{"local"}
	if retainedNativeMultihopSelected() && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
		if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
			ordinary = []string{"local", "server", "auto"}
		}
		if runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			imported = []string{"local", "server", "auto"}
		}
	}
	if !reflect.DeepEqual(actual.Ordinary, ordinary) || !reflect.DeepEqual(actual.Imported, imported) {
		t.Fatal("public status conflated paired and imported execution authority", actual)
	}
}
