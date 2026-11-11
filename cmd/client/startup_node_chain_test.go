package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// These tests execute the shipping capture, source readers, JSON decoder and
// startup adapter guards. The manifest selects an explicit native test boundary;
// no installed runtime, host firewall, TUN, peer or encrypted traffic is claimed.
func startupOrderedTestApp(t *testing.T, count int) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("ordered startup retains the shipping protected-platform admission")
	}
	a, nodes := desktopNodeChainCaptureFixture(t, count)
	t.Setenv("HOMEVPN_PORTABLE", "0")
	modes := make([]string, count)
	for i := 0; i < count-1; i++ {
		modes[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3]
	}
	modes[count-1] = "shadowsocks"
	installOrderedAWGAssets(t, a, nodes, modes, "aes-256-gcm+xor-whitening")
	for i := range a.profiles.Profiles {
		p := &a.profiles.Profiles[i]
		p.KillSwitch, p.KillSwitchPolicy = true, "on-connect"
		p.AutoConnect, p.StartupMode = false, "manual"
	}
	control := &a.profiles.Profiles[count-1]
	control.AutoConnect, control.StartupMode = true, "auto"
	a.cfg.StateFile = filepath.Join(clientRoot(a), "startup.json")
	manifest := filepath.Join(clientRoot(a), "runtime", "native", "NATIVE-RUNTIME.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !nativeNodeChainPlatformSupported() {
		t.Fatal("explicit native boundary was not selected")
	}
	t.Cleanup(func() { startupPolicyCancels.Delete(a) })
	return a, nodes
}

func startupNodeChainCaptureForTest(t *testing.T, a *app) *startupPolicyCapture {
	t.Helper()
	capture, err := a.captureStartupPolicy()
	if err != nil || capture == nil || capture.nodeChain == nil {
		t.Fatalf("complete ordered startup capture failed: %v", err)
	}
	if err := capture.current(a); err != nil {
		t.Fatal("newly captured startup is not current", err)
	}
	return capture
}

func startupOrderedReceipt(t *testing.T, capture *startupPolicyCapture) startupSelection {
	t.Helper()
	selection := capture.nodeChain.selection
	last := startupSelection{
		RouterID: selection.Control.ID, RuntimeMode: selection.ExitMode,
		LogicalMode: "multihop", Base: selection.Base,
		ProfileToken: startupExternalProfileToken(selection.Control),
		UpdatedAt: time.Unix(1700000000, 0).UTC(), PathKind: startupNodeChainPathKind,
		NodeChain: capture.nodeChain.receipt(),
	}
	if err := validateStartupNodeChainSelection(last); err != nil {
		t.Fatal("fixture did not construct a complete reference-only receipt", err)
	}
	return last
}

func startupOrderedAssetPath(a *app, node common.MultihopNodeSelection, mode string) string {
	name := "wg.conf"
	if strings.HasPrefix(mode, "awg2-") {
		name = "awg.conf"
	} else if mode == "shadowsocks" {
		name = "sing-box.json"
	}
	return filepath.Join(clientRoot(a), "generated", node.ID, mode, name)
}

func startupOrderedChangeAsset(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte(nil), raw...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStartupNodeChainCapturesAllOriginalModesAndPrivateSources(t *testing.T) {
	for _, count := range []int{2, 3, 4, 8} {
		for _, mode := range []string{"auto", "smart-auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, mode), func(t *testing.T) {
				a, nodes := startupOrderedTestApp(t, count)
				a.profiles.Profiles[count-1].StartupMode = mode
				before := cloneRouterProfileStore(a.profiles)
				capture := startupNodeChainCaptureForTest(t, a)
				chain := capture.nodeChain
				if len(chain.selection.Nodes) != count || len(chain.tokens) != count ||
					chain.selection.ExitMode != "shadowsocks" || chain.selection.Base != desktopExternalEntryBase(nodes[0].Mode) ||
					!reflect.DeepEqual(before, a.profiles) || a.cmd != nil || a.state.Connected {
					t.Fatal("capture truncated, rewrote or launched its original ordered path")
				}
				var expected []viaEntryAsset
				for i, member := range chain.selection.Nodes {
					if member.Profile.ID != nodes[i].ID || member.Mode != nodes[i].Mode ||
						chain.tokens[i] != startupProfileToken(before.Profiles[i]) ||
						startupProfileToken(member.Profile) != chain.tokens[i] {
						t.Fatal("capture lost original ordered profile, mode or complete policy", i)
					}
					sources, err := captureSavedNodeChainSources(chain.root, before.Profiles[i], nodes[i].Mode)
					if err != nil {
						t.Fatal(err)
					}
					wantModes := []string{"wg"}
					if strings.HasPrefix(nodes[i].Mode, "awg2-") {
						wantModes = append(wantModes, nodes[i].Mode)
					}
					wantModes = append(wantModes, "shadowsocks")
					var actualModes []string
					for _, source := range sources {
						actualModes = append(actualModes, source.Mode)
						expected = append(expected, viaEntryAsset{nodes[i].ID, source.Mode, source.SHA256})
					}
					if !reflect.DeepEqual(actualModes, wantModes) {
						t.Fatal("capture omitted standard identity, exact transport or Start Layer source", i, actualModes)
					}
				}
				if !reflect.DeepEqual(chain.assets, expected) {
					t.Fatal("startup source inventory differs from original bounded file reads")
				}
				last := startupOrderedReceipt(t, capture)
				raw, err := json.Marshal(last)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range []string{"private-api-", "api_token", "private_key", "preshared_key", "password", clientRoot(a)} {
					if bytes.Contains(raw, []byte(forbidden)) {
						t.Fatalf("Last copied private material instead of its digest: %s", forbidden)
					}
				}
				var decoded startupSelection
				if err := json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(last, decoded) {
					t.Fatal("typed original receipt failed strict round trip", err)
				}
			})
		}
	}
}

func TestStartupNodeChainDelayRejectsEveryMemberAndSourceReplacement(t *testing.T) {
	changes := map[string]func(*app, []common.MultihopNodeSelection){
		"first-credential": func(a *app, _ []common.MultihopNodeSelection) { a.profiles.Profiles[0].APIToken += "-replacement" },
		"middle-policy": func(a *app, _ []common.MultihopNodeSelection) { a.profiles.Profiles[1].HomeLANAccess = !a.profiles.Profiles[1].HomeLANAccess },
		"final-policy": func(a *app, _ []common.MultihopNodeSelection) { a.profiles.Profiles[3].DNSPort = 5353 },
		"selected-control": func(a *app, nodes []common.MultihopNodeSelection) { a.profiles.SelectedID = nodes[0].ID },
		"order": func(a *app, _ []common.MultihopNodeSelection) {
			p := &a.profiles.Profiles[3]
			p.MultihopNodes[0], p.MultihopNodes[1] = p.MultihopNodes[1], p.MultihopNodes[0]
		},
		"mode": func(a *app, _ []common.MultihopNodeSelection) { a.profiles.Profiles[3].MultihopNodes[1].Mode = "awg2-strong" },
		"missing-middle": func(a *app, _ []common.MultihopNodeSelection) { a.profiles.Profiles = append(a.profiles.Profiles[:1], a.profiles.Profiles[2:]...) },
		"duplicate-middle": func(a *app, _ []common.MultihopNodeSelection) { a.profiles.Profiles = append(a.profiles.Profiles, cloneRouterProfile(a.profiles.Profiles[1])) },
		"startup-policy": func(a *app, _ []common.MultihopNodeSelection) { a.profiles.Profiles[3].StartupMode = "manual" },
		"auto-connect": func(a *app, _ []common.MultihopNodeSelection) { a.profiles.Profiles[3].AutoConnect = false },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			a, nodes := startupOrderedTestApp(t, 4)
			capture := startupNodeChainCaptureForTest(t, a)
			change(a, nodes)
			if capture.current(a) == nil {
				t.Fatal("delayed capture adopted replacement profile, selection or mode")
			}
			if a.cmd != nil || a.state.Connected {
				t.Fatal("source validation started a runtime")
			}
		})
	}
	t.Run("canonical-root", func(t *testing.T) {
		a, _ := startupOrderedTestApp(t, 4)
		capture := startupNodeChainCaptureForTest(t, a)
		t.Setenv("HOMEVPN_ROOT", t.TempDir())
		if capture.current(a) == nil {
			t.Fatal("delayed capture followed a replacement private root")
		}
	})
	for index, modes := range map[int][]string{
		0: {"wg", "shadowsocks"}, 1: {"wg", "awg2-fast", "shadowsocks"},
		2: {"wg", "awg2-strong", "shadowsocks"}, 3: {"wg", "shadowsocks"},
	} {
		for _, mode := range modes {
			t.Run(fmt.Sprintf("asset-%d-%s", index, mode), func(t *testing.T) {
				a, nodes := startupOrderedTestApp(t, 4)
				capture := startupNodeChainCaptureForTest(t, a)
				startupOrderedChangeAsset(t, startupOrderedAssetPath(a, nodes[index], mode))
				if capture.current(a) == nil {
					t.Fatal("delayed startup adopted a replaced original private source")
				}
			})
		}
	}
}

func TestStartupNodeChainLastKeepsProvedDraftAndNormalizedPolicy(t *testing.T) {
	a, nodes := startupOrderedTestApp(t, 4)
	control := cloneRouterProfile(a.profiles.Profiles[3])
	draft := append([]common.MultihopNodeSelection(nil), nodes...)
	draft[0], draft[1] = draft[1], draft[0]
	selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, draft, "local")
	if err != nil {
		t.Fatal(err)
	}
	root, err := canonicalBundleRoot(clientRoot(a))
	if err != nil {
		t.Fatal(err)
	}
	chain := &startupNodeChainCapture{root: root, selection: selection}
	for _, member := range selection.Nodes {
		chain.tokens = append(chain.tokens, startupProfileToken(member.Profile))
		sources, err := captureSavedNodeChainSources(root, member.Profile, member.Mode)
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range sources {
			chain.assets = append(chain.assets, viaEntryAsset{member.Profile.ID, source.Mode, source.SHA256})
		}
	}
	original := &startupPolicyCapture{profile: control, profileToken: startupProfileToken(control), nodeChain: chain}
	last := startupOrderedReceipt(t, original)
	if err := a.saveStartupSelection(last); err != nil {
		t.Fatal(err)
	}
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].EffectiveMTU = 1320 + i
	}
	a.profiles.Profiles[3].StartupMode = "last"
	capture := startupNodeChainCaptureForTest(t, a)
	if capture.nodeChain.last == nil || !reflect.DeepEqual(capture.nodeChain.receipt(), last.NodeChain) {
		t.Fatal("Last replaced its actually proved draft with the current saved order")
	}
	for i, member := range capture.nodeChain.selection.Nodes {
		if member.Profile.ID != draft[i].ID || member.Mode != draft[i].Mode {
			t.Fatal("Last lost an original ordered member", i)
		}
	}
	if !reflect.DeepEqual(a.profiles.Profiles[3].MultihopNodes, nodes) {
		t.Fatal("Last rewrote saved editor preferences")
	}
	withoutStartup := cloneRouterProfile(control)
	withoutStartup.AutoConnect, withoutStartup.StartupMode, withoutStartup.EffectiveMTU = false, "manual", 9000
	if startupExternalProfileToken(control) != startupExternalProfileToken(withoutStartup) {
		t.Fatal("durable original path identity depends on later startup or measured MTU settings")
	}
	last.UpdatedAt = last.UpdatedAt.Add(time.Second)
	if err := a.saveStartupSelection(last); err != nil {
		t.Fatal(err)
	}
	if capture.current(a) == nil {
		t.Fatal("delayed Last accepted replacement durable receipt bytes")
	}
}

func startupOrderedJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStartupNodeChainLastRejectsMalformedOrCrossFamilyReceipt(t *testing.T) {
	a, _ := startupOrderedTestApp(t, 4)
	capture := startupNodeChainCaptureForTest(t, a)
	good := startupOrderedJSON(t, startupOrderedReceipt(t, capture))
	mutate := func(change func(map[string]any)) []byte {
		var object map[string]any
		if err := json.Unmarshal(good, &object); err != nil {
			t.Fatal(err)
		}
		change(object)
		return startupOrderedJSON(t, object)
	}
	chain := func(object map[string]any) map[string]any { return object["node_chain"].(map[string]any) }
	members := func(object map[string]any) []any { return chain(object)["nodes"].([]any) }
	cases := map[string][]byte{
		"missing-tag": mutate(func(o map[string]any) { delete(o, "path_kind") }),
		"missing-chain": mutate(func(o map[string]any) { delete(o, "node_chain") }),
		"null-tag": mutate(func(o map[string]any) { o["path_kind"] = nil }),
		"null-tag-no-chain": mutate(func(o map[string]any) { o["path_kind"] = nil; delete(o, "node_chain") }),
		"empty-tag-no-chain": mutate(func(o map[string]any) { o["path_kind"] = ""; delete(o, "node_chain") }),
		"case-tag-no-chain": mutate(func(o map[string]any) { o["Path_Kind"] = o["path_kind"]; delete(o, "path_kind"); delete(o, "node_chain") }),
		"empty-tag": mutate(func(o map[string]any) { o["path_kind"] = "" }),
		"wrong-tag": mutate(func(o map[string]any) { o["path_kind"] = "pair-v1" }),
		"number-tag": mutate(func(o map[string]any) { o["path_kind"] = 1 }),
		"case-tag": mutate(func(o map[string]any) { o["Path_Kind"] = o["path_kind"]; delete(o, "path_kind") }),
		"null-chain": mutate(func(o map[string]any) { o["node_chain"] = nil }),
		"case-chain": mutate(func(o map[string]any) { o["Node_Chain"] = o["node_chain"]; delete(o, "node_chain") }),
		"cross-family": mutate(func(o map[string]any) { o["external"] = map[string]any{"protocol": "socks5", "direct": true} }),
		"null-external": mutate(func(o map[string]any) { o["external"] = nil }),
		"unknown": mutate(func(o map[string]any) { o["fallback"] = true }),
		"wrong-schema": mutate(func(o map[string]any) { chain(o)["schema"] = 2 }),
		"server": mutate(func(o map[string]any) { chain(o)["execution"] = "server" }),
		"compare": mutate(func(o map[string]any) { chain(o)["execution"] = "auto" }),
		"bad-root": mutate(func(o map[string]any) { chain(o)["root_sha256"] = "not-a-digest" }),
		"too-few-members": mutate(func(o map[string]any) { chain(o)["nodes"] = members(o)[:1] }),
		"duplicate-member": mutate(func(o map[string]any) { n := members(o); n[1] = n[0] }),
		"wrong-final": mutate(func(o map[string]any) { n := members(o); n[len(n)-1].(map[string]any)["mode"] = "wg" }),
		"wrong-prefix": mutate(func(o map[string]any) { members(o)[0].(map[string]any)["mode"] = "shadowsocks" }),
		"wrong-base": mutate(func(o map[string]any) { o["base"] = "awg" }),
		"foreign-control": mutate(func(o map[string]any) { o["router_id"] = "other-control" }),
		"missing-identity-source": mutate(func(o map[string]any) { m := members(o)[1].(map[string]any); m["sources"] = m["sources"].([]any)[1:] }),
		"bad-source-digest": mutate(func(o map[string]any) { m := members(o)[1].(map[string]any); m["sources"].([]any)[0].(map[string]any)["sha256"] = "bad" }),
		"unknown-member": mutate(func(o map[string]any) { members(o)[1].(map[string]any)["password"] = "not-an-owned-source" }),
		"case-member-id": mutate(func(o map[string]any) { m := members(o)[1].(map[string]any); m["ID"] = m["id"]; delete(m, "id") }),
		"unknown-source": mutate(func(o map[string]any) { m := members(o)[1].(map[string]any); m["sources"].([]any)[0].(map[string]any)["source"] = "replacement" }),
		"source-order": mutate(func(o map[string]any) { m := members(o)[1].(map[string]any); src := m["sources"].([]any); src[0], src[1] = src[1], src[0] }),
		"duplicate-tag": append([]byte("{\"path_kind\":\"node-chain-v1\","), good[1:]...),
		"duplicate-chain": append([]byte("{\"node_chain\":null,"), good[1:]...),
		"trailing-json": append(append([]byte(nil), good...), []byte(" {}")...),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := atomicWritePrivate(a.startupStatePath(), raw); err != nil {
				t.Fatal(err)
			}
			a.profiles.Profiles[3].StartupMode = "last"
			if next, err := a.captureStartupPolicy(); next != nil || !errors.Is(err, errOrderedNodeChainDispatch) {
				t.Fatalf("malformed or substituted ordered receipt downgraded to ordinary Last/AUTO: %v", err)
			}
			if a.cmd != nil || a.state.Connected {
				t.Fatal("invalid receipt started a runtime")
			}
		})
	}
	// Even with no saved ordered editor preference, the typed durable record
	// owns family admission and cannot silently become ordinary AUTO.
	t.Run("typed-record-without-editor-graph", func(t *testing.T) {
		for _, name := range []string{"missing-chain", "null-tag-no-chain", "empty-tag-no-chain", "case-tag-no-chain"} {
			a.profiles.Profiles[3].MultihopEnabled = false
			a.profiles.Profiles[3].MultihopNodes = nil
			if err := atomicWritePrivate(a.startupStatePath(), cases[name]); err != nil {
				t.Fatal(err)
			}
			if next, err := a.captureStartupPolicy(); next != nil || !errors.Is(err, errOrderedNodeChainDispatch) {
				t.Fatalf("typed record %s lost its refusal-only family: %v", name, err)
			}
		}
	})
	t.Run("valid-typed-record-wrong-selected-control", func(t *testing.T) {
		if err := atomicWritePrivate(a.startupStatePath(), good); err != nil {
			t.Fatal(err)
		}
		a.profiles.SelectedID = a.profiles.Profiles[0].ID
		a.profiles.Profiles[0].AutoConnect, a.profiles.Profiles[0].StartupMode = true, "last"
		if next, err := a.captureStartupPolicy(); next != nil || !errors.Is(err, errOrderedNodeChainDispatch) {
			t.Fatalf("foreign selected control discarded typed Last intent: %v", err)
		}
	})
}

func TestStartupNodeChainPreservesHistoricalUntaggedPairAndExternalReceipts(t *testing.T) {
	a, nodes := startupOrderedTestApp(t, 3)
	p := &a.profiles.Profiles[2]
	p.MultihopNodes = nil
	p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = nodes[0].ID, p.ID, "wg"
	p.StartupMode = "last"
	for _, logical := range []string{"multihop", "smart-auto", ""} {
		last := startupSelection{RouterID: p.ID, RuntimeMode: "shadowsocks", LogicalMode: logical, Base: "wg",
			ProfileToken: startupProfileToken(*p), UpdatedAt: time.Unix(1700000000, 0).UTC()}
		raw := startupOrderedJSON(t, last)
		if bytes.Contains(raw, []byte("path_kind")) || bytes.Contains(raw, []byte("node_chain")) {
			t.Fatal("historical receipt acquired an ordered discriminator")
		}
		if err := atomicWritePrivate(a.startupStatePath(), raw); err != nil {
			t.Fatal(err)
		}
		got, err := a.loadStartupSelection()
		if err != nil || !reflect.DeepEqual(got, last) {
			t.Fatal("historical receipt failed strict round trip", logical, err)
		}
		if typed, ordered, err := a.loadStartupNodeChainReceipt(p.ID); err != nil || ordered || typed != nil {
			t.Fatal("historical multihop label became ordered authority", logical, err)
		}
		captured, err := a.captureStartupPolicy()
		if err != nil || captured == nil || captured.nodeChain != nil {
			t.Fatal("historical pair startup was blocked by ordered family classification", logical, err)
		}
	}
	t.Run("external", func(t *testing.T) {
		external, _ := startupExternalTestApp(t, "hysteria2")
		captured := startupCaptureForTest(t, external)
		last := startupSelection{RouterID: captured.profile.ID, RuntimeMode: "external-hysteria2",
			LogicalMode: "external-node", ProfileToken: startupExternalProfileToken(captured.profile),
			UpdatedAt: time.Unix(1700000000, 0).UTC(),
			External: &startupExternalSelection{Protocol: "hysteria2", Direct: true, SourceToken: captured.sourceToken, Execution: "local"}}
		if err := external.saveStartupSelection(last); err != nil {
			t.Fatal(err)
		}
		got, err := external.loadStartupSelection()
		if err != nil || !reflect.DeepEqual(got, last) {
			t.Fatal("untagged External Last compatibility changed", err)
		}
		if typed, ordered, err := external.loadStartupNodeChainReceipt(last.RouterID); err != nil || ordered || typed != nil {
			t.Fatal("untagged External Last was classified as ordered", err)
		}
	})
}


// These adapters retain real shared compilation and sealed launch projection.
// Stage/proof are explicit boundaries and never start the unstarted command.
type startupOrderedHarness struct {
	driver nativeMultihopConnectRuntime
	prepared *desktopNodeLaunch
	captures, preflights, stages, proofs int
	beforeCapture, afterCapture, afterPreflight, afterStage, afterProof func()
}

func startupOrderedDriver(t *testing.T, ctx context.Context, original *app) *startupOrderedHarness {
	t.Helper()
	h := &startupOrderedHarness{}
	h.driver.capture = func(a *app, selection multihopSelection, modes []string) (multihopSelection, error) {
		h.captures++
		if a != original {
			t.Fatal("native capture boundary received another application")
		}
		if h.beforeCapture != nil {
			h.beforeCapture()
		}
		captured, err := captureNativeNodeChainSelection(ctx, clientRoot(a), selection, modes, nil)
		if h.afterCapture != nil {
			h.afterCapture()
		}
		return captured, err
	}
	h.driver.preflight = func(a *app, selection multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
		h.preflights++
		if a != original || descriptor != nil {
			t.Fatal("ordered preflight boundary lost its original Local owner")
		}
		launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "windows")
		h.prepared = launch
		if err == nil && h.afterPreflight != nil {
			h.afterPreflight()
		}
		return launch, err
	}
	h.driver.stage = func(a *app, selection multihopSelection, launch *desktopNodeLaunch) error {
		h.stages++
		if a != original || launch != h.prepared || launch == nil {
			t.Fatal("native staging boundary received a replacement launch")
		}
		launch.command = exec.Command("unstarted-ordered-startup-test-boundary")
		if h.afterStage != nil {
			h.afterStage()
		}
		return nil
	}
	h.driver.proof = func(a *app, selection multihopSelection, command *exec.Cmd) error {
		h.proofs++
		if a != original || h.prepared == nil || command != h.prepared.command || command.Process != nil {
			t.Fatal("proof boundary received another command or a started process")
		}
		if h.afterProof != nil {
			h.afterProof()
		}
		return nil
	}
	t.Cleanup(func() {
		if h.prepared != nil {
			if h.prepared.command != nil && h.prepared.command.Process != nil {
				t.Error("startup adapter test unexpectedly started an OS process")
			}
			clear(h.prepared.config)
			clear(h.prepared.metadata)
		}
	})
	return h
}

func TestStartupNodeChainAdaptersRejectTransientSourceAndPreflightChanges(t *testing.T) {
	for _, fault := range []string{"none", "capture-source-revert", "preflight-source", "preflight-policy", "preflight-cancel", "preflight-owner", "stage-source", "proof-source", "proof-cancel"} {
		t.Run(fault, func(t *testing.T) {
			a, nodes := startupOrderedTestApp(t, 4)
			capture := startupNodeChainCaptureForTest(t, a)
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, finish, err := a.beginConnectionTransactionContext(caller)
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			h := startupOrderedDriver(t, ctx, a)
			path := startupOrderedAssetPath(a, nodes[1], nodes[1].Mode)
			change := func() { startupOrderedChangeAsset(t, path) }
			switch fault {
			case "capture-source-revert":
				var old []byte
				h.beforeCapture = func() { old = startupOrderedChangeAsset(t, path) }
				h.afterCapture = func() {
					if err := os.WriteFile(path, old, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "preflight-source":
				h.afterPreflight = change
			case "preflight-policy":
				h.afterPreflight = func() { a.profiles.Profiles[1].HomeLANAccess = !a.profiles.Profiles[1].HomeLANAccess }
			case "preflight-cancel":
				h.afterPreflight = cancel
			case "preflight-owner":
				h.afterPreflight = func() {
					replacement := *h.prepared.chain.selection.Native
					h.prepared.chain.selection.Native = &replacement
				}
			case "stage-source":
				h.afterStage = change
			case "proof-source":
				h.afterProof = change
			case "proof-cancel":
				h.afterProof = cancel
			}
			wrapped, err := a.nodeChainStartupDriver(ctx, capture, h.driver)
			if err != nil {
				t.Fatal("valid original adapter admission failed", err)
			}
			selection, captureErr := wrapped.capture(a, capture.nodeChain.selection, []string{"shadowsocks"})
			if fault == "capture-source-revert" {
				if captureErr == nil || h.captures != 1 || h.preflights != 0 || capture.current(a) != nil {
					t.Fatal("transient changed source was accepted, or rejection relied on a still-changed source", captureErr)
				}
				return
			}
			if captureErr != nil {
				t.Fatal("unmodified capture failed before the intended fault", captureErr)
			}
			launch, preflightErr := wrapped.preflight(a, selection, nil)
			if strings.HasPrefix(fault, "preflight-") {
				if preflightErr == nil || launch != nil || h.prepared == nil || h.stages != 0 {
					t.Fatal("altered preflight owner entered staging", preflightErr)
				}
				if len(bytes.Trim(h.prepared.config, "\x00")) != 0 || len(bytes.Trim(h.prepared.metadata, "\x00")) != 0 {
					t.Fatal("rejected unstarted original preflight was not retired and zeroed")
				}
				return
			}
			if preflightErr != nil {
				t.Fatal("unmodified preflight failed before the intended fault", preflightErr)
			}
			stageErr := wrapped.stage(a, selection, launch)
			if fault == "stage-source" {
				if stageErr == nil || h.stages != 1 || h.proofs != 0 {
					t.Fatal("changed staging source reached proof", stageErr)
				}
				return
			}
			if stageErr != nil {
				t.Fatal("unmodified stage failed before the intended fault", stageErr)
			}
			proofErr := wrapped.proof(a, selection, launch.command)
			if strings.HasPrefix(fault, "proof-") {
				if proofErr == nil || h.proofs != 1 {
					t.Fatal("changed or cancelled proof retained original startup authority", proofErr)
				}
				return
			}
			if proofErr != nil || h.captures != 1 || h.preflights != 1 || h.stages != 1 || h.proofs != 1 ||
				a.cmd != nil || a.state.Connected || launch.command.Process != nil {
				t.Fatal("unchanged actual capture/projection did not preserve its explicit unstarted boundary", proofErr)
			}
		})
	}
}

func TestStartupNodeChainAdaptersRejectReplacementCalls(t *testing.T) {
	a, _ := startupOrderedTestApp(t, 3)
	capture := startupNodeChainCaptureForTest(t, a)
	ctx, finish, err := a.beginConnectionTransactionContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	h := startupOrderedDriver(t, ctx, a)
	wrapped, err := a.nodeChainStartupDriver(ctx, capture, h.driver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.capture(&app{}, capture.nodeChain.selection, []string{"shadowsocks"}); err == nil || h.captures != 0 {
		t.Fatal("another application reached original native capture")
	}
	if _, err := wrapped.capture(a, capture.nodeChain.selection, []string{"wg", "shadowsocks"}); err == nil || h.captures != 0 {
		t.Fatal("replacement mode inventory reached original native capture")
	}
	selection, err := wrapped.capture(a, capture.nodeChain.selection, []string{"shadowsocks"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.capture(a, capture.nodeChain.selection, []string{"shadowsocks"}); err == nil || h.captures != 1 {
		t.Fatal("one scheduled capture was compiled twice")
	}
	launch, err := wrapped.preflight(a, selection, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrapped.stage(a, selection, &desktopNodeLaunch{}); err == nil || h.stages != 0 {
		t.Fatal("replacement prepared owner reached stage")
	}
	if err := wrapped.stage(a, selection, launch); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.proof(a, selection, exec.Command("another-unstarted-command")); err == nil || h.proofs != 0 {
		t.Fatal("foreign process reached original proof boundary")
	}
}

func TestStartupNodeChainCancelledIntentNeverEntersAnotherTransaction(t *testing.T) {
	for _, decision := range []string{"cancelled", "manual-connect", "disconnect", "busy-transaction"} {
		t.Run(decision, func(t *testing.T) {
			a, _ := startupOrderedTestApp(t, 3)
			capture := startupNodeChainCaptureForTest(t, a)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			startupPolicyCancels.Store(a, context.CancelFunc(cancel))
			var existing context.Context
			var finishExisting func()
			switch decision {
			case "cancelled":
				cancel()
			case "manual-connect":
				_, finish, err := a.beginConnectionOperation()
				if err != nil {
					t.Fatal(err)
				}
				finish()
			case "disconnect":
				a.cancelConnectionOperation()
			case "busy-transaction":
				var err error
				existing, finishExisting, err = a.beginConnectionTransactionContext(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer finishExisting()
			}
			h := startupOrderedDriver(t, ctx, a)
			a.applyCapturedStartupPolicyOwned(ctx, capture, externalConnectRuntime{}, h.driver)
			if h.captures != 0 || h.preflights != 0 || h.stages != 0 || h.proofs != 0 || a.cmd != nil || a.state.Connected {
				t.Fatal("retired intent reached a native boundary or replaced its current owner")
			}
			a.mu.Lock()
			current := a.connectionContext
			a.mu.Unlock()
			if decision == "busy-transaction" {
				if current != existing || existing.Err() != nil {
					t.Fatal("scheduled startup cancelled or replaced the existing transaction")
				}
			} else if ctx.Err() == nil || current != nil {
				t.Fatal("explicit user decision did not retire the scheduled transaction")
			}
			if _, err := os.Stat(a.startupStatePath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("retired intent persisted an unproved Last receipt", err)
			}
		})
	}
}
