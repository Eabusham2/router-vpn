//go:build darwin

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
)

// This fixture exercises only the correlation of an already pinned typed
// heartbeat with the independent native MTU readback. It cannot admit a
// process, physical policy, PF reference, adopted projection or graph.
func macOSExecutionReaderFixture() (*desktopMacOSNodeChainHost, desktopNodeMTURecord) {
	record := desktopNodeMTURecord{Session: "original-session", Config: "preparation-config", Path: "original-path",
		Reader: 2, Interface: "utun7", Index: 17, MTU: 1400}
	ready := &mobilemultihop.DesktopNodeChainExecutionReadyRecord{
		Identity:                mobilemultihop.NodeChainIdentity{SessionID: record.Session, ConfigSHA256: "adopted-config"},
		PreparationConfigSHA256: record.Config, Reader: record.Reader, InterfaceName: record.Interface,
		InterfaceIndex: uint32(record.Index), MTU: record.MTU,
	}
	ordinary := &mobilemultihop.DesktopNodeChainReadyRecord{
		Identity: mobilemultihop.NodeChainIdentity{SessionID: record.Session, ConfigSHA256: record.Config},
		Reader:   record.Reader, InterfaceName: "utun999", InterfaceIndex: uint32(record.Index), MTU: record.MTU,
	}
	h := &desktopMacOSNodeChainHost{
		execution: &desktopNodeChainExecutionLaunch{ready: ready, mtuPath: record.Path},
		launch:    &desktopNodeLaunch{chain: &desktopNodeChainLaunch{ready: ordinary, mtuPath: record.Path}},
	}
	return h, record
}

func TestDesktopMacOSExecutionReaderKeepsPreparationAndAdoptionDistinct(t *testing.T) {
	h, record := macOSExecutionReaderFixture()
	name, index, reader, err := h.capturedReaderLocked(context.Background())
	if err != nil || name != record.Interface || index != record.Index || reader != record.Reader {
		t.Fatal("execution reader observation borrowed ordinary Local readiness", name, index, reader, err)
	}
	if matched, err := h.matchesMTUReaderLocked(context.Background(), record); err != nil || !matched {
		t.Fatal("actual preparation MTU reader lost its adopted execution proof", err)
	}
	for name, change := range map[string]func(*desktopNodeMTURecord){
		"session":                 func(r *desktopNodeMTURecord) { r.Session = "replacement" },
		"config":                  func(r *desktopNodeMTURecord) { r.Config = "replacement" },
		"adoption-as-preparation": func(r *desktopNodeMTURecord) { r.Config = h.execution.ready.Identity.ConfigSHA256 },
		"path":                    func(r *desktopNodeMTURecord) { r.Path = "replacement" },
		"reader":                  func(r *desktopNodeMTURecord) { r.Reader++ },
		"interface":               func(r *desktopNodeMTURecord) { r.Interface = "utun999" },
		"index":                   func(r *desktopNodeMTURecord) { r.Index++ },
		"MTU":                     func(r *desktopNodeMTURecord) { r.MTU++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := record
			change(&changed)
			if matched, err := h.matchesMTUReaderLocked(context.Background(), changed); err != nil || matched {
				t.Fatal("execution MTU correlation accepted a foreign native reader", err)
			}
		})
	}
	h.execution.ready = nil
	if name, index, reader, err := h.capturedReaderLocked(context.Background()); err != nil || name != "" || index != 0 || reader != 0 {
		t.Fatal("missing execution observation borrowed an ordinary heartbeat", err)
	}
	if matched, err := h.matchesMTUReaderLocked(context.Background(), record); err != nil || matched {
		t.Fatal("missing execution observation acquired an ordinary MTU owner", err)
	}
}

func TestDesktopMacOSExecutionReaderCancellationDoesNotWaitForOwnerMutex(t *testing.T) {
	for _, action := range []string{"capture", "match"} {
		t.Run(action, func(t *testing.T) {
			h, record := macOSExecutionReaderFixture()
			h.execution.mu.Lock()
			var once sync.Once
			release := func() { once.Do(h.execution.mu.Unlock) }
			defer release()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, joined := make(chan struct{}), make(chan error, 1)
			go func() {
				close(entered)
				var err error
				if action == "capture" {
					_, _, _, err = h.capturedReaderLocked(ctx)
				} else {
					_, err = h.matchesMTUReaderLocked(ctx, record)
				}
				joined <- err
			}()
			<-entered
			cancel()
			select {
			case err := <-joined:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("execution reader discarded caller cancellation", err)
				}
			case <-time.After(time.Second):
				release()
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Fatal("execution reader cleanup did not join")
				}
				t.Fatal("execution reader waited for a held owner mutex after cancellation")
			}
		})
	}
}

func TestDesktopMacOSExecutionReaderRequiresPhysicalRetirement(t *testing.T) {
	h, record := macOSExecutionReaderFixture()
	previousName, previousIndex, previousReader, err := h.capturedReaderLocked(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record.Reader++
	record.Interface, record.Index = "utun8", 18
	newLink := net.Interface{Name: record.Interface, Index: record.Index, MTU: record.MTU, Flags: net.FlagUp}
	if err := validateDesktopMacOSReaderRetirement(previousName, previousIndex, previousReader, record, []net.Interface{newLink}); err != nil {
		t.Fatal("observed retired old reader and exact new reader were refused", err)
	}
	oldLink := net.Interface{Name: previousName, Index: previousIndex, MTU: 1400, Flags: net.FlagUp}
	if validateDesktopMacOSReaderRetirement(previousName, previousIndex, previousReader, record, []net.Interface{oldLink, newLink}) == nil {
		t.Fatal("generation advance substituted for actual old utun retirement")
	}
	if validateDesktopMacOSReaderRetirement(previousName, previousIndex, previousReader, record, nil) == nil {
		t.Fatal("generation advance substituted for actual new utun presence")
	}
	record.Reader = previousReader
	if validateDesktopMacOSReaderRetirement(previousName, previousIndex, previousReader, record, []net.Interface{newLink}) == nil {
		t.Fatal("new interface substituted for reader succession")
	}
}

// The actual typed source, installed-parent/session owner, private workspace
// and host retirement run here. The child ACK and PF command are explicit
// boundary models; the Python journal handoff separately checks deny retention.
func macOSExecutionRetirementFixture(t *testing.T) (*desktopMacOSNodeChainHost, *[]string) {
	t.Helper()
	p, session, controller, _, _ := macOSParentFixture(t)
	a, launch := desktopNodeChainLaunchFixture(t, 3, "darwin")
	execution, err := newDesktopNodeChainExecutionSource(launch.chain, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.attach(launch); err != nil {
		t.Fatal(err)
	}
	operation, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a.localController, a.connectionContext, a.connectionCancel = controller, operation, cancel
	launch.command = &exec.Cmd{}
	a.cmd = launch.command
	parent := &desktopMacOSSessionCapture{app: a, controller: controller, parent: p, session: session}
	meta := launch.chain.policyMetadata()
	runtime := &desktopNodeChainPlatformRuntime{registered: true}
	h := &desktopMacOSNodeChainHost{parent: parent, runtime: runtime, launch: launch, policy: launch.chain.policy,
		execution: execution, executionPreparation: execution.preparation, executionPhysical: execution.physical,
		operation: operation, gate: make(chan struct{}, 1), entered: true, published: true, staged: true, baselineEntered: true,
		selection: desktopMacOSNodeChainSelection{Schema: 2, Family: launch.chain.macOSFamily(), ProfileID: meta.ProfileID,
			Session: meta.SessionID, Source: meta.SourceSHA256, Config: meta.ConfigSHA256, HomeLAN: meta.HomeLANAccess, Policy: meta.KillSwitchPolicy}}
	if h.selection.Policy != "on-connect" {
		t.Fatal("replacement fixture must exercise the releasable on-connect policy")
	}
	runtime.host, launch.chain.platform, session.nodeChain = h, runtime, runtime
	h.gate <- struct{}{}
	if err := session.Retain(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "original-execution")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	h.stageDirectory, h.stageInfo = directory, launch.directoryInfo
	for name, body := range map[string][]byte{launch.chain.sourceName(): []byte(launch.chain.input), "sing-box.json": launch.config} {
		if err := writeDesktopRuntimeFile(launch, name, body, false); err != nil {
			t.Fatal(err)
		}
	}
	h.baseline = &desktopMacOSNodeChainReceipt{Schema: 2, Capture: h.selection, Phase: "active", Token: "417",
		Baseline: desktopMacOSBaselineProof{Present: true, Rules: strings.Repeat("a", 64)}}
	actions := &[]string{}
	h.baselineRun = func(ctx context.Context, captured *desktopMacOSSessionCapture, selection desktopMacOSNodeChainSelection,
		action string, expected *desktopMacOSNodeChainReceipt, _ func()) (*desktopMacOSNodeChainReceipt, error) {
		if captured != parent || selection != h.selection || expected != h.baseline || !h.nativeRetired || action != "retire" {
			return nil, errors.New("execution replacement tried to release protection or skipped original child join")
		}
		*actions = append(*actions, action)
		copy := *expected
		copy.Phase = "held"
		return &copy, ctx.Err()
	}
	child := &desktopMacOSProcess{parent: parent, command: launch.command, execution: execution.preparation,
		executionPhysical: execution.physical, gate: make(chan struct{}, 1), joined: make(chan struct{})}
	child.gate <- struct{}{}
	child.started.Store(true)
	close(child.joined)
	h.process = child
	return h, actions
}

func TestDesktopMacOSExecutionReplacementJoinsBeforeHoldingOriginalProtection(t *testing.T) {
	h, actions := macOSExecutionRetirementFixture(t)
	if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err == nil || h.closed ||
		h.nativeRetired || h.baselineRetired || h.workspaceRetired || len(*actions) != 0 {
		t.Fatal("replacement retirement accepted child exit without native cleanup acknowledgment", err)
	}
	if _, err := os.Stat(h.launch.directory); err != nil {
		t.Fatal("unacknowledged execution child lost original source workspace", err)
	}
	h.process.nativeAcknowledged, h.process.nativeStopped = true, true
	if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err != nil {
		t.Fatal("exact joined replacement could not retain protection", err)
	}
	if !h.closed || !h.nativeRetired || !h.baselineRetired || !h.workspaceRetired || h.baseline.Phase != "held" ||
		!h.baseline.Baseline.Present || !reflect.DeepEqual(*actions, []string{"retire"}) ||
		h.parent.session.nodeChain != nil || h.parent.app.cmd != nil {
		t.Fatal("replacement retirement released deny protection or retained the joined runtime", *actions)
	}
}

func TestDesktopMacOSExecutionReplacementRefusesForeignPreparation(t *testing.T) {
	h, actions := macOSExecutionRetirementFixture(t)
	h.process.nativeAcknowledged, h.process.nativeStopped = true, true
	_, other := desktopExecutionAttachedFixture(t, "darwin")
	if err := h.runtime.closeForExecutionRestore(context.Background(), other); err == nil || len(*actions) != 0 || h.closed {
		t.Fatal("another execution source acquired original retirement authority")
	}
	original := h.process.execution
	h.process.execution = other.preparation
	if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err == nil || len(*actions) != 0 || h.closed {
		t.Fatal("replacement process preparation acquired original PF retirement")
	}
	h.process.execution = original
	if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err != nil || !h.closed ||
		!reflect.DeepEqual(*actions, []string{"retire"}) || !h.baseline.Baseline.Present {
		t.Fatal("original retained preparation could not retry protected retirement", err)
	}
}
