//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

// Actual host/session/source/Stop and retirement code; only the installed PF
// command and the explicitly marked original process ACK are modeled. No
// ordinary graph or Ready record is supplied by this prefix fixture.
func desktopMacOSCandidatePrefixRetirementFixture(t *testing.T) (*desktopMacOSCandidatePrefixHost, *[]string) {
	t.Helper()
	p, s, c, _, _ := macOSParentFixture(t)
	a, full := desktopNodeChainLaunchFixture(t, 3, "darwin")
	candidate := desktopCandidateAddCustomSource(t, a, "2022-blake3-aes-256-gcm")
	catalog, err := captureDesktopNodeChainCandidateSources(context.Background(), a, full, 1, []string{candidate})
	if err != nil {
		t.Fatal(err)
	}
	prep, err := captureDesktopNodeCandidatePrefixSource(context.Background(), full.chain.selection, 1, catalog.inventory)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := mobilemultihop.NewDesktopNodeCandidatePreparationPolicy(prep, strings.Repeat("c", 32), "darwin", 0)
	if err != nil {
		t.Fatal(err)
	}
	meta := policy.Metadata()
	metadata, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	launch := &desktopNodeLaunch{root: full.root, endpoint: full.endpoint, profileID: meta.ProfileID, policyProfileID: meta.PolicyProfileID, mode: meta.Mode,
		config: []byte(policy.Config()), metadata: metadata, configSHA256: meta.ConfigSHA256, mtuSession: meta.SessionID,
		candidatePrefix: &desktopNodeCandidatePrefixLaunch{policy: policy, selection: full.chain.selection, input: policy.Source()}}
	a.localController = c
	operation, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a.connectionContext, a.connectionCancel = operation, cancel
	launch.command = &exec.Cmd{}
	a.cmd = launch.command
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode = "multihop", "multihop", launch.mode
	a.state.RouterID, a.state.Base = launch.policyProfileID, launch.candidatePrefix.selection.Base
	a.state.Connected, a.state.Phase = false, "candidate:testing"
	parent := &desktopMacOSSessionCapture{app: a, controller: c, parent: p, session: s}
	runtime := &desktopNodeCandidatePrefixPlatformRuntime{registered: true}
	h := &desktopMacOSCandidatePrefixHost{parent: parent, runtime: runtime, launch: launch, policy: policy, operation: operation, gate: make(chan struct{}, 1),
		entered: true, published: true, staged: true, baselineEntered: true,
		selection: desktopMacOSCandidatePrefixSelection{Schema: 2, Family: macosprocess.CandidatePrefixFamily, ProfileID: meta.PolicyProfileID,
			Session: meta.SessionID, Source: meta.SourceSHA256, Config: meta.ConfigSHA256, HomeLAN: meta.HomeLANAccess, Policy: meta.KillSwitchPolicy}}
	runtime.host, launch.candidatePrefix.platform = h, runtime
	h.gate <- struct{}{}
	h.baseline = &desktopMacOSCandidatePrefixReceipt{Schema: 2, Capture: h.selection, Phase: "active", Token: "417", Baseline: desktopMacOSBaselineProof{Present: true, Rules: strings.Repeat("a", 64)}}
	s.candidatePrefix = runtime
	if err := s.Retain(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		nativeMultihopOwners.Delete(a)
		activeMultihopGraphs.Delete(a)
		activeDNSRuntimeIdentities.Delete(a)
		mtuLiveOwners.Delete(a)
	})
	directory := filepath.Join(t.TempDir(), "original-prefix")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	h.stageDirectory, h.stageInfo = directory, launch.directoryInfo
	if err := writeDesktopRuntimeFile(launch, "node-candidate-prefix-source.json", []byte(launch.candidatePrefix.input), false); err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopRuntimeFile(launch, "sing-box.json", launch.config, false); err != nil {
		t.Fatal(err)
	}
	actions := &[]string{}
	h.baselineRun = func(ctx context.Context, captured *desktopMacOSSessionCapture, selection desktopMacOSCandidatePrefixSelection, action string, expected *desktopMacOSCandidatePrefixReceipt, _ func()) (*desktopMacOSCandidatePrefixReceipt, error) {
		if captured != parent || selection != h.selection || expected == nil || expected.Capture != selection || expected.Token != "417" || !h.nativeRetired {
			return nil, errors.New("modeled prefix PF boundary rejected changed authority or unjoined child")
		}
		*actions = append(*actions, action)
		value := *expected
		switch action {
		case "retire":
			value.Phase = "held"
		case "release":
			value.Phase, value.Baseline = "retired", desktopMacOSBaselineProof{}
		default:
			return nil, errors.New("unexpected modeled prefix PF action")
		}
		return &value, ctx.Err()
	}
	return h, actions
}

func TestDesktopMacOSCandidatePrefixRetirementRequiresNativeAcknowledgment(t *testing.T) {
	h, actions := desktopMacOSCandidatePrefixRetirementFixture(t)
	child := &desktopMacOSProcess{parent: h.parent, command: h.launch.command, gate: make(chan struct{}, 1), joined: make(chan struct{})}
	child.gate <- struct{}{}
	child.started.Store(true)
	close(child.joined) // Process exit alone supplies no authenticated PF cleanup.
	h.process = child
	if err := h.Close(context.Background()); err == nil {
		t.Fatal("exited child without its native ACK released prefix protection")
	}
	if h.nativeRetired || h.baselineRetired || h.workspaceRetired || h.closed || len(*actions) != 0 ||
		h.parent.session.candidatePrefix != h.runtime || h.parent.app.cmd != h.launch.command {
		t.Fatal("failed native cleanup discarded its original retained owner", *actions)
	}
	if _, err := os.Stat(h.launch.directory); err != nil {
		t.Fatal("unacknowledged native cleanup removed its private workspace", err)
	}
	// Explicit native-boundary receipt: the real Bootstrap.Stop test owns its
	// socket authentication; this fixture now exercises the original retry.
	child.nativeAcknowledged, child.nativeStopped = true, true
	if err := h.Close(context.Background()); err != nil {
		t.Fatal("same acknowledged original child could not complete cleanup", err)
	}
	if !h.closed || !reflect.DeepEqual(*actions, []string{"release"}) || h.parent.session.candidatePrefix != nil ||
		h.parent.app.cmd != nil {
		t.Fatal("joined original owner did not retire exactly once", *actions)
	}
}

func TestDesktopMacOSCandidatePrefixRetirementRetryEscalatesHeldBaseline(t *testing.T) {
	h, actions := desktopMacOSCandidatePrefixRetirementFixture(t)
	unknown := filepath.Join(h.launch.directory, "replacement-owner")
	if err := os.WriteFile(unknown, []byte("retain unknown owner"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.closeWithIntent(context.Background(), true); err == nil {
		t.Fatal("unknown private owner was discarded")
	}
	if h.closed || !h.nativeRetired || !h.baselineRetired || h.workspaceRetired || h.baseline.Phase != "held" ||
		!reflect.DeepEqual(*actions, []string{"retire"}) {
		t.Fatal("failed workspace retirement lost the original held PF receipt", *actions)
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	stop, err := h.parent.app.captureDesktopRetainedStop()
	if err != nil || stop == nil {
		t.Fatal("Disconnect could not recapture the original pending prefix owner", err)
	}
	if err := stop.Retire(context.Background(), h.launch.command, true); err != nil {
		t.Fatal(err)
	}
	if !h.closed || h.baseline.Phase != "retired" || !reflect.DeepEqual(*actions, []string{"retire", "release"}) {
		t.Fatal("Disconnect did not release its exact held original baseline", *actions)
	}
}

func TestDesktopMacOSCandidatePrefixStopRetainsPartialAttemptBeforeGraphBind(t *testing.T) {
	h, actions := desktopMacOSCandidatePrefixRetirementFixture(t)
	a := h.parent.app
	a.cmd, h.launch.command = nil, nil
	nativeMultihopOwners.Delete(a)
	activeMultihopGraphs.Delete(a)
	stop, err := a.captureDesktopRetainedStop()
	if err != nil || stop == nil {
		t.Fatal("partial prefix PF attempt fell through to ordinary cleanup", err)
	}
	if err := stop.Retire(context.Background(), nil, true); err != nil {
		t.Fatal("partial original prefix attempt could not drain", err)
	}
	if !h.closed || !reflect.DeepEqual(*actions, []string{"release"}) || h.parent.session.candidatePrefix != nil {
		t.Fatal("partial PF and workspace owner was discarded", *actions)
	}
}

func TestDesktopMacOSCandidatePrefixStopCaptureRejectsReplacementAfterHold(t *testing.T) {
	for _, fault := range []string{"command", "operation", "session"} {
		t.Run(fault, func(t *testing.T) {
			h, actions := desktopMacOSCandidatePrefixRetirementFixture(t)
			a := h.parent.app
			stop, err := a.captureDesktopRetainedStop()
			if err != nil || stop == nil {
				t.Fatal(err)
			}
			originalCommand, originalOperation := a.cmd, a.connectionContext
			switch fault {
			case "command":
				a.cmd = &exec.Cmd{}
			case "operation":
				replacement, cancel := context.WithCancel(context.Background())
				defer cancel()
				a.connectionContext = replacement
			case "session":
				h.parent.session.candidatePrefix = &desktopNodeCandidatePrefixPlatformRuntime{}
			}
			if err := stop.Retire(context.Background(), originalCommand, true); err == nil ||
				h.nativeRetired || len(*actions) != 0 {
				t.Fatal("captured Stop retargeted the owner that appeared during its MTU hold", err)
			}
			a.cmd, a.connectionContext, h.parent.session.candidatePrefix = originalCommand, originalOperation, h.runtime
			if err := stop.Retire(context.Background(), originalCommand, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopMacOSCandidatePrefixStopMalformedOwnerCannotFallThrough(t *testing.T) {
	p, s, c, _, _ := macOSParentFixture(t)
	a := &app{localController: c}
	s.candidatePrefix = &desktopNodeCandidatePrefixPlatformRuntime{}
	if captured, err := a.captureDesktopRetainedStop(); err == nil || captured != nil {
		t.Fatal("malformed retained prefix owner fell through to ordinary Stop", err)
	}
	s.candidatePrefix = nil
	if captured, err := p.CaptureNodeChainStop(a); err != nil || captured != nil {
		t.Fatal("absent prefix owner changed ordinary Stop dispatch", err)
	}
}

func TestDesktopMacOSCandidatePrefixRetainsClosedFullSavedProvenance(t *testing.T) {
	h, _ := desktopMacOSCandidatePrefixRetirementFixture(t)
	meta := h.policy.Metadata()
	if meta.ProfileID == meta.PolicyProfileID || h.selection.ProfileID != meta.PolicyProfileID ||
		h.launch.policyProfileID != h.launch.candidatePrefix.selection.Control.ID || meta.ApplicationOpen || meta.DNSOpen ||
		h.launch.chain != nil || h.launch.candidatePrefix.ready != nil || h.parent.app.state.Connected {
		t.Fatal("prefix protection or Home borrowed its tested member as full saved authority")
	}
	if _, found := nativeMultihopOwners.Load(h.parent.app); found {
		t.Fatal("prefix fixture manufactured ordinary connected graph authority")
	}
	if _, found := getActiveMultihopGraph(h.parent.app); found {
		t.Fatal("prefix fixture manufactured ordinary connected graph authority")
	}
	h.parent.session.nodeChain = &desktopNodeChainPlatformRuntime{}
	if captured, err := h.parent.app.captureDesktopRetainedStop(); err == nil || captured != nil {
		t.Fatal("mixed prefix and full-chain slots silently selected one cleanup owner")
	}
	h.parent.session.nodeChain = nil
	if err := h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
