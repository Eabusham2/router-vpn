package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobiletor"
)

// This controlled subprocess publishes the actual shared wire types and uses
// the existing publication barrier. Its reader values are explicit fixtures;
// it creates no TUN, Tor daemon, firewall rule or network connection.
func TestDesktopTorMTUTransitionChildFixture(t *testing.T) {
	if os.Getenv("ROUTERVPN_TOR_TRANSITION_TEST_CHILD") != "1" {
		return
	}
	directory := os.Getenv("ROUTERVPN_TOR_TEST_DIRECTORY")
	raw, _ := base64.StdEncoding.DecodeString(os.Getenv("ROUTERVPN_TOR_TEST_EXPECTED"))
	var expected mobiletor.DesktopBridgeMetadata
	if json.Unmarshal(raw, &expected) != nil {
		os.Exit(91)
	}
	publisher, err := newDesktopNativeFixturePublisher(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.root.Close()
	write := func(name string, value any) {
		raw, err := json.Marshal(value)
		if err == nil {
			err = publisher.publish(name, raw)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "isolated Tor transition fixture %s: %v\n", name, err)
			os.Exit(92)
		}
	}
	proof := desktopTorFixtureProof(expected, time.Now())
	write("progress.json", desktopTorProgress{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256, Stage: "proving"})
	admitted := false
	for {
		if !admitted {
			var request desktopMTURequest
			raw, err := os.ReadFile(filepath.Join(directory, "mtu-request.json"))
			if err == nil {
				if decodeRelayControlJSON(raw, &request) != nil || request.Schema != 1 || request.Session != expected.SessionID || request.SourceSHA256 != expected.SourceSHA256 || request.ConfigSHA256 != expected.ConfigSHA256 || request.Generation != 1 || !desktopMTURequestPattern.MatchString(request.Request) {
					os.Exit(93)
				}
				now := time.Now().Truncate(time.Millisecond)
				from := mobiletor.DesktopBridgeMTUReadback{Generation: request.Generation, RequestID: request.Request,
					InterfaceName: proof.InterfaceName, InterfaceIndex: proof.InterfaceIndex, EffectiveMTU: proof.EffectiveMTU}
				proof.MTUReadback, proof.HeartbeatAt = &from, now.UnixMilli()
				receipt := mobiletor.DesktopBridgeMTUTransition{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256,
					Generation: request.Generation, RequestID: request.Request, TransitionID: 1, From: from, TargetMTU: 1380,
					StartedAt: now.UnixMilli(), ExpiresAt: now.Add(mobiletor.DesktopBridgeMTUTransitionLimit).UnixMilli(), FromHeartbeatAt: proof.HeartbeatAt}
				write("proof.json", proof)
				write("mtu-transition.json", receipt)
				// The acknowledgement proves both writes and their directory
				// handles completed. Only the parent can resume this reader.
				desktopTorFixturePublicationBarrier("proof-directory-retire", expected)
				fresh := from
				fresh.Revision, fresh.InterfaceIndex, fresh.EffectiveMTU = 1, from.InterfaceIndex+1, receipt.TargetMTU
				proof.MTUReadback, proof.InterfaceIndex, proof.EffectiveMTU = &fresh, fresh.InterfaceIndex, fresh.EffectiveMTU
				admitted = true
			}
		}
		proof.HeartbeatAt = time.Now().UnixMilli()
		write("proof.json", proof)
		if raw, err := os.ReadFile(filepath.Join(directory, "stop.json")); err == nil {
			var request desktopExternalStop
			if decodeRelayControlJSON(raw, &request) != nil || request.SessionID != expected.SessionID || request.SourceSHA256 != expected.SourceSHA256 {
				os.Exit(94)
			}
			write("stopped.json", desktopExternalStop{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, Closed: true})
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type desktopTorTransitionChild struct {
	a       *app
	launch  *desktopNodeLaunch
	control string
	receipt mobiletor.DesktopBridgeMTUTransition
}

func newDesktopTorTransitionChild(t *testing.T) *desktopTorTransitionChild {
	t.Helper()
	profile, _ := desktopTorPolicyFixture(t)
	policy, err := speedLabTorPolicy(profile)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := stageDesktopTorInputs(t.TempDir(), policy, profile, installFakeExecutable(t, t.TempDir(), "tor"), installFakeExecutable(t, t.TempDir(), "sing-box-routervpn"))
	if err != nil {
		t.Fatal(err)
	}
	launch := prepared.Launch
	launch.tor.network, launch.tor.networkIdentity = "transition-fixture-network", func() string { return "transition-fixture-network" }
	control := filepath.Join(t.TempDir(), "transition-publication")
	expected, _ := json.Marshal(launch.tor.expected)
	command := exec.Command(os.Args[0], "-test.run=^TestDesktopTorMTUTransitionChildFixture$")
	command.Env = append(os.Environ(), "ROUTERVPN_TOR_TRANSITION_TEST_CHILD=1", "ROUTERVPN_TOR_TEST_DIRECTORY="+launch.directory, "ROUTERVPN_TOR_TEST_EXPECTED="+base64.StdEncoding.EncodeToString(expected), "ROUTERVPN_TOR_TEST_RELEASE="+control, "GORACE=atexit_sleep_ms=0")
	var output desktopTorFixtureOutput
	command.Stdout, command.Stderr = io.Discard, &output
	launch.command, launch.tor.started = command, time.Now()
	a := &app{profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}, state: state{Mode: "external-node", RuntimeMode: launch.mode, RouterID: profile.ID}}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	a.cmd = command
	desktopNodeOwners.Store(a, launch)
	t.Cleanup(func() {
		// Retire the actual monitor's ownership before joining the child. A
		// concurrent monitor completion must not launch a host stop helper.
		a.mu.Lock()
		a.cmd, a.state.Connected = nil, false
		a.mu.Unlock()
		_ = command.Process.Kill()
		<-desktopNodeProcessDone(launch)
		if t.Failed() {
			t.Logf("isolated transition child: %v; stderr:\n%s", command.ProcessState, output.String())
		}
		desktopNodeOwners.Delete(a)
		_ = launch.directoryRoot.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.state.Connected, a.state.Phase = true, "connected"
	captureDesktopMTUBaselineLocked(a, launch)
	a.mu.Unlock()
	owner := desktopMeasurementMTUSession(launch)
	request := desktopMTURequest{Schema: 1, Session: launch.tor.expected.SessionID, SourceSHA256: launch.tor.expected.SourceSHA256, ConfigSHA256: launch.tor.expected.ConfigSHA256,
		Generation: 1, Request: strings.Repeat("c", 32), Force: true}
	owner.mu.Lock()
	owner.generation, owner.active = request.Generation, request.Request
	owner.mu.Unlock()
	if err := atomicWritePrivate(control+".pause", []byte(desktopTorFixturePauseIdentity(launch.tor.expected))); err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopMTUControl(launch, "mtu-request.json", request); err != nil {
		t.Fatal(err)
	}
	pauseDesktopTorFixturePublications(t, ctx, launch, control)
	fixture := &desktopTorTransitionChild{a: a, launch: launch, control: control}
	raw, err := readDesktopRuntimeFile(launch, "mtu-transition.json", 8192)
	if err != nil || decodeRelayControlJSON(raw, &fixture.receipt) != nil || fixture.receipt.RequestID != request.Request || fixture.receipt.ExpiresAt-fixture.receipt.StartedAt != mobiletor.DesktopBridgeMTUTransitionLimit.Milliseconds() {
		t.Fatal("child did not publish the exact bounded transition", err)
	}
	if _, err := a.readDesktopTorProof(launch); err != nil {
		t.Fatal("transition base was not a real admitted fresh publication", err)
	}
	return fixture
}

func (fixture *desktopTorTransitionChild) waitForOldHeartbeat(t *testing.T) {
	t.Helper()
	when := time.UnixMilli(fixture.receipt.FromHeartbeatAt).Add(mobiletor.DesktopBridgeHeartbeatMaxAge + 150*time.Millisecond)
	timer := time.NewTimer(time.Until(when))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-desktopNodeProcessDone(fixture.launch):
		t.Fatal("transition child exited while its actual publication was paused")
	}
	if _, err := fixture.a.readDesktopTorProof(fixture.launch); err == nil {
		t.Fatal("paused old publication passed the normal heartbeat bound")
	}
}

func (fixture *desktopTorTransitionChild) resumeFresh() (desktopTorProof, error) {
	identity := desktopTorFixturePauseIdentity(fixture.launch.tor.expected)
	if err := atomicWritePrivate(fixture.control+".resume", []byte(identity)); err != nil {
		return desktopTorProof{}, err
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := readDesktopRuntimeFile(fixture.launch, "proof.json", 64<<10)
		var proof desktopTorProof
		if err == nil && decodeRelayControlJSON(raw, &proof) == nil && proof.HeartbeatAt > fixture.receipt.FromHeartbeatAt && proof.MTUReadback != nil && proof.MTUReadback.Revision == 1 {
			return proof, nil
		}
		select {
		case <-timer.C:
			return proof, errors.New("transition child did not publish its resumed reader")
		case <-desktopNodeProcessDone(fixture.launch):
			return proof, errors.New("transition child exited before its resumed publication")
		case <-ticker.C:
		}
	}
}

func TestDesktopTorMTUTransitionActualChildPendingIsNotMeasurementProof(t *testing.T) {
	fixture := newDesktopTorTransitionChild(t)
	a, launch := fixture.a, fixture.launch
	// Exercise the real monitor's proof decision, but keep host teardown
	// outside this fixture even if that decision regresses. The explicit
	// monitor predicate assertions below still have to accept only the receipt.
	a.operationMu.Lock()
	defer func() {
		a.mu.Lock()
		a.cmd = nil
		a.mu.Unlock()
		a.operationMu.Unlock()
	}()
	a.monitorDesktopTorRuntime(launch)
	fixture.waitForOldHeartbeat(t)
	if err := a.desktopMeasurementCurrentProof(launch); !errors.Is(err, errDesktopTorMTUTransitionPending) || !a.desktopTorMonitorCurrent(launch) {
		t.Fatal("exact transition failed to separate monitor liveness from fresh measurement proof", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	err := a.waitDesktopMeasurementProof(ctx, launch)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pending transition was counted as successful measurement proof", err)
	}
	if _, err := captureDesktopMTUSnapshot(a, launch); !errors.Is(err, errDesktopTorMTUTransitionPending) {
		t.Fatal("old transition base admitted another MTU measurement", err)
	}
	a.mu.Lock()
	connected := a.state.Connected && a.state.Phase == "connected" && a.cmd == launch.command
	a.mu.Unlock()
	if !connected || desktopNodeProcessExited(launch) {
		t.Fatal("the actual monitor retired an owned bounded reader transition")
	}
	if _, err := os.Stat(filepath.Join(launch.directory, "stop.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("monitor sent a stop while exact transition was still pending", err)
	}
	before := fixture.receipt
	if _, err := fixture.resumeFresh(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	err = a.waitDesktopMeasurementProof(ctx, launch)
	cancel()
	if err != nil {
		t.Fatal("resumed child did not earn a new strict proof", err)
	}
	launch.tor.mu.Lock()
	retired, pending, heartbeat := launch.tor.mtuRetiredTransition, launch.tor.mtuTransition, launch.tor.lastProofHeartbeat
	launch.tor.mu.Unlock()
	if retired != before.TransitionID || pending != nil || heartbeat <= before.FromHeartbeatAt || a.desktopTorMTUTransitionPending(launch) {
		t.Fatal("fresh strict proof did not retire the old transition receipt")
	}
}

func TestDesktopTorMTUTransitionActualChildWrongOwnerAndExpiryCannotExtend(t *testing.T) {
	fixture := newDesktopTorTransitionChild(t)
	a, launch := fixture.a, fixture.launch
	fixture.waitForOldHeartbeat(t)
	writeReceipt := func(value mobiletor.DesktopBridgeMTUTransition) {
		raw, _ := json.Marshal(value)
		if err := atomicWritePrivate(filepath.Join(launch.directory, "mtu-transition.json"), raw); err != nil {
			t.Fatal(err)
		}
	}
	if !a.desktopTorMTUTransitionPending(launch) {
		t.Fatal("exact child transition could not establish the pending baseline")
	}
	for _, kind := range []string{"session", "source", "config", "request", "generation", "reader", "deadline", "target"} {
		value := fixture.receipt
		switch kind {
		case "session":
			value.SessionID = strings.Repeat("e", 32)
		case "source":
			value.SourceSHA256 = strings.Repeat("e", 64)
		case "config":
			value.ConfigSHA256 = strings.Repeat("e", 64)
		case "request":
			value.RequestID = strings.Repeat("e", 32)
		case "generation":
			value.Generation++
		case "reader":
			value.From.InterfaceIndex++
		case "deadline":
			value.ExpiresAt++
		case "target":
			value.TargetMTU++
		}
		writeReceipt(value)
		if a.desktopTorMTUTransitionPending(launch) || a.desktopTorMonitorCurrent(launch) {
			t.Fatal("a foreign or relabeled file kept the old heartbeat alive", kind)
		}
	}
	writeReceipt(fixture.receipt)
	desktopNodeOwners.Store(a, &desktopNodeLaunch{command: launch.command, profileID: launch.profileID, tor: launch.tor})
	if a.desktopTorMTUTransitionPending(launch) || a.desktopTorMonitorCurrent(launch) {
		t.Fatal("transition receipt accepted a replacement registration")
	}
	desktopNodeOwners.Store(a, launch)
	if !a.desktopTorMTUTransitionPending(launch) {
		t.Fatal("restored exact owner lost the unchanged pending receipt")
	}
	timer := time.NewTimer(time.Until(time.UnixMilli(fixture.receipt.ExpiresAt).Add(time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-desktopNodeProcessDone(launch):
		t.Fatal("fixture exited before the original transition deadline")
	}
	err := a.desktopMeasurementCurrentProof(launch)
	if a.desktopTorMTUTransitionPending(launch) || a.desktopTorMonitorCurrent(launch) || err == nil || errors.Is(err, errDesktopTorMTUTransitionPending) {
		t.Fatal("expired receipt extended the original deadline or became measurement proof", err)
	}
	launch.tor.mu.Lock()
	retained, heartbeat := *launch.tor.mtuTransition, launch.tor.lastProofHeartbeat
	launch.tor.mu.Unlock()
	if retained != fixture.receipt || heartbeat != fixture.receipt.FromHeartbeatAt {
		t.Fatal("repeated polls renewed the exact transition or refreshed its old heartbeat")
	}
}

func TestDesktopTorMTUTransitionActualChildPublicationRaceUsesFreshStrictRead(t *testing.T) {
	for _, method := range []string{"measurement-proof", "mtu-readback"} {
		t.Run(method, func(t *testing.T) {
			fixture := newDesktopTorTransitionChild(t)
			a, launch := fixture.a, fixture.launch
			fixture.waitForOldHeartbeat(t)
			var calls atomic.Int32
			var publicationErr error
			// The second ownership check is the transition reader, after the
			// first strict read rejected the aged file. Resume the real child
			// here and require its new atomic publication before the base read.
			launch.tor.networkIdentity = func() string {
				if calls.Add(1) == 2 {
					_, publicationErr = fixture.resumeFresh()
				}
				return "transition-fixture-network"
			}
			var err error
			if method == "measurement-proof" {
				err = a.desktopMeasurementCurrentProof(launch)
			} else {
				readback := fixture.receipt.From
				readback.Revision, readback.InterfaceIndex, readback.EffectiveMTU = 1, readback.InterfaceIndex+1, fixture.receipt.TargetMTU
				record := desktopMTURecord{Schema: 1, Session: fixture.receipt.SessionID, SourceSHA256: fixture.receipt.SourceSHA256, ConfigSHA256: fixture.receipt.ConfigSHA256, Generation: fixture.receipt.Generation,
					Status: mobilemtu.Status{Request: fixture.receipt.RequestID, Complete: true, EffectiveMTU: readback.EffectiveMTU}, MTUReadback: &readback}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				err = a.waitDesktopTorMTUReadback(ctx, launch, record)
				cancel()
			}
			if publicationErr != nil || err != nil || calls.Load() < 3 {
				t.Fatal("a completed native publication race discarded the fresh strict proof", method, publicationErr, err, calls.Load())
			}
			proof, err := a.readDesktopTorProof(launch)
			if err != nil || proof.MTUReadback == nil || proof.MTUReadback.Revision != 1 || proof.HeartbeatAt <= fixture.receipt.FromHeartbeatAt {
				t.Fatal("publication retry succeeded without the resumed native reader", err)
			}
		})
	}
}
