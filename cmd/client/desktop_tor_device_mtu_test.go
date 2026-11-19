package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

func TestDesktopTorStagesAndAdoptsOnlyCapturedDeviceMTU(t *testing.T) {
	a, original := desktopTorPreparedFixture(t, clientTorBridge)
	initial, err := captureDeviceMTUPolicy(a)
	if err != nil {
		t.Fatal(err)
	}
	if reply := deviceMTUTestPost(t, a, initial.token, 8192); reply.Code != 200 {
		t.Fatal(reply.Body.String())
	}
	capture, err := captureDeviceMTUPolicy(a)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), deviceMTUContextKey{}, capture)
	profile := a.profiles.Profiles[0]
	prepare := func() (torBridgeRuntime, error) {
		return stageDesktopTorInputsWithPredecessorContext(ctx, filepath.Dir(a.cfg.ProfilesFile), profile, profile, original.TorBinary, original.NativeBinary, nil)
	}
	staged, err := prepare()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = staged.Launch.directoryRoot.Close() })
	read := func(name string) string {
		t.Helper()
		raw, err := readDesktopRuntimeFile(staged.Launch, name, 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	worker, err := mobiletor.DecodeDesktopBridgeCapture(read("tor-profile.json"), read("tor-capture.json"), staged.RuntimeDir)
	if err != nil {
		t.Fatal(err)
	}
	owner := staged.Launch.tor
	if worker.Policy().Config() != read("sing-box.json") || worker.Digests() != owner.digests || worker.Policy().Metadata() != owner.expected ||
		owner.expected.DeviceMTURevision != capture.policy.Revision || owner.expected.ConfiguredMTU != 8192 || owner.expected.AllowMTUOptimization() {
		t.Fatal("staged worker inputs diverged from original device request")
	}
	now := time.Now()
	proof := desktopTorFixtureProof(owner.expected, now)
	check := func(want bool) {
		t.Helper()
		wire, err := json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		_, err = validateDesktopTorProof(wire, owner, now)
		if (err == nil) != want {
			t.Fatalf("unexpected admission with revision %q, OS MTU %d: %v", proof.Policy.DeviceMTURevision, proof.EffectiveMTU, err)
		}
	}
	check(false) // Staging has not started this native worker.
	owner.started = now.Add(-time.Second)
	check(true)
	proof.EffectiveMTU = original.Launch.tor.expected.ConfiguredMTU
	check(false)
	proof.EffectiveMTU = 8192
	proof.Policy.DeviceMTURevision = strings.Repeat("a", 32)
	check(false)
	if reply := deviceMTUTestPost(t, a, capture.token, 0); reply.Code != 200 {
		t.Fatal(reply.Body.String())
	}
	if _, err := prepare(); err == nil {
		t.Fatal("obsolete settings capture prepared a replacement Tor worker")
	}
}
