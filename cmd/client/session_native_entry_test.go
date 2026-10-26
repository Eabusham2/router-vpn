package main

import "testing"

func TestTypedSessionKeepsNativeMultihopRequestBase(t *testing.T) {
	for _, requested := range []string{"multihop", "speed-lab:multihop", "speed-lab:restore:multihop"} {
		a := &app{}
		tracker := &sessionTracker{a: a}
		tracker.declareRequest(requested, "native")
		captured := tracker.snapshot(0)
		if captured.RequestedMode != requested || captured.RequestedBase != "native" || captured.Connected || captured.PathProof == "passed" || captured.DNSProof.Status == "passed" {
			t.Fatal("native entry request adopted the saved WG/AWG base or an unearned proof", captured)
		}
	}
}
