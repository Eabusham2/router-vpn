package main

import (
	"context"
	"errors"
	"testing"
)

// The parent lifecycle is real; the fixture explicitly models the native child
// and Windows controller. This checks status ownership, not encrypted DNS.
func assertDesktopOrderedDNSObservation(t *testing.T, f *desktopNodeChainOwnedFixture) {
	t.Helper()
	a, selection := f.a, f.selection
	if err := registerNativeMultihopDNSRuntime(a, selection, f.launch.command); err != nil {
		t.Fatal(err)
	}
	registered, found := activeDNSRuntimeIdentities.Load(a)
	identity, valid := registered.(activeDNSRuntimeIdentity)
	if !found || !valid || !identity.ImportedEntry {
		t.Fatal("ordered DNS fixture omitted the production native registration")
	}
	lookup := func(context.Context, string) ([]string, error) {
		t.Error("owned ordered DNS reached the ambient resolver")
		return nil, errors.New("ambient resolver is not ordered DNS proof")
	}
	observed := observedConnection{Connected: true, Phase: "connected", Mode: "multihop", RouterID: selection.Control.ID, Profile: selection.Control}
	_, _, capture, err := f.launch.chain.readPolicy()
	proof := proveSelectedDNSWithLookup(f.operation, a, observed, selection.ExitMode, lookup)
	if err != nil || proof.Status != "passed" || proof.Mode != capture.SelectedDNS.Mode || proof.Host != capture.SelectedDNS.Host || proof.LatencyMs != 0 || proof.Reason == "" {
		t.Fatal("retained ordered DNS observation lost its final resolver or fabricated a fresh duration", proof, err)
	}
	for _, changed := range []string{"profile", "runtime", "disconnected", "cancelled"} {
		t.Run("dns-"+changed, func(t *testing.T) {
			other, runtimeID, ctx := observed, selection.ExitMode, f.operation
			switch changed {
			case "profile":
				other.Profile.Endpoint = "replacement.invalid"
			case "runtime":
				runtimeID = "replacement"
			case "disconnected":
				other.Connected = false
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if result := proveSelectedDNSWithLookup(ctx, a, other, runtimeID, lookup); result.Status == "passed" || result.LatencyMs != 0 {
				t.Fatal("ordered DNS accepted changed ownership", result)
			}
		})
	}
	graph, present := getActiveMultihopGraph(a)
	native, retained := nativeMultihopOwners.Load(a)
	if !present || !retained {
		t.Fatal("ordered DNS fixture lost its original publication")
	}
	for _, missing := range []string{"graph", "native", "both"} {
		t.Run("dns-missing-"+missing, func(t *testing.T) {
			defer activeMultihopGraphs.Store(a, graph)
			defer nativeMultihopOwners.Store(a, native)
			if missing != "native" {
				activeMultihopGraphs.Delete(a)
			}
			if missing != "graph" {
				nativeMultihopOwners.Delete(a)
			}
			if result := proveSelectedDNSWithLookup(f.operation, a, observed, selection.ExitMode, lookup); result.Status == "passed" || result.LatencyMs != 0 {
				t.Fatal("ordered DNS lost its owner and accepted another observer", result)
			}
		})
	}
}
