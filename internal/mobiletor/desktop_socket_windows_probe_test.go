//go:build windows && routervpn_windows_wfp

package mobiletor

import (
	"context"
	"strings"
	"testing"
	"time"
)

func desktopWindowsProbeTestScope(t *testing.T) []byte {
	t.Helper()
	api, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := api.executableAppID()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	absent, err := probeDesktopWindowsProtectionAbsent(ctx, scope)
	if err != nil || !absent {
		t.Fatal("probe fixture found another live owner at its exact executable keys", err)
	}
	return scope
}

func TestDesktopSocketWindowsWFPProbeOrdinaryAbsence(t *testing.T) {
	scope := desktopWindowsProbeTestScope(t)
	process := desktopWindowsProbeTestProcess(t)
	reply, err := process.run(scope)
	if err != nil {
		t.Fatal("actual ordinary process absence fixture", err)
	}
	if reply.Lookups != [3]uint32{0x80320007, 0x80320007, 0x80320007} || !reply.Absent || reply.ProbeError != "" {
		t.Fatal("ordinary process did not independently prove both managed keys absent", reply)
	}
	t.Log("Actual distinct non-admin primary-token process proved lock, baseline, and lock absent")
}

func TestDesktopSocketWindowsWFPProbeOrdinaryProtectedObjects(t *testing.T) {
	scope := desktopWindowsProbeTestScope(t)
	process := desktopWindowsProbeTestProcess(t)
	for _, kind := range []string{"session-lock", "baseline"} {
		t.Run(kind, func(t *testing.T) {
			engine, err := desktopWFPOpen(true)
			if engine != nil {
				t.Cleanup(func() {
					if err := engine.Close(); err != nil {
						t.Error("owned probe fixture sublayer did not retire", err)
					}
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			key := desktopWindowsManagedKey(kind, scope)
			// A real protected object is enough to disqualify absence, including
			// an incomplete baseline. No traffic rule or broader read ACL is added.
			if err := engine.addSublayer(key, []byte("RouterVPN private absence-probe fixture"), false, 0); err != nil {
				t.Fatal(err)
			}
			if err := engine.assertLayerSecurity(key); err != nil {
				t.Fatal("probe fixture lost its actual administrator-only object ACL", err)
			}
			reply, err := process.run(scope)
			if err != nil {
				t.Fatal("actual ordinary protected-object fixture", err)
			}
			expected := [3]uint32{0x80320007, 0x80320007, 0x80320007}
			if kind == "session-lock" {
				expected[0], expected[2] = 5, 5
			} else {
				expected[1] = 5
			}
			if reply.Lookups != expected {
				t.Fatal("ordinary fixture did not receive independent native ACCESS_DENIED for the protected object", kind, reply.Lookups)
			}
			if reply.Absent || !strings.Contains(reply.ProbeError, "0x00000005") {
				t.Fatal("ordinary protected "+kind+" access denial was reported as missing native protection", reply)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if absent, err := probeDesktopWindowsProtectionAbsent(ctx, scope); err != nil || absent {
				t.Fatal("elevated probe overlooked its actual existing object", err)
			}
			t.Log("Actual non-admin primary process preserved ACCESS_DENIED for", kind)
		})
	}
	reply, err := process.run(scope)
	if err != nil || !reply.Absent || reply.ProbeError != "" || reply.Lookups != [3]uint32{0x80320007, 0x80320007, 0x80320007} {
		t.Fatal("ordinary probe did not observe exact owned sublayer cleanup", err, reply)
	}
}

func TestDesktopSocketWindowsWFPProbeCancelledGate(t *testing.T) {
	// An existing worker owns this gate until its actual read session joins.
	// A cancelled waiter must not consume/release that ownership or claim absence.
	desktopWindowsProtectionReadGate <- struct{}{}
	defer func() { <-desktopWindowsProtectionReadGate }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if absent, err := ProbeDesktopWindowsProtectionAbsent(ctx); absent || err == nil {
		t.Fatal("cancelled absence probe returned a successful result", err)
	}
	if len(desktopWindowsProtectionReadGate) != 1 {
		t.Fatal("cancelled absence probe released another read owner")
	}
	if absent, err := ProbeDesktopWindowsProtectionAbsent(nil); absent || err == nil {
		t.Fatal("missing probe context acquired absence authority", err)
	}
}
