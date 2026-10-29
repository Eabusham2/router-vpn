//go:build windows && routervpn_windows_wfp

package mobiletor

import (
	"bytes"
	"context"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
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

func desktopWindowsProbeOrdinaryObservation(t *testing.T, reply desktopWindowsProbeReply, expected [3]uint32, protected string) {
	t.Helper()
	if reply.OpenStatus == uint32(syscall.ERROR_ACCESS_DENIED) {
		if reply.Opened || reply.Lookups != [3]uint32{} || reply.Pointers != [3]bool{} {
			t.Fatal("ordinary BFE open denial acquired an unproved session or key lookup", reply)
		}
		if reply.Absent || reply.ProbeError != "Windows owned WFP open failed (0x00000005)\nWFP did not return a session owner" {
			t.Fatal("ordinary BFE open denial was reported as missing native protection", reply)
		}
		t.Log("Actual distinct non-admin primary process received BFE OPEN status5 with no session; production kept false plus the exact open error")
		return
	}
	if reply.OpenStatus != 0 || !reply.Opened || reply.Lookups != expected || reply.Pointers != [3]bool{} {
		t.Fatal("ordinary fixture did not preserve its independent native open and key observations", reply)
	}
	if protected == "" {
		if !reply.Absent || reply.ProbeError != "" {
			t.Fatal("ordinary readable process did not independently prove both managed keys absent", reply)
		}
		t.Log("Actual distinct non-admin primary process proved lock, baseline, and lock absent")
		return
	}
	if reply.Absent || reply.ProbeError != "Windows owned WFP probe managed protection absence failed (0x00000005)" {
		t.Fatal("ordinary protected "+protected+" access denial was reported as missing native protection", reply)
	}
	t.Log("Actual non-admin primary process preserved key READ status5 for", protected)
}

func desktopWindowsProbeRequireElevatedState(t *testing.T, scope []byte, wantAbsent bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	absent, err := probeDesktopWindowsProtectionAbsent(ctx, scope)
	if err != nil || absent != wantAbsent {
		t.Fatal("elevated probe overlooked its actual owned-object state", wantAbsent, err)
	}
}

func TestDesktopSocketWindowsWFPProbeOrdinaryAbsence(t *testing.T) {
	if !desktopWindowsProbeInOwnedWorker(t) {
		return
	}
	scope := desktopWindowsProbeTestScope(t)
	process := desktopWindowsProbeTestProcess(t)
	reply, err := process.run(scope)
	if err != nil {
		t.Fatal("actual ordinary process absence fixture", err)
	}
	desktopWindowsProbeOrdinaryObservation(t, reply, [3]uint32{0x80320007, 0x80320007, 0x80320007}, "")
	// An OPEN denial is deliberately not absence evidence. The independently
	// authorized process proves the actual state before and after the read.
	desktopWindowsProbeRequireElevatedState(t, scope, true)
}

func TestDesktopSocketWindowsWFPProbeOrdinaryProtectedObjects(t *testing.T) {
	if !desktopWindowsProbeInOwnedWorker(t) {
		return
	}
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
			before, err := engine.readSublayer(key, false)
			if err != nil || before == nil {
				t.Fatal("owned protected probe object was not independently readable", err)
			}
			desktopWindowsProbeRequireElevatedState(t, scope, false)
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
			desktopWindowsProbeOrdinaryObservation(t, reply, expected, kind)
			after, err := engine.readSublayer(key, false)
			if err != nil || after == nil || before.Weight != after.Weight || !bytes.Equal(before.Metadata, after.Metadata) {
				t.Fatal("ordinary read changed its exact owned object or administrator-only ACL", err)
			}
			desktopWindowsProbeRequireElevatedState(t, scope, false)
		})
	}
	reply, err := process.run(scope)
	if err != nil {
		t.Fatal("ordinary probe after exact owned sublayer cleanup", err)
	}
	desktopWindowsProbeOrdinaryObservation(t, reply, [3]uint32{0x80320007, 0x80320007, 0x80320007}, "")
	desktopWindowsProbeRequireElevatedState(t, scope, true)
}

func TestDesktopSocketWindowsWFPProbeDeniedRead(t *testing.T) {
	scope := desktopWindowsProbeTestScope(t)
	for _, kind := range []string{"session-lock", "baseline"} {
		t.Run(kind, func(t *testing.T) {
			engine, err := desktopWFPOpen(true)
			if engine != nil {
				t.Cleanup(func() {
					if err := engine.Close(); err != nil {
						t.Error("fresh denied-read sublayer did not retire with its dynamic session", err)
					}
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			// Keep an actual READ-denial negative even on hosts whose ordinary
			// logon cannot open BFE. This newly owned, filterless dynamic object
			// only RESTRICTS the usual owner descriptor: no engine/container or
			// other object ACL changes, privileges or additional access grants.
			// The SDK defines FWPM_ACTRL_READ as 0x80. DELETE/owner management
			// remain intact; closing this exact dynamic session retires it.
			sddl, _ := syscall.UTF16PtrFromString("O:BAG:BAD:P(D;;0x00000080;;;BA)(A;;GA;;;SY)(A;;GA;;;BA)")
			var descriptor unsafe.Pointer
			var size uint32
			ok, _, callErr := engine.api.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)))
			if descriptor != nil {
				defer engine.api.freeLocal.Call(uintptr(descriptor))
			}
			if ok == 0 || descriptor == nil || size < 20 || size > 4096 {
				t.Fatal("fresh denied-read fixture descriptor was not created", callErr)
			}
			key := desktopWindowsManagedKey(kind, scope)
			metadata := []byte("RouterVPN owned read-denial probe fixture")
			name, _ := syscall.UTF16PtrFromString("RouterVPN owned probe READ-denial fixture")
			value := desktopWFPSubLayer{Key: key, Display: desktopWFPDisplay{Name: name}, Metadata: desktopWFPBlob{Size: uint32(len(metadata)), Data: &metadata[0]}}
			status, _, _ := engine.api.addLayer.Call(uintptr(engine.handle), uintptr(unsafe.Pointer(&value)), uintptr(descriptor))
			runtime.KeepAlive(sddl)
			runtime.KeepAlive(name)
			runtime.KeepAlive(value)
			runtime.KeepAlive(metadata)
			if status != 0 {
				t.Fatal("fresh denied-read fixture was not actually added", desktopWFPError("add fixture", status))
			}
			var pointer *desktopWFPSubLayer
			status, _, _ = engine.api.getLayer.Call(uintptr(engine.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&pointer)))
			if pointer != nil {
				engine.free(unsafe.Pointer(pointer))
			}
			if uint32(status) != uint32(syscall.ERROR_ACCESS_DENIED) || pointer != nil {
				t.Fatal("fresh owner-denied object did not return actual native READ5 and nil", status, pointer != nil)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			absent, err := probeDesktopWindowsProtectionAbsent(ctx, scope)
			if absent || err == nil || err.Error() != "Windows owned WFP probe managed protection absence failed (0x00000005)" {
				t.Fatal("actual denied key read was reported as missing native protection", kind, absent, err)
			}
		})
		desktopWindowsProbeRequireElevatedState(t, scope, true)
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
