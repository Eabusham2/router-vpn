//go:build windows && routervpn_windows_physical_composition

package tun

// This fixture is compiled only into the checksum-pinned sing-tun package.
// New still creates a real adapter and follows its shipping failure branch.
// The sole failure injection asks the real driver for an invalid ring size.
import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	"github.com/sagernet/sing-tun/internal/wintun"
)

var routervpnFailedSession struct {
	adapter *wintun.Adapter
	luid    uint64
	err     error
	starts  int
	closes  int
}

func routervpnWintunInvalidSession(adapter *wintun.Adapter, capacity uint32) (wintun.Session, error) {
	if adapter == nil || capacity != 0x800000 || routervpnFailedSession.adapter != nil {
		panic("failed-session fixture lost its exact newly created adapter")
	}
	routervpnFailedSession.adapter = adapter
	routervpnFailedSession.luid = adapter.LUID()
	routervpnFailedSession.starts++
	// Wintun requires a power of two between 128 KiB and 64 MiB. Keep the
	// actual kernel error and let the shipping New implementation handle it.
	session, err := adapter.StartSession(1)
	routervpnFailedSession.err = err
	return session, err
}

func routervpnWintunObservedFailureClose(adapter *wintun.Adapter) error {
	if adapter == nil || adapter != routervpnFailedSession.adapter || routervpnFailedSession.closes != 0 {
		panic("failed-session cleanup substituted or repeated adapter ownership")
	}
	routervpnFailedSession.closes++
	return adapter.Close()
}

func routervpnSessionFixtureName(t *testing.T) string {
	t.Helper()
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	return "rvpn-fail-" + hex.EncodeToString(nonce[:])
}

func routervpnSessionFixtureAbsent(t *testing.T, name string, luid uint64) bool {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		interfaces, err := net.Interfaces()
		present := false
		if err == nil {
			for _, iface := range interfaces {
				actual, readErr := winipcfg.LUIDFromIndex(uint32(iface.Index))
				if readErr != nil {
					err = readErr
					break
				}
				if iface.Name == name || uint64(actual) == luid {
					present = true
				}
			}
		}
		if err == nil && !present {
			return true
		}
		if time.Now().After(deadline) {
			t.Error("failed-session fixture adapter absence is unproved", name, luid, err)
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRouterVPNWintunFailedSessionRetiresCreatedAdapter(t *testing.T) {
	name, controlName := routervpnSessionFixtureName(t), routervpnSessionFixtureName(t)
	control, err := wintun.CreateAdapter(controlName, TunnelType, generateGUIDByDeviceName(controlName))
	if err != nil {
		t.Fatal("create independent owned adapter control", err)
	}
	controlLUID := control.LUID()
	t.Cleanup(func() {
		// Retain the exact failed adapter even for the missing-Close mutant.
		// This also prevents a finalizer from concealing the shipping leak.
		if routervpnFailedSession.adapter != nil && routervpnFailedSession.closes == 0 {
			_ = routervpnWintunObservedFailureClose(routervpnFailedSession.adapter)
		}
		_ = control.Close()
		clean := routervpnSessionFixtureAbsent(t, controlName, controlLUID)
		if routervpnFailedSession.luid != 0 {
			clean = routervpnSessionFixtureAbsent(t, name, routervpnFailedSession.luid) && clean
		}
		runtime.KeepAlive(routervpnFailedSession.adapter)
		if clean {
			t.Log("actual failed-session adapter cleanup proved")
		}
	})
	if controlLUID == 0 {
		t.Fatal("independent adapter control has no actual LUID")
	}
	reader, err := New(Options{Name: name, MTU: 1280, AutoRoute: false, DNSMode: DNSModeDisabled, EXP_ExternalConfiguration: true})
	if reader != nil {
		_ = reader.Close()
		// An unexpected successful session already closed its own reader.
		routervpnFailedSession.closes++
		t.Fatal("invalid real Wintun ring unexpectedly returned a successful reader", err)
	}
	if routervpnFailedSession.starts != 1 || routervpnFailedSession.luid == 0 || routervpnFailedSession.err == nil || !errors.Is(err, routervpnFailedSession.err) {
		t.Fatal("shipping New did not preserve the actual Wintun session error", err, routervpnFailedSession.err)
	}
	// Check the real driver before the fallback cleanup, not just a callback
	// counter. An opened observation handle does not own adapter deletion.
	leaked, openErr := wintun.OpenAdapter(name)
	if leaked != nil {
		_ = leaked.Close()
		t.Fatal("failed Wintun session retained its created adapter", openErr)
	}
	if routervpnFailedSession.closes != 1 || openErr == nil {
		t.Fatal("failed Wintun session did not synchronously close its exact adapter", openErr)
	}
	if !routervpnSessionFixtureAbsent(t, name, routervpnFailedSession.luid) {
		t.Fatal("failed Wintun session retained its created adapter")
	}
	other, err := wintun.OpenAdapter(controlName)
	if err != nil || other == nil {
		t.Fatal("failed-session cleanup removed the unrelated adapter control", err)
	}
	observed := other.LUID()
	_ = other.Close()
	if observed != controlLUID {
		t.Fatal("failed-session cleanup replaced the unrelated adapter control")
	}
	runtime.KeepAlive(routervpnFailedSession.adapter)
	t.Logf("real session failure preserved; exact adapter %s LUID=%x retired; independent control retained", name, routervpnFailedSession.luid)
}
