//go:build windows && routervpn_windows_wfp

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Every kernel filter created here is scoped to this exact test executable's
// AppID. Production loopback exemptions are omitted by the private fixture
// constructor. No Firewall profile, route, existing user or foreign filter is
// changed, including on a deliberately broken negative-control run.
func desktopWindowsWFPTestCapture(t *testing.T) DesktopSocketCapture {
	t.Helper()
	var value [64]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return DesktopSocketCapture{hex.EncodeToString(value[:16]), hex.EncodeToString(value[16:48]), hex.EncodeToString(value[48:])}
}
func desktopWindowsWFPTestOptions(t *testing.T, policy string) (DesktopWindowsSocketOptions, []byte) {
	t.Helper()
	api, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := api.executableAppID()
	if err != nil {
		t.Fatal(err)
	}
	options := DesktopWindowsSocketOptions{KillSwitchPolicy: policy, IPv6Enabled: true}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err == nil && (prefix.Addr() == netip.MustParseAddr("127.0.0.1") || prefix.Addr() == netip.MustParseAddr("::1")) {
				options.Interfaces = append(options.Interfaces, DesktopWindowsSocketInterface{iface.Name, uint32(iface.Index), prefix.Addr()})
			}
		}
	}
	if len(options.Interfaces) != 2 {
		t.Fatal("required real Windows IPv4/IPv6 loopback interfaces are unavailable")
	}
	return options, scope
}
func desktopWindowsWFPTestRecovery(t *testing.T, scope []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	recovery, err := newDesktopWindowsProtectionRecovery(ctx, scope)
	if recovery != nil {
		err = errors.Join(err, recovery.Close(ctx))
	}
	if err != nil {
		t.Error("exact test-owned WFP recovery failed", err)
	}
}
func desktopWindowsWFPTestOwner(t *testing.T, policy string, full bool) *DesktopWindowsSocketPolicy {
	t.Helper()
	options, scope := desktopWindowsWFPTestOptions(t, policy)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	var p *DesktopWindowsSocketPolicy
	var err error
	if full {
		p, err = newDesktopWindowsSocketPolicy(ctx, desktopWindowsWFPTestCapture(t), options, scope)
	} else {
		p, err = newDesktopWindowsPolicyOwner(ctx, desktopWindowsWFPTestCapture(t), options, scope)
		if err == nil {
			_, err = desktopWindowsPolicyCall(p, ctx, false, func() (struct{}, error) { return struct{}{}, p.prepareBaseline() })
		}
	}
	t.Cleanup(func() {
		defer cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if p != nil {
			if err := p.Close(cleanup); err != nil {
				t.Error("owned Windows WFP policy did not retire", err)
			}
		}
		desktopWindowsWFPTestRecovery(t, scope)
	})
	if err != nil {
		t.Fatal("actual captured Windows WFP preparation", err)
	}
	return p
}

func TestDesktopSocketWindowsWFPLayout(t *testing.T) {
	if err := desktopWFPRequireLayout(); err != nil {
		t.Fatal(err)
	}
}
func TestDesktopSocketWindowsWFPActualBaseline(t *testing.T) {
	p := desktopWindowsWFPTestOwner(t, "on-connect", false)
	if err := p.assertBaseline(); err != nil {
		t.Fatal("actual complete baseline readback", err)
	}
	metadata, found, err := p.baselineEngine.ReadSublayer(p.sublayer, true, 65535)
	if err != nil || !found || !bytes.Equal(metadata, p.metadata) {
		t.Fatal("actual baseline record differs", err)
	}
	decoded, err := desktopWindowsDecodeBaseline(metadata, p.fixtureScope)
	if err != nil || decoded.capture != p.capture {
		t.Fatal("baseline record did not preserve exact native capture", err)
	}
	if err := p.baselineEngine.AssertComplete(p.sublayer, decoded.baseline); err != nil {
		t.Fatal("record reconstruction omitted a real baseline rule", err)
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := desktopWFPOpen(false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.SublayerAbsent(p.sublayer); err != nil {
		t.Fatal("on-connect baseline remained after owned cleanup", err)
	}
}
func TestDesktopSocketWindowsWFPRejectsActiveOwner(t *testing.T) {
	p := desktopWindowsWFPTestOwner(t, "on-connect", false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	other, err := newDesktopWindowsPolicyOwner(ctx, desktopWindowsWFPTestCapture(t), p.options, p.fixtureScope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = desktopWindowsPolicyCall(other, ctx, false, func() (struct{}, error) { return struct{}{}, other.prepareBaseline() })
	if err == nil {
		t.Fatal("second native session stole a live WFP baseline")
	}
	if err := other.Close(ctx); err != nil {
		t.Fatal("failed contender could not release its own empty session", err)
	}
	if err := p.assertBaseline(); err != nil {
		t.Fatal("contender cleanup changed the active owner's baseline", err)
	}
}
func TestDesktopSocketWindowsWFPAlwaysReplacement(t *testing.T) {
	old := desktopWindowsWFPTestOwner(t, "always", false)
	if err := old.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := desktopWFPOpen(false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.AssertSublayer(old.sublayer, old.metadata); err != nil {
		t.Fatal("Always lost its persistent baseline", err)
	}
	if err := reader.SublayerAbsent(old.lockKey); err != nil {
		t.Fatal("closed owner kept its dynamic native lock", err)
	}
	current := desktopWindowsWFPTestOwner(t, "on-connect", false)
	if current.sublayer != old.sublayer || current.capture == old.capture {
		t.Fatal("replacement did not retain one stable baseline and a fresh capture")
	}
	if err := current.assertBaseline(); err != nil {
		t.Fatal(err)
	}
	for _, rule := range old.baseline {
		if err := reader.Absent(rule.Key); err != nil {
			t.Fatal("atomic replacement retained an old baseline rule", err)
		}
	}
	if err := old.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := current.assertBaseline(); err != nil {
		t.Fatal("old cleanup removed the replacement owner's baseline", err)
	}
}
func TestDesktopSocketWindowsWFPRejectsAdditionalPermit(t *testing.T) {
	p := desktopWindowsWFPTestOwner(t, "on-connect", false)
	extra := p.rule("unexpected-extra", 4, false, 99, true, false)
	if err := p.leaseEngine.Add(&extra); err != nil {
		t.Fatal("add scoped negative fixture", err)
	}
	defer func() {
		if err := p.leaseEngine.Delete(extra.Key); err != nil {
			t.Error(err)
		}
		if err := p.baselineEngine.Absent(extra.Key); err != nil {
			t.Error(err)
		}
	}()
	if err := p.assertBaseline(); err == nil {
		t.Fatal("full WFP readback accepted an extra broader permit")
	}
}
func TestDesktopSocketWindowsWFPRejectsNoncanonicalRecords(t *testing.T) {
	p := desktopWindowsWFPTestOwner(t, "on-connect", false)
	for _, bad := range [][]byte{
		append(append([]byte(nil), p.metadata...), '\n'),
		bytes.Replace(p.metadata, []byte(`"schema":1`), []byte(`"schema":2`), 1),
		bytes.Replace(p.metadata, []byte(`"lan_prefixes":null`), []byte(`"lan_prefixes":["0.0.0.0/0"]`), 1),
		bytes.Replace(p.metadata, []byte(`"kind":"routervpn-owned-physical-baseline"`), []byte(`"kind":"foreign-policy"`), 1),
	} {
		if bytes.Equal(bad, p.metadata) {
			t.Fatal("malformed record fixture lost its mutation seam")
		}
		if _, err := desktopWindowsDecodeBaseline(bad, p.fixtureScope); err == nil {
			t.Fatal("untrusted WFP record acquired baseline replacement authority")
		}
	}
	if _, err := desktopWindowsDecodeBaseline(p.metadata, nil); err == nil {
		t.Fatal("test scope was accepted as a production baseline")
	}
}
func TestDesktopSocketWindowsWFPExplicitRecovery(t *testing.T) {
	p := desktopWindowsWFPTestOwner(t, "always", false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	blocked, err := newDesktopWindowsProtectionRecovery(ctx, p.fixtureScope)
	if err == nil {
		t.Fatal("recovery stole an active native session")
	}
	if blocked != nil {
		if err := blocked.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.assertBaseline(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	desktopWindowsWFPTestRecovery(t, p.fixtureScope)
	reader, err := desktopWFPOpen(false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.SublayerAbsent(p.sublayer); err != nil {
		t.Fatal("explicit recovery retained the proved managed baseline", err)
	}
}
