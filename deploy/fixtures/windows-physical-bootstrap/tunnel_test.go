//go:build windows && routervpn_windows_physical_composition

package mobiletor

// This test is overlaid only into the exact prepared native module, whose
// checksum-pinned sing-tun replacement includes the shipping Wintun ownership
// patch. It never enables AutoRoute or configures any address or DNS setting.
// WFP rules additionally match only this actual test executable.
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	tun "github.com/sagernet/sing-tun"
)

type desktopWindowsActualTunnel struct {
	reader *tun.NativeTun
	name   string
	index  uint32
	luid   uint64
}

func desktopWindowsActualTunnelCapture(t *testing.T) DesktopSocketCapture {
	t.Helper()
	var value [64]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return DesktopSocketCapture{hex.EncodeToString(value[:16]), hex.EncodeToString(value[16:48]), hex.EncodeToString(value[48:])}
}

func desktopWindowsActualTunnelOptions(t *testing.T, ipv6 bool) (DesktopWindowsSocketOptions, []byte) {
	t.Helper()
	api, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := api.executableAppID()
	if err != nil || len(scope) == 0 {
		t.Fatal("actual Wintun fixture lost its executable identity", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range addresses {
			prefix, err := netip.ParsePrefix(candidate.String())
			if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsGlobalUnicast() {
				continue
			}
			return DesktopWindowsSocketOptions{
				Interfaces:       []DesktopWindowsSocketInterface{{Name: iface.Name, Index: uint32(iface.Index), Address: prefix.Addr()}},
				KillSwitchPolicy: "on-connect", IPv6Enabled: ipv6,
			}, scope
		}
	}
	t.Fatal("actual Wintun fixture requires an existing up physical IPv4 interface")
	return DesktopWindowsSocketOptions{}, nil
}

func desktopWindowsCreateActualTunnel(t *testing.T, ctx context.Context, owners *[]*desktopWindowsActualTunnel) *desktopWindowsActualTunnel {
	t.Helper()
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := "rvpn-test-" + hex.EncodeToString(nonce[:])
	if current, err := net.InterfaceByName(name); err == nil || current != nil {
		t.Fatal("random Wintun fixture name already belongs to an interface", name)
	}
	options := tun.Options{Name: name, MTU: 1280, AutoRoute: false, DNSMode: tun.DNSModeDisabled, EXP_ExternalConfiguration: true}
	reader, err := tun.New(options)
	if err != nil {
		t.Fatal("create uniquely owned actual Wintun reader", err)
	}
	native, ok := reader.(*tun.NativeTun)
	if !ok || native == nil {
		_ = reader.Close()
		t.Fatal("actual Windows tunnel did not return its shipping Wintun owner")
	}
	owned := &desktopWindowsActualTunnel{reader: native, name: name}
	*owners = append(*owners, owned)
	if err := reader.Start(); err != nil {
		t.Fatal("start actual Wintun session without routes or DNS", err)
	}
	actualName, err := native.Name()
	if err != nil || actualName != name || native.LUID() == 0 {
		t.Fatal("retained Wintun reader identity differs", actualName, native.LUID(), err)
	}
	// PnP publishes a newly created adapter asynchronously. Every retry reads
	// the real interface and independently maps its index to its current LUID;
	// no elapsed time is treated as readiness.
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		actual, err := net.InterfaceByName(name)
		if err == nil && actual.Flags&net.FlagUp != 0 && actual.Flags&net.FlagLoopback == 0 {
			luid, readErr := desktopWindowsInterfaceLUID(uint32(actual.Index))
			if readErr != nil || luid != native.LUID() {
				t.Fatal("independent actual Wintun index/LUID readback differs", actual.Index, luid, native.LUID(), readErr)
			}
			owned.index, owned.luid = uint32(actual.Index), luid
			break
		}
		select {
		case <-deadline.Done():
			t.Fatal("actual Wintun interface did not become up", err, deadline.Err())
		case <-ticker.C:
		}
	}
	duplicate, err := tun.New(options)
	if duplicate != nil {
		_ = duplicate.Close()
	}
	if err == nil || duplicate != nil {
		t.Fatal("exclusive native Wintun creation adopted an existing reader")
	}
	t.Logf("actual owned Wintun name=%s index=%d retained LUID=%x", name, owned.index, owned.luid)
	return owned
}

// Each expected condition is derived from the actual retained Wintun handle,
// independently of the policy's generated rule. A separate BFE session then
// reads the real filter and the complete owned sublayer.
func desktopWindowsReadActualTunnelRules(t *testing.T, ctx context.Context, p *DesktopWindowsSocketPolicy, owned *desktopWindowsActualTunnel) []desktopWFPRule {
	t.Helper()
	rules, err := desktopWindowsPolicyCall(p, ctx, true, func() ([]desktopWFPRule, error) {
		count := 2
		if p.options.IPv6Enabled {
			count = 4
		}
		if p.tunnelName != owned.name || p.tunnelIndex != owned.index || p.tunnelLUID != owned.luid || len(p.tunnel) != count {
			return nil, errors.New("actual Wintun permit lost its exact reader or address-family policy")
		}
		reader, err := desktopWFPOpen(false)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		layers := map[syscall.GUID]bool{desktopWFPConnect4: true, desktopWFPAccept4: true}
		if p.options.IPv6Enabled {
			layers[desktopWFPConnect6], layers[desktopWFPAccept6] = true, true
		}
		for _, rule := range p.tunnel {
			if rule.Persistent || !rule.Permit || rule.Weight != 55 || rule.ID == 0 || !layers[rule.Layer] || len(rule.Conditions) != 2 {
				return nil, errors.New("actual Wintun filter broadened its native lifetime, action, family or condition count")
			}
			delete(layers, rule.Layer)
			iface, image := rule.Conditions[0], rule.Conditions[1]
			if iface.Field != desktopWFPInterface || iface.Type != 4 || iface.Match != 0 || iface.Number != owned.luid || len(iface.Bytes) != 0 ||
				image.Field != desktopWFPAppID || image.Type != 12 || image.Match != 0 || !bytes.Equal(image.Bytes, p.fixtureScope) {
				return nil, errors.New("actual Wintun filter does not match the exact retained LUID and test image")
			}
			if err := reader.Assert(rule); err != nil {
				return nil, err
			}
		}
		if len(layers) != 0 {
			return nil, errors.New("actual Wintun filter omitted a required direction or family")
		}
		if err := reader.AssertComplete(p.sublayer, p.expected()); err != nil {
			return nil, err
		}
		return append([]desktopWFPRule(nil), p.tunnel...), nil
	})
	if err != nil {
		t.Fatal("independent actual Wintun/WFP readback", err)
	}
	return rules
}

func desktopWindowsAssertRetiredTunnel(t *testing.T, ctx context.Context, p *DesktopWindowsSocketPolicy, rules []desktopWFPRule) {
	t.Helper()
	_, err := desktopWindowsPolicyCall(p, ctx, true, func() (struct{}, error) {
		if len(p.tunnel) != 0 || p.tunnelName != "" || p.tunnelIndex != 0 || p.tunnelLUID != 0 {
			return struct{}{}, errors.New("native Wintun retirement retained its policy identity")
		}
		reader, err := desktopWFPOpen(false)
		if err != nil {
			return struct{}{}, err
		}
		defer reader.Close()
		for _, rule := range rules {
			if err := reader.Absent(rule.Key); err != nil {
				return struct{}{}, err
			}
		}
		return struct{}{}, reader.AssertComplete(p.sublayer, p.expected())
	})
	if err != nil {
		t.Fatal("owned Wintun permit remained after acknowledged native retirement", err)
	}
}

func desktopWindowsCloseActualTunnel(t *testing.T, ctx context.Context, owned *desktopWindowsActualTunnel) bool {
	t.Helper()
	if err := owned.reader.Close(); err != nil {
		t.Error("owned actual Wintun reader did not close", err)
		return false
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		interfaces, err := net.Interfaces()
		present := false
		if err == nil {
			for _, actual := range interfaces {
				luid, readErr := desktopWindowsInterfaceLUID(uint32(actual.Index))
				if readErr != nil {
					err = readErr
					break
				}
				if actual.Name == owned.name || luid == owned.luid {
					present = true
				}
			}
		}
		if err == nil && !present {
			return true
		}
		select {
		case <-ctx.Done():
			t.Error("closed actual Wintun name/LUID absence is unproved", owned.name, owned.luid, err, ctx.Err())
			return false
		case <-ticker.C:
		}
	}
}

func TestDesktopSocketWindowsActualWintunBindingAndRetirement(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		label := "ipv4-only"
		if ipv6 {
			label = "ipv4-and-ipv6"
		}
		t.Run(label, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
			options, scope := desktopWindowsActualTunnelOptions(t, ipv6)
			capture := desktopWindowsActualTunnelCapture(t)
			var p *DesktopWindowsSocketPolicy
			var owners []*desktopWindowsActualTunnel
			t.Cleanup(func() {
				defer cancel()
				cleanup, stop := context.WithTimeout(context.Background(), 12*time.Second)
				defer stop()
				// Retire kernel permits while their actual reader identity is still
				// held. Close only adapters this fixture itself created.
				clean := true
				if p != nil {
					if err := p.Close(cleanup); err != nil {
						clean = false
						t.Error("actual Wintun policy did not retire before reader close", err)
					}
				}
				for _, owned := range owners {
					if !desktopWindowsCloseActualTunnel(t, cleanup, owned) {
						clean = false
					}
				}
				recovery, err := newDesktopWindowsProtectionRecovery(cleanup, scope)
				if recovery != nil {
					err = errors.Join(err, recovery.Close(cleanup))
				}
				if err != nil {
					clean = false
					t.Error("actual Wintun fixture left its exact scoped baseline", err)
				}
				if clean {
					t.Log("actual Wintun fixture cleanup proved")
				}
			})
			var err error
			p, err = newDesktopWindowsSocketPolicy(ctx, capture, options, scope)
			if err != nil {
				t.Fatal("actual Wintun fixture could not prepare its real captured WFP owner", err)
			}
			first := desktopWindowsCreateActualTunnel(t, ctx, &owners)
			stale := capture
			if stale.NetworkID[0] == '0' {
				stale.NetworkID = "1" + stale.NetworkID[1:]
			} else {
				stale.NetworkID = "0" + stale.NetworkID[1:]
			}
			if err := p.BindTunnel(ctx, stale, first.name, first.index); err == nil {
				t.Fatal("actual Wintun binding accepted another captured network")
			}
			physical := options.Interfaces[0]
			if err := p.BindTunnel(ctx, capture, physical.Name, physical.Index); err == nil {
				t.Fatal("actual Wintun binding authorized the captured physical interface")
			}
			if err := p.BindTunnel(ctx, capture, first.name, first.index); err != nil {
				t.Fatal("bind exact actual Wintun reader to its real WFP owner", err)
			}
			firstRules := desktopWindowsReadActualTunnelRules(t, ctx, p, first)
			if err := p.BindTunnel(ctx, capture, first.name, first.index); err == nil {
				t.Fatal("actual Wintun binding replaced a reader without acknowledged retirement")
			}
			if err := p.RetireTunnel(ctx, stale, first.name, first.index); err == nil {
				t.Fatal("actual Wintun retirement accepted another captured network")
			}
			if err := p.RetireTunnel(ctx, capture, first.name+"-stale", first.index); err == nil {
				t.Fatal("actual Wintun retirement accepted another native reader")
			}
			desktopWindowsReadActualTunnelRules(t, ctx, p, first)
			if err := p.RetireTunnel(ctx, capture, first.name, first.index); err != nil {
				t.Fatal("retire exact actual Wintun reader before replacement", err)
			}
			desktopWindowsAssertRetiredTunnel(t, ctx, p, firstRules)
			second := desktopWindowsCreateActualTunnel(t, ctx, &owners)
			if first.luid == second.luid || first.index == second.index || first.name == second.name {
				t.Fatal("two held Wintun owners reused their native identity")
			}
			if err := p.BindTunnel(ctx, capture, second.name, second.index); err != nil {
				t.Fatal("bind actual replacement Wintun reader", err)
			}
			secondRules := desktopWindowsReadActualTunnelRules(t, ctx, p, second)
			if err := p.RetireTunnel(ctx, capture, first.name, first.index); err == nil {
				t.Fatal("stale actual Wintun callback retired a replacement reader")
			}
			desktopWindowsReadActualTunnelRules(t, ctx, p, second)
			if err := p.RetireTunnel(ctx, capture, second.name, second.index); err != nil {
				t.Fatal("retire actual replacement Wintun reader", err)
			}
			desktopWindowsAssertRetiredTunnel(t, ctx, p, secondRules)
			if err := p.Close(ctx); err != nil {
				t.Fatal("close exact actual Wintun WFP owner", err)
			}
			absent, err := probeDesktopWindowsProtectionAbsent(ctx, scope)
			if err != nil || !absent {
				t.Fatal("actual Wintun fixture baseline/session-lock cleanup is unproved", err)
			}
		})
	}
}
