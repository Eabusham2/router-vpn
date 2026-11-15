package mobilemultihop

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"router-vpn/internal/nativeopenvpn"
)

type externalOpenVPNEntryFixture struct {
	*externalProofFixture
	state   nativeopenvpn.PacketObservation
	observe func(context.Context, string) (nativeopenvpn.PacketObservation, error)
}

func (e *externalOpenVPNEntryFixture) OpenVPNEntryStateContext(ctx context.Context, tag string) (nativeopenvpn.PacketObservation, error) {
	if e.observe != nil {
		return e.observe(ctx, tag)
	}
	if tag != externalEntryTag {
		return nativeopenvpn.PacketObservation{}, errors.New("foreign entry")
	}
	return e.state, ctx.Err()
}
func externalOpenVPNEntryRequest(t *testing.T) (*ExternalProofRequest, *externalOpenVPNEntryFixture, *[]string) {
	t.Helper()
	graph, capture := externalTestFixture(t, "shadowsocks", "wireguard")
	externalOpenVPNReplace(t, graph, capture, true, "tcp")
	capture["entry"].(map[string]any)["mtu_policy"] = "fixed"
	capture["entry"].(map[string]any)["manual_mtu"] = float64(1500)
	policy, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	order := []string{}
	engine := &externalOpenVPNEntryFixture{externalProofFixture: &externalProofFixture{}, state: nativeopenvpn.PacketObservation{
		Remote: nativeopenvpn.RemoteReceipt{Remote: nativeopenvpn.Remote{Host: "198.51.100.24", Port: 1194, Network: "tcp"}, Generation: 7, ConnectedAt: time.Now().UnixMilli()}, MTU: 1500}}
	engine.current.Store(true)
	engine.dns = func(context.Context, string) error { order = append(order, "dns"); return nil }
	request, err := NewExternalProofRequest(context.Background(), policy, "entry-owned-session", engine)
	if err != nil {
		t.Fatal(err)
	}
	request.public = func(_ context.Context, tag, ip string) error {
		if !externalPublicIP(ip) {
			t.Fatal("missing captured public proof")
		}
		order = append(order, tag)
		return nil
	}
	t.Cleanup(func() {
		if err := request.Close(); err != nil {
			t.Error(err)
		}
	})
	return request, engine, &order
}
func TestExternalOpenVPNEntryRetainsGenerationCapacityAndProofOrder(t *testing.T) {
	r, e, order := externalOpenVPNEntryRequest(t)
	if _, err := NewExternalProofRequest(context.Background(), r.policy, "other-owner", e.externalProofFixture); err == nil {
		t.Fatal("missing native capacity observer admitted")
	}
	if _, err := r.Run(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*order, []string{externalEntryTag, "dns", ExternalFinalTag}) || !r.Healthy() {
		t.Fatal("lost independently routed entry/final/DNS proof", *order)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r.VerifyCurrentPathContext(ctx) == nil || !r.Healthy() {
		t.Fatal("cancelled observer retired the original proof")
	}
	e.state.Remote.Generation++
	if r.VerifyCurrentPath() == nil || r.Healthy() {
		t.Fatal("reconnected entry reused stale proof")
	}
}
func TestExternalOpenVPNEntryRejectsWrongNativeStateBeforeTraffic(t *testing.T) {
	for _, fault := range []string{"remote", "generation", "capacity", "network", "owner"} {
		t.Run(fault, func(t *testing.T) {
			r, e, order := externalOpenVPNEntryRequest(t)
			switch fault {
			case "remote":
				e.state.Remote.Host = "198.51.100.99"
			case "generation":
				e.state.Remote.Generation = 0
			case "capacity":
				e.state.MTU = 1280
			case "network":
				e.state.Remote.Network = "udp"
			case "owner":
				e.current.Store(false)
			}
			if _, err := r.Run(); err == nil || r.Healthy() || len(*order) != 0 {
				t.Fatal("unbound entry admitted proof traffic", err, *order)
			}
		})
	}
}
func TestExternalOpenVPNEntryChangesDuringProofCannotSucceed(t *testing.T) {
	for _, phase := range []string{externalEntryTag, "dns", ExternalFinalTag} {
		t.Run(phase, func(t *testing.T) {
			r, e, _ := externalOpenVPNEntryRequest(t)
			r.public = func(_ context.Context, tag, _ string) error {
				if tag == phase {
					e.state.MTU++
				}
				return nil
			}
			e.dns = func(context.Context, string) error {
				if phase == "dns" {
					e.state.Remote.Generation++
				}
				return nil
			}
			if _, err := r.Run(); err == nil || r.Healthy() {
				t.Fatal("changed entry acquired a completed proof")
			}
		})
	}
}
func TestExternalOpenVPNEntryPendingAndHeldObserversKeepOriginalCaller(t *testing.T) {
	r, e, _ := externalOpenVPNEntryRequest(t)
	calls := 0
	e.observe = func(ctx context.Context, tag string) (nativeopenvpn.PacketObservation, error) {
		calls++
		if calls == 1 {
			return nativeopenvpn.PacketObservation{}, nativeopenvpn.ErrRemotePending
		}
		return e.state, ctx.Err()
	}
	if _, err := r.Run(); err != nil || calls < 2 {
		t.Fatal("original pending handshake was not joined", err, calls)
	}
	e.observe = func(ctx context.Context, _ string) (nativeopenvpn.PacketObservation, error) {
		<-ctx.Done()
		return nativeopenvpn.PacketObservation{}, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.VerifyCurrentPathContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("held capacity reader escaped caller", err)
	}
	e.observe = nil
	if !r.Healthy() {
		t.Fatal("short observation stole retained VPN lifetime")
	}
}
