package desktopnetwork

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func networkTestObject(kind string, index, table uint32, destination, gateway string) DesktopNetworkObject {
	if runtime.GOOS != "linux" {
		return DesktopNetworkObject{Kind: "route", Family: 4, Index: index, LUID: func() uint64 {
			if runtime.GOOS == "windows" {
				return uint64(index) + 100
			}
			return 0
		}(), Destination: destination, Gateway: gateway}
	}
	body := make([]byte, 12)
	body[0] = 2
	body[5] = 4
	body[7] = 1
	if kind == "rule" {
		body[5] = 0
		body[7] = 1
	}
	attribute := func(id uint16, value []byte) {
		raw := make([]byte, (len(value)+7)&^3)
		binary.LittleEndian.PutUint16(raw, uint16(len(value)+4))
		binary.LittleEndian.PutUint16(raw[2:], id)
		copy(raw[4:], value)
		body = append(body, raw...)
	}
	integer := func(v uint32) []byte { raw := make([]byte, 4); binary.LittleEndian.PutUint32(raw, v); return raw }
	attribute(15, integer(table))
	attribute(6, integer(100))
	if kind == "route" {
		p := netip.MustParsePrefix(destination)
		body[1] = byte(p.Bits())
		attribute(1, p.Addr().AsSlice())
		attribute(4, integer(index))
		if gateway != "" {
			attribute(5, netip.MustParseAddr(gateway).AsSlice())
		}
	}
	object, err := ParseDesktopLinuxNetworkObject(kind, body)
	if err != nil {
		panic(err)
	}
	return object
}

func networkTestReceipt(index uint32) DesktopNetworkReceipt {
	r := DesktopNetworkReceipt{Schema: 1, TargetOS: runtime.GOOS, Incarnation: strings.Repeat("a", 30) + string("0123456789abcdef"[index%16]) + "1", Name: "owned-test", Index: index, MTU: 1376, Addresses: []string{"10.0.0.2/24"}}
	if runtime.GOOS == "windows" {
		r.LUID = uint64(index) + 100
	}
	r.Objects = []DesktopNetworkObject{networkTestObject("route", index, 2022, "0.0.0.0/0", "")}
	if runtime.GOOS == "linux" {
		r.Objects = append(r.Objects, networkTestObject("rule", 0, 2022, "", ""))
	}
	SortDesktopNetworkObjects(r.Objects)
	return r
}

func networkTestPhysical() Snapshot {
	luid := uint64(0)
	if runtime.GOOS == "windows" {
		luid = 102
	}
	return Snapshot{Links: []Link{{Index: 2, LUID: luid, Name: "physical-test", MTU: 1500, Flags: 1, Hardware: "02:00:00:00:00:01"}}, Addresses: []Address{{Index: 2, LUID: luid, Prefix: "192.0.2.2/24"}}, Objects: []DesktopNetworkObject{networkTestObject("route", 2, 254, "0.0.0.0/0", "192.0.2.1")}}
}

func networkTestWith(snapshot Snapshot, r *DesktopNetworkReceipt) Snapshot {
	copy := Snapshot{Links: append([]Link(nil), snapshot.Links...), Addresses: append([]Address(nil), snapshot.Addresses...), Objects: append([]DesktopNetworkObject(nil), snapshot.Objects...)}
	if r == nil {
		return copy
	}
	copy.Links = append(copy.Links, Link{Index: r.Index, LUID: r.LUID, Name: r.Name, MTU: r.MTU, Flags: 1})
	for _, address := range r.Addresses {
		copy.Addresses = append(copy.Addresses, Address{Index: r.Index, LUID: r.LUID, Prefix: address})
	}
	copy.Objects = append(copy.Objects, r.Objects...)
	return copy
}

type networkFakeNative struct {
	mu                    sync.Mutex
	snapshot              Snapshot
	barrier               func()
	onClose               func()
	closeFailures, closes int
}

func (f *networkFakeNative) Snapshot(context.Context) (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return networkTestWith(f.snapshot, nil), nil
}
func (f *networkFakeNative) Barrier(context.Context) error {
	f.mu.Lock()
	callback := f.barrier
	f.barrier = nil
	f.mu.Unlock()
	if callback != nil {
		callback()
	}
	return nil
}
func (f *networkFakeNative) Close() error {
	f.mu.Lock()
	f.closes++
	if f.closeFailures > 0 {
		f.closeFailures--
		f.mu.Unlock()
		return errors.New("modeled native unregister failure")
	}
	callback := f.onClose
	f.onClose = nil
	f.mu.Unlock()
	if callback != nil {
		callback()
	}
	return nil
}
func (f *networkFakeNative) set(snapshot Snapshot) {
	f.mu.Lock()
	f.snapshot = networkTestWith(snapshot, nil)
	f.mu.Unlock()
}

func networkTestTracker(t *testing.T, original *DesktopNetworkReceipt) (*Tracker, *networkFakeNative) {
	t.Helper()
	native := &networkFakeNative{snapshot: networkTestWith(networkTestPhysical(), original)}
	owner := &Tracker{ctx: context.Background(), native: native, initializing: true, current: cloneReceipt(original)}
	if err := owner.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	return owner, native
}

func networkTestEvents(owner *Tracker, r DesktopNetworkReceipt, action string) {
	owner.observe(Event{Kind: "link", Action: action, Index: r.Index, LUID: r.LUID, Name: r.Name}, nil)
	for _, address := range r.Addresses {
		owner.observe(Event{Kind: "address", Action: action, Index: r.Index, LUID: r.LUID, Address: address}, nil)
	}
	for _, object := range r.Objects {
		owner.observe(Event{Kind: object.Kind, Action: action, Index: object.Index, LUID: object.LUID, Object: object}, nil)
	}
}

func TestNetworkCohortOwnedTransitionsAndTransient(t *testing.T) {
	ctx := context.Background()
	owner, native := networkTestTracker(t, nil)
	identity := owner.Identity()
	first, transient, final := networkTestReceipt(11), networkTestReceipt(12), networkTestReceipt(13)
	if err := owner.Begin(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := owner.Current(); err == nil {
		t.Fatal("measurement admitted an unclassified transition")
	}
	networkTestEvents(owner, first, "add")
	native.set(networkTestWith(networkTestPhysical(), &first))
	if err := owner.End(ctx, &first); err != nil {
		t.Fatal(err)
	}
	if err := owner.Current(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Begin(ctx, &first); err != nil {
		t.Fatal(err)
	}
	networkTestEvents(owner, first, "delete")
	networkTestEvents(owner, transient, "add")
	if err := owner.Record(transient); err != nil {
		t.Fatal(err)
	}
	networkTestEvents(owner, transient, "delete")
	networkTestEvents(owner, final, "add")
	native.set(networkTestWith(networkTestPhysical(), &final))
	if err := owner.End(ctx, &final); err != nil {
		t.Fatal(err)
	}
	if owner.Identity() != identity {
		t.Fatal("temporary paths rebased the physical cohort")
	}
	if err := owner.Begin(ctx, &final); err != nil {
		t.Fatal(err)
	}
	networkTestEvents(owner, final, "delete")
	native.set(networkTestPhysical())
	if err := owner.End(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := owner.Current(); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkCohortPhysicalAndUnclaimedChangesStayInvalid(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Tracker, *networkFakeNative, DesktopNetworkReceipt)
	}{
		{"gateway-away-and-back", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			route := networkTestPhysical().Objects[0]
			o.observe(Event{Kind: "route", Action: "delete", Index: route.Index, LUID: route.LUID, Object: route}, nil)
			o.observe(Event{Kind: "route", Action: "add", Index: route.Index, LUID: route.LUID, Object: route}, nil)
		}},
		{"physical-link-away-and-back", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			o.observe(Event{Kind: "link", Action: "change", Index: 2, Name: "physical-test"}, nil)
			o.observe(Event{Kind: "link", Action: "change", Index: 2, Name: "physical-test"}, nil)
		}},
		{"physical-address-away-and-back", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			o.observe(Event{Kind: "address", Action: "delete", Index: 2, Address: "192.0.2.2/24"}, nil)
			o.observe(Event{Kind: "address", Action: "add", Index: 2, Address: "192.0.2.2/24"}, nil)
		}},
		{"unclaimed-virtual-name", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			o.observe(Event{Kind: "link", Action: "add", Index: 99, Name: "utun-router-vpn"}, nil)
			o.observe(Event{Kind: "link", Action: "delete", Index: 99, Name: "utun-router-vpn"}, nil)
		}},
		{"same-index-wrong-name", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			o.observe(Event{Kind: "link", Action: "add", Index: r.Index, LUID: r.LUID, Name: "replacement"}, nil)
		}},
		{"unclaimed-address", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			o.observe(Event{Kind: "address", Action: "add", Index: r.Index, LUID: r.LUID, Address: "10.0.0.3/24"}, nil)
		}},
		{"same-interface-other-route", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			route := networkTestObject("route", r.Index, 2022, "198.51.100.0/24", "")
			o.observe(Event{Kind: "route", Action: "add", Index: r.Index, LUID: r.LUID, Object: route}, nil)
		}},
		{"native-event-loss", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			o.observe(Event{}, errors.New("native dropped message"))
		}},
		{"malformed-native-event", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) { o.observe(Event{}, nil) }},
		{"leftover-old-interface", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			snapshot := networkTestWith(networkTestPhysical(), &r)
			snapshot.Links = append(snapshot.Links, Link{Index: 99, Name: "leftover", MTU: 1376})
			n.set(snapshot)
		}},
		{"foreign-routing-leftover", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			snapshot := networkTestWith(networkTestPhysical(), &r)
			snapshot.Objects = append(snapshot.Objects, networkTestObject("route", r.Index, 2022, "198.51.100.0/24", ""))
			n.set(snapshot)
		}},
		{"barrier-observes-late-physical-event", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			n.mu.Lock()
			n.barrier = func() { o.observe(Event{Kind: "link", Action: "change", Index: 2}, nil) }
			n.mu.Unlock()
		}},
	}
	if runtime.GOOS == "linux" {
		cases = append(cases, struct {
			name   string
			mutate func(*Tracker, *networkFakeNative, DesktopNetworkReceipt)
		}{"same-priority-foreign-rule", func(o *Tracker, n *networkFakeNative, r DesktopNetworkReceipt) {
			rule := networkTestObject("rule", 0, 2023, "", "")
			o.observe(Event{Kind: "rule", Action: "add", Object: rule}, nil)
			o.observe(Event{Kind: "rule", Action: "delete", Object: rule}, nil)
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, n := networkTestTracker(t, nil)
			r := networkTestReceipt(11)
			if err := o.Begin(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			networkTestEvents(o, r, "add")
			n.set(networkTestWith(networkTestPhysical(), &r))
			tc.mutate(o, n, r)
			if err := o.End(context.Background(), &r); err == nil {
				t.Fatal("changed or unclaimed path acquired a comparison score")
			}
			n.set(networkTestPhysical())
			if err := o.Current(); err == nil {
				t.Fatal("restored snapshot cleared the invalidation latch")
			}
			if err := o.Begin(context.Background(), nil); err == nil {
				t.Fatal("new transition rebased a failed cohort")
			}
		})
	}
}

func TestNetworkCohortOriginalAndUnregisterOwnership(t *testing.T) {
	t.Run("wrong-original", func(t *testing.T) {
		r := networkTestReceipt(11)
		o, _ := networkTestTracker(t, &r)
		foreign := r
		foreign.Incarnation = strings.Repeat("b", 32)
		if err := o.Begin(context.Background(), &foreign); err == nil {
			t.Fatal("same named TUN replaced original native incarnation")
		}
	})
	t.Run("unclaimed-failed-start", func(t *testing.T) {
		o, _ := networkTestTracker(t, nil)
		r := networkTestReceipt(11)
		if err := o.Begin(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		networkTestEvents(o, r, "add")
		networkTestEvents(o, r, "delete")
		if err := o.End(context.Background(), nil); err == nil {
			t.Fatal("failed start's unproved temporary routes disappeared into the old snapshot")
		}
	})
	t.Run("close-retry", func(t *testing.T) {
		o, n := networkTestTracker(t, nil)
		n.closeFailures = 1
		if err := o.Close(); err == nil {
			t.Fatal("native unregister failure was dropped")
		}
		if err := o.Current(); err == nil {
			t.Fatal("failed cleanup kept score admission live")
		}
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		if n.closes != 2 {
			t.Fatal("cleanup retried or dropped another observer", n.closes)
		}
	})
	t.Run("late-callback-before-joined-close", func(t *testing.T) {
		o, n := networkTestTracker(t, nil)
		if err := o.Current(); err != nil {
			t.Fatal(err)
		}
		n.onClose = func() { o.observe(Event{Kind: "link", Action: "change", Index: 2}, nil) }
		if err := o.Close(); err == nil {
			t.Fatal("a delivered physical callback during unregister left the round valid")
		}
		if err := o.Current(); err == nil {
			t.Fatal("joined invalid observer regained score admission")
		}
		if err := o.Close(); err != nil || n.closes != 1 {
			t.Fatal("same-owner retry reopened or repeated joined callbacks", err, n.closes)
		}
	})
	t.Run("reported-latch-still-joins", func(t *testing.T) {
		o, n := networkTestTracker(t, nil)
		o.observe(Event{}, errors.New("native event continuity lost"))
		if err := o.Current(); err == nil {
			t.Fatal("lost event stream admitted scores")
		}
		if err := o.Close(); err != nil || n.closes != 1 {
			t.Fatal("already-reported failure prevented original observer cleanup", err)
		}
	})
	t.Run("snapshot-after-callback-loss", func(t *testing.T) {
		o, n := networkTestTracker(t, nil)
		snapshot := networkTestPhysical()
		snapshot.Objects[0] = networkTestObject("route", 2, 254, "0.0.0.0/0", "192.0.2.99")
		n.set(snapshot)
		if err := o.Current(); err == nil {
			t.Fatal("changed gateway was hidden by an unchanged interface inventory")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		o, _ := networkTestTracker(t, nil)
		ctx, cancel := context.WithCancel(context.Background())
		o.ctx = ctx
		cancel()
		if err := o.Current(); err == nil {
			t.Fatal("cancelled cohort stayed admissible")
		}
	})
}

func TestNetworkReceiptAndLinuxWireStrictIdentity(t *testing.T) {
	r := networkTestReceipt(11)
	raw, err := CanonicalDesktopNetworkReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseDesktopNetworkReceipt(raw)
	if err != nil || receiptKey(&decoded) != raw {
		t.Fatal("canonical receipt lost its captured object", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*DesktopNetworkReceipt)
	}{{"empty-incarnation", func(r *DesktopNetworkReceipt) { r.Incarnation = strings.Repeat("0", 32) }}, {"wrong-target", func(r *DesktopNetworkReceipt) { r.TargetOS = "android" }}, {"duplicate-address", func(r *DesktopNetworkReceipt) { r.Addresses = append(r.Addresses, r.Addresses[0]) }}, {"wildcard-address", func(r *DesktopNetworkReceipt) { r.Addresses = []string{"0.0.0.0/0"} }}, {"other-route-interface", func(r *DesktopNetworkReceipt) { r.Objects[0].Index = 99 }}, {"duplicate-route", func(r *DesktopNetworkReceipt) { r.Objects = append(r.Objects, r.Objects[0]) }}, {"unbounded-interface", func(r *DesktopNetworkReceipt) { r.Name = strings.Repeat("x", 65) }}} {
		t.Run(tc.name, func(t *testing.T) {
			copy := *cloneReceipt(&r)
			tc.mutate(&copy)
			if _, err := CanonicalDesktopNetworkReceipt(copy); err == nil {
				t.Fatal("invalid native identity admitted")
			}
		})
	}
	for _, raw := range []string{raw + " ", "{\"schema\":1," + raw[1:], raw[:len(raw)-1] + ",\"unknown\":true}", strings.Repeat("x", DesktopNetworkReceiptLimit+1)} {
		if _, err := ParseDesktopNetworkReceipt(raw); err == nil {
			t.Fatal("noncanonical or unbounded native receipt admitted")
		}
	}
	object := networkTestObject("route", 11, 2022, "0.0.0.0/0", "")
	if runtime.GOOS != "linux" {
		return
	}
	body, _ := base64.StdEncoding.DecodeString(object.Native)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{{"short", body[:11]}, {"duplicate-attribute", append(append([]byte(nil), body...), body[12:20]...)}, {"trailing-fragment", append(append([]byte(nil), body...), 1)}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDesktopLinuxNetworkObject("route", tc.raw); err == nil {
				t.Fatal("ambiguous rtnetlink object admitted")
			}
		})
	}
	unknown := append(append([]byte(nil), body...), 8, 0, 111, 0, 1, 2, 3, 4)
	changed, err := ParseDesktopLinuxNetworkObject("route", unknown)
	if err != nil || changed.Native == object.Native {
		t.Fatal("unknown native route attributes were discarded", err)
	}
	cache := append(append([]byte(nil), body...), 8, 0, 12, 0, 1, 2, 3, 4)
	stable, err := ParseDesktopLinuxNetworkObject("route", cache)
	if err != nil || stable != object {
		t.Fatal("volatile route-cache age changed a routing key", err)
	}
}

func TestNetworkReceiptMTUMatchesAddressFamily(t *testing.T) {
	r := networkTestReceipt(11)
	r.MTU = 576
	if _, err := CanonicalDesktopNetworkReceipt(r); err != nil {
		t.Fatal("valid IPv4-only native MTU gained a new IPv6 restriction", err)
	}
	r.Addresses = append(r.Addresses, "fd00::2/64")
	if _, err := CanonicalDesktopNetworkReceipt(r); err == nil {
		t.Fatal("IPv6 native receipt admitted an MTU below its family minimum")
	}
	r.MTU = 1280
	if _, err := CanonicalDesktopNetworkReceipt(r); err != nil {
		t.Fatal("valid dual-stack native MTU rejected", err)
	}
}

func TestLinuxRouteTableCompatibilityAndOwnedCarrierTransition(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux kernel route encoding and captured interface transition")
	}
	r := networkTestReceipt(11)
	object := networkTestObject("route", r.Index, 2022, "0.0.0.0/0", "")
	body, _ := base64.StdEncoding.DecodeString(object.Native)
	body[4] = 252 // RT_TABLE_COMPAT; full RTA_TABLE remains 2022.
	compatible, err := ParseDesktopLinuxNetworkObject("route", body)
	if err != nil || compatible.Table != 2022 || compatible.Native == object.Native {
		t.Fatal("high kernel table encoding lost its full native identity", err)
	}
	body[4] = 254
	if _, err := ParseDesktopLinuxNetworkObject("route", body); err == nil {
		t.Fatal("contradictory non-compat table IDs were accepted")
	}
	for _, tc := range []struct {
		name    string
		flags   uint32
		gateway string
		index   uint32
		want    bool
	}{{"owned-carrier-down", 16, "", r.Index, true}, {"other-route-flag", 4, "", r.Index, false}, {"carrier-plus-other-flag", 20, "", r.Index, false}, {"changed-gateway", 16, "192.0.2.99", r.Index, false}, {"other-interface", 16, "", 99, false}} {
		t.Run(tc.name, func(t *testing.T) {
			changed := networkTestObject("route", tc.index, 2022, "0.0.0.0/0", tc.gateway)
			raw, _ := base64.StdEncoding.DecodeString(changed.Native)
			binary.LittleEndian.PutUint32(raw[8:12], tc.flags)
			changed, err = ParseDesktopLinuxNetworkObject("route", raw)
			if err != nil {
				t.Fatal(err)
			}
			event := Event{Kind: "route", Action: "add", Index: changed.Index, Object: changed}
			if got := eventOwnedBy(event, &r); got != tc.want {
				t.Fatal("owned transition did not retain exact native route bytes", got, tc.want)
			}
			if eventMatchesObject(event, object) {
				t.Fatal("transition exception weakened snapshot/physical route identity")
			}
		})
	}
}

func TestDarwinCloneRequiresExactCapturedParent(t *testing.T) {
	parent := DesktopNetworkObject{Kind: "route", Family: 4, Index: 2, Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Flags: 0x2 | 0x800 | 0x10000}
	clone := DesktopNetworkObject{Kind: "route", Family: 4, Index: 2, Destination: "198.51.100.5/32", Gateway: "192.0.2.1", Flags: 0x2 | 0x4 | 0x20000}
	if derived, err := DesktopDarwinDerivedRoute(clone, []DesktopNetworkObject{parent}); !derived || err != nil {
		t.Fatal("exact native parent was not recognized", err)
	}
	for _, tc := range []struct {
		name    string
		object  DesktopNetworkObject
		parents []DesktopNetworkObject
	}{{"missing-parent", clone, nil}, {"ambiguous-parent", clone, []DesktopNetworkObject{parent, parent}}, {"changed-gateway", func() DesktopNetworkObject { c := clone; c.Gateway = "192.0.2.99"; return c }(), []DesktopNetworkObject{parent}}, {"redirect", func() DesktopNetworkObject { c := clone; c.Flags |= 0x10; return c }(), []DesktopNetworkObject{parent}}, {"static", func() DesktopNetworkObject { c := clone; c.Flags |= 0x800; return c }(), []DesktopNetworkObject{parent}}, {"unmatched-prefix", clone, []DesktopNetworkObject{func() DesktopNetworkObject { p := parent; p.Destination = "203.0.113.0/24"; return p }()}}, {"other-interface", func() DesktopNetworkObject { c := clone; c.Index = 3; return c }(), []DesktopNetworkObject{parent}}, {"other-scope", func() DesktopNetworkObject { c := clone; c.Flags |= 0x1000000; return c }(), []DesktopNetworkObject{parent}}} {
		t.Run(tc.name, func(t *testing.T) {
			if derived, err := DesktopDarwinDerivedRoute(tc.object, tc.parents); derived || err == nil {
				t.Fatal("unproved route cache bypassed cohort invalidation")
			}
		})
	}
}
