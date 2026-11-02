package desktopnetwork

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

func darwinUnusedTestReadback(link Link) desktopDarwinInterfaceReadback {
	return desktopDarwinInterfaceReadback{Bytes: 132, Records: 1,
		Shapes:     []desktopDarwinInterfaceShape{{Index: link.Index, Type: 1}},
		identities: []desktopDarwinInterfaceIdentity{{Index: link.Index, Name: link.Name, Type: 1}}}
}

func darwinUnusedTestLink(t *testing.T) Link {
	t.Helper()
	link := Link{Index: 31, Name: "captured-unused", MTU: 0}
	actual, err := desktopDarwinCaptureUnusedInterface(link, func(uint32) (desktopDarwinInterfaceReadback, error) {
		return darwinUnusedTestReadback(link), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return actual
}

func darwinUnusedTestPayload(index uint16, name string, kind byte, hardware []byte) []byte {
	length := 8 + len(name) + len(hardware)
	raw := make([]byte, (length+3)&^3)
	raw[0], raw[1], raw[4], raw[5], raw[6] = byte(length), 18, kind, byte(len(name)), byte(len(hardware))
	binary.LittleEndian.PutUint16(raw[2:4], index)
	copy(raw[8:], name)
	copy(raw[8+len(name):], hardware)
	return raw
}

func TestDarwinInterfaceLinkIdentityWireBoundsAndOwnership(t *testing.T) {
	for _, hardware := range [][]byte{nil, {2, 0, 0, 0, 0, 1}} {
		raw := darwinUnusedTestPayload(31, "captured-unused", 1, hardware)
		identity, ok := desktopDarwinInterfaceLinkIdentity(0x10, raw)
		want := desktopDarwinInterfaceIdentity{Index: 31, Name: "captured-unused", Type: 1, Hardware: net.HardwareAddr(hardware).String()}
		if !ok || identity != want {
			t.Fatal("Darwin AF_LINK lost its complete copied identity", identity, ok)
		}
		clear(raw)
		if identity != want {
			t.Fatal("Darwin AF_LINK retained borrowed identity bytes")
		}
	}
	for _, test := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"truncated-header", func(v []byte) []byte { return v[:7] }},
		{"truncated-name", func(v []byte) []byte { return v[:12] }},
		{"extra-payload", func(v []byte) []byte { return append(v, 0, 0, 0, 0) }},
		{"wrong-family", func(v []byte) []byte { v[1] = 2; return v }},
		{"empty-name", func(v []byte) []byte { v[5] = 0; return v }},
		{"unbounded-name", func(v []byte) []byte { v[5] = 255; return v }},
		{"truncated-hardware", func(v []byte) []byte { v[6] = 255; return v }},
		{"unrecognized-selector", func(v []byte) []byte { v[7] = 1; return v }},
		{"invalid-native-length", func(v []byte) []byte { v[0] = 7; return v }},
		{"private-control-name", func(v []byte) []byte { v[8] = 0; return v }},
		{"invalid-utf8-name", func(v []byte) []byte { v[8] = 0xfe; return v }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := desktopDarwinInterfaceLinkIdentity(0x10, test.edit(darwinUnusedTestPayload(31, "captured-unused", 1, nil))); ok {
				t.Fatal("incomplete native AF_LINK became interface identity")
			}
		})
	}
	for _, mask := range []uint32{0, 1, 0x11, ^uint32(0)} {
		if _, ok := desktopDarwinInterfaceLinkIdentity(mask, darwinUnusedTestPayload(31, "captured-unused", 1, nil)); ok {
			t.Fatal("another native address layout became an AF_LINK identity")
		}
	}
}

func TestDarwinUnusedInterfaceCaptureRequiresCompleteNativeIdentity(t *testing.T) {
	original := Link{Index: 31, Name: "captured-unused", MTU: 0}
	for _, test := range []struct {
		name string
		edit func(*Link, *desktopDarwinInterfaceReadback)
	}{
		{"empty-name", func(l *Link, _ *desktopDarwinInterfaceReadback) { l.Name = "" }},
		{"lossy-name-identity", func(l *Link, r *desktopDarwinInterfaceReadback) {
			l.Name += string([]byte{0xfe})
			r.identities[0].Name = l.Name
		}},
		{"windows-identity", func(l *Link, _ *desktopDarwinInterfaceReadback) { l.LUID = 12 }},
		{"negative-mtu", func(l *Link, _ *desktopDarwinInterfaceReadback) { l.MTU = -1 }},
		{"changed-mtu", func(l *Link, _ *desktopDarwinInterfaceReadback) { l.MTU = 1500 }},
		{"active-link", func(l *Link, _ *desktopDarwinInterfaceReadback) { l.Flags = uint32(net.FlagUp) }},
		{"running-link", func(l *Link, _ *desktopDarwinInterfaceReadback) { l.Flags = uint32(net.FlagRunning) }},
		{"hardware-present", func(l *Link, _ *desktopDarwinInterfaceReadback) { l.Hardware = "02:00:00:00:00:01" }},
		{"foreign-policy", func(l *Link, _ *desktopDarwinInterfaceReadback) { l.Policy = "saved" }},
		{"empty-read", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Bytes = 0 }},
		{"oversized-read", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Bytes = 64<<10 + 1 }},
		{"missing-record", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Records = 0 }},
		{"extra-record", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Records = 2 }},
		{"native-address", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Addresses = 1 }},
		{"missing-shape", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Shapes = nil }},
		{"duplicate-shape", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Shapes = append(r.Shapes, r.Shapes[0]) }},
		{"replacement-index", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Shapes[0].Index++ }},
		{"positive-native-mtu", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Shapes[0].MTU = 1500 }},
		{"active-native-flag", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Shapes[0].Flags = 1 }},
		{"unmapped-native-flag", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Shapes[0].Flags = 0x100 }},
		{"native-hardware-length", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.Shapes[0].AddressLength = 6 }},
		{"diagnostic-only-shape", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.identities = nil }},
		{"duplicate-identity", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.identities = append(r.identities, r.identities[0]) }},
		{"wrong-link-index", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.identities[0].Index++ }},
		{"wrong-link-name", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.identities[0].Name = "replacement" }},
		{"wrong-link-hardware", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.identities[0].Hardware = "02:00:00:00:00:02" }},
		{"wrong-link-type", func(_ *Link, r *desktopDarwinInterfaceReadback) { r.identities[0].Type++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, observed := original, darwinUnusedTestReadback(original)
			test.edit(&link, &observed)
			before, calls := link, 0
			_, err := desktopDarwinCaptureUnusedInterface(link, func(index uint32) (desktopDarwinInterfaceReadback, error) {
				calls++
				if index != original.Index {
					t.Fatal("native read escaped the original captured index")
				}
				return observed, nil
			})
			if err == nil || calls != 1 || link != before || strings.Contains(err.Error(), original.Name) {
				t.Fatal("incomplete or changed native link was retained or leaked private identity", err, calls)
			}
		})
	}
	for _, index := range []uint32{0, 65536} {
		link := original
		link.Index = index
		if _, err := desktopDarwinCaptureUnusedInterface(link, func(uint32) (desktopDarwinInterfaceReadback, error) {
			t.Fatal("invalid interface index broadened the native query")
			return desktopDarwinInterfaceReadback{}, nil
		}); err == nil {
			t.Fatal("invalid interface index acquired native identity")
		}
	}
	for _, failure := range []error{context.Canceled, errors.New("private native path")} {
		if _, err := desktopDarwinCaptureUnusedInterface(original, func(uint32) (desktopDarwinInterfaceReadback, error) {
			return darwinUnusedTestReadback(original), failure
		}); err == nil || strings.Contains(err.Error(), "private native") {
			t.Fatal("failed native read became a usable link or leaked host data", err)
		}
	}
}

func TestDarwinUnusedInterfaceRetainsExactCohortIdentity(t *testing.T) {
	link := darwinUnusedTestLink(t)
	base := networkTestPhysical()
	base.Links = append(base.Links, link)
	t.Run("retained-original", func(t *testing.T) {
		physical, key, err := project(base, nil)
		if err != nil || len(physical.Links) != len(base.Links) || physical.Links[1] != link ||
			link.MTU != 0 || !strings.Contains(key, `"mtu":0`) || !strings.Contains(key, link.Name) || !strings.Contains(key, link.Policy) {
			t.Fatal("unused interface disappeared from its exact physical cohort", err)
		}
		var replay Snapshot
		if err := json.Unmarshal([]byte(key), &replay); err != nil {
			t.Fatal(err)
		}
		if _, _, err := project(replay, nil); err == nil {
			t.Fatal("serialized inactive metadata recreated private native observation")
		}
	})
	for _, test := range []struct {
		name string
		edit func(*Link)
	}{
		{"index", func(l *Link) { l.Index++ }},
		{"name", func(l *Link) { l.Name = "replacement" }},
		{"mtu", func(l *Link) { l.MTU = 1500 }},
		{"flags", func(l *Link) { l.Flags = 1 }},
		{"hardware", func(l *Link) { l.Hardware = "02:00:00:00:00:01" }},
		{"policy", func(l *Link) { l.Policy += ":changed" }},
		{"luid", func(l *Link) { l.LUID = 31 }},
		{"missing-native-capture", func(l *Link) { l.darwinUnused = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := networkTestWith(base, nil)
			test.edit(&changed.Links[1])
			if _, _, err := project(changed, nil); err == nil {
				t.Fatal("changed interface reused the original unused-link capture")
			}
		})
	}
}

func TestDarwinUnusedInterfaceCannotOwnOrCarryTraffic(t *testing.T) {
	link := darwinUnusedTestLink(t)
	base := networkTestPhysical()
	base.Links = append(base.Links, link)
	for _, test := range []struct {
		name string
		edit func(*Snapshot)
	}{
		{"ipv4-address", func(s *Snapshot) {
			s.Addresses = append(s.Addresses, Address{Index: link.Index, Prefix: "192.0.2.9/24"})
		}},
		{"ipv6-address", func(s *Snapshot) {
			s.Addresses = append(s.Addresses, Address{Index: link.Index, Prefix: "2001:db8::9/64"})
		}},
		{"route", func(s *Snapshot) {
			s.Objects = append(s.Objects, networkTestObject("route", link.Index, 254, "198.51.100.0/24", ""))
		}},
		{"cloned-route", func(s *Snapshot) {
			s.Objects = append(s.Objects, DesktopNetworkObject{Kind: "route", Index: link.Index, Family: 4, Destination: "198.51.100.9/32", Flags: 0x20004})
		}},
		{"duplicate-index", func(s *Snapshot) { s.Links = append(s.Links, Link{Index: link.Index, Name: "replacement", MTU: 1500}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := networkTestWith(base, nil)
			test.edit(&changed)
			if _, _, err := project(changed, nil); err == nil {
				t.Fatal("unused interface carried traffic or lost unique identity")
			}
		})
	}
	receipt := networkTestReceipt(link.Index)
	receipt.Name, receipt.LUID, receipt.MTU = link.Name, link.LUID, link.MTU
	if receipt.Validate() == nil {
		t.Fatal("unused interface became an owned native TUN")
	}
	if _, _, err := project(base, &receipt); err == nil {
		t.Fatal("unused interface was removed as an owned native receipt")
	}
}

func TestDarwinUnusedInterfaceChangesStayLatched(t *testing.T) {
	link := darwinUnusedTestLink(t)
	base := networkTestPhysical()
	base.Links = append(base.Links, link)
	newTracker := func(t *testing.T) (*Tracker, *networkFakeNative) {
		t.Helper()
		native := &networkFakeNative{snapshot: networkTestWith(base, nil)}
		owner := &Tracker{ctx: context.Background(), native: native, initializing: true}
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
	for _, kind := range []string{"link", "address", "route"} {
		t.Run(kind+"-away-and-back", func(t *testing.T) {
			owner, native := newTracker(t)
			if err := owner.Begin(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			owner.observe(Event{Kind: kind, Action: "change", Index: link.Index}, nil)
			native.set(base)
			if err := owner.End(context.Background(), nil); err == nil {
				t.Fatal("restored unused-link snapshot hid a transient native event")
			}
			if err := owner.Current(); err == nil {
				t.Fatal("unused-link event lost its invalidation latch")
			}
		})
	}
	for _, field := range []string{"index", "name", "type", "physical", "active-mtu", "removed"} {
		t.Run("snapshot-"+field, func(t *testing.T) {
			owner, native := newTracker(t)
			changed := networkTestWith(base, nil)
			original := Link{Index: link.Index, Name: link.Name, MTU: 0}
			readback := darwinUnusedTestReadback(original)
			switch field {
			case "index":
				original.Index++
				readback.Shapes[0].Index, readback.identities[0].Index = original.Index, original.Index
			case "name":
				original.Name = "replacement"
				readback.identities[0].Name = original.Name
			case "type":
				readback.Shapes[0].Type, readback.identities[0].Type = 6, 6
			case "physical":
				readback.Shapes[0].Physical = 8
			case "active-mtu":
				original.MTU, original.Flags = 1500, uint32(net.FlagUp)
			case "removed":
				changed.Links = changed.Links[:1]
			}
			if field != "removed" {
				if original.MTU == 0 {
					var err error
					original, err = desktopDarwinCaptureUnusedInterface(original, func(uint32) (desktopDarwinInterfaceReadback, error) { return readback, nil })
					if err != nil {
						t.Fatal("new complete native observation was not representable", err)
					}
				}
				changed.Links[1] = original
			}
			native.set(changed)
			if err := owner.Current(); err == nil {
				t.Fatal("replacement native observation retained the old cohort identity")
			}
			native.set(base)
			if err := owner.Current(); err == nil {
				t.Fatal("restored native observation cleared the captured failure")
			}
		})
	}
	if !reflect.DeepEqual(base.Links[1], link) {
		t.Fatal("changing observations mutated the original cohort")
	}
}
