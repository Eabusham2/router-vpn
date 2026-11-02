package desktopnetwork

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"testing"
)

func multicastFIBTestBody(family byte) []byte {
	// Linux fib_nl_fill_rule: complete default multicast FIB rule with its
	// own table/priority and opaque attributes, not an owned TUN rule.
	body := []byte{family, 0, 0, 0, 253, 0, 0, 1, 0, 0, 0, 0}
	for _, a := range []struct {
		id    uint16
		value uint32
	}{{15, 253}, {14, ^uint32(0)}, {6, 32767}} {
		v := make([]byte, 8)
		binary.LittleEndian.PutUint16(v, 8)
		binary.LittleEndian.PutUint16(v[2:], a.id)
		binary.LittleEndian.PutUint32(v[4:], a.value)
		body = append(body, v...)
	}
	return body
}

func TestLinuxMulticastFIBIdentityRemainsAmbient(t *testing.T) {
	for _, family := range []byte{128, 129} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			body := multicastFIBTestBody(family)
			object, err := ParseDesktopLinuxNetworkObject("rule", body)
			if err != nil || object.Family != int(family) || object.Validate("linux") != nil {
				t.Fatal("multicast FIB identity was rejected or normalized", err, object.Family)
			}
			encoded, _ := base64.StdEncoding.DecodeString(object.Native)
			if encoded[0] != family {
				t.Fatal("lost exact native family")
			}
			unicast := append([]byte(nil), body...)
			unicast[0] = 2
			if family == 129 {
				unicast[0] = 10
			}
			other, err := ParseDesktopLinuxNetworkObject("rule", unicast)
			if err != nil || object.Key() == other.Key() {
				t.Fatal("multicast and unicast FIBs collided", err)
			}
			if object.Validate("windows") == nil || object.Validate("darwin") == nil {
				t.Fatal("Linux multicast identity escaped its native family")
			}
			if runtime.GOOS != "linux" {
				return
			}
			r := networkTestReceipt(11)
			r.Objects = append(r.Objects, object)
			SortDesktopNetworkObjects(r.Objects)
			if r.Validate() == nil {
				t.Fatal("ambient multicast rule became owned TUN policy")
			}
			physical := networkTestPhysical()
			physical.Objects = append(physical.Objects, object)
			native := &networkFakeNative{snapshot: physical}
			owner := &Tracker{ctx: context.Background(), native: native, initializing: true}
			if err := owner.initialize(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(owner.physical.Objects) != len(physical.Objects) {
				t.Fatal("ambient FIB omitted from frozen physical identity")
			}
			if err := owner.Begin(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			owner.observe(Event{Kind: "rule", Action: "delete", Object: object}, nil)
			owner.observe(Event{Kind: "rule", Action: "add", Object: object}, nil)
			if err := owner.End(context.Background(), nil); err == nil {
				t.Fatal("multicast away-and-back did not invalidate the cohort")
			}
			if err := owner.Current(); err == nil {
				t.Fatal("ambient multicast mutation became current again")
			}
			_ = owner.Close()
		})
	}
	for _, family := range []byte{0, 1, 3, 127, 130, 255} {
		if _, err := ParseDesktopLinuxNetworkObject("rule", multicastFIBTestBody(family)); err == nil {
			t.Fatal("unknown native routing family was admitted", family)
		}
	}
	for _, family := range []byte{128, 129} {
		body := multicastFIBTestBody(family)
		body[1] = 129
		if _, err := ParseDesktopLinuxNetworkObject("rule", body); err == nil {
			t.Fatal("invalid multicast prefix length admitted")
		}
		body = multicastFIBTestBody(family)
		body = append(body, body[12:20]...)
		if _, err := ParseDesktopLinuxNetworkObject("rule", body); err == nil {
			t.Fatal("ambiguous multicast attribute admitted")
		}
	}
}

func TestWindowsUnlimitedLoopbackMTURetainsNativeIdentity(t *testing.T) {
	original := Link{Index: 1, LUID: 1001, Name: "captured-loopback", MTU: -1, Flags: uint32(net.FlagLoopback | net.FlagUp), Policy: "2:50:4294967295:1:0;23:50:4294967295:1:0;"}
	rows := []desktopWindowsIPInterfaceShape{{2, 1, 1001, ^uint32(0)}, {23, 1, 1001, ^uint32(0)}}
	for _, input := range [][]desktopWindowsIPInterfaceShape{rows, rows[:1], {rows[1], rows[0]}} {
		actual, err := desktopWindowsLinkMTU(original, input)
		want := original
		want.MTU = 4294967295
		if err != nil || actual != want {
			t.Fatal("exact unlimited loopback sentinel lost identity", actual, err)
		}
		projected, identity, err := project(Snapshot{Links: []Link{actual}}, nil)
		if err != nil || identity == "" || len(projected.Links) != 1 || projected.Links[0] != actual {
			t.Fatal("unlimited loopback omitted from physical cohort", err)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*Link, *[]desktopWindowsIPInterfaceShape)
	}{
		{"zero-mtu", func(l *Link, _ *[]desktopWindowsIPInterfaceShape) { l.MTU = 0 }},
		{"other-negative", func(l *Link, _ *[]desktopWindowsIPInterfaceShape) { l.MTU = -2 }},
		{"not-loopback", func(l *Link, _ *[]desktopWindowsIPInterfaceShape) { l.Flags = uint32(net.FlagUp) }},
		{"zero-index", func(l *Link, _ *[]desktopWindowsIPInterfaceShape) { l.Index = 0 }},
		{"zero-luid", func(l *Link, _ *[]desktopWindowsIPInterfaceShape) { l.LUID = 0 }},
		{"missing-rows", func(_ *Link, r *[]desktopWindowsIPInterfaceShape) { *r = nil }},
		{"foreign-index", func(_ *Link, r *[]desktopWindowsIPInterfaceShape) { (*r)[0].Index++ }},
		{"foreign-luid", func(_ *Link, r *[]desktopWindowsIPInterfaceShape) { (*r)[0].LUID++ }},
		{"family-mismatch", func(_ *Link, r *[]desktopWindowsIPInterfaceShape) { (*r)[0].Family = 10 }},
		{"duplicate-family", func(_ *Link, r *[]desktopWindowsIPInterfaceShape) { (*r)[1].Family = 2 }},
		{"different-native-mtu", func(_ *Link, r *[]desktopWindowsIPInterfaceShape) { (*r)[1].MTU = 65536 }},
		{"zero-native-mtu", func(_ *Link, r *[]desktopWindowsIPInterfaceShape) { (*r)[0].MTU = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, r := original, append([]desktopWindowsIPInterfaceShape(nil), rows...)
			tc.change(&l, &r)
			if _, err := desktopWindowsLinkMTU(l, r); err == nil {
				t.Fatal("unproved unlimited sentinel accepted")
			}
		})
	}
	ordinary := original
	ordinary.MTU = 1500
	if actual, err := desktopWindowsLinkMTU(ordinary, nil); err != nil || actual != ordinary {
		t.Fatal("ordinary positive MTU changed", err)
	}
	r := networkTestReceipt(11)
	r.MTU = 4294967295
	if r.Validate() == nil {
		t.Fatal("ambient unlimited sentinel relaxed the native TUN MTU contract")
	}
}

func linuxGotoShape(t *testing.T, family byte, priority, target uint32, flags uint32, action byte) DesktopNetworkObject {
	t.Helper()
	body := []byte{family, 0, 0, 0, 0, 0, 0, action, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(body[8:], flags)
	attrs := []struct {
		id    uint16
		value uint32
	}{{6, priority}, {15, 0}, {14, ^uint32(0)}}
	if target != 0 {
		attrs = append(attrs, struct {
			id    uint16
			value uint32
		}{4, target})
	}
	for _, a := range attrs {
		v := make([]byte, 8)
		binary.LittleEndian.PutUint16(v, 8)
		binary.LittleEndian.PutUint16(v[2:], a.id)
		binary.LittleEndian.PutUint32(v[4:], a.value)
		body = append(body, v...)
	}
	o, err := ParseDesktopLinuxNetworkObject("rule", body)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestLinuxOwnedGotoRuleTransitions(t *testing.T) {
	for _, family := range []byte{2, 10} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			before := linuxGotoShape(t, family, 9001, 9010, 4, 2)
			after := linuxGotoShape(t, family, 9001, 9010, 0, 2)
			target := linuxGotoShape(t, family, 9010, 0, 0, 3)
			if !DesktopLinuxRuleResolvedBy(before, after, target) {
				t.Fatal("exact owned GOTO resolution was rejected")
			}
			for _, tc := range []struct {
				name         string
				old, now, to DesktopNetworkObject
			}{
				{"wrong-target", before, after, linuxGotoShape(t, family, 9011, 0, 0, 3)},
				{"wrong-family", before, after, linuxGotoShape(t, byte(12-family), 9010, 0, 0, 3)},
				{"wrong-action", before, after, linuxGotoShape(t, family, 9010, 0, 0, 1)},
				{"extra-flags", before, linuxGotoShape(t, family, 9001, 9010, 2, 2), target},
				{"changed-priority", before, linuxGotoShape(t, family, 9002, 9010, 0, 2), target},
				{"changed-target", before, linuxGotoShape(t, family, 9001, 9011, 0, 2), target},
				{"already-resolved", after, after, target},
				{"unresolved-final", before, before, target},
				{"malformed-native", func() DesktopNetworkObject { v := before; v.Native = "broken"; return v }(), after, target},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if DesktopLinuxRuleResolvedBy(tc.old, tc.now, tc.to) {
						t.Fatal("unrelated rule mutation admitted")
					}
				})
			}
			if runtime.GOOS != "linux" {
				return
			}
			r := networkTestReceipt(11)
			r.Objects = append(r.Objects, after, target)
			SortDesktopNetworkObjects(r.Objects)
			for _, retireFirst := range []bool{false, true} {
				name := "startup-before-target"
				if retireFirst {
					name = "target-first-retirement"
				}
				t.Run(name, func(t *testing.T) {
					var original *DesktopNetworkReceipt
					if retireFirst {
						original = &r
					}
					owner, native := networkTestTracker(t, original)
					if err := owner.Begin(context.Background(), original); err != nil {
						t.Fatal(err)
					}
					action := "add"
					if retireFirst {
						action = "delete"
						owner.observe(Event{Kind: "rule", Action: action, Object: target}, nil)
					}
					owner.observe(Event{Kind: "rule", Action: action, Object: before}, nil)
					networkTestEvents(owner, r, action)
					var final *DesktopNetworkReceipt
					if !retireFirst {
						final = &r
					}
					native.set(networkTestWith(networkTestPhysical(), final))
					if err := owner.End(context.Background(), final); err != nil {
						t.Fatal("bounded exact GOTO lifecycle event rejected", err)
					}
					if err := owner.Current(); err != nil {
						t.Fatal(err)
					}
					// The same event outside its captured transition is a real
					// policy change, never a globally masked flags difference.
					owner.observe(Event{Kind: "rule", Action: "change", Object: before}, nil)
					if owner.Current() == nil {
						t.Fatal("GOTO flags ignored outside owned transition")
					}
				})
			}
			missing := *cloneReceipt(&r)
			missing.Objects = nil
			if eventOwnedBy(Event{Kind: "rule", Object: before}, &missing) {
				t.Fatal("uncaptured target authorized GOTO event")
			}
			unproved := *cloneReceipt(&r)
			for i, o := range unproved.Objects {
				if o == target {
					unproved.Objects = append(unproved.Objects[:i], unproved.Objects[i+1:]...)
					break
				}
			}
			if eventOwnedBy(Event{Kind: "rule", Object: before}, &unproved) {
				t.Fatal("missing same-owner NOP authorized GOTO event")
			}
		})
	}
}
