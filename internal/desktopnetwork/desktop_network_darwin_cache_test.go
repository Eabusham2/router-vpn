package desktopnetwork

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func darwinIdleCacheFixture(family int) (DesktopNetworkObject, DesktopNetworkObject) {
	parent, child := darwinCloneScopeFixture(family)
	parent.MTU, child.MTU = 1500, 1500
	child.Flags |= 0x40000
	child = desktopDarwinCaptureCacheObservation(child, child.Flags|1, parent.Flags|1, 0, 1700000000)
	return parent, child
}

func TestDarwinIdleCacheRequiresOriginalNativeProof(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			parent, child := darwinIdleCacheFixture(family)
			original, originalParent := child, parent
			if derived, err := DesktopDarwinDerivedRoute(child, []DesktopNetworkObject{parent}); !derived || err != nil {
				t.Fatal("original native idle cache was not classified", err)
			}
			if child != original || parent != originalParent {
				t.Fatal("native cache classification rewrote its original objects")
			}
			plain := child
			plain.darwinCache = nil
			if child.Key() != plain.Key() {
				t.Fatal("live reference/expiry evidence changed a stable routing key")
			}
			encoded, err := json.Marshal(child)
			if err != nil || strings.Contains(string(encoded), "references") || strings.Contains(string(encoded), "expires") || strings.Contains(string(encoded), "darwinCache") {
				t.Fatal("private kernel proof escaped into JSON", err)
			}
			var decoded DesktopNetworkObject
			if json.Unmarshal(encoded, &decoded) != nil || decoded.darwinCache != nil || decoded != plain {
				t.Fatal("JSON changed the original public identity")
			}
			if derived, err := DesktopDarwinDerivedRoute(decoded, []DesktopNetworkObject{parent}); derived || err == nil {
				t.Fatal("decoded JSON manufactured native idle-cache proof", err)
			}
			// Counts/expiry are not immutable policy. A later original observation has
			// the same key but still has to independently meet the native idle shape.
			later := desktopDarwinCaptureCacheObservation(plain, plain.Flags|1, parent.Flags|1, 0, 1800000000)
			if later.Key() != child.Key() || later == child {
				t.Fatal("native observations shared authority or changed stable keys")
			}
			if derived, err := DesktopDarwinDerivedRoute(later, []DesktopNetworkObject{parent}); !derived || err != nil {
				t.Fatal(err)
			}
		})
	}
	parent, child := darwinIdleCacheFixture(4)
	_ = parent
	receipt := DesktopNetworkReceipt{Schema: 1, TargetOS: "darwin", Incarnation: strings.Repeat("1", 32), Name: "fixture", Index: child.Index, MTU: 1500, Addresses: []string{"192.0.2.2/24"}, Objects: []DesktopNetworkObject{child}}
	if receipt.Validate() == nil {
		t.Fatal("ambient cache observation became an owned connection receipt")
	}
	for _, property := range []string{"darwinCache", "darwin_cache", "references", "expires", "parentFlags"} {
		encoded, _ := json.Marshal(child)
		var body map[string]any
		_ = json.Unmarshal(encoded, &body)
		body[property] = map[string]any{"references": 0, "expires": 1700000000}
		forged, _ := json.Marshal(body)
		var object DesktopNetworkObject
		_ = json.Unmarshal(forged, &object)
		if object.darwinCache != nil {
			t.Fatal("unexported proof field was populated by JSON", property)
		}
		if derived, _ := DesktopDarwinDerivedRoute(object, []DesktopNetworkObject{parent}); derived {
			t.Fatal("forged JSON manufactured native cache proof", property)
		}
	}
}

func TestDarwinIdleCacheRefusesForgedOrChangedOriginal(t *testing.T) {
	parent, original := darwinIdleCacheFixture(4)
	changes := map[string]func(*DesktopNetworkObject){
		"destination":           func(o *DesktopNetworkObject) { o.Destination = "198.51.100.99/32" },
		"gateway":               func(o *DesktopNetworkObject) { o.Gateway = "192.0.2.99" },
		"interface":             func(o *DesktopNetworkObject) { o.Index++ },
		"flags":                 func(o *DesktopNetworkObject) { o.Flags |= 0x4000 },
		"mtu":                   func(o *DesktopNetworkObject) { o.MTU++ },
		"priority":              func(o *DesktopNetworkObject) { o.Priority++ },
		"family":                func(o *DesktopNetworkObject) { o.Family = 6 },
		"kind":                  func(o *DesktopNetworkObject) { o.Kind = "rule" },
		"luid":                  func(o *DesktopNetworkObject) { o.LUID = 1 },
		"table":                 func(o *DesktopNetworkObject) { o.Table = 254 },
		"native":                func(o *DesktopNetworkObject) { o.Native = "foreign" },
		"missing-private-proof": func(o *DesktopNetworkObject) { o.darwinCache = nil },
		"copied-cross-object-proof": func(o *DesktopNetworkObject) {
			other := *o
			other.Destination = "198.51.100.100/32"
			other.darwinCache = nil
			other = desktopDarwinCaptureCacheObservation(other, other.Flags|1, parent.Flags|1, 0, 1700000000)
			o.darwinCache = other.darwinCache
		},
		"recursive-private-original": func(o *DesktopNetworkObject) { proof := *o.darwinCache; proof.original = *o; o.darwinCache = &proof },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			child := original
			change(&child)
			if derived, _ := DesktopDarwinDerivedRoute(child, []DesktopNetworkObject{parent}); derived {
				t.Fatal("foreign object borrowed original native cache evidence")
			}
		})
	}
	for _, target := range []string{"linux", "windows"} {
		if original.Validate(target) == nil {
			t.Fatal("native Darwin cache proof crossed platforms", target)
		}
	}
}

func TestDarwinIdleCacheParentAndLifetimeConstraints(t *testing.T) {
	parent, original := darwinIdleCacheFixture(4)
	for _, tc := range []struct {
		name                   string
		refs, expires          int32
		add, remove, parentXOR uint32
	}{
		{"live-reference", 1, 1700000000, 0, 0, 0}, {"invalid-reference", -1, 1700000000, 0, 0, 0},
		{"absent-expiry", 0, 0, 0, 0, 0}, {"invalid-expiry", 0, -1, 0, 0, 0},
		{"down", 0, 1700000000, 0, 1, 0}, {"message-done", 0, 1700000000, 0x40, 0, 0},
		{"interface-reference", 0, 1700000000, 0x4000000, 0, 0}, {"delete-clone", 0, 1700000000, 0x80, 0, 0},
		{"link-layer", 0, 1700000000, 0x400, 0, 0}, {"static", 0, 1700000000, 0x800, 0, 0},
		{"redirect", 0, 1700000000, 0x10, 0, 0}, {"modified", 0, 1700000000, 0x20, 0, 0},
		{"reject", 0, 1700000000, 0x8, 0, 0}, {"blackhole", 0, 1700000000, 0x1000, 0, 0},
		{"proxy", 0, 1700000000, 0x8000000, 0, 0}, {"condemned", 0, 1700000000, 0x2000000, 0, 0}, {"dead", 0, 1700000000, 0x20000000, 0, 0},
		{"different-parent", 0, 1700000000, 0, 0, 0x4000}, {"down-parent", 0, 1700000000, 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := original
			child.darwinCache = nil
			raw := (child.Flags | 1 | tc.add) &^ tc.remove
			child.Flags = raw &^ uint32(1|0x40)
			child = desktopDarwinCaptureCacheObservation(child, raw, (parent.Flags|1)^tc.parentXOR, tc.refs, tc.expires)
			if derived, err := DesktopDarwinDerivedRoute(child, []DesktopNetworkObject{parent}); derived || err == nil {
				t.Fatal("unproved native cache lifetime or parent admitted", err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*DesktopNetworkObject)
	}{
		{"gateway", func(o *DesktopNetworkObject) { o.Gateway = "192.0.2.44" }},
		{"interface", func(o *DesktopNetworkObject) { o.Index++ }},
		{"non-cloning", func(o *DesktopNetworkObject) { o.Flags &^= 0x100 | 0x10000 }},
		{"redirect", func(o *DesktopNetworkObject) { o.Flags |= 0x10 }},
		{"proto1", func(o *DesktopNetworkObject) { o.Flags |= 0x8000 }},
		{"different-native-parent-flags", func(o *DesktopNetworkObject) { o.Flags ^= 0x40000000 }},
	} {
		t.Run("parent-"+tc.name, func(t *testing.T) {
			changed := parent
			tc.change(&changed)
			if derived, err := DesktopDarwinDerivedRoute(original, []DesktopNetworkObject{changed}); derived || err == nil {
				t.Fatal("idle cache changed its captured parent", err)
			}
		})
	}
	if derived, err := DesktopDarwinDerivedRoute(original, []DesktopNetworkObject{parent, parent}); derived || err == nil {
		t.Fatal("idle cache accepted ambiguous equally-specific parents", err)
	}
	narrow := parent
	narrow.Destination = "198.51.100.0/24"
	if derived, err := DesktopDarwinDerivedRoute(original, []DesktopNetworkObject{parent, parent, narrow}); !derived || err != nil {
		t.Fatal("unique longest-prefix parent was lost", err)
	}
	if derived, err := DesktopDarwinDerivedRoute(original, []DesktopNetworkObject{parent, narrow, narrow}); derived || err == nil {
		t.Fatal("duplicate longest-prefix parent was accepted", err)
	}
	parent.Flags |= 0x40000
	cleared := original
	cleared.darwinCache = nil
	cleared.Flags &^= 0x40000
	if derived, err := DesktopDarwinDerivedRoute(cleared, []DesktopNetworkObject{parent}); derived || err == nil {
		t.Fatal("unproved PROTO3 clearing was accepted", err)
	}
}
