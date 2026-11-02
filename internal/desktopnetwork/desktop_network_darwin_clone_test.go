package desktopnetwork

import (
	"strings"
	"testing"
)

func darwinCloneScopeFixture(family int) (DesktopNetworkObject, DesktopNetworkObject) {
	parent := DesktopNetworkObject{Kind: "route", Family: family, Index: 2, Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Flags: 0x2 | 0x800 | 0x10000}
	clone := DesktopNetworkObject{Kind: "route", Family: family, Index: 2, Destination: "198.51.100.5/32", Gateway: "192.0.2.1", Flags: 0x2 | 0x4 | 0x20000 | 0x1000000}
	if family == 6 {
		parent.Destination, parent.Gateway = "::/0", "2001:db8::1"
		clone.Destination, clone.Gateway = "2001:db8:2::5/128", "2001:db8::1"
	}
	return parent, clone
}

func TestDarwinCloneDerivesOriginalInterfaceScope(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, name := range []string{"unscoped-parent", "scoped-parent", "retained-noifref", "link-local-parent", "scoped-link-local-parent"} {
			if family == 6 && strings.Contains(name, "link-local") {
				continue // XNU's clearing exception is specifically IPv4 link-local.
			}
			t.Run(string(rune('0'+family))+"/"+name, func(t *testing.T) {
				parent, clone := darwinCloneScopeFixture(family)
				switch name {
				case "scoped-parent":
					parent.Flags |= 0x1000000
				case "retained-noifref":
					parent.Flags |= 0x2000
					clone.Flags |= 0x2000
				case "link-local-parent", "scoped-link-local-parent":
					parent.Destination, parent.Gateway, parent.Flags = "169.254.0.0/16", "", 0x100
					clone.Destination, clone.Gateway, clone.Flags = "169.254.9.7/32", "", 0x4|0x400|0x2000|0x20000
					if name == "scoped-link-local-parent" {
						parent.Flags |= 0x1000000
					}
				}
				originalParent, originalClone := parent, clone
				parents := []DesktopNetworkObject{parent}
				if derived, err := DesktopDarwinDerivedRoute(clone, parents); err != nil || !derived {
					t.Fatal("XNU-derived scope lost its unique original parent", err)
				}
				if parents[0] != originalParent || parent != originalParent || clone != originalClone {
					t.Fatal("scope classification rewrote an observed route")
				}
			})
		}
	}
}

func TestDarwinCloneScopeKeepsExactParentRefusals(t *testing.T) {
	for _, fault := range []string{"missing-scope", "lost-parent-scope", "extra-noifref", "lost-noifref", "link-local-scope", "link-local-noifref", "proxy-parent", "non-cloning-parent", "other-interface", "other-gateway", "redirect", "modified", "static", "reject", "blackhole", "unproved-proto3", "ambiguous-longest-prefix", "missing-prefix"} {
		t.Run(fault, func(t *testing.T) {
			parent, clone := darwinCloneScopeFixture(4)
			var extra []DesktopNetworkObject
			switch fault {
			case "missing-scope":
				clone.Flags &^= 0x1000000
			case "lost-parent-scope":
				parent.Flags |= 0x1000000
				clone.Flags &^= 0x1000000
			case "extra-noifref":
				clone.Flags |= 0x2000
			case "lost-noifref":
				parent.Flags |= 0x2000
			case "link-local-scope", "link-local-noifref":
				parent.Destination, parent.Gateway, parent.Flags = "169.254.0.0/16", "", 0x100
				clone.Destination, clone.Gateway, clone.Flags = "169.254.9.7/32", "", 0x4|0x400|0x2000|0x20000
				if fault == "link-local-scope" {
					clone.Flags |= 0x1000000
				} else {
					clone.Flags &^= 0x2000
				}
			case "proxy-parent":
				parent.Flags |= 0x8000000
			case "non-cloning-parent":
				parent.Flags &^= 0x10000
			case "other-interface":
				clone.Index++
			case "other-gateway":
				clone.Gateway = "192.0.2.99"
			case "redirect":
				clone.Flags |= 0x10
			case "modified":
				clone.Flags |= 0x20
			case "static":
				clone.Flags |= 0x800
			case "reject":
				clone.Flags |= 0x8
			case "blackhole":
				clone.Flags |= 0x1000
			case "unproved-proto3":
				clone.Flags |= 0x40000
			case "ambiguous-longest-prefix":
				moreSpecific := parent
				moreSpecific.Destination = "198.51.100.0/24"
				extra = []DesktopNetworkObject{moreSpecific, moreSpecific}
			case "missing-prefix":
				parent.Destination = "203.0.113.0/24"
			}
			if derived, err := DesktopDarwinDerivedRoute(clone, append([]DesktopNetworkObject{parent}, extra...)); derived || err == nil {
				t.Fatal("unproved parent or scope authorized a cloned route")
			}
		})
	}
	parent, clone := darwinCloneScopeFixture(4)
	moreSpecific := parent
	moreSpecific.Destination = "198.51.100.0/24"
	if derived, err := DesktopDarwinDerivedRoute(clone, []DesktopNetworkObject{parent, parent, moreSpecific}); !derived || err != nil {
		t.Fatal("duplicate less-specific entries displaced the unique longest parent", err)
	}
}

func TestDarwinCloneFailureDiagnosticsStayBoundedAndPrivate(t *testing.T) {
	parent, clone := darwinCloneScopeFixture(4)
	clone.Flags |= 0x40000 // The unobserved idle-cache lifecycle remains unsupported.
	parents := make([]DesktopNetworkObject, 40)
	for i := range parents {
		parents[i] = parent
	}
	derived, err := DesktopDarwinDerivedRoute(clone, parents)
	if derived || err == nil {
		t.Fatal("diagnostic classified an unproved idle-cache route")
	}
	message := err.Error()
	for _, wanted := range []string{"reason=unique-parent", "family=4", "index=2", "flags=0x1060006", "prefix=32", "parents=40", "best=-1", "matches=0", "candidates=40", "shown=8", "proto3_equal=false", "scope_equal=true", "inventory_truncated=false"} {
		if !strings.Contains(message, wanted) {
			t.Fatal("failure omitted its bounded comparison shape", wanted, message)
		}
	}
	if len(message) > 2048 || strings.Count(message, "{index=") != 8 {
		t.Fatal("failure diagnostic exceeded its candidate/output bound", len(message))
	}
	for _, private := range []string{clone.Destination, clone.Gateway, parent.Destination, "198.51.100.5", "192.0.2.1"} {
		if strings.Contains(message, private) {
			t.Fatal("failure exposed private routing input")
		}
	}
	tooMany := make([]DesktopNetworkObject, 32769)
	for i := range tooMany {
		tooMany[i] = parent
	}
	if derived, err := DesktopDarwinDerivedRoute(clone, tooMany); derived || err == nil || len(err.Error()) > 2048 ||
		!strings.Contains(err.Error(), "parents=32769") || !strings.Contains(err.Error(), "candidates=32768") ||
		!strings.Contains(err.Error(), "shown=8") || !strings.Contains(err.Error(), "inventory_truncated=true") {
		t.Fatal("diagnostic scanned or printed an unbounded parent inventory", err)
	}
	clone.Native, clone.Destination, clone.Gateway = "private-native-token", "private-invalid-destination", "private-invalid-gateway"
	if derived, err = DesktopDarwinDerivedRoute(clone, parents); derived || err == nil || !strings.Contains(err.Error(), "reason=object-shape") || strings.Contains(err.Error(), "private-") {
		t.Fatal("malformed private input escaped its bounded diagnostic", err)
	}
}
