package desktopnetwork

import (
	"encoding/binary"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

func retirementLimitFixture(t *testing.T, count int) DesktopNetworkRetirementReceipt {
	t.Helper()
	r := DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: true, Incarnation: strings.Repeat("1", 32), Name: "original0", Index: 17, Objects: []DesktopNetworkObject{}}
	for priority := 1; priority <= count; priority++ {
		body := make([]byte, 12)
		body[0] = 2
		body[4] = 254
		body[5] = 4
		body[7] = 1
		for _, a := range []struct {
			kind  uint16
			value []byte
		}{{4, make([]byte, 4)}, {6, make([]byte, 4)}, {1000, make([]byte, 8000)}} {
			if a.kind == 4 {
				binary.NativeEndian.PutUint32(a.value, r.Index)
			}
			if a.kind == 6 {
				binary.NativeEndian.PutUint32(a.value, uint32(priority))
			}
			raw := make([]byte, 4+len(a.value))
			binary.NativeEndian.PutUint16(raw, uint16(len(raw)))
			binary.NativeEndian.PutUint16(raw[2:], a.kind)
			copy(raw[4:], a.value)
			body = append(body, raw...)
		}
		object, err := ParseDesktopLinuxNetworkObject("route", body)
		if err != nil {
			t.Fatal(err)
		}
		r.Objects = append(r.Objects, object)
	}
	sort.Slice(r.Objects, func(i, j int) bool { return r.Objects[i].Key() < r.Objects[j].Key() })
	return r
}

func TestDesktopNetworkRetirementKeepsSeparateBound(t *testing.T) {
	for _, scenario := range []string{"complete-history", "oversized-writer", "oversized-parser", "ready-stays-bounded"} {
		t.Run(scenario, func(t *testing.T) {
			count := 4
			if strings.HasPrefix(scenario, "oversized") {
				count = 5
			}
			r := retirementLimitFixture(t, count)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "complete-history":
				encoded, err := CanonicalDesktopNetworkRetirementReceipt(r)
				if err != nil || len(encoded) <= DesktopNetworkReceiptLimit || len(encoded) > DesktopNetworkRetirementReceiptLimit {
					t.Fatal("actual complete retirement exceeded wrong bound", len(encoded), err)
				}
				got, err := ParseDesktopNetworkRetirementReceipt(encoded)
				if err != nil || len(got.Objects) != 4 {
					t.Fatal("complete original history was truncated", err)
				}
				again, err := CanonicalDesktopNetworkRetirementReceipt(got)
				if err != nil || again != encoded {
					t.Fatal("retirement bytes changed", err)
				}
			case "oversized-writer":
				if len(raw) <= DesktopNetworkRetirementReceiptLimit {
					t.Fatal("fixture underflows")
				}
				if _, err := CanonicalDesktopNetworkRetirementReceipt(r); err == nil {
					t.Fatal("unbounded retirement emitted")
				}
			case "oversized-parser":
				if len(raw) <= DesktopNetworkRetirementReceiptLimit {
					t.Fatal("fixture underflows")
				}
				if _, err := ParseDesktopNetworkRetirementReceipt(string(raw)); err == nil {
					t.Fatal("unbounded retirement accepted")
				}
			case "ready-stays-bounded":
				ready := DesktopNetworkReceipt{Schema: r.Schema, TargetOS: r.TargetOS, Incarnation: r.Incarnation, Name: r.Name, Index: r.Index, MTU: 1500, Addresses: []string{"172.19.0.1/30"}, Objects: r.Objects}
				if _, err := CanonicalDesktopNetworkReceipt(ready); err == nil {
					t.Fatal("Ready silently acquired retirement allowance")
				}
				body, err := json.Marshal(ready)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ParseDesktopNetworkReceipt(string(body)); err == nil {
					t.Fatal("oversized Ready parsed")
				}
			}
		})
	}
}
