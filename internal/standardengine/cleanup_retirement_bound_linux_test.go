//go:build linux && routervpn_controller_privileged

package standardengine

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"router-vpn/internal/desktopnetwork"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// Only the native route evidence is modeled. The original sealed FD10 object,
// duplicated child descriptor, framing, digest and JSON transport are actual.
func TestCleanupCompleteRetirementFitsOriginalFD10(t *testing.T) {
	for _, shape := range []string{"large-attributes", "many-objects"} {
		t.Run(shape, func(t *testing.T) {
			count, payload := 5, 7000
			if shape == "many-objects" {
				count, payload = 256, 0
			}
			r := desktopnetwork.DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: true, Incarnation: strings.Repeat("1", 32), Name: "original0", Index: 17, Objects: []desktopnetwork.DesktopNetworkObject{}}
			for i := 1; i <= count; i++ {
				body := make([]byte, 12)
				body[0] = 2
				body[4] = 254
				body[5] = 4
				body[7] = 1
				for _, a := range []struct {
					k uint16
					v []byte
				}{{4, make([]byte, 4)}, {6, make([]byte, 4)}, {1000, make([]byte, payload)}} {
					if a.k == 4 {
						binary.NativeEndian.PutUint32(a.v, r.Index)
					}
					if a.k == 6 {
						binary.NativeEndian.PutUint32(a.v, uint32(i))
					}
					raw := make([]byte, len(a.v)+4)
					binary.NativeEndian.PutUint16(raw, uint16(len(raw)))
					binary.NativeEndian.PutUint16(raw[2:], a.k)
					copy(raw[4:], a.v)
					body = append(body, raw...)
				}
				o, err := desktopnetwork.ParseDesktopLinuxNetworkObject("route", body)
				if err != nil {
					t.Fatal(err)
				}
				r.Objects = append(r.Objects, o)
			}
			sort.Slice(r.Objects, func(i, j int) bool { return r.Objects[i].Key() < r.Objects[j].Key() })
			ledger, err := desktopnetwork.CanonicalDesktopNetworkRetirementReceipt(r)
			if err != nil || len(ledger) <= 16<<10 {
				t.Fatal("large complete native history unavailable", len(ledger), err)
			}
			original, err := NewCleanupFile()
			if err != nil {
				t.Fatal(err)
			}
			defer original.Close()
			dev, ino := original.Identity()
			fd, err := syscall.Dup(int(original.File().Fd()))
			if err != nil {
				t.Fatal(err)
			}
			child, err := CaptureCleanupFile(os.NewFile(uintptr(fd), "original-fd10-child"), dev, ino)
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			expected := strings.Repeat("a", 64)
			request := CleanupRequest{1, expected, 1, 1234567}
			if err = original.WriteRequest(request); err != nil {
				t.Fatal(err)
			}
			if got, err := child.ReadRequest(expected); err != nil || got != request {
				t.Fatal("original FD10 request changed", err)
			}
			result := CleanupResult{Schema: 1, CaptureSHA256: expected, Sequence: 1, DeadlineNS: request.DeadlineNS, StartedNS: 1, Authority: "request", Complete: true, Ledger: ledger}
			encoded, err := json.Marshal(result)
			if err != nil || len(encoded)+4 > cleanupSize-cleanupRequestSize {
				t.Fatal("escaped retirement exceeds fixed FD10 result area", len(ledger), len(encoded), err)
			}
			if err = child.WriteResult(result); err != nil {
				t.Fatal("original FD10 rejected bounded complete history", err)
			}
			got, err := original.ReadResult(expected)
			if err != nil || got != result {
				t.Fatal("original FD10 altered raw retirement history", err)
			}
			if _, err = desktopnetwork.ParseDesktopNetworkRetirementReceipt(got.Ledger); err != nil {
				t.Fatal(err)
			}
			t.Logf("raw=%d escaped-result=%d fixed-result-area=%d", len(ledger), len(encoded), cleanupSize-cleanupRequestSize)
		})
	}
}
