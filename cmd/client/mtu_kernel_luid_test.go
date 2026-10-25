package main

import (
	"errors"
	"reflect"
	"runtime"
	"testing"
	"unsafe"
)

func TestMTUKernelWindowsSDKLayout(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("64-bit Windows SDK ABI")
	}
	if unsafe.Sizeof(mtuIPInterfaceRow{}) != 168 || unsafe.Offsetof(mtuIPInterfaceRow{}.LUID) != 8 || unsafe.Offsetof(mtuIPInterfaceRow{}.Index) != 16 || unsafe.Offsetof(mtuIPInterfaceRow{}.MTU) != 152 {
		t.Fatal("Windows IP interface row layout differs from the SDK")
	}
}

func TestMTUKernelLUIDPreservesPolicyAndRejectsReplacement(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(string(rune('0'+family)), func(t *testing.T) {
			id := mtuLUIDIdentity{LUID: 0x123400000123, GUID: [16]byte{1, 2, 3}, Index: 19, Alias: "Router VPN"}
			identity := id
			nativeFamily := uint16(2)
			if family == 6 {
				nativeFamily = 23
			}
			row := mtuIPInterfaceRow{Family: nativeFamily, LUID: id.LUID, Index: id.Index, MTU: 1400,
				Metric: 67, Forwarding: 1, NeighborDetection: 1, RouterDiscovery: 2, DadTransmits: 3,
				SitePrefixLength: 64, ZoneIndices: [16]uint32{7, 8, 9}, DisableDefaultRoutes: 1}
			original := row
			writes := 0
			calls := mtuLUIDCalls{
				identity: func(luid uint64) (mtuLUIDIdentity, error) {
					if luid != id.LUID {
						t.Fatal("read targeted another LUID")
					}
					return identity, nil
				},
				read: func(luid uint64, family uint16) (mtuIPInterfaceRow, error) {
					if luid != id.LUID || family != nativeFamily {
						t.Fatal("read did not retain exact LUID and family")
					}
					return row, nil
				},
				write: func(change *mtuIPInterfaceRow) error {
					writes++
					wanted := original
					wanted.MTU, wanted.Index = change.MTU, 0
					if wanted.Family == 2 {
						wanted.SitePrefixLength = 0
					}
					if !reflect.DeepEqual(*change, wanted) {
						t.Fatal("MTU write changed unrelated interface policy or retained index targeting")
					}
					row = *change
					row.Index = id.Index // GetIpInterfaceEntry returns the current index.
					return nil
				},
			}
			owner, err := newMTULUIDKernelOwner(mtuLiveSnapshot{Interface: id.Alias, Family: family, OriginalMTU: 1400}, id, calls)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := owner.Read()
			after, err := owner.Change(before, 1320)
			if err != nil || after.MTU != 1320 || writes != 1 || after.Identity != before.Identity {
				t.Fatal("captured Windows MTU mutation failed", err)
			}
			if _, err := owner.Change(before, 1280); err == nil || writes != 1 {
				t.Fatal("stale MTU readback authorized a later write")
			}
			identity.GUID[0]++
			if _, err := owner.Change(after, 1400); err == nil || writes != 1 {
				t.Fatal("replacement interface identity authorized rollback")
			}
			identity = id
			_ = owner.Close()
			if _, err := owner.Change(after, 1400); err == nil || writes != 1 {
				t.Fatal("closed owner mutated its old interface")
			}
		})
	}
}

func TestMTUKernelLUIDWriteCannotTargetRecycledIndex(t *testing.T) {
	id := mtuLUIDIdentity{LUID: 101, GUID: [16]byte{1}, Index: 19, Alias: "Router VPN"}
	row := mtuIPInterfaceRow{Family: 2, LUID: id.LUID, Index: id.Index, MTU: 1400}
	replacement := mtuIPInterfaceRow{Family: 2, LUID: 202, Index: id.Index, MTU: 1500}
	owner, err := newMTULUIDKernelOwner(mtuLiveSnapshot{Interface: id.Alias, Family: 4, OriginalMTU: 1400}, id, mtuLUIDCalls{
		identity: func(uint64) (mtuLUIDIdentity, error) { return id, nil },
		read:     func(uint64, uint16) (mtuIPInterfaceRow, error) { return row, nil },
		write: func(change *mtuIPInterfaceRow) error {
			// Simulate removal after the last read. The replacement has reused
			// its index and alias, but the kernel write still targets only101.
			if change.LUID == replacement.LUID || change.Index == replacement.Index {
				replacement.MTU = change.MTU
				return nil
			}
			return errors.New("captured LUID no longer exists")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := owner.Read()
	if _, err := owner.Change(before, 1320); err == nil || replacement.MTU != 1500 {
		t.Fatal("recycled interface index received the captured owner's write")
	}
}
