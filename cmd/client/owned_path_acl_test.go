//go:build linux || darwin

package main

import (
	"encoding/binary"
	"testing"
)

func ownedACLFixture(entries ...[2]uint32) []byte {
	data := make([]byte, 12+44+len(entries)*24)
	put := binary.LittleEndian.PutUint32
	put(data[:4], uint32(len(data)))
	put(data[4:8], 8)
	put(data[8:12], uint32(len(data)-12))
	put(data[12:16], 0x012cc16d)
	put(data[48:52], uint32(len(entries)))
	for index, entry := range entries {
		offset := 12 + 44 + index*24
		put(data[offset+16:offset+20], entry[0])
		put(data[offset+20:offset+24], entry[1])
	}
	return data
}

func TestOwnedDarwinACLReadback(t *testing.T) {
	absent := make([]byte, 12)
	binary.LittleEndian.PutUint32(absent[:4], 12)
	binary.LittleEndian.PutUint32(absent[4:8], 8)
	for name, data := range map[string][]byte{
		"absent": absent, "empty": ownedACLFixture(),
		"deny-delete":     ownedACLFixture([2]uint32{2, 1 << 4}),
		"read-only-grant": ownedACLFixture([2]uint32{1, 1<<1 | 1<<3 | 1<<7 | 1<<9 | 1<<11}),
		"inherited-read":  ownedACLFixture([2]uint32{1 | 1<<4 | 1<<5, 1 << 24}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateOwnedDarwinACL(data, false); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, bit := range []uint{0, 2, 4, 5, 6, 8, 10, 12, 13, 21, 23, 25, 31} {
		if err := validateOwnedDarwinACL(ownedACLFixture([2]uint32{1 | 1<<8, 1 << bit}), false); err == nil {
			t.Fatalf("unsafe or unknown ACL right %d was accepted", bit)
		}
	}
	for _, change := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[:4], 5000) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[4:8], 0xffffffff) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[8:12], 45) },
		func(b []byte) { b[12] ^= 1 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[48:52], 129) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[48:52], 0xffffffff) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[72:76], 3) },
	} {
		data := ownedACLFixture([2]uint32{1, 1 << 1})
		change(data)
		if err := validateOwnedDarwinACL(data, false); err == nil {
			t.Fatal("malformed native ACL was accepted")
		}
	}
	if err := validateOwnedDarwinACL([]byte{1, 2, 3}, false); err == nil {
		t.Fatal("short ACL response was accepted")
	}
	if err := validateOwnedDarwinACL(ownedACLFixture([2]uint32{1, 1 << 1}), true); err == nil {
		t.Fatal("a private object exposed data through a read ACL")
	}
	if err := validateOwnedDarwinACL(ownedACLFixture([2]uint32{2, 1 << 4}), true); err != nil {
		t.Fatal("a private deny-only ACL was rejected", err)
	}
}
