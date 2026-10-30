package windowscontroller

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// This fixture-only validator is shared with the actual pre-resume kernel
// readback. Windows added NO_READ_UP to the requested NO_WRITE_UP on a newly
// created process. Both are restrictions; the latter must remain present.
// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-system_mandatory_label_ace
func fixtureMediumStartupLabel(descriptor []byte) error {
	if len(descriptor) < 20 || descriptor[0] != 1 || binary.LittleEndian.Uint16(descriptor[2:4])&0x8010 != 0x8010 {
		return errors.New("new Medium process/thread has no bounded self-relative mandatory label")
	}
	start := int(binary.LittleEndian.Uint32(descriptor[12:16]))
	if start < 20 || start > len(descriptor)-8 {
		return errors.New("new Medium process/thread has no captured mandatory label")
	}
	acl := descriptor[start:]
	size, count := int(binary.LittleEndian.Uint16(acl[2:4])), int(binary.LittleEndian.Uint16(acl[4:6]))
	if acl[0] != 2 || size < 8 || size > len(acl) || count != 1 {
		return errors.New("new Medium process/thread has an unexpected mandatory ACL")
	}
	ace := acl[8:size]
	if len(ace) < 16 {
		return errors.New("new Medium process/thread has a truncated mandatory ACE")
	}
	mask := binary.LittleEndian.Uint32(ace[4:8])
	if ace[0] != 17 || ace[1] != 0 || int(binary.LittleEndian.Uint16(ace[2:4])) != len(ace) ||
		mask&1 == 0 || mask&^uint32(7) != 0 {
		return fmt.Errorf("new Medium process/thread lost its explicit no-write-up label (type=%d flags=0x%x ACE-size=%d captured-span=%d mask=0x%x)",
			ace[0], ace[1], binary.LittleEndian.Uint16(ace[2:4]), len(ace), mask)
	}
	sid, length, err := systemImageSID(ace, 8)
	if err != nil || length != len(ace)-8 || sid.authority != 16 || len(sid.parts) != 1 || sid.parts[0] != 8192 {
		return errors.Join(err, errors.New("new Medium process/thread changed its captured integrity"))
	}
	return nil
}

func fixtureVerifyMediumStartupLabel(t *testing.T, descriptor []byte) {
	t.Helper()
	if err := fixtureMediumStartupLabel(descriptor); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsControllerFoundationProtectedShellMediumLabelPolicy(t *testing.T) {
	label := func(mask uint32) []byte {
		// Exact self-relative descriptor, one label ACL and S-1-16-8192.
		value := make([]byte, 48)
		value[0] = 1
		binary.LittleEndian.PutUint16(value[2:4], 0x8010)
		binary.LittleEndian.PutUint32(value[12:16], 20)
		value[20] = 2
		binary.LittleEndian.PutUint16(value[22:24], 28)
		binary.LittleEndian.PutUint16(value[24:26], 1)
		value[28] = 17
		binary.LittleEndian.PutUint16(value[30:32], 20)
		binary.LittleEndian.PutUint32(value[32:36], mask)
		value[36], value[37], value[43] = 1, 1, 16
		binary.LittleEndian.PutUint32(value[44:48], 8192)
		return value
	}
	for _, mask := range []uint32{1, 3, 5, 7} {
		if err := fixtureMediumStartupLabel(label(mask)); err != nil {
			t.Fatalf("documented additional mandatory restrictions rejected (mask=0x%x): %v", mask, err)
		}
	}
	for _, mask := range []uint32{0, 2, 4, 6, 8, 9, 0x80000001} {
		if err := fixtureMediumStartupLabel(label(mask)); err == nil {
			t.Fatalf("Medium label admitted a missing no-write-up restriction or unknown bit (mask=0x%x)", mask)
		}
	}
	for _, change := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"short-descriptor", func(value []byte) []byte { return value[:12] }},
		{"descriptor-revision", func(value []byte) []byte { value[0] = 2; return value }},
		{"absolute-descriptor", func(value []byte) []byte { value[3] &^= 0x80; return value }},
		{"missing-sacl", func(value []byte) []byte { value[2] &^= 0x10; return value }},
		{"absent-sacl", func(value []byte) []byte { binary.LittleEndian.PutUint32(value[12:16], 0); return value }},
		{"outside-sacl", func(value []byte) []byte { binary.LittleEndian.PutUint32(value[12:16], 45); return value }},
		{"acl-revision", func(value []byte) []byte { value[20] = 4; return value }},
		{"acl-bound", func(value []byte) []byte { binary.LittleEndian.PutUint16(value[22:24], 29); return value }},
		{"second-label", func(value []byte) []byte { binary.LittleEndian.PutUint16(value[24:26], 2); return value }},
		{"truncated-ace", func(value []byte) []byte { binary.LittleEndian.PutUint16(value[22:24], 12); return value }},
		{"discretionary-ace", func(value []byte) []byte { value[28] = 0; return value }},
		{"inherit-only", func(value []byte) []byte { value[29] = 8; return value }},
		{"inherited", func(value []byte) []byte { value[29] = 16; return value }},
		{"ace-bound", func(value []byte) []byte { binary.LittleEndian.PutUint16(value[30:32], 16); return value }},
		{"sid-revision", func(value []byte) []byte { value[36] = 2; return value }},
		{"sid-authority", func(value []byte) []byte { value[43] = 5; return value }},
		{"sid-count", func(value []byte) []byte { value[37] = 2; return value }},
		{"low-integrity", func(value []byte) []byte { binary.LittleEndian.PutUint32(value[44:48], 4096); return value }},
		{"high-integrity", func(value []byte) []byte { binary.LittleEndian.PutUint32(value[44:48], 12288); return value }},
	} {
		t.Run(change.name, func(t *testing.T) {
			if err := fixtureMediumStartupLabel(change.edit(label(3))); err == nil {
				t.Fatal("Medium label admitted a substituted mandatory descriptor")
			}
		})
	}
}
