package macosprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func fixtureImage(cpu uint32) []byte {
	raw := make([]byte, 120)
	put := binary.LittleEndian.PutUint32
	put(raw, 0xfeedfacf)
	put(raw[4:], cpu)
	put(raw[12:], 2)
	put(raw[16:], 2)
	put(raw[20:], 40)
	put(raw[32:], 0x1b)
	put(raw[36:], 24)
	copy(raw[40:56], []byte("original-main-id!"))
	put(raw[56:], 0x1d)
	put(raw[60:], 16)
	put(raw[64:], 72)
	put(raw[68:], 48)
	cd := raw[72:]
	big := binary.BigEndian.PutUint32
	big(cd, 0xfade0c02)
	big(cd[4:], 48)
	big(cd[8:], 0x20000)
	big(cd[16:], 48)
	big(cd[20:], 44)
	cd[36], cd[37] = 32, 2
	copy(cd[44:], []byte("bin\x00"))
	return raw
}

func fixtureUniversal() []byte {
	x86, arm := fixtureImage(CPUAMD64), fixtureImage(CPUARM64)
	raw := make([]byte, 48+len(x86)+len(arm))
	put := binary.BigEndian.PutUint32
	put(raw, 0xcafebabe)
	put(raw[4:], 2)
	put(raw[8:], CPUAMD64)
	put(raw[16:], 48)
	put(raw[20:], uint32(len(x86)))
	put(raw[28:], CPUARM64)
	put(raw[36:], uint32(48+len(x86)))
	put(raw[40:], uint32(len(arm)))
	copy(raw[48:], x86)
	copy(raw[48+len(x86):], arm)
	return raw
}

func TestImageCapturesNativeSlicesAndExactSignature(t *testing.T) {
	for _, cpu := range []uint32{CPUAMD64, CPUARM64} {
		for _, raw := range [][]byte{fixtureImage(cpu), fixtureUniversal()} {
			image, err := ReadImage(bytes.NewReader(raw), int64(len(raw)), cpu)
			if err != nil || len(image.Slices) != 1 || len(image.Slices[0].CodeHashes) != 1 {
				t.Fatal(err, image)
			}
			if image.SHA256 != sha256.Sum256(raw) {
				t.Fatal("whole image digest changed")
			}
			identity := Identity{PID: 123, StartSeconds: 1, UniqueID: 2, IDVersion: 3, UUID: image.Slices[0].UUID, CodeHash: image.Slices[0].CodeHashes[0]}
			if !identity.Matches(image) {
				t.Fatal("actual captured image rejected")
			}
			for _, field := range []string{"pid", "start", "generation", "exec", "uuid", "hash"} {
				changed := identity
				switch field {
				case "pid":
					changed.PID = 0
				case "start":
					changed.StartSeconds = 0
				case "generation":
					changed.UniqueID = 0
				case "exec":
					changed.IDVersion = 0
				case "uuid":
					changed.UUID[0] ^= 1
				case "hash":
					changed.CodeHash[0] ^= 1
				}
				if changed.Matches(image) {
					t.Fatal("replaced main image admitted", field)
				}
			}
		}
	}
}

func TestImageRejectsMalformedOrAmbiguousNativeBounds(t *testing.T) {
	for _, fault := range []string{"architecture", "file-type", "commands", "command-size", "uuid-size", "signature-offset", "signature-size", "directory-length", "directory-version", "hash-kind", "hash-size", "identifier", "pages", "duplicate-signature"} {
		t.Run(fault, func(t *testing.T) {
			raw := fixtureImage(CPUAMD64)
			put := binary.LittleEndian.PutUint32
			big := binary.BigEndian.PutUint32
			switch fault {
			case "architecture":
				put(raw[4:], CPUARM64)
			case "file-type":
				put(raw[12:], 6)
			case "commands":
				put(raw[16:], 32769)
			case "command-size":
				put(raw[36:], 0)
			case "uuid-size":
				put(raw[36:], 20)
			case "signature-offset":
				put(raw[64:], 64)
			case "signature-size":
				put(raw[68:], signatureLimit+1)
			case "directory-length":
				big(raw[76:], 100)
			case "directory-version":
				big(raw[80:], 0x20601)
			case "hash-kind":
				raw[109] = 7
			case "hash-size":
				raw[108] = 48
			case "identifier":
				big(raw[92:], 48)
			case "pages":
				big(raw[100:], 1)
			case "duplicate-signature":
				put(raw[32:], 0x1d)
			}
			if _, err := ReadImage(bytes.NewReader(raw), int64(len(raw)), CPUAMD64); err == nil {
				t.Fatal("malformed native image accepted")
			}
		})
	}
	for _, fault := range []string{"count", "overlap", "duplicate-cpu", "slice-disagrees", "alignment", "outside"} {
		t.Run("universal-"+fault, func(t *testing.T) {
			raw := fixtureUniversal()
			put := binary.BigEndian.PutUint32
			switch fault {
			case "count":
				put(raw[4:], 33)
			case "overlap":
				put(raw[36:], 48)
			case "duplicate-cpu":
				put(raw[28:], CPUAMD64)
			case "slice-disagrees":
				binary.LittleEndian.PutUint32(raw[48+4:], CPUARM64)
			case "alignment":
				put(raw[24:], 30)
			case "outside":
				put(raw[36:], ^uint32(0))
			}
			if _, err := ReadImage(bytes.NewReader(raw), int64(len(raw)), CPUAMD64); err == nil {
				t.Fatal("malformed universal image accepted")
			}
		})
	}
	for _, length := range []int64{0, 31, ImageLimit + 1} {
		if _, err := ReadImage(bytes.NewReader(nil), length, CPUAMD64); err == nil {
			t.Fatal("unbounded original file accepted")
		}
	}
}

func TestSignatureAlternativesRemainDistinctAndBounded(t *testing.T) {
	cd := fixtureImage(CPUAMD64)[72:]
	raw := make([]byte, 28+2*len(cd))
	put := binary.BigEndian.PutUint32
	put(raw, 0xfade0cc0)
	put(raw[4:], uint32(len(raw)))
	put(raw[8:], 2)
	put(raw[12:], 0)
	put(raw[16:], 28)
	put(raw[20:], 0x1000)
	put(raw[24:], 76)
	copy(raw[28:], cd)
	copy(raw[76:], cd)
	raw[76+36], raw[76+37] = 20, 1
	hashes, err := signatureHashes(raw)
	if err != nil || len(hashes) != 2 || hashes[0] == hashes[1] {
		t.Fatal("alternatives lost", err)
	}
	for _, fault := range []string{"same-slot", "overlap", "unknown-only", "bad-offset", "too-many"} {
		changed := append([]byte(nil), raw...)
		switch fault {
		case "same-slot":
			put(changed[20:], 0)
		case "overlap":
			put(changed[24:], 28)
		case "unknown-only":
			put(changed[12:], 7)
			put(changed[20:], 8)
		case "bad-offset":
			put(changed[16:], 20)
		case "too-many":
			put(changed[8:], 65)
		}
		if _, err := signatureHashes(changed); err == nil {
			t.Fatal("ambiguous signature accepted", fault)
		}
	}
}
