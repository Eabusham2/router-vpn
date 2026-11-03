// Package macosprocess authenticates an inherited Darwin native child. Image
// identifiers are comparison inputs, never substitutes for package trust or
// for the original process/channel lifetime.
package macosprocess

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
)

const ImageLimit int64 = 1 << 30
const signatureLimit = 32 << 20
const CPUAMD64 uint32 = 0x01000007
const CPUARM64 uint32 = 0x0100000c

type ImageSlice struct {
	UUID       [16]byte
	CodeHashes [][20]byte
}

type Image struct {
	SHA256 [32]byte
	Slices []ImageSlice
}

// ReadImage retains each executable slice for the requested CPU and every
// supported CodeDirectory alternative. The caller separately verifies its
// pinned file identity before/after this bounded read and package signature.
func ReadImage(reader io.ReaderAt, size int64, cpu uint32) (Image, error) {
	var result Image
	if reader == nil || size < 32 || size > ImageLimit || cpu != CPUAMD64 && cpu != CPUARM64 {
		return result, errors.New("native image has no bounded supported architecture")
	}
	read := func(offset, length int64) ([]byte, error) {
		if offset < 0 || length < 0 || offset > size || length > size-offset || length > signatureLimit {
			return nil, errors.New("native image read exceeds its captured bound")
		}
		value := make([]byte, int(length))
		_, err := reader.ReadAt(value, offset)
		return value, err
	}
	header, err := read(0, 8)
	if err != nil {
		return result, err
	}
	type region struct {
		offset, length int64
		architecture   [2]uint32
	}
	regions := []region{{offset: 0, length: size}}
	magic := binary.BigEndian.Uint32(header)
	if magic == 0xcafebabe || magic == 0xbebafeca || magic == 0xcafebabf || magic == 0xbfbafeca {
		var order binary.ByteOrder = binary.BigEndian
		if magic == 0xbebafeca || magic == 0xbfbafeca {
			order = binary.LittleEndian
		}
		width := int64(20)
		if magic == 0xcafebabf || magic == 0xbfbafeca {
			width = 32
		}
		count := int64(order.Uint32(header[4:]))
		if count < 1 || count > 32 {
			return result, errors.New("native universal image has unbounded slices")
		}
		table, err := read(8, count*width)
		if err != nil {
			return result, err
		}
		regions = nil
		architectures := map[[2]uint32]bool{}
		for i := int64(0); i < count; i++ {
			row := table[i*width : (i+1)*width]
			arch := [2]uint32{order.Uint32(row), order.Uint32(row[4:])}
			var offset, length uint64
			var align uint32
			if width == 20 {
				offset = uint64(order.Uint32(row[8:]))
				length = uint64(order.Uint32(row[12:]))
				align = order.Uint32(row[16:])
			} else {
				offset = order.Uint64(row[8:])
				length = order.Uint64(row[16:])
				align = order.Uint32(row[24:])
				if order.Uint32(row[28:]) != 0 {
					return result, errors.New("native universal image has reserved fields")
				}
			}
			if architectures[arch] || align > 30 || offset < uint64(8+count*width) || offset > uint64(size) || length < 32 || length > uint64(size)-offset || offset%(uint64(1)<<align) != 0 {
				return result, errors.New("native universal image has invalid slice bounds")
			}
			architectures[arch] = true
			for _, old := range regions {
				if int64(offset) < old.offset+old.length && old.offset < int64(offset+length) {
					return result, errors.New("native universal image overlaps slices")
				}
			}
			regions = append(regions, region{int64(offset), int64(length), arch})
		}
	}
	for _, part := range regions {
		header, err := read(part.offset, 32)
		if err != nil {
			return result, err
		}
		var order binary.ByteOrder
		switch binary.BigEndian.Uint32(header) {
		case 0xcffaedfe:
			order = binary.LittleEndian
		case 0xfeedfacf:
			order = binary.BigEndian
		default:
			return result, errors.New("native child image is not Mach-O 64")
		}
		if part.architecture != [2]uint32{} && part.architecture != [2]uint32{order.Uint32(header[4:]), order.Uint32(header[8:])} {
			return result, errors.New("native universal architecture differs from its actual slice")
		}
		if order.Uint32(header[4:]) != cpu {
			continue
		}
		if order.Uint32(header[12:]) != 2 {
			return result, errors.New("native child image is not an executable")
		}
		count, length := int64(order.Uint32(header[16:])), int64(order.Uint32(header[20:]))
		if count < 1 || count > 32768 || length > signatureLimit || length > part.length-32 {
			return result, errors.New("native image load commands exceed their slice")
		}
		commands, err := read(part.offset+32, length)
		if err != nil {
			return result, err
		}
		cursor := int64(0)
		signatureOffset, signatureSize := int64(0), int64(0)
		slice := ImageSlice{}
		uuidSeen := false
		for i := int64(0); i < count; i++ {
			if cursor > length-8 {
				return result, errors.New("native image load command is truncated")
			}
			command, width := order.Uint32(commands[cursor:]), int64(order.Uint32(commands[cursor+4:]))
			if width < 8 || width%4 != 0 || width > length-cursor {
				return result, errors.New("native image load command has invalid size")
			}
			switch command {
			case 0x1d:
				if width != 16 || signatureSize != 0 {
					return result, errors.New("native image repeats its signature")
				}
				signatureOffset, signatureSize = int64(order.Uint32(commands[cursor+8:])), int64(order.Uint32(commands[cursor+12:]))
				if signatureOffset < 32+length || signatureSize < 8 || signatureSize > signatureLimit || signatureOffset > part.length || signatureSize > part.length-signatureOffset {
					return result, errors.New("native signature exceeds its captured slice")
				}
			case 0x1b:
				if width != 24 || uuidSeen {
					return result, errors.New("native image has an ambiguous main UUID")
				}
				copy(slice.UUID[:], commands[cursor+8:cursor+24])
				uuidSeen = true
			}
			cursor += width
		}
		if cursor != length || signatureSize == 0 {
			return result, errors.New("native image has no complete code signature")
		}
		signature, err := read(part.offset+signatureOffset, signatureSize)
		if err != nil {
			return result, err
		}
		slice.CodeHashes, err = signatureHashes(signature)
		if err != nil {
			return result, err
		}
		result.Slices = append(result.Slices, slice)
	}
	if len(result.Slices) == 0 {
		return result, errors.New("native image omitted its actual architecture")
	}
	digest := sha256.New()
	if _, err := io.CopyN(digest, io.NewSectionReader(reader, 0, size), size); err != nil {
		return result, err
	}
	copy(result.SHA256[:], digest.Sum(nil))
	return result, nil
}

func signatureHashes(raw []byte) ([][20]byte, error) {
	if len(raw) < 8 {
		return nil, errors.New("native signature is truncated")
	}
	magic, length := binary.BigEndian.Uint32(raw), uint64(binary.BigEndian.Uint32(raw[4:]))
	if length < 8 || length > uint64(len(raw)) {
		return nil, errors.New("native signature has invalid length")
	}
	if magic == 0xfade0c02 {
		hash, err := codeDirectoryHash(raw[:length])
		return [][20]byte{hash}, err
	}
	if magic != 0xfade0cc0 || length < 12 {
		return nil, errors.New("native signature container is unsupported")
	}
	count := uint64(binary.BigEndian.Uint32(raw[8:]))
	if count < 1 || count > 64 || 12+8*count > length {
		return nil, errors.New("native signature has unbounded entries")
	}
	slots := map[uint32]bool{}
	ranges := [][2]uint64{}
	hashes := [][20]byte{}
	for i := uint64(0); i < count; i++ {
		row := raw[12+8*i:]
		slot, offset := binary.BigEndian.Uint32(row), uint64(binary.BigEndian.Uint32(row[4:]))
		if slots[slot] || offset < 12+8*count || offset > length-8 {
			return nil, errors.New("native signature entry is repeated or outside container")
		}
		slots[slot] = true
		size := uint64(binary.BigEndian.Uint32(raw[offset+4:]))
		if size < 8 || size > length-offset {
			return nil, errors.New("native signature entry exceeds its container")
		}
		for _, old := range ranges {
			if offset < old[1] && old[0] < offset+size {
				return nil, errors.New("native signature entries overlap")
			}
		}
		ranges = append(ranges, [2]uint64{offset, offset + size})
		if slot == 0 || slot >= 0x1000 && slot < 0x1005 {
			hash, err := codeDirectoryHash(raw[offset : offset+size])
			if err != nil {
				return nil, err
			}
			hashes = append(hashes, hash)
		}
	}
	if len(hashes) == 0 {
		return nil, errors.New("native signature has no supported CodeDirectory")
	}
	return hashes, nil
}

func codeDirectoryHash(raw []byte) ([20]byte, error) {
	var result [20]byte
	if len(raw) < 44 || binary.BigEndian.Uint32(raw) != 0xfade0c02 || binary.BigEndian.Uint32(raw[4:]) != uint32(len(raw)) {
		return result, errors.New("native CodeDirectory is truncated")
	}
	version := binary.BigEndian.Uint32(raw[8:])
	minimum := uint32(44)
	if version < 0x20000 || version > 0x20600 {
		return result, errors.New("native CodeDirectory version is unsupported")
	}
	for _, entry := range [][2]uint32{{0x20100, 48}, {0x20200, 52}, {0x20300, 64}, {0x20400, 88}, {0x20500, 96}, {0x20600, 108}} {
		if version >= entry[0] {
			minimum = entry[1]
		}
	}
	if uint32(len(raw)) < minimum {
		return result, errors.New("native CodeDirectory lacks version fields")
	}
	hashOffset, identifier, special, pages := binary.BigEndian.Uint32(raw[16:]), binary.BigEndian.Uint32(raw[20:]), binary.BigEndian.Uint32(raw[24:]), binary.BigEndian.Uint32(raw[28:])
	hashSize, kind := uint64(raw[36]), raw[37]
	wanted := map[byte]uint64{1: 20, 2: 32, 3: 20, 4: 48}
	if wanted[kind] == 0 || hashSize != wanted[kind] || identifier < minimum || identifier >= uint32(len(raw)) || bytes.IndexByte(raw[identifier:], 0) < 0 ||
		hashOffset < minimum || hashOffset > uint32(len(raw)) || uint64(special)*hashSize > uint64(hashOffset-minimum) || uint64(pages)*hashSize > uint64(len(raw))-uint64(hashOffset) {
		return result, errors.New("native CodeDirectory has invalid digest bounds")
	}
	switch kind {
	case 1:
		value := sha1.Sum(raw)
		copy(result[:], value[:])
	case 2, 3:
		value := sha256.Sum256(raw)
		copy(result[:], value[:])
	case 4:
		value := sha512.Sum384(raw)
		copy(result[:], value[:])
	}
	return result, nil
}
