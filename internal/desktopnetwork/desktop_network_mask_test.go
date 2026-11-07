package desktopnetwork

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

// Reproduce XNU rn_addmask/rtm_scrub's fixed address offset, all-ones header
// and trimmed mask. This is a wire fixture; it does not claim a kernel change.
func darwinMaskFixture(width, ones int, compact bool) []byte {
	offset, size, family := 4, 16, byte(2)
	if width == 128 {
		offset, size, family = 8, 28, 30
	}
	raw := make([]byte, size)
	raw[0], raw[1] = byte(size), family
	copy(raw[offset:], net.CIDRMask(ones, width))
	if compact {
		if ones == 0 {
			return make([]byte, 4)
		}
		length := offset + (ones+7)/8
		raw = raw[:(length+3)&^3]
		raw[0] = byte(length)
		for index := 1; index < offset; index++ {
			raw[index] = 0xff
		}
	}
	return raw
}

func darwinMaskMessage(mask []byte) []byte {
	// DST, GATEWAY, NETMASK and a following IFA: the decoder must stop at
	// the mask's declared length without borrowing another address's bytes.
	address := []byte{4, 0, 0, 0}
	message := append(append([]byte(nil), address...), address...)
	message = append(message, mask...)
	return append(message, address...)
}

func TestDarwinNetworkMaskRetainsEveryPrefix(t *testing.T) {
	for _, width := range []int{32, 128} {
		for ones := 0; ones <= width; ones++ {
			for _, compact := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%d/compact-%t", width, ones, compact), func(t *testing.T) {
					input := darwinMaskMessage(darwinMaskFixture(width, ones, compact))
					original := append([]byte(nil), input...)
					actual, err := desktopDarwinNetworkMask(0x27, input, width)
					if err != nil || actual != ones || !bytes.Equal(input, original) {
						t.Fatal("original native prefix changed or its bytes were rewritten", actual, ones, err)
					}
				})
			}
		}
	}
}

func TestDarwinNetworkMaskRejectsIncompleteIdentity(t *testing.T) {
	original := darwinMaskMessage(darwinMaskFixture(128, 128, true))
	for _, fault := range []string{"missing-mask", "foreign-bit", "negative-bits", "wrong-width", "no-addresses", "truncated-prior", "truncated-mask", "truncated-padding", "unclaimed-tail", "oversized", "short-mask", "long-mask", "noncontiguous", "scope-suffix"} {
		t.Run(fault, func(t *testing.T) {
			input := append([]byte(nil), original...)
			addrs, width := int32(0x27), 128
			switch fault {
			case "missing-mask":
				addrs &^= 1 << 2
			case "foreign-bit":
				addrs |= 1 << 8
			case "negative-bits":
				addrs = -1
			case "wrong-width":
				width = 64
			case "no-addresses":
				input = nil
			case "truncated-prior":
				input = input[:7]
			case "truncated-mask":
				input = input[:31]
			case "truncated-padding":
				input = darwinMaskMessage(darwinMaskFixture(128, 65, true))[:27]
			case "unclaimed-tail":
				input = append(input, 0, 0, 0, 0)
			case "oversized":
				input = make([]byte, 8193)
			case "short-mask":
				input = darwinMaskMessage([]byte{4, 0, 0, 0})
			case "long-mask":
				mask := make([]byte, 32)
				mask[0] = 32
				input = darwinMaskMessage(mask)
			case "noncontiguous":
				input[16] = 0xfe
			case "scope-suffix":
				mask := darwinMaskFixture(128, 128, false)
				mask[27] = 1
				input = darwinMaskMessage(mask)
			}
			before := append([]byte(nil), input...)
			if actual, err := desktopDarwinNetworkMask(addrs, input, width); err == nil || actual != 0 || !bytes.Equal(input, before) {
				t.Fatal("incomplete or changed mask became route identity", actual, err)
			}
		})
	}
}
