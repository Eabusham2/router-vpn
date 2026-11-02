package desktopnetwork

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

type desktopDarwinInterfaceIdentity struct {
	Index    uint32
	Name     string
	Hardware string
	Type     uint8
}

// Decode the exact Darwin AF_LINK payload without pointer casts or borrowed
// storage. An incomplete identity is still useful to the numeric diagnostic,
// but cannot support retaining an unused interface.
func desktopDarwinInterfaceLinkIdentity(addresses uint32, raw []byte) (desktopDarwinInterfaceIdentity, bool) {
	const darwinRTAIFP, darwinAFLink = 0x10, 18
	if addresses != darwinRTAIFP || len(raw) < 8 || raw[1] != darwinAFLink {
		return desktopDarwinInterfaceIdentity{}, false
	}
	length, names, hardware, selectors := int(raw[0]), int(raw[5]), int(raw[6]), int(raw[7])
	if length < 8 || (length+3)&^3 != len(raw) || 8+names+hardware+selectors > length ||
		names == 0 || names > 63 || selectors != 0 {
		return desktopDarwinInterfaceIdentity{}, false
	}
	name := string(raw[8 : 8+names])
	if !utf8.ValidString(name) || strings.IndexFunc(name, func(v rune) bool { return v <= 0x20 || v == 0x7f }) >= 0 {
		return desktopDarwinInterfaceIdentity{}, false
	}
	return desktopDarwinInterfaceIdentity{Index: uint32(binary.LittleEndian.Uint16(raw[2:4])), Name: name,
		Hardware: net.HardwareAddr(raw[8+names : 8+names+hardware]).String(), Type: raw[4]}, true
}

type desktopDarwinUnusedInterface struct {
	original Link
}

// XNU permits an attached interface to retain MTU zero. Such a link remains
// part of the frozen cohort only when the captured Go identity and a complete
// same-index native read both describe an unused interface. No interface name,
// index, type or saved flag exempts a link from the ordinary change observer.
// The final projection independently rejects every address and routing use.
func desktopDarwinCaptureUnusedInterface(link Link, read func(uint32) (desktopDarwinInterfaceReadback, error)) (Link, error) {
	if link.Index == 0 || link.Index > 65535 || read == nil {
		return Link{}, desktopDarwinIncompleteInterface(link, nil)
	}
	observed, failure := read(link.Index)
	bad := func() (Link, error) {
		return Link{}, desktopDarwinIncompleteInterface(link, func(uint32) (desktopDarwinInterfaceReadback, error) {
			return observed, failure
		})
	}
	if failure != nil || link.Name == "" || !utf8.ValidString(link.Name) || link.LUID != 0 || link.MTU != 0 || link.Flags != 0 ||
		link.Hardware != "" || link.Policy != "" || link.darwinUnused != nil ||
		observed.Bytes <= 0 || observed.Bytes > 64<<10 || observed.Records != 1 || observed.Addresses != 0 ||
		len(observed.Shapes) != 1 || len(observed.identities) != 1 {
		return bad()
	}
	shape, identity := observed.Shapes[0], observed.identities[0]
	if shape.Index != link.Index || shape.MTU != 0 || shape.Flags != 0 || shape.AddressLength != 0 ||
		identity.Index != link.Index || identity.Name != link.Name || identity.Hardware != link.Hardware || identity.Type != shape.Type {
		return bad()
	}
	// This is read-only identity, not a policy setting or serialized authority.
	// Keep every native shape field in the ordinary canonical cohort key.
	link.Policy = fmt.Sprintf("darwin-ifinfo:%d:%d:%d:%d:%d:%d", shape.Index, shape.Type, shape.MTU, shape.Flags, shape.Physical, shape.AddressLength)
	link.darwinUnused = &desktopDarwinUnusedInterface{original: link}
	return link, nil
}

func desktopDarwinUnusedInterfaceMatches(link Link) bool {
	proof := link.darwinUnused
	if proof == nil {
		return false
	}
	link.darwinUnused = nil
	return link.MTU == 0 && link.Flags == 0 && link == proof.original
}
