package desktopnetwork

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
)

// Numeric shape alone cannot replace the captured interface, supply a
// receipt or admit a snapshot. Names, hardware addresses and IPs never enter
// this diagnostic record.
type desktopDarwinInterfaceShape struct {
	Index, MTU, Flags uint32
	Type, Physical    uint8
	AddressLength     uint8
}

type desktopDarwinInterfaceReadback struct {
	Bytes, Records, Addresses int
	Shapes                    []desktopDarwinInterfaceShape
	// Complete AF_LINK identities are private admission evidence. The
	// diagnostic below intentionally prints only the numeric shape.
	identities []desktopDarwinInterfaceIdentity
}

func desktopDarwinIncompleteInterface(link Link, read func(uint32) (desktopDarwinInterfaceReadback, error)) error {
	original := fmt.Errorf("network snapshot contains an incomplete interface (index=%d luid=%d name_present=%t mtu=%d flags=%d)", link.Index, link.LUID, link.Name != "", link.MTU, link.Flags)
	if link.Index == 0 || link.Index > 65535 || read == nil {
		return fmt.Errorf("%w; Darwin interface readback unavailable for captured index", original)
	}
	observed, failure := read(link.Index)
	status := "observed"
	var number syscall.Errno
	if failure != nil {
		status = "read-failed"
		errors.As(failure, &number)
	}
	if observed.Bytes < 0 || observed.Bytes > 64<<10 || observed.Records < 0 || observed.Records > 256 ||
		observed.Addresses < 0 || observed.Addresses > observed.Records || len(observed.Shapes) > 4 {
		status = "out-of-bounds"
		observed.Shapes = nil
	}
	var rows strings.Builder
	for _, row := range observed.Shapes {
		fmt.Fprintf(&rows, "%d:%d:%d:%d:%d:%d;", row.Index, row.Type, row.MTU, row.Flags, row.Physical, row.AddressLength)
	}
	// Always retain the original rejection, including when another native read
	// succeeds, reports a different MTU, or observes a replacement interface.
	return fmt.Errorf("%w; Darwin interface readback (state=%s bytes=%d records=%d address_records=%d errno=%d native_index_type_mtu_flags_physical_addrlen=%s)",
		original, status, observed.Bytes, observed.Records, observed.Addresses, number, rows.String())
}
