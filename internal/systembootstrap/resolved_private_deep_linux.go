//go:build linux

package systembootstrap

import "encoding/binary"

// NewResolvedPrivateDeepCandidate is an inert exact THREE-label unsigned
// address or negative candidate. It cannot be adopted using the two-label
// exception: its caller needs the separate completed DS dependency proof.
func NewResolvedPrivateDeepCandidate(question, packet []byte) (*ResolvedPrivateTLDCandidate, error) {
	negative := len(packet) >= 12 && binary.BigEndian.Uint16(packet[6:]) == 0
	return newResolvedPrivateTLDCandidate(question, packet, negative, 3)
}
