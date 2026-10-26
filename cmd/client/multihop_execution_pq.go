package main

import (
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// The paired PQ fingerprint and classical public key are one immutable lease
// choice. The private KEM and packet keys never leave their captured stores.
func (o *desktopRelayOwner) validPQPin() bool {
	return !mobilemultihop.IsPQMode(o.request.ExitMode) ||
		common.ValidNodeProofID(o.localPQIdentity) && common.ValidNodeProofID(o.serverPQIdentity) &&
			o.localPQIdentity != o.serverPQIdentity && o.request.ExpectedPQClientIdentity == o.serverPQIdentity
}
