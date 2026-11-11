package main

import (
	"errors"

	"router-vpn/internal/common"
)

var errOrderedNodeChainDispatch = errors.New("ordered selected-node path requires its captured native chain runtime")

// A saved ordered selection cannot fall through an older single-node or pair
// dispatcher. The typed chain path must capture every member before stopping
// another usable connection or creating any native process.
func guardLegacyOrderedNodeDispatch(profile common.RouterProfile) error {
	if profile.MultihopEnabled && len(profile.MultihopNodes) != 0 {
		return errOrderedNodeChainDispatch
	}
	return nil
}
