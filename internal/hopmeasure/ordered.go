package hopmeasure

import (
	"context"
	"errors"
	"regexp"
)

// Both digests and the zero-based position are emitted by the sealed chain
// compiler. The NodeChain adapter additionally checks the exact captured tag.
var orderedPrefixTag = regexp.MustCompile(`^routervpn-chain-[0-7]-[0-9a-f]{12}-node-[0-9a-f]{12}$`)

var orderedServerPrefixTag = regexp.MustCompile(`^routervpn-chain-server-[1-7]-[0-9a-f]{16}$`)

// NewOrderedServerContext keeps the original Local entry and exactly one
// positional Server source for every later private node. The shared execution
// adapter independently binds these tags to its actual selected runtime.
// Ordinary ordered and imported constructors do not admit these tags.
func NewOrderedServerContext(ctx context.Context, engine Engine, hops []Hop) (*Service, error) {
	if len(hops) < 2 {
		return nil, errors.New("ordered server measurement requires its complete node path")
	}
	return newContext(ctx, engine, hops, true, false, true)
}

// NewOrderedImportedServerContext retains one authenticated entry, one actual
// imported public-path proof and the authenticated final node. The two Server
// tags must have the same captured source digest and exact original positions.
// This does not widen either the ordinary Server or ordinary Local constructor.
func NewOrderedImportedServerContext(ctx context.Context, engine Engine, hops []Hop) (*Service, error) {
	if len(hops) != 3 || hops[0].Kind != "private-node" || hops[1].Kind != "public-path" || hops[2].Kind != "private-node" {
		return nil, errors.New("ordered imported server measurement requires one original public middle")
	}
	return newContext(ctx, engine, hops, true, true, true)
}
