package hopmeasure

import (
	"context"
	"errors"
	"regexp"
)

// PhysicalTraversalDepth is the existing native recursion budget shared by
// node and DNS validation. Each ordered node requires at least one traversal
// frame. Native graph validation still accounts for every auxiliary frame.
const PhysicalTraversalDepth = 96

// Both digests and the zero-based position come from the sealed chain. The
// constructor checks the exact decimal index as well as the ordered inventory.
var orderedPrefixTag = regexp.MustCompile(`^routervpn-chain-(0|[1-9][0-9]*)-[0-9a-f]{12}-node-[0-9a-f]{12}$`)

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

// NewOrderedImportedSSServerPrefixContext keeps one original Local entry,
// independently captured paired Server prefixes, one penultimate imported SS
// public path, and a paired final. The execution adapter binds the schema2
// source; the shared validator retains every role, tag and Server digest.
func NewOrderedImportedSSServerPrefixContext(ctx context.Context, engine Engine, hops []Hop) (*Service, error) {
	if len(hops) < 3 || len(hops) > 8 {
		return nil, errors.New("ordered imported SS Server measurement requires its complete captured prefix")
	}
	for i, hop := range hops {
		want := "private-node"
		if i == len(hops)-2 {
			want = "public-path"
		}
		if hop.Kind != want {
			return nil, errors.New("ordered imported SS Server measurement changed its captured public position")
		}
	}
	return newContext(ctx, engine, hops, true, true, true)
}

// NewOrderedCONNECTServerPrefixContext accepts only the complete typed remote
// prefix tag inventory. The caller retains its original CONNECT binding.
func NewOrderedCONNECTServerPrefixContext(ctx context.Context, engine Engine, hops []Hop) (*Service, error) {
	if len(hops) < 3 || len(hops) > 8 {
		return nil, errors.New("ordered CONNECT Server measurement requires its complete captured prefix")
	}
	for i, hop := range hops {
		want := "private-node"
		if i == len(hops)-2 {
			want = "public-path"
		}
		if hop.Kind != want {
			return nil, errors.New("ordered CONNECT Server measurement changed its captured public position")
		}
	}
	return newContext(ctx, engine, hops, true, true, true)
}

// NewOrderedSOCKSServerPrefixContext accepts only the complete typed remote
// prefix tag inventory. The caller retains its original SOCKS binding.
func NewOrderedSOCKSServerPrefixContext(ctx context.Context, engine Engine, hops []Hop) (*Service, error) {
	if len(hops) < 3 || len(hops) > 8 {
		return nil, errors.New("ordered SOCKS Server measurement requires its complete captured prefix")
	}
	for i, hop := range hops {
		want := "private-node"
		if i == len(hops)-2 {
			want = "public-path"
		}
		if hop.Kind != want {
			return nil, errors.New("ordered SOCKS Server measurement changed its captured public position")
		}
	}
	return newContext(ctx, engine, hops, true, true, true)
}

// NewOrderedOpenVPNServerPrefixContext retains the exact typed remote tag and
// public penultimate position; native endpoint ownership remains with its caller.
func NewOrderedOpenVPNServerPrefixContext(ctx context.Context, engine Engine, hops []Hop) (*Service, error) {
	if len(hops) < 3 || len(hops) > 8 {
		return nil, errors.New("ordered OpenVPN Server measurement requires its complete captured prefix")
	}
	for i, hop := range hops {
		want := "private-node"
		if i == len(hops)-2 {
			want = "public-path"
		}
		if hop.Kind != want {
			return nil, errors.New("ordered OpenVPN Server measurement changed its captured public position")
		}
	}
	return newContext(ctx, engine, hops, true, true, true)
}
