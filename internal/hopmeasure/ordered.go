package hopmeasure

import "regexp"

// Both digests and the zero-based position are emitted by the sealed chain
// compiler. The NodeChain adapter additionally checks the exact captured tag.
var orderedPrefixTag = regexp.MustCompile(`^routervpn-chain-[0-7]-[0-9a-f]{12}-node-[0-9a-f]{12}$`)
