package multihoprelay

import "router-vpn/internal/nativeopenvpn"

// NodeChainOpenVPNPairDigest binds the canonical independent provider and
// pairing identities without exposing provider names or private credentials in
// authenticated discovery. Both roles retain their original private source.
func NodeChainOpenVPNPairDigest(local, server nativeopenvpn.PublicDescriptor) (string, error) {
	if err := nativeopenvpn.ValidatePublicPair(local, server); err != nil {
		return "", err
	}
	return nodeChainDigest("routervpn-node-chain-openvpn-pair-v1", []nativeopenvpn.PublicDescriptor{local, server})
}
