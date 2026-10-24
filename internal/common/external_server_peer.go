package common

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
)

func (peer *ExternalServerPeer) UnmarshalJSON(raw []byte) error {
	bad := errors.New("external server peer requires only its public key, addresses, MTU and optional keepalive")
	fields, err := externalLayerJSONObject(raw)
	if err != nil || len(fields) < 3 || len(fields) > 4 {
		return bad
	}
	for key, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return bad
		}
		switch key {
		case "public_key", "addresses", "mtu", "persistent_keepalive_interval":
		default:
			return bad
		}
	}
	for _, key := range []string{"public_key", "addresses", "mtu"} {
		if _, exists := fields[key]; !exists {
			return bad
		}
	}
	type plain ExternalServerPeer
	var decoded plain
	if json.Unmarshal(raw, &decoded) != nil {
		return bad
	}
	*peer = ExternalServerPeer(decoded)
	return nil
}

func validateExternalServerPeer(ext *ExternalNodeConfig) error {
	if ext.ServerPeer == nil {
		return nil
	}
	bad := errors.New("external packet comparison requires distinct canonical local/server peer identities and assigned addresses")
	var local *ExternalWireGuardConfig
	switch ext.Protocol {
	case "wireguard":
		local = ext.WireGuard
	case "amneziawg":
		if ext.AmneziaWG != nil {
			local = &ext.AmneziaWG.ExternalWireGuardConfig
		}
	}
	peer := ext.ServerPeer
	if local == nil || peer.MTU < 1280 || peer.MTU > 9000 || peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
		return bad
	}
	privateBytes, err := base64.StdEncoding.Strict().DecodeString(local.PrivateKey)
	if err != nil || len(privateBytes) != 32 {
		return bad
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	clear(privateBytes)
	if err != nil {
		return bad
	}
	publicBytes, err := base64.StdEncoding.Strict().DecodeString(peer.PublicKey)
	if err != nil || !externalCanonicalX25519Public(publicBytes) || base64.StdEncoding.EncodeToString(publicBytes) != peer.PublicKey || bytes.Equal(private.PublicKey().Bytes(), publicBytes) {
		return bad
	}
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return bad
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return bad
	}
	clear(shared)
	localFamilies, localAddresses, err := externalPacketAddresses(local.Addresses)
	if err != nil {
		return bad
	}
	serverFamilies, serverAddresses, err := externalPacketAddresses(peer.Addresses)
	if err != nil || len(localFamilies) != len(serverFamilies) {
		return bad
	}
	for family := range localFamilies {
		if !serverFamilies[family] {
			return bad
		}
	}
	for address := range serverAddresses {
		if localAddresses[address] {
			return bad
		}
	}
	return nil
}

func externalCanonicalX25519Public(raw []byte) bool {
	if len(raw) != 32 || raw[31]&128 != 0 {
		return false
	}
	for i := 31; i > 0; i-- {
		limit := byte(255)
		if i == 31 {
			limit = 127
		}
		if raw[i] < limit {
			return true
		}
	}
	return raw[0] < 237
}

func externalPacketAddresses(addresses []string) (map[bool]bool, map[netip.Addr]bool, error) {
	bad := errors.New("packet peer requires one canonical assigned address per IP family")
	if len(addresses) < 1 || len(addresses) > 2 {
		return nil, nil, bad
	}
	families, seen := map[bool]bool{}, map[netip.Addr]bool{}
	for _, text := range addresses {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.String() != text || prefix.Addr().Is4In6() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsLoopback() || families[prefix.Addr().Is4()] {
			return nil, nil, bad
		}
		families[prefix.Addr().Is4()], seen[prefix.Addr()] = true, true
	}
	return families, seen, nil
}
