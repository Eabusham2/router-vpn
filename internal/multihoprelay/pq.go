package multihoprelay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/mobilepq"
)

// PacketMode includes PQ only when the independent negotiation is retained.
func PacketMode(mode string) bool { return awgpolicy.WireGuardFamily(mode) || mobilepq.IsMode(mode) }

func pqConfig(transport map[string]any) (mobilepq.Config, error) {
	var config mobilepq.Config
	bad := errors.New("invalid bounded paired PQ configuration")
	object, ok := transport["pq"].(map[string]any)
	if !ok || len(object) != 5 {
		return config, bad
	}
	raw, err := json.Marshal(object)
	if err != nil || len(raw) > 8*1024*1024 {
		return config, bad
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		config.Erase()
		return mobilepq.Config{}, bad
	}
	if err = config.Validate(); err != nil {
		config.Erase()
		return mobilepq.Config{}, bad
	}
	return config, nil
}

func pqIdentity(transport map[string]any) (string, error) {
	config, err := pqConfig(transport)
	if err != nil {
		return "", err
	}
	defer config.Erase()
	return mobilepq.ClientIdentity(config)
}

// Relay validation is independent of mobile configuration compilation. Requests
// cannot introduce keys, helper commands or a second routing owner: this map is
// loaded only from the administrator's private paired registry.
func validatePQTransport(p map[string]any, mode, nodeID string) error {
	bad := errors.New("PQ relay transport lost its captured protocol, node or peer")
	if !mobilepq.IsMode(mode) || !proofID.MatchString(nodeID) || p["type"] != "routervpn-pq" || p["mode"] != mode || p["node_id"] != nodeID || !key32(p["private_key"]) {
		return bad
	}
	peers, ok := p["peers"].([]any)
	if !ok || len(peers) != 1 {
		return bad
	}
	peer, ok := peers[0].(map[string]any)
	if !ok || !literalServer(peer["address"]) || !validPort(peer["port"]) || !key32(peer["public_key"]) {
		return bad
	}
	if mode == "awg2-pq" {
		if err := validateAmnezia(p, peer); err != nil {
			return err
		}
	} else {
		if params, exists := p["amnezia"]; exists && params != nil {
			if values, ok := params.(map[string]any); !ok || len(values) != 0 {
				return bad
			}
		}
		hash := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + peer["public_key"].(string)))
		if hex.EncodeToString(hash[:]) != nodeID {
			return bad
		}
		if err := validatePacketPeer(p, peer); err != nil {
			return err
		}
	}
	config, err := pqConfig(p)
	if err != nil {
		return err
	}
	defer config.Erase()
	host, _, err := net.SplitHostPort(config.Endpoint)
	if err != nil || host != peer["address"] {
		return bad
	}
	return nil
}
