package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"router-vpn/internal/common"
)

const desktopNodeProofKind = "router-vpn-private-agent-v1"
const nodeProofDomain = "router-vpn-node-proof-v1\n"

func nodeProofIDFromWGConfig(data []byte) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	section := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")))
			continue
		}
		if section != "peer" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "PublicKey") {
			continue
		}
		publicKey := strings.TrimSpace(value)
		if publicKey == "" {
			return "", errors.New("WireGuard peer PublicKey is empty")
		}
		digest := sha256.Sum256([]byte(nodeProofDomain + publicKey))
		return hex.EncodeToString(digest[:]), nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read WireGuard profile: %w", err)
	}
	return "", errors.New("WireGuard profile has no server peer PublicKey")
}

func expectedNodeProofID(p common.RouterProfile) (string, error) {
	if !validProfileID(p.ID) {
		return "", errors.New("selected router profile id is invalid")
	}
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	profilePath := filepath.Join(root, "generated", p.ID, "wg", "wg.conf")
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return "", fmt.Errorf("selected router has no saved WireGuard identity profile; re-link/import this node: %w", err)
	}
	derived, err := nodeProofIDFromWGConfig(data)
	if err != nil {
		return "", fmt.Errorf("derive selected router node identity: %w", err)
	}
	if !common.ValidNodeProofID(derived) {
		return "", errors.New("derived selected router node identity is invalid")
	}
	provided := strings.TrimSpace(p.NodeProofID)
	if provided != "" {
		if !common.ValidNodeProofID(provided) {
			return "", errors.New("selected router node proof id is invalid")
		}
		if provided != derived {
			return "", errors.New("selected router node proof id does not match its saved WireGuard server public key")
		}
	}
	return derived, nil
}

func validateSelectedNodeProof(p common.RouterProfile, body []byte) error {
	expected, err := expectedNodeProofID(p)
	if err != nil {
		return err
	}
	var proof struct {
		OK     bool   `json:"ok"`
		NodeID string `json:"node_id"`
		Proof  string `json:"proof"`
	}
	if err := json.Unmarshal(body, &proof); err != nil {
		return errors.New("path proof endpoint did not return valid Router VPN proof JSON")
	}
	if !proof.OK || proof.Proof != desktopNodeProofKind || proof.NodeID != expected {
		return errors.New("path proof endpoint identity did not match the selected Router VPN node")
	}
	return nil
}
