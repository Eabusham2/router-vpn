package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

func TestServerStreamCandidateUsesExistingRegistration(t *testing.T) {
	descriptor := pairingOrderedDescriptor(t, 2)
	lease, err := relayNodeChainValidationCapture(descriptor, "10.77.0.1", "10.77.0.2", 32001, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encode := func(x any) string {
		raw, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(server.PublicKey().Bytes())
	node := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + public))
	const host = "198.51.100.155"
	profile := map[string]any{"node_kind": "router-vpn", "id": "separately-paired", "node_proof_id": hex.EncodeToString(node[:]), "endpoint": host, "router_api": "http://10.99.0.1:8771", "api_token": "private-candidate-token", "adguard_ipv4": "10.99.0.53", "dns_mode": "home", "start_layer": "off", "ipv6_mode": "off", "mtu_policy": "auto", "home_lan_access": true, "kill_switch_policy": "on-connect"}
	ss := map[string]any{"type": "shadowsocks", "tag": "proxy", "server": host, "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{52}, 32))}
	cfg := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}}, "outbounds": []any{ss}, "route": map[string]any{"final": "proxy"}}
	files := encode(map[string]string{"sing-box.json": base64.StdEncoding.EncodeToString([]byte(encode(cfg)))})
	paired, err := mobilemultihop.NewNodeProfile("shadowsocks", files, encode(profile), "", "")
	if err != nil {
		t.Fatal(err)
	}
	input, err := paired.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	wg := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.99.0.2/32, fd99::2/128\nDNS = 10.99.0.53\nMTU = 1420\n[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n", base64.StdEncoding.EncodeToString(client.Bytes()), public, host)
	identity := encode(map[string]string{"wg.conf": base64.StdEncoding.EncodeToString([]byte(wg))})
	policy, err := mobilemultihop.NewNodeChainServerPolicy(encode(mobilemultihop.NodeChainServerSource{Schema: 1, EntryID: descriptor.EntryID, EntryNodeID: descriptor.EntryNodeID, EntryMode: descriptor.EntryMode, Nodes: []string{input}, IdentitySources: []string{identity}}))
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := lease.Digest()
	q := multihoprelay.NodeChainCandidateRequest{Schema: 2, Lease: lease.Request.Clone(), OwnerID: lease.OwnerID, CaptureSHA256: digest, Operation: strings.Repeat("a", 64), ExecutionSHA256: strings.Repeat("b", 64), Trial: strings.Repeat("d", 32), SelectionEpoch: 1, InventorySHA256: strings.Repeat("c", 64), Position: 1, CandidateID: "separately-paired", CandidateSourceSHA256: paired.SourceSHA256(), Address: host + ":8388", Password: strings.Repeat("f", 64), DeadlineAt: time.Now().Add(time.Minute).UnixMilli()}
	c, err := multihoprelay.NewNodeChainCandidateCapture(lease, q, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := &relayNodeChainExecRunner{sources: t.TempDir()}
	path := filepath.Join(r.sources, policy.SourceSHA256()+".json")
	write := func(name string) {
		t.Helper()
		if err := os.WriteFile(name, []byte(policy.Source()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(path)
	if _, _, err = r.originalCandidateSource(t.Context(), c); !errors.Is(err, multihoprelay.ErrCandidateNotRegistered) {
		t.Fatal("candidate outside the registry must produce a specific no-authority outcome", err)
	}
	r.registered = []multihoprelay.NodeChainDescriptor{policy.Descriptor()}
	got, current, err := r.originalCandidateSource(t.Context(), c)
	if err != nil || got != input || current == nil || !current() {
		t.Fatal("original registration", err)
	}
	changed := c.Clone()
	changed.Request.Address = "198.51.100.99:8388"
	if _, _, err = r.originalCandidateSource(t.Context(), changed); err == nil || errors.Is(err, multihoprelay.ErrCandidateNotRegistered) {
		t.Fatal("changed registered tuple became an allowed absence", err)
	}
	write(path + ".new")
	if err = os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	if current() {
		t.Fatal("equal-byte file replacement kept original authority")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.originalCandidateSource(t.Context(), c); err == nil {
		t.Fatal("unprotected candidate source acquired authority")
	}
}
