package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

// Structural keys exercise compiler/pairing policy, not a KEM negotiation.
func pqPairingFixture(mode string) (map[string][]byte, string) {
	key := func(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }
	hash := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + key(2)))
	node := hex.EncodeToString(hash[:])
	tool, asset := "wg", "wg.conf"
	raw := "[Interface]\nAddress=10.88.0.2/32,fd88:88::2/128\nPrivateKey=" + key(3) + "\nDNS=10.77.0.1\nMTU=1400\n[Peer]\nPublicKey=" + key(2) + "\nPresharedKey=" + key(4) + "\nEndpoint=198.51.100.2:51820\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n"
	if mode == "awg2-pq" {
		tool, asset = "awg", "awg.conf"
		raw = strings.Replace(raw, "[Peer]", "Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n[Peer]", 1)
	}
	return map[string][]byte{asset: []byte(raw), "rosenpass-client-secret": bytes.Repeat([]byte{7}, 64), "rosenpass-client-public": bytes.Repeat([]byte{8}, 128), "rosenpass-server-public": bytes.Repeat([]byte{9}, 128), "rosenpass.env": []byte("ROSENPASS_TOOL=" + tool + "\nROSENPASS_INTERFACE=" + tool + "\nROSENPASS_WG_PEER=" + key(2) + "\nROSENPASS_KEY_OUT=rosenpass.psk\nROSENPASS_PORT=51822\n"), "rosenpass.toml": []byte("public_key = \"rosenpass-client-public\"\nsecret_key = \"rosenpass-client-secret\"\nlisten = []\nverbosity = \"Quiet\"\n[[peers]]\npublic_key = \"rosenpass-server-public\"\nendpoint = \"fixture.example.test:51822\"\nkey_out = \"rosenpass.psk\"\n")}, node
}
func TestPQRelayCompilerPreservesAllCapturedCredentials(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		assets, node := pqPairingFixture(mode)
		raw, _ := json.Marshal(assets)
		before := append([]byte(nil), raw...)
		var output bytes.Buffer
		if err := compilePQRelayProfile(bytes.NewReader(raw), &output, mode, node, "198.51.100.2"); err != nil {
			t.Fatal(err)
		}
		compiled, err := mobilemultihop.CompilePQProfile(mode, string(raw), node)
		if err != nil {
			t.Fatal(err)
		}
		var graph struct{ Endpoints []map[string]any }
		if json.Unmarshal([]byte(compiled), &graph) != nil {
			t.Fatal("invalid reference")
		}
		expected := graph.Endpoints[0]
		delete(expected, "system")
		delete(expected, "listen_port")
		expected["tag"] = "exit"
		expectedBytes, _ := json.Marshal(expected)
		if !bytes.Equal(bytes.TrimSpace(output.Bytes()), expectedBytes) || !bytes.Equal(raw, before) {
			t.Fatal("pairing changed captured assets")
		}
		var transport map[string]any
		if json.Unmarshal(output.Bytes(), &transport) != nil {
			t.Fatal("invalid output")
		}
		// The exact output must be accepted by the production server graph
		// builder, without acquiring a lease or starting a process.
		entry := multihoprelay.Exit{ID: "exit", Mode: mode, NodeID: node, DNS: "192.168.50.133", Transport: transport}
		lease := multihoprelay.Lease{Host: "10.77.0.1", Port: 26240, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48)}
		plan, err := multihoprelay.Build(entry, netip.MustParseAddr("10.77.0.2"), lease)
		if err != nil || len(plan) == 0 {
			t.Fatal("compiler output cannot be used by the relay", err)
		}
	}
}
func TestPQRelayCompilerRejectsReassignmentAndUnownedAssets(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, fault := range []string{"empty", "unknown", "duplicate", "missing-key", "same-public", "env-exec", "wrong-server", "hostname", "wrong-mode", "wrong-node", "extra-document"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				assets, node := pqPairingFixture(mode)
				selected := mode
				server := "198.51.100.2"
				switch fault {
				case "unknown":
					assets["run.sh"] = []byte("private-sentinel-never-execute")
				case "missing-key":
					delete(assets, "rosenpass-client-secret")
				case "same-public":
					assets["rosenpass-server-public"] = assets["rosenpass-client-public"]
				case "env-exec":
					assets["rosenpass.env"] = append(assets["rosenpass.env"], []byte("COMMAND=private-sentinel-never-execute\n")...)
				case "wrong-server":
					server = "198.51.100.3"
				case "hostname":
					server = "fixture.example.test"
				case "wrong-mode":
					selected = "wg"
				case "wrong-node":
					node = "not-a-node"
				}
				raw, _ := json.Marshal(assets)
				if fault == "empty" {
					raw = nil
				}
				if fault == "extra-document" {
					raw = append(raw, []byte("{}")...)
				}
				if fault == "duplicate" {
					raw = append(raw[:len(raw)-1], []byte(`,"stack.json":"e30=","stack.json":"e30="}`)...)
				}
				var out bytes.Buffer
				err := compilePQRelayProfile(bytes.NewReader(raw), &out, selected, node, server)
				if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private-sentinel") {
					t.Fatal("invalid pairing leaked output or was accepted", err)
				}
			})
		}
	}
}

type pqReadFault struct{}

func (pqReadFault) Read([]byte) (int, error) { return 0, errors.New("private-sentinel") }

type pqShortWriter struct{}

func (pqShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestPQRelayCompilerBoundedIO(t *testing.T) {
	assets, node := pqPairingFixture("wg-pq")
	raw, _ := json.Marshal(assets)
	for _, reader := range []io.Reader{pqReadFault{}, bytes.NewReader(bytes.Repeat([]byte{'x'}, maxPQPairingBytes+1))} {
		var out bytes.Buffer
		err := compilePQRelayProfile(reader, &out, "wg-pq", node, "198.51.100.2")
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private-sentinel") {
			t.Fatal("read failure leaked or passed")
		}
	}
	if err := compilePQRelayProfile(bytes.NewReader(raw), pqShortWriter{}, "wg-pq", node, "198.51.100.2"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short write ignored", err)
	}
	if err := compilePQRelayProfile(bytes.NewReader(raw), failedRelayOutput{}, "wg-pq", node, "198.51.100.2"); err == nil {
		t.Fatal("write failure ignored")
	}
}
