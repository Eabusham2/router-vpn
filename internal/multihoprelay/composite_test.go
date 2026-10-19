package multihoprelay

import (
	"context"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/nativecomposite"
)

func compositeExit(t *testing.T, mode, layer string) Exit {
	t.Helper()
	rawMode := "reality-vision"
	if mode == "max" {
		rawMode = "reality-pq-vision"
	}
	exit := nativeXrayExit(t, rawMode)
	exit.Mode = mode
	tcp := exit.Transport
	tcp["mode"], tcp["tag"] = mode, nativecomposite.TCPTag
	if mode == "max" {
		var raw map[string]any
		if err := json.Unmarshal([]byte(tcp["config_json"].(string)), &raw); err != nil {
			t.Fatal(err)
		}
		pq, err := mlkem.NewDecapsulationKey768(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		user := raw["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
		user["encryption"] = "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(pq.EncapsulationKey().Bytes())
		encoded, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		tcp["config_json"] = string(encoded)
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	if mode == "ss-v2ray" {
		tcp = map[string]any{"type": "shadowsocks", "tag": nativecomposite.TCPTag, "server": "192.0.2.9", "server_port": 10443, "method": "2022-blake3-aes-256-gcm", "password": key, "plugin": "v2ray-plugin", "plugin_opts": "tls;host=paired.example.test;path=/shadowsocks", "network": "tcp"}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "paired.example.test"}, DNSNames: []string{"paired.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, spec, spec, public, private)
	if err != nil {
		t.Fatal(err)
	}
	udp := map[string]any{"type": "hysteria2", "tag": nativecomposite.UDPTag, "server": "192.0.2.9", "server_port": 8443, "password": "paired-private-hysteria", "obfs": map[string]any{"type": "salamander", "password": "paired-private-mask"}, "tls": map[string]any{"enabled": true, "server_name": "paired.example.test", "certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))}}
	exit.Transport = map[string]any{"type": nativecomposite.PlanType, "mode": mode, "node_id": exit.NodeID, "start_layer": "", "tcp": tcp, "udp": udp}
	if layer != "" {
		exit.StartLayer = &StartLayer{Mode: layer, API: "http://10.88.0.1:8787", Transport: map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.9", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": key}}
	}
	if err := nativecomposite.ValidatePlan(exit.Transport, mode, exit.NodeID, ""); err != nil {
		t.Fatal(err)
	}
	return exit
}

func TestCompositeRelayKeepsBothCapturedTransportsAndExactLease(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				cfg, r := config(), &runner{}
				exit := compositeExit(t, mode, layer)
				cfg.Exits = []Exit{exit}
				captured, err := compositePlan(exit)
				if err != nil {
					t.Fatal(err)
				}
				manager, err := New(cfg, req().EntryNodeID, r)
				if err != nil {
					t.Fatal(err)
				}
				defer manager.Close(context.Background())
				q, peer := req(), netip.MustParseAddr("10.77.0.2")
				q.ExitMode = mode
				q.ExitStartLayer = layer
				wrong := q
				wrong.ExitStartLayer = "aes-256-gcm"
				if layer == "aes-256-gcm" {
					wrong.ExitStartLayer = ""
				}
				if _, err = manager.Create(context.Background(), peer, wrong); !errors.Is(err, ErrUnavailable) || r.starts != 0 {
					t.Fatal("wrong encryption selected a different paired graph")
				}
				// The live manager must retain its owned copy of both credentials.
				exit.Transport["udp"].(map[string]any)["password"] = "changed-by-caller"
				lease, err := manager.Create(context.Background(), peer, q)
				if err != nil || lease.ExitMode != mode || lease.ExitStartLayer != layer || lease.ExitNodeID != exit.NodeID || r.starts != 1 {
					t.Fatal("complete relay lease lost node, mode or layer", err)
				}
				var graph map[string]any
				if err = json.Unmarshal(r.configs[0], &graph); err != nil {
					t.Fatal(err)
				}
				actual, err := nativecomposite.Extract(graph, mode, exit.NodeID, layer, "exit", CompositePrefix, "")
				if err != nil || !reflect.DeepEqual(actual, captured) {
					t.Fatal("relay discarded or changed an authenticated lane", err)
				}
				if graph["endpoints"] != nil || len(graph["inbounds"].([]any)) != 1 {
					t.Fatal("relay invented another network interface or listener")
				}
				dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["detour"] != "exit" || dns["server"] != exit.DNS {
					t.Fatal("selected DNS escaped complete exit")
				}
				guard := graph["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
				if guard["source_ip_cidr"].([]any)[0] != "10.77.0.2/32" || guard["invert"] != true || guard["action"] != "reject" {
					t.Fatal("paired relay lost its client source guard")
				}
				again, err := manager.Create(context.Background(), peer, q)
				if err != nil || again.Password != lease.Password || r.starts != 1 {
					t.Fatal("renewal replaced exact owned graph")
				}
				available, err := json.Marshal(manager.Available())
				if err != nil {
					t.Fatal(err)
				}
				for _, private := range []string{"password", "transport", "config_json", "paired-private-mask", "paired-private-hysteria", "changed-by-caller"} {
					if strings.Contains(string(available), private) {
						t.Fatal("public capability leaked paired source")
					}
				}
				if err = manager.Delete(context.Background(), peer, q); err != nil || r.processes[0].alive {
					t.Fatal("complete relay did not release owned listener", err)
				}
			})
		}
	}
}

func TestCompositeRelayRejectsIncompleteOrWeakenedPairing(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, fault := range []string{"missing-TCP", "missing-UDP", "weak-UDP", "weak-TLS", "foreign-node", "foreign-layer", "foreign-API", "foreign-detour", "wrong-label", "runtime-selector"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				exit := compositeExit(t, mode, "aes-256-gcm")
				switch fault {
				case "missing-TCP":
					delete(exit.Transport, "tcp")
				case "missing-UDP":
					delete(exit.Transport, "udp")
				case "weak-UDP":
					exit.Transport["udp"].(map[string]any)["type"] = "direct"
				case "weak-TLS":
					exit.Transport["udp"].(map[string]any)["tls"].(map[string]any)["insecure"] = true
				case "foreign-node":
					exit.Transport["node_id"] = strings.Repeat("c", 64)
				case "foreign-layer":
					exit.StartLayer.Transport["server"] = "192.0.2.99"
				case "foreign-API":
					exit.StartLayer.API = "http://127.0.0.1:8787"
				case "foreign-detour":
					exit.Transport["udp"].(map[string]any)["detour"] = "bypass"
				case "wrong-label":
					exit.Mode = "shadowsocks"
				case "runtime-selector":
					exit.Transport["type"] = "selector"
				}
				cfg, r := config(), &runner{}
				cfg.Exits = []Exit{exit}
				if _, err := New(cfg, req().EntryNodeID, r); err == nil || r.starts != 0 {
					t.Fatal("invalid paired source reached an owned process")
				}
			})
		}
	}
}

func TestExportPinnedCoreCompositeRelayConfigurations(t *testing.T) {
	root := os.Getenv("ROUTER_VPN_RELAY_FIXTURES_DIR")
	if root == "" {
		t.Skip("fixture export requested by native image build")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			exit := compositeExit(t, mode, layer)
			lease := Lease{Request: Request{ExitMode: mode, ExitStartLayer: layer}, Host: "10.77.0.1", Port: 26240, Username: "public-fixture-user", Password: "public-fixture-password"}
			body, err := Build(exit, netip.MustParseAddr("10.77.0.2"), lease)
			if err != nil {
				t.Fatal(err)
			}
			label := layer
			if label == "" {
				label = "off"
			}
			if err = os.WriteFile(filepath.Join(root, mode+"-"+label+".json"), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
