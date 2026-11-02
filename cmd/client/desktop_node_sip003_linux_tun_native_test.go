//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

// The same retained installed controller owns both independent SS2022/plugin
// TCP and Hysteria2 UDP lanes. Each named scenario retains the full original
// native journal, guard, TUN, proof, teardown and restoration assertions.
var linuxHostTUNSIP003Cases = []string{
	"ss-v2ray-off-public-connect",
	"ss-v2ray-off-home-lan",
	"ss-v2ray-off-tcp-key",
	"ss-v2ray-off-tcp-host",
	"ss-v2ray-off-tcp-path",
	"ss-v2ray-off-tcp-server-name",
	"ss-v2ray-off-tcp-certificate",
	"ss-v2ray-off-udp-key",
	"ss-v2ray-off-udp-trust",
	"ss-v2ray-off-udp-salamander",
	"ss-v2ray-off-resolver-failure",
	"ss-v2ray-off-wrong-node",
	"ss-v2ray-off-active-network-change",
	"ss-v2ray-off-cancelled-proof",
	"ss-v2ray-off-restore-sealed",
	"ss-v2ray-off-always",
	"ss-v2ray-off-cover-connect",
	"ss-v2ray-off-cover-restore",
	"ss-v2ray-off-cover-replies-lost",
	"ss-v2ray-off-cover-wrong-node",
	"ss-v2ray-off-cover-no-replies",
	"ss-v2ray-off-mtu-rollback",
	"ss-v2ray-off-mtu-commit",
	"ss-v2ray-aes-public-connect",
	"ss-v2ray-aes-home-lan",
	"ss-v2ray-aes-tcp-key",
	"ss-v2ray-aes-tcp-host",
	"ss-v2ray-aes-tcp-path",
	"ss-v2ray-aes-tcp-server-name",
	"ss-v2ray-aes-tcp-certificate",
	"ss-v2ray-aes-udp-key",
	"ss-v2ray-aes-udp-trust",
	"ss-v2ray-aes-udp-salamander",
	"ss-v2ray-aes-resolver-failure",
	"ss-v2ray-aes-wrong-node",
	"ss-v2ray-aes-active-network-change",
	"ss-v2ray-aes-cancelled-proof",
	"ss-v2ray-aes-restore-sealed",
	"ss-v2ray-aes-always",
	"ss-v2ray-aes-cover-connect",
	"ss-v2ray-aes-cover-restore",
	"ss-v2ray-aes-cover-replies-lost",
	"ss-v2ray-aes-cover-wrong-node",
	"ss-v2ray-aes-cover-no-replies",
	"ss-v2ray-aes-mtu-rollback",
	"ss-v2ray-aes-mtu-commit",
	"ss-v2ray-whitening-public-connect",
	"ss-v2ray-whitening-home-lan",
	"ss-v2ray-whitening-tcp-key",
	"ss-v2ray-whitening-tcp-host",
	"ss-v2ray-whitening-tcp-path",
	"ss-v2ray-whitening-tcp-server-name",
	"ss-v2ray-whitening-tcp-certificate",
	"ss-v2ray-whitening-udp-key",
	"ss-v2ray-whitening-udp-trust",
	"ss-v2ray-whitening-udp-salamander",
	"ss-v2ray-whitening-resolver-failure",
	"ss-v2ray-whitening-wrong-node",
	"ss-v2ray-whitening-active-network-change",
	"ss-v2ray-whitening-cancelled-proof",
	"ss-v2ray-whitening-restore-sealed",
	"ss-v2ray-whitening-always",
	"ss-v2ray-whitening-cover-connect",
	"ss-v2ray-whitening-cover-restore",
	"ss-v2ray-whitening-cover-replies-lost",
	"ss-v2ray-whitening-cover-wrong-node",
	"ss-v2ray-whitening-cover-no-replies",
	"ss-v2ray-whitening-mtu-rollback",
	"ss-v2ray-whitening-mtu-commit",
	"ss-v2ray-aes-wrong-layer-key",
	"ss-v2ray-whitening-wrong-layer-key",
	"ss-v2ray-whitening-wrong-whitening",
}

func linuxHostTUNSIP003Case(scenario string) bool {
	for _, value := range linuxHostTUNSIP003Cases {
		if value == scenario {
			return true
		}
	}
	return false
}
func linuxHostTUNSIP003Layer(scenario string) string {
	if !linuxHostTUNSIP003Case(scenario) {
		return ""
	}
	if strings.HasPrefix(scenario, "ss-v2ray-aes-") {
		return common.StartLayerAES256GCM
	}
	if strings.HasPrefix(scenario, "ss-v2ray-whitening-") {
		return common.StartLayerAES256GCMXOR
	}
	return ""
}
func linuxHostTUNSIP003Action(scenario string) string {
	if !linuxHostTUNSIP003Case(scenario) {
		return ""
	}
	for _, prefix := range []string{"ss-v2ray-off-", "ss-v2ray-aes-", "ss-v2ray-whitening-"} {
		if strings.HasPrefix(scenario, prefix) {
			return strings.TrimPrefix(scenario, prefix)
		}
	}
	return ""
}
func linuxHostTUNSIP003TCPFault(scenario string) bool {
	switch linuxHostTUNSIP003Action(scenario) {
	case "tcp-key", "tcp-host", "tcp-path", "tcp-server-name", "tcp-certificate":
		return true
	}
	return false
}
func linuxHostTUNSIP003DNS(peer *linuxHostTUNPeer, reply linuxHostTUNPeerReply) bool {
	if peer.mode != "ss-v2ray" {
		return false
	}
	return reply.UDPBranchRawUDP > 0 && reply.UDPBranchUDP > 0 && reply.UDPBranchTCP == 0 && reply.ProtocolUDP == 0 &&
		(peer.layer == "" || reply.RawUDP > 0 && reply.PlainUDP > 0)
}
func linuxHostTUNSIP003Rejected(scenario string, reply linuxHostTUNPeerReply) bool {
	if !linuxHostTUNSIP003Case(scenario) {
		return false
	}
	if reply.DNSQueries != 0 || reply.RouterQueries != 0 || reply.ProtocolTCP != 0 || reply.ProtocolUDP != 0 || reply.UDPBranchTCP != 0 || reply.UDPBranchUDP != 0 {
		return false
	}
	switch linuxHostTUNSIP003Action(scenario) {
	case "udp-key", "udp-trust", "udp-salamander":
		return reply.UDPBranchRawUDP > 0
	case "wrong-layer-key", "wrong-whitening":
		return reply.RawUDP > 0 && reply.PlainUDP == 0 && reply.ProtocolRawTCP == 0 && reply.UDPBranchRawUDP == 0
	}
	return false
}

func linuxHostTUNSIP003Assets(t *testing.T, peer *linuxHostTUNPeer, scenario string) map[string][]byte {
	t.Helper()
	if peer.mode != "ss-v2ray" || peer.layer != linuxHostTUNSIP003Layer(scenario) || !linuxHostTUNSIP003Case(scenario) || peer.protocolFiles == "" {
		t.Fatal("SIP003 fixture lost its exact captured source")
	}
	var encoded map[string]string
	if json.Unmarshal([]byte(peer.protocolFiles), &encoded) != nil || len(encoded) != 3 || encoded["sing-box.json"] == "" || encoded["sslocal.json"] == "" || encoded["cert.pem"] == "" {
		t.Fatal("SIP003 fixture lost either private lane or selected CA")
	}
	assets := map[string][]byte{}
	for name, value := range encoded {
		raw, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) == 0 || len(raw) > 32<<10 || base64.StdEncoding.EncodeToString(raw) != value {
			t.Fatal("SIP003 source bytes changed", err)
		}
		assets[name] = raw
	}
	var helper map[string]any
	var graph map[string]any
	if json.Unmarshal(assets["sslocal.json"], &helper) != nil || json.Unmarshal(assets["sing-box.json"], &graph) != nil {
		t.Fatal("SIP003 lost its two exact JSON sources")
	}
	outbounds, ok := graph["outbounds"].([]any)
	if !ok || len(outbounds) != 3 {
		t.Fatal("SIP003 fixture acquired another runtime lane")
	}
	tcp, ok := outbounds[0].(map[string]any)
	if !ok {
		t.Fatal("SIP003 missing TCP wrapper")
	}
	udp, ok := outbounds[1].(map[string]any)
	if !ok {
		t.Fatal("SIP003 missing UDP branch")
	}
	tls, ok := udp["tls"].(map[string]any)
	if !ok {
		t.Fatal("SIP003 missing UDP trust")
	}
	obfs, ok := udp["obfs"].(map[string]any)
	if !ok {
		t.Fatal("SIP003 missing UDP Salamander")
	}
	plugin, ok := helper["plugin_opts"].(string)
	const prefix = "tls;host=captured-sip003.test;path=/captured-shadowsocks;certRaw="
	if !ok || !strings.HasPrefix(plugin, prefix) || len(plugin) <= len(prefix) || strings.Contains(plugin[len(prefix):], ";") {
		t.Fatal("SIP003 fixture changed selected TLS host/path/CA")
	}
	certificate, err := base64.StdEncoding.Strict().DecodeString(plugin[len(prefix):])
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certificate)
	if err != nil || cert.VerifyHostname("captured-sip003.test") != nil {
		t.Fatal("SIP003 fixture lost its real selected TCP certificate", err)
	}
	key, ok := helper["password"].(string)
	if !ok {
		t.Fatal("SIP003 missing TCP credential")
	}
	keyBytes, err := base64.StdEncoding.Strict().DecodeString(key)
	if err != nil || len(keyBytes) != 32 || key == peer.password || helper["method"] != "2022-blake3-aes-256-gcm" || helper["mode"] != "tcp_only" || helper["plugin"] != "v2ray-plugin" || helper["server"] != peer.baseAddress.Addr().String() || helper["server_port"] != float64(peer.baseAddress.Port()) || helper["local_address"] != "127.0.0.1" || helper["local_port"] != float64(1092) ||
		tcp["type"] != "socks" || tcp["tag"] != "tcp-stack" || tcp["server"] != "127.0.0.1" || tcp["server_port"] != float64(1092) || tcp["version"] != "5" ||
		udp["type"] != "hysteria2" || udp["tag"] != "udp-stack" || udp["server"] != peer.udpBranchAddress.Addr().String() || udp["server_port"] != float64(peer.udpBranchAddress.Port()) ||
		tls["enabled"] != true || tls["insecure"] == true || tls["server_name"] != "captured-node.test" || tls["certificate_path"] != "cert.pem" || obfs["type"] != "salamander" {
		t.Fatal("SIP003 changed its endpoint, credential, protocol, trust or separate lane")
	}
	clear(keyBytes)
	password, ok := udp["password"].(string)
	if !ok || password == "" {
		t.Fatal("SIP003 lost independent UDP credential")
	}
	mask, ok := obfs["password"].(string)
	if !ok || mask == "" || mask == password {
		t.Fatal("SIP003 lost separate Salamander source")
	}
	// Positive cases copy the complete original three byte strings. Only the
	// named negative mutates its one authentication/trust field.
	action := linuxHostTUNSIP003Action(scenario)
	switch action {
	case "tcp-key":
		helper["password"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32))
	case "tcp-host":
		helper["plugin_opts"] = strings.Replace(plugin, "host=captured-sip003.test", "host=captured-sip003-alias.test", 1)
	case "tcp-path":
		helper["plugin_opts"] = strings.Replace(plugin, "path=/captured-shadowsocks", "path=/unrelated-path", 1)
	case "tcp-server-name":
		helper["plugin_opts"] = strings.Replace(plugin, "host=captured-sip003.test", "host=wrong-node.test", 1)
	case "tcp-certificate":
		block, rest := pem.Decode(assets["cert.pem"])
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatal("SIP003 negative lost its other valid certificate")
		}
		helper["plugin_opts"] = prefix + base64.StdEncoding.EncodeToString(block.Bytes)
	case "udp-key":
		udp["password"] = password + "-wrong"
	case "udp-trust":
		tls["server_name"] = "wrong-node.test"
	case "udp-salamander":
		obfs["password"] = mask + "-wrong"
	}
	if linuxHostTUNSIP003TCPFault(scenario) {
		raw, err := json.Marshal(helper)
		if err != nil {
			t.Fatal(err)
		}
		assets["sslocal.json"] = raw
	}
	if strings.HasPrefix(action, "udp-") {
		raw, err := json.Marshal(graph)
		if err != nil {
			t.Fatal(err)
		}
		assets["sing-box.json"] = raw
	}
	return assets
}

// A bad TCP credential may still pass the independent selected-DNS readiness.
// It must then fail the real routed Router proof, without reporting Connected
// or borrowing the healthy UDP response as evidence for its TCP lane.
func linuxHostTUNSIP003AssertTCPRejected(t *testing.T, peer *linuxHostTUNPeer, scenario string, result linuxHostTUNResult, before, after linuxHostTUNPeerReply) {
	t.Helper()
	if !linuxHostTUNSIP003TCPFault(scenario) || result.Outcome != "rejected-proof" || result.Ready == nil || before.RouterQueries != 0 || after.RouterQueries != 0 || after.DirectQueries != before.DirectQueries || after.DNSQueries != before.DNSQueries || !linuxHostTUNSIP003DNS(peer, before) || after.ProtocolRawTCP <= before.ProtocolRawTCP || after.ProtocolTCP != 0 || after.RawTCP <= before.RawTCP {
		t.Fatal("installed SIP003 TCP negative skipped its real encrypted failure or independent healthy DNS", scenario, result, before, after)
	}
	switch linuxHostTUNSIP003Action(scenario) {
	case "tcp-key":
		if after.ProtocolTLSHTTP == 0 || after.ProtocolWebSocket == 0 || after.ProtocolMux == 0 {
			t.Fatal("bad SS2022 key did not reach the actual TLS/WebSocket/mux peer")
		}
	case "tcp-host", "tcp-path":
		if after.ProtocolTLSHTTP == 0 || after.ProtocolWebSocket != 0 || after.ProtocolMux != 0 {
			t.Fatal("wrong SIP003 host/path bypassed its exact WebSocket guard")
		}
	case "tcp-server-name", "tcp-certificate":
		if after.ProtocolTLSHTTP != 0 || after.ProtocolWebSocket != 0 || after.ProtocolMux != 0 {
			t.Fatal("wrong SIP003 trust reached the HTTP server")
		}
	}
}
