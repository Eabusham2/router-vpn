//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/netip"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"strings"
	"testing"
)

type macOSExternalPacketEntryReceipt struct {
	Protocol         string `json:"protocol"`
	ParametersSHA256 string `json:"parameters_sha256,omitempty"`
	Address          string `json:"address"`
	PhysicalUDP      int64  `json:"physical_udp"`
	Streams          int64  `json:"streams"`
	Packets          int64  `json:"packets"`
	PublicReplies    uint32 `json:"public_replies"`
}

func macOSExternalNativePacketEntryRead(t *testing.T, p *macOSExternalNativePeer, reply macOSExternalPeerReply) {
	t.Helper()
	value := reply.PacketEntry
	if !p.packetEntry {
		if value != nil {
			t.Fatal("ordinary peer acquired an unrequested encrypted entry")
		}
		return
	}
	expectedParameters := ""
	if p.entryProtocol == "amneziawg" {
		expectedParameters = macOSExternalNativeAmneziaDigest(t, p.entryVariant)
	}
	if value == nil || value.Protocol != p.entryProtocol || value.ParametersSHA256 != expectedParameters || reply.Address != macOSExternalNativePacketEntryFinalAddress(p) {
		t.Fatal("packet entry lost its only captured tunneled stream exit")
	}
	address, err := netip.ParseAddrPort(value.Address)
	if err != nil || address.Addr() != p.physical || address.Port() == 0 || p.entryAddress.IsValid() && address != p.entryAddress || value.PhysicalUDP < 0 || value.Streams < 0 || value.Packets < 0 || p.protocol != "hysteria2" && p.protocol != "socks5" && p.protocol != "wireguard" && p.protocol != "amneziawg" && p.protocol != "openvpn" && value.Packets != 0 {
		t.Fatal("WG entry changed its captured physical peer or fixed TCP inner routes")
	}
	p.entryAddress = address
}
func macOSExternalNativePacketEntryProfile(t *testing.T, p *macOSExternalNativePeer, exit *common.RouterProfile) *common.RouterProfile {
	t.Helper()
	if !p.packetEntry {
		return nil
	}
	exit.Endpoint = p.address.Addr().String()
	exit.MultihopEnabled, exit.MultihopEntryID, exit.MultihopExitID = true, macOSExternalNativeEntryID(p), exit.ID
	exit.MultihopExecution, exit.MultihopEntryMode = "local", ""
	entry := common.RouterProfile{ID: macOSExternalNativeEntryID(p), Name: "Original encrypted WG entry", NodeKind: "external", Endpoint: p.physical.String(), DNSMode: "custom", DNSProtocol: "tcp", DNSHost: "203.0.113.53", DNSPort: 5353, IPv6Mode: "on", HomeLANAccess: true, StartLayer: "off", MTUPolicy: "auto", External: &common.ExternalNodeConfig{Protocol: "wireguard", ExpectedPublicIP: "203.0.113.77", WireGuard: &common.ExternalWireGuardConfig{PrivateKey: p.clientKey, PeerPublicKey: p.peerKey, PresharedKey: p.psk, Endpoint: p.entryAddress.String(), Addresses: []string{"10.78.0.2/32", "fd78:78::2/128"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, MTU: 1420, PersistentKeepalive: 25}}}
	if p.protocol == "openvpn" {
		entry.External.WireGuard.MTU = 1440
	}
	finalPacket := exit.External.WireGuard
	if exit.External.AmneziaWG != nil {
		finalPacket = &exit.External.AmneziaWG.ExternalWireGuardConfig
	}
	wireguard := entry.External.WireGuard
	if p.entryProtocol == "amneziawg" {
		entry.Name = "Original encrypted AWG entry"
		entry.External.Protocol, entry.External.WireGuard = "amneziawg", nil
		entry.External.AmneziaWG = &common.ExternalAmneziaWGConfig{ExternalWireGuardConfig: *wireguard, Parameters: macOSExternalNativeAmneziaParameters(t, p.entryVariant)}
		wireguard = &entry.External.AmneziaWG.ExternalWireGuardConfig
	}
	switch p.fault {
	case "wrong-entry-key":
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wireguard.PrivateKey = base64.StdEncoding.EncodeToString(key.Bytes())
	case "wrong-entry-psk":
		wireguard.PresharedKey = p.clientKey
	case "wrong-entry-parameters":
		if entry.External.AmneziaWG == nil {
			t.Fatal("parameter negative requires actual AWG")
		}
		entry.External.AmneziaWG.Parameters["h1"] = "50000000-59999999"
	case "wrong-entry-public":
		entry.External.ExpectedPublicIP = "203.0.113.76"
	case "wrong-exit-key":
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		switch p.protocol {
		case "wireguard", "amneziawg":
			finalPacket.PrivateKey = base64.StdEncoding.EncodeToString(key[:])
		case "shadowsocks":
			exit.External.Shadowsocks.Password = base64.StdEncoding.EncodeToString(key[:])
		case "http-connect":
			exit.External.HTTPConnect.Password = base64.StdEncoding.EncodeToString(key[:])
		case "https-connect":
			exit.External.HTTPSConnect.Password = base64.StdEncoding.EncodeToString(key[:])
		case "socks5":
			exit.External.SOCKS5.Password = base64.StdEncoding.EncodeToString(key[:])
		case "hysteria2":
			exit.External.Hysteria2.Password = base64.StdEncoding.EncodeToString(key[:])
		default:
			t.Fatal("unowned final credential negative")
		}
		clear(key[:])
	case "wrong-exit-peer-key":
		finalPacket.PeerPublicKey = p.peerKey
	case "wrong-exit-psk":
		finalPacket.PresharedKey = p.psk
	case "wrong-exit-parameters":
		exit.External.AmneziaWG.Parameters["h1"] = "50000000-59999999"
	case "wrong-exit-padding":
		exit.External.AmneziaWG.Parameters["s4"] = "31"
	case "wrong-exit-username":
		if exit.External.SOCKS5 != nil {
			exit.External.SOCKS5.Username += "-different"
			break
		}
		if exit.External.HTTPConnect == nil {
			t.Fatal("username negative requires captured CONNECT")
		}
		exit.External.HTTPConnect.Username += "-different"
	case "wrong-exit-server-name":
		if exit.External.HTTPSConnect != nil {
			exit.External.HTTPSConnect.TLSServerName = "untrusted-exit.example"
		} else if exit.External.Hysteria2 != nil {
			exit.External.Hysteria2.TLSServerName = "untrusted-exit.example"
		} else {
			t.Fatal("TLS name negative requires a captured TLS final")
		}
	case "wrong-layer-route":
		if exit.External.StartLayer == nil || exit.External.Hysteria2 == nil {
			t.Fatal("layer route negative requires captured HY2 layer")
		}
		exit.External.StartLayer.Transport["server"] = "198.51.100.241"
		exit.External.Hysteria2.Server, exit.Endpoint = "198.51.100.241", "198.51.100.241"
	case "wrong-exit-address":
		if exit.External.OpenVPN != nil {
			exit.External.OpenVPN.Config = strings.ReplaceAll(exit.External.OpenVPN.Config, "198.51.100.240", "198.51.100.241")
			exit.Endpoint = "198.51.100.241"
			break
		}
		if finalPacket != nil {
			finalPacket.Endpoint = "198.51.100.241:8388"
			exit.Endpoint = "198.51.100.241"
			break
		}
		if exit.External.SOCKS5 != nil {
			exit.External.SOCKS5.Host = "198.51.100.241"
			exit.Endpoint = "198.51.100.241"
			break
		}
		if exit.External.Hysteria2 == nil {
			t.Fatal("UDP route negative requires captured QUIC")
		}
		exit.External.Hysteria2.Server = "198.51.100.241"
		exit.Endpoint = "198.51.100.241"
	case "wrong-exit":
		exit.External.ExpectedPublicIP = "203.0.113.89"
	}
	if err := common.NormalizeRouterProfile(&entry); err != nil {
		t.Fatal(err)
	}
	return &entry
}
func macOSExternalNativePacketEntryProved(t *testing.T, p *macOSExternalNativePeer, live macOSExternalNativeResult, observed macOSExternalPeerReply) {
	t.Helper()
	entry := observed.PacketEntry
	ipv6 := "off"
	if p.policy == "always" {
		ipv6 = "on"
	}
	transportProved := entry != nil && entry.Streams >= 2 && entry.Packets == 0 && observed.Connections >= 1 && observed.Streams >= 2
	dnsProtocol := "tcp"
	if p.protocol == "hysteria2" || p.protocol == "wireguard" || p.protocol == "amneziawg" {
		dnsProtocol = "udp"
		transportProved = entry != nil && entry.Streams >= 1 && entry.Packets >= 1 && observed.PhysicalUDP >= 1 && observed.Connections == 0 && observed.Streams >= 1 && observed.Packets >= 1
	}
	if p.protocol == "socks5" {
		dnsProtocol = "udp"
		transportProved = entry != nil && entry.Streams >= 2 && entry.Packets >= 1 && observed.Connections >= 2 && observed.PhysicalUDP >= 1 && observed.Streams >= 1 && observed.Packets >= 1 && observed.SOCKSRejectedReplies == 0
		macOSExternalNativeSOCKSEntryRelays(t, p, observed)
	}
	if p.protocol == "openvpn" {
		dnsProtocol = "udp"
		transportProved = entry != nil && entry.Streams >= 1 && observed.Packets >= 1 && observed.Streams >= 1
		if p.openvpnNetwork == "tcp" {
			transportProved = transportProved && entry.Streams >= 2 && entry.Packets == 0 && observed.Connections >= 1 && observed.PhysicalUDP == 0
		} else {
			transportProved = transportProved && entry.Packets >= 1 && observed.PhysicalUDP >= 1 && observed.Connections == 0
		}
	}
	mtu := 1376
	if p.protocol == "openvpn" {
		mtu = 1280
	}
	if p.protocol == "wireguard" || p.protocol == "amneziawg" {
		mtu = 1360
		if p.protocol == "amneziawg" {
			mtu = 1328
		}
	}
	if entry == nil || entry.PhysicalUDP < 1 || !transportProved || entry.PublicReplies < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 || !live.Proof.EntryProven || live.Proof.EntryID != macOSExternalNativeEntryID(p) || live.Proof.EntryNodeID != "" || live.Proof.ExitID != "installed-macos-external" || live.Proof.IP != "203.0.113.88" || live.OuterTag != "external-entry" || live.OuterType != macOSExternalNativeEntryType(p) || live.PhysicalNetwork != "udp" || live.PhysicalAddress != p.entryAddress.String() || live.InnerHost != macOSExternalNativePacketEntryFinalHost(p) || live.InnerDetour != macOSExternalNativePacketEntryFinalDetour(p) || live.DNSProtocol != dnsProtocol || live.DNSHost != "203.0.113.53" || live.DNSPort != 5353 || live.Network.MTU != mtu || live.IPv6 != ipv6 || live.HomeLAN != (p.policy == "always") {
		t.Fatal("packet-entry/stream-exit lost its actual separate authenticated paths, independent entry proof or captured policy")
	}
}
func macOSExternalNativePacketEntryRefused(t *testing.T, ctx context.Context, client *http.Client, p *macOSExternalNativePeer, status int, raw []byte, failure error, controllerPID int, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if failure != nil || status != http.StatusConflict && status != http.StatusBadGateway {
		t.Fatal("WG entry negative did not complete actual refusal", status, failure, string(raw))
	}
	observed := p.stats(t)
	entry := observed.PacketEntry
	if entry == nil || entry.PhysicalUDP < 1 {
		t.Fatal("WG entry negative missed its actual first encrypted peer")
	}
	if p.protocol == "openvpn" {
		macOSExternalNativeOpenVPNEntryRefusalWitness(t, p, entry, observed)
	} else if p.protocol == "wireguard" || p.protocol == "amneziawg" {
		macOSExternalNativeWireGuardFinalRefusalWitness(t, p, entry, observed)
	} else if p.protocol == "socks5" {
		macOSExternalNativeSOCKSEntryRefusalWitness(t, p, entry, observed)
	} else if p.protocol == "hysteria2" && p.layer != "" {
		macOSExternalNativeHysteriaLayerEntryRefusalWitness(t, p, entry, observed)
	} else if p.protocol == "hysteria2" {
		macOSExternalNativeHysteriaEntryRefusalWitness(t, p, entry, observed)
	} else {
		switch p.fault {
		case "wrong-entry-key", "wrong-entry-psk", "wrong-entry-parameters":
			if entry.Streams != 0 || entry.PublicReplies != 0 || observed.Connections != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
				t.Fatal("wrong entry key acquired a proof or second encrypted peer")
			}
		case "wrong-trust":
			if entry.Streams < 1 || entry.PublicReplies != 0 || observed.Connections != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
				t.Fatal("entry TLS negative missed original trust boundary")
			}
		case "wrong-entry-public":
			if entry.PublicReplies < 1 || observed.Connections != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
				t.Fatal("entry mismatch acquired final-path proof")
			}
		case "wrong-exit-key", "wrong-exit-username":
			if entry.PublicReplies < 1 || observed.Connections < 1 || observed.Streams != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
				t.Fatal("second peer credential negative missed actual captured authentication boundary")
			}
			if p.protocol != "shadowsocks" && observed.AuthFailures < 1 {
				t.Fatal("CONNECT negative never reached actual independent credentials")
			}
		case "wrong-exit-server-name":
			if entry.PublicReplies < 1 || observed.Connections < 1 || observed.Streams != 0 || observed.AuthFailures != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
				t.Fatal("HTTPS CONNECT name negative missed original exit TLS boundary")
			}
		case "wrong-dns":
			if entry.PublicReplies < 1 || observed.Connections < 1 || observed.DNSQueries < 1 || observed.PublicReplies != 0 {
				t.Fatal("entry path DNS negative missed the selected final resolver")
			}
		case "wrong-exit":
			if entry.PublicReplies < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 {
				t.Fatal("entry path exit mismatch missed actual final public proof")
			}
		default:
			t.Fatal("unowned entry negative")
		}
	}
	status, raw, failure = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if failure != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || retired.Connected || !retired.NativeJoined || !retired.WorkspaceRetired || retired.ProcessID <= 0 || retired.ProcessID == controllerPID || retired.Baseline == nil || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present || retired.OuterTag != "external-entry" || retired.OuterType != macOSExternalNativeEntryType(p) || retired.PhysicalAddress != p.entryAddress.String() || retired.PhysicalNetwork != "udp" || retired.InnerDetour != macOSExternalNativePacketEntryFinalDetour(p) {
		t.Fatal("entry refusal lost original firstroot/child/PF/utun retirement", status, failure, string(raw))
	}
	macOSExternalNativeLayerAuthority(t, p, retired)
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, before)
}

func macOSExternalNativeEntryID(p *macOSExternalNativePeer) string {
	if p.entryProtocol == "amneziawg" {
		return "installed-macos-awg-entry"
	}
	return "installed-macos-wg-entry"
}
func macOSExternalNativeEntryType(p *macOSExternalNativePeer) string {
	if p.entryProtocol == "amneziawg" {
		return mobilemultihop.AmneziaType
	}
	return "wireguard"
}
