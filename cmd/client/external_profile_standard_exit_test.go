package main

import (
	"strings"
	"testing"

	"router-vpn/internal/common"
)

const externalTestWGKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func externalProfileBase(id, protocol string) common.RouterProfile {
	return common.RouterProfile{ID:id,Name:id,NodeKind:"external",External:&common.ExternalNodeConfig{Protocol:protocol,ExpectedPublicIP:"203.0.113.90"}}
}

func TestExternalWireGuardProfileBecomesStandardExit(t *testing.T) {
	p:=externalProfileBase("ext-wg","wireguard")
	p.External.WireGuard=&common.ExternalWireGuardConfig{PrivateKey:externalTestWGKey,Addresses:[]string{"10.1.0.2/32"},PeerPublicKey:externalTestWGKey,Endpoint:"198.51.100.10:51820",AllowedIPs:[]string{"0.0.0.0/0"},MTU:1380}
	e,err:=standardExitFromExternalProfile(p);if err!=nil{t.Fatal(err)}
	if e.Protocol!="wireguard"||e.Server!="198.51.100.10"||e.ServerPort!=51820||e.ExpectedPublicIP!="203.0.113.90"{t.Fatalf("bad bridge: %+v",e)}
	if e.WGPrivateKey!=externalTestWGKey||e.WGMTU!=1380{t.Fatalf("wireguard credentials lost: %+v",e)}
}

func TestExternalProxyProfilesBecomeStandardExits(t *testing.T) {
	ss:=externalProfileBase("ext-ss","shadowsocks");ss.External.Shadowsocks=&common.ExternalShadowsocksConfig{Server:"198.51.100.11",Port:8388,Method:"aes-256-gcm",Password:"secret"}
	socks:=externalProfileBase("ext-socks","socks5");socks.External.SOCKS5=&common.ExternalSOCKS5Config{Host:"198.51.100.12",Port:1080,Username:"u",Password:"p"}
	hy:=externalProfileBase("ext-hy","hysteria2");hy.External.Hysteria2=&common.ExternalHysteria2Config{Server:"198.51.100.13",Port:8443,Password:"pw",TLSServerName:"hy.example.com"}
	for _,p:=range []common.RouterProfile{ss,socks,hy}{
		e,err:=standardExitFromExternalProfile(p);if err!=nil{t.Fatalf("%s: %v",p.ID,err)}
		if e.ID!=p.ID||e.ExpectedPublicIP!="203.0.113.90"{t.Fatalf("identity/proof lost: %+v",e)}
	}
}

func TestExternalOpenVPNUsesExistingSanitizer(t *testing.T) {
	p:=externalProfileBase("ext-ovpn","openvpn")
	p.External.OpenVPN=&common.ExternalOpenVPNConfig{Config:"client\nproto tcp-client\nremote 198.51.100.14 443 tcp-client\n<ca>\nTEST\n</ca>"}
	e,err:=standardExitFromExternalProfile(p);if err!=nil{t.Fatal(err)}
	if e.Server!="198.51.100.14"||e.ServerPort!=443||e.Method!="tcp-client"{t.Fatalf("openvpn remote not derived: %+v",e)}
	p.External.OpenVPN.Config="client\nremote 198.51.100.14 443 tcp-client\nscript-security 2\n"
	if _,err=standardExitFromExternalProfile(p);err==nil||!strings.Contains(err.Error(),"script-security"){t.Fatalf("unsafe OpenVPN config was not rejected: %v",err)}
}

func TestExternalProfileBridgeRejectsRouterVPNProfile(t *testing.T) {
	if _,err:=standardExitFromExternalProfile(common.RouterProfile{ID:"home"});err==nil||!strings.Contains(err.Error(),"not an external"){t.Fatalf("expected kind rejection, got %v",err)}
}

func TestSplitExternalEndpoint(t *testing.T) {
	cases:=[]struct{in string;port int;host string;want int}{
		{"example.com:51820",51820,"example.com",51820},
		{"203.0.113.1",51820,"203.0.113.1",51820},
		{"[2001:db8::1]:51821",51820,"2001:db8::1",51821},
		{"2001:db8::2",51820,"2001:db8::2",51820},
	}
	for _,tc:=range cases{h,p,err:=splitExternalEndpoint(tc.in,tc.port);if err!=nil||h!=tc.host||p!=tc.want{t.Fatalf("%q => %q/%d err=%v",tc.in,h,p,err)}}
}
