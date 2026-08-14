package main

import (
	"testing"

	"router-vpn/internal/common"
)

func TestExternalRuntimePolicyDefaultsToEncryptedRescue(t *testing.T) {
	p:=common.RouterProfile{ID:"ext",Name:"External",NodeKind:"external",HomeLANAccess:false,KillSwitchPolicy:"always",External:&common.ExternalNodeConfig{Protocol:"socks5",ExpectedPublicIP:"203.0.113.101",SOCKS5:&common.ExternalSOCKS5Config{Host:"198.51.100.10",Port:1080}}}
	policy,err:=externalRuntimePolicy(p);if err!=nil{t.Fatal(err)}
	if policy.DNSMode!="rescue"||policy.DNSProtocol!="https"||policy.DNSHost!="1.1.1.1"||policy.DNSServerName!="cloudflare-dns.com"{t.Fatalf("unexpected rescue policy: %+v",policy)}
	if policy.KillSwitchPolicy!="always"||policy.HomeLANAccess{t.Fatalf("network policy changed: %+v",policy)}
}

func TestExternalRuntimePolicyPreservesExplicitDNS(t *testing.T) {
	p:=common.RouterProfile{ID:"ext",Name:"External",NodeKind:"external",DNSMode:"custom",DNSProtocol:"udp",DNSHost:"9.9.9.9",DNSPort:53,External:&common.ExternalNodeConfig{Protocol:"socks5",ExpectedPublicIP:"203.0.113.102",SOCKS5:&common.ExternalSOCKS5Config{Host:"198.51.100.11",Port:1080}}}
	policy,err:=externalRuntimePolicy(p);if err!=nil{t.Fatal(err)}
	if policy.DNSMode!="custom"||policy.DNSHost!="9.9.9.9"||policy.DNSPort!=53{t.Fatalf("explicit DNS changed: %+v",policy)}
}

func TestExternalRuntimePolicyRejectsRouterVPNNode(t *testing.T) {
	if _,err:=externalRuntimePolicy(common.RouterProfile{ID:"home"});err==nil{t.Fatal("Router VPN node was accepted as external policy")}
}
