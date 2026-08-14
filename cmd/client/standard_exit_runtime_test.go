package main

import (
	"testing"

	"router-vpn/internal/common"
)

func TestBuildNativeStandardExitConfigRoutesOnlyThroughControlledExit(t *testing.T) {
	wg:=nativeWG{PrivateKey:testWGKey('c'),PublicKey:testWGKey('d'),Host:"198.51.100.20",Addresses:[]string{"10.66.0.2/32"},AllowedIPs:[]string{"0.0.0.0/0"},Port:51820,MTU:1380}
	control:=common.RouterProfile{DNSMode:"fastest",FastestDNSHost:"1.1.1.1",EffectiveMTU:1320}
	for _,protocol:=range []string{"socks5","shadowsocks","hysteria2","wireguard"}{
		e:=validTestStandardExit(protocol);cfg,err:=buildNativeStandardExitConfig(control,wg,e);if err!=nil{t.Fatalf("%s: %v",protocol,err)}
		route:=cfg["route"].(map[string]any);if route["final"]!="custom-exit"{t.Fatalf("%s final=%v",protocol,route["final"])}
		inbounds:=cfg["inbounds"].([]any);tun:=inbounds[0].(map[string]any);if tun["strict_route"]!=true||tun["auto_route"]!=true{t.Fatalf("%s TUN not strict: %#v",protocol,tun)}
		endpoints:=cfg["endpoints"].([]any);if endpoints[0].(map[string]any)["tag"]!="entry-wg"{t.Fatalf("%s missing entry endpoint",protocol)}
		if protocol=="wireguard"{if len(endpoints)!=2||endpoints[1].(map[string]any)["detour"]!="entry-wg"{t.Fatalf("WG not chained: %#v",endpoints)}}else{out:=cfg["outbounds"].([]any);if len(out)!=1||out[0].(map[string]any)["detour"]!="entry-wg"{t.Fatalf("%s not chained: %#v",protocol,out)}}
		dns:=cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any);if dns["detour"]!="custom-exit"{t.Fatalf("%s DNS escaped custom exit: %#v",protocol,dns)}
	}
}

func TestHomeDNSStaysOnPrivateEntryPath(t *testing.T){
	control:=common.RouterProfile{DNSMode:"home",AdGuardIPv4:"10.77.0.1"};dns,err:=selectedStandardExitDNS(control);if err!=nil{t.Fatal(err)};if dns["detour"]!="entry-wg"||dns["server"]!="10.77.0.1"{t.Fatalf("unexpected home DNS: %#v",dns)}
}

func TestEncryptedDNSRequiresSNI(t *testing.T){
	control:=common.RouterProfile{DNSMode:"doh",DNSHost:"1.1.1.1",DNSPort:443};if _,err:=selectedStandardExitDNS(control);err==nil{t.Fatal("expected fail closed without TLS server name")}
}
