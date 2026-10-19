package common

import (
	"encoding/json"
	"strings"
	"testing"
)

const testWGKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestLegacyProfileDefaultsToRouterVPNKind(t *testing.T) {
	var p RouterProfile
	if err := json.Unmarshal([]byte(`{"schema_version":2,"id":"home","home_lan_access":false}`), &p); err != nil { t.Fatal(err) }
	if p.SchemaVersion != RouterProfileSchemaVersion { t.Fatalf("schema=%d", p.SchemaVersion) }
	if p.NodeKind != "router-vpn" { t.Fatalf("node_kind=%q", p.NodeKind) }
	if p.External != nil { t.Fatal("legacy Router VPN profile gained external config") }
}

func TestExternalWireGuardRoundTrip(t *testing.T) {
	p := RouterProfile{ID:"wg-exit",Name:"Office WireGuard",NodeKind:"external",HomeLANAccess:false,External:&ExternalNodeConfig{
		Protocol:" WireGuard ",ExpectedPublicIP:"203.0.113.10",WireGuard:&ExternalWireGuardConfig{
			PrivateKey:testWGKey,Addresses:[]string{"10.10.0.2/32"},PeerPublicKey:testWGKey,Endpoint:"vpn.example.com:51820",AllowedIPs:[]string{"0.0.0.0/0","::/0"},DNS:[]string{"1.1.1.1"},MTU:1380,
	}}}
	b, err := json.Marshal(p); if err != nil { t.Fatal(err) }
	if strings.Contains(string(b), `"node_kind":"router-vpn"`) { t.Fatalf("wrong kind: %s", b) }
	var out RouterProfile
	if err := json.Unmarshal(b,&out); err != nil { t.Fatal(err) }
	if out.NodeKind!="external" || out.External==nil || out.External.Protocol!="wireguard" { t.Fatalf("bad roundtrip: %+v",out) }
	if out.External.WireGuard==nil || out.External.WireGuard.MTU!=1380 || out.External.ExpectedPublicIP!="203.0.113.10" { t.Fatalf("wireguard data lost: %+v",out.External) }
	if out.Endpoint!="vpn.example.com" { t.Fatalf("display endpoint=%q",out.Endpoint) }
}

func TestExternalOpenVPNProfileAcceptedAsDataOnly(t *testing.T) {
	p:=RouterProfile{ID:"ovpn",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"openvpn",ExpectedPublicIP:"203.0.113.11",OpenVPN:&ExternalOpenVPNConfig{Config:"client\nremote 198.51.100.20 1194 udp\n<ca>\nTEST\n</ca>"}}}
	if err:=NormalizeRouterProfile(&p);err!=nil{t.Fatal(err)}
	if p.External.Protocol!="openvpn"||p.Endpoint!="198.51.100.20"{t.Fatalf("profile not normalized: %+v",p)}
}

func TestExternalHysteria2Profile(t *testing.T) {
	p:=RouterProfile{ID:"hy2",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"hysteria2",ExpectedPublicIP:"203.0.113.12",Hysteria2:&ExternalHysteria2Config{Server:"hy.example.com",Port:8443,Password:"secret",TLSServerName:"hy.example.com"}}}
	if err:=NormalizeRouterProfile(&p);err!=nil{t.Fatal(err)}
	if p.Endpoint!="hy.example.com"{t.Fatalf("endpoint=%q",p.Endpoint)}
}

func TestExternalExpectedExitMustBePublicIP(t *testing.T) {
	for _, value := range []string{"", "not-an-ip", "127.0.0.1", "10.0.0.1", "::1", "fd00::1"} {
		p:=RouterProfile{ID:"bad",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"socks5",ExpectedPublicIP:value,SOCKS5:&ExternalSOCKS5Config{Host:"proxy.example.com",Port:1080}}}
		if err:=NormalizeRouterProfile(&p);err==nil||!strings.Contains(err.Error(),"expected_public_ip"){t.Fatalf("expected public-IP rejection for %q, got %v",value,err)}
	}
}

func TestExternalProtocolsRequireExactlyMatchingBlock(t *testing.T) {
	baseIP:="203.0.113.20"
	bad:=[]RouterProfile{
		{ID:"none",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"wireguard",ExpectedPublicIP:baseIP}},
		{ID:"two",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"socks5",ExpectedPublicIP:baseIP,SOCKS5:&ExternalSOCKS5Config{Host:"127.0.0.1",Port:1080},Shadowsocks:&ExternalShadowsocksConfig{Server:"x",Port:8388,Method:"2022-blake3-aes-128-gcm",Password:"secret"}}},
		{ID:"wrong",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"wireguard",ExpectedPublicIP:baseIP,SOCKS5:&ExternalSOCKS5Config{Host:"127.0.0.1",Port:1080}}},
		{ID:"unknown",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"pptp",ExpectedPublicIP:baseIP,SOCKS5:&ExternalSOCKS5Config{Host:"127.0.0.1",Port:1080}}},
	}
	for _,p:=range bad{if err:=NormalizeRouterProfile(&p);err==nil{t.Fatalf("expected rejection: %+v",p)}}
}

func TestExternalNodeRejectsRouterVPNAdminSecrets(t *testing.T) {
	for _,mutate:=range []func(*RouterProfile){func(p *RouterProfile){p.APIToken="secret"},func(p *RouterProfile){p.RouterAPI="https://admin.example"},func(p *RouterProfile){p.NodeProofID=strings.Repeat("a",64)}}{
		p:=RouterProfile{ID:"ext",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"socks5",ExpectedPublicIP:"203.0.113.30",SOCKS5:&ExternalSOCKS5Config{Host:"proxy.example.com",Port:1080}}};mutate(&p)
		if err:=NormalizeRouterProfile(&p);err==nil||!strings.Contains(err.Error(),"proof/admin"){t.Fatalf("expected admin-secret rejection, got %v",err)}
	}
}

func TestInjectedRouterDefaultsAreStrippedFromExternal(t *testing.T) {
	p:=legacyInjectedExternalHomeProfile()
	if err:=NormalizeRouterProfile(&p);err!=nil{t.Fatal(err)}
	if p.RouterAPI!=""||p.AdGuardIPv4!=""||p.SocksHost!=""||p.BaseTunnel!=""||p.DNSMode!=""||p.PathProbeURL!=""{t.Fatalf("Router VPN defaults leaked into external profile: %+v",p)}
}

func legacyInjectedExternalHomeProfile() RouterProfile {
	return RouterProfile{ID:"ext",NodeKind:"external",RouterAPI:"http://10.77.0.1:8787",AdGuardIPv4:"10.77.0.1",SocksHost:"10.77.0.1",SocksPort:1080,DAITAHost:"10.77.0.1",DAITAPort:45999,BaseTunnel:"wg",DNSMode:"home",DNSProtocol:"udp",DNSHost:"10.77.0.1",DNSPort:53,PathProbeURL:"http://10.77.0.1:8787/health",External:&ExternalNodeConfig{Protocol:"socks5",ExpectedPublicIP:"203.0.113.31",SOCKS5:&ExternalSOCKS5Config{Host:"proxy.example.com",Port:1080}}}
}

func TestExternalHomeDNSMigrationDoesNotEraseExplicitSelection(t *testing.T) {
	for _, schema := range []int{0, 1, 3, RouterProfileSchemaVersion} {
		p := RouterProfile{SchemaVersion: schema, ID: "explicit-home", NodeKind: "external", DNSMode: "home", DNSProtocol: "tcp", DNSHost: "10.77.0.1", DNSPort: 5353,
			External: &ExternalNodeConfig{Protocol: "socks5", ExpectedPublicIP: "203.0.113.31", SOCKS5: &ExternalSOCKS5Config{Host: "203.0.113.30", Port: 1080}}}
		b, err := json.Marshal(p)
		if err != nil { t.Fatal(err) }
		var saved RouterProfile
		if err := json.Unmarshal(b, &saved); err != nil { t.Fatal(err) }
		if saved.DNSMode != "home" || saved.DNSProtocol != "tcp" || saved.DNSHost != "10.77.0.1" || saved.DNSPort != 5353 {
			t.Fatalf("schema %d lost an explicit Home DNS choice: %s", schema, b)
		}
		if saved.RouterAPI != "" || saved.AdGuardIPv4 != "" || saved.NodeProofID != "" { t.Fatal("external Home choice invented a Router VPN owner") }
	}
}

func TestExternalHomeDNSMigrationRequiresCompleteUnversionedSignature(t *testing.T) {
	mutations := map[string]func(*RouterProfile){
		"versioned old": func(p *RouterProfile) { p.SchemaVersion = 3 },
		"versioned current": func(p *RouterProfile) { p.SchemaVersion = RouterProfileSchemaVersion },
		"no router API": func(p *RouterProfile) { p.RouterAPI = "" },
		"different AdGuard": func(p *RouterProfile) { p.AdGuardIPv4 = "10.78.0.1" },
		"AdGuard IPv6": func(p *RouterProfile) { p.AdGuardIPv6 = "fd77:77::1" },
		"no SOCKS host": func(p *RouterProfile) { p.SocksHost = "" },
		"SOCKS port": func(p *RouterProfile) { p.SocksPort = 1081 },
		"SOCKS username": func(p *RouterProfile) { p.SocksUsername = "saved-user" },
		"SOCKS password": func(p *RouterProfile) { p.SocksPassword = "saved-password" },
		"DAITA host": func(p *RouterProfile) { p.DAITAHost = "10.78.0.1" },
		"DAITA port": func(p *RouterProfile) { p.DAITAPort = 45998 },
		"DAITA rate": func(p *RouterProfile) { p.DAITARateKbps = 64 },
		"base": func(p *RouterProfile) { p.BaseTunnel = "awg" },
		"fallback": func(p *RouterProfile) { p.BaseFallback = true },
		"custom layers": func(p *RouterProfile) { p.CustomLayers = []string{"reality"} },
		"start layer": func(p *RouterProfile) { p.StartLayer = "off" },
		"probe URL": func(p *RouterProfile) { p.PathProbeURL = "" },
		"DNS mode": func(p *RouterProfile) { p.DNSMode = "custom" },
		"DNS protocol": func(p *RouterProfile) { p.DNSProtocol = "tcp" },
		"DNS host": func(p *RouterProfile) { p.DNSHost = "10.78.0.1" },
		"DNS port": func(p *RouterProfile) { p.DNSPort = 5353 },
		"DNS TLS identity": func(p *RouterProfile) { p.DNSServerName = "dns.example" },
		"DNS path": func(p *RouterProfile) { p.DNSPath = "/selected-dns" },
		"fastest host": func(p *RouterProfile) { p.FastestDNSHost = "9.9.9.9" },
		"fastest name": func(p *RouterProfile) { p.FastestDNSName = "saved resolver" },
		"fastest sample": func(p *RouterProfile) { p.FastestDNSLatencyMs = 12 },
		"DNS samples": func(p *RouterProfile) { p.DNSResults = []DNSBenchmarkResult{{Address: "9.9.9.9", Working: true}} },
		"plain Tor": func(p *RouterProfile) { p.External = &ExternalNodeConfig{Protocol: "tor"} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := legacyInjectedExternalHomeProfile()
			mutate(&p)
			mode, protocol, host, port, serverName, path := p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort, p.DNSServerName, p.DNSPath
			if err := NormalizeRouterProfile(&p); err != nil { t.Fatal(err) }
			if p.DNSMode != mode || p.DNSProtocol != protocol || p.DNSHost != host || p.DNSPort != port || p.DNSServerName != serverName || p.DNSPath != path {
				t.Fatalf("partial legacy signature erased a saved DNS choice: %+v", p)
			}
			if err := NormalizeRouterProfile(&p); err != nil { t.Fatal(err) }
			if p.DNSMode != mode || p.DNSHost != host { t.Fatal("repeat normalization erased the choice") }
		})
	}
}

func TestExternalCredentialPairsFailClosed(t *testing.T) {
	p:=RouterProfile{ID:"socks",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"socks5",ExpectedPublicIP:"203.0.113.40",SOCKS5:&ExternalSOCKS5Config{Host:"proxy.example.com",Port:1080,Username:"u"}}}
	if err:=NormalizeRouterProfile(&p);err==nil||!strings.Contains(err.Error(),"username/password"){t.Fatalf("expected incomplete auth rejection, got %v",err)}
	p=RouterProfile{ID:"ovpn",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"openvpn",ExpectedPublicIP:"203.0.113.41",OpenVPN:&ExternalOpenVPNConfig{Config:"client\nremote 198.51.100.20 1194",Password:"p"}}}
	if err:=NormalizeRouterProfile(&p);err==nil||!strings.Contains(err.Error(),"username/password"){t.Fatalf("expected incomplete auth rejection, got %v",err)}
}

func TestExternalWireGuardRejectsMalformedKeyAndCIDR(t *testing.T) {
	p:=RouterProfile{ID:"wg",NodeKind:"external",External:&ExternalNodeConfig{Protocol:"wireguard",ExpectedPublicIP:"203.0.113.50",WireGuard:&ExternalWireGuardConfig{PrivateKey:"bad",Addresses:[]string{"10.0.0.2/32"},PeerPublicKey:testWGKey,Endpoint:"198.51.100.5:51820",AllowedIPs:[]string{"0.0.0.0/0"}}}}
	if err:=NormalizeRouterProfile(&p);err==nil||!strings.Contains(err.Error(),"32-byte base64"){t.Fatalf("expected key rejection, got %v",err)}
	p.External.WireGuard.PrivateKey=testWGKey;p.External.WireGuard.Addresses=[]string{"not-cidr"}
	if err:=NormalizeRouterProfile(&p);err==nil||!strings.Contains(err.Error(),"invalid external WireGuard interface addresses"){t.Fatalf("expected CIDR rejection, got %v",err)}
}

func TestProfileStoreRejectsDuplicateAndMissingSelection(t *testing.T) {
	store:=RouterProfileStore{SelectedID:"missing",Profiles:[]RouterProfile{{ID:"one"}}}
	if err:=NormalizeRouterProfileStore(&store);err==nil||!strings.Contains(err.Error(),"not present"){t.Fatalf("expected missing selection rejection, got %v",err)}
	store=RouterProfileStore{Profiles:[]RouterProfile{{ID:"dup"},{ID:"dup"}}}
	if err:=NormalizeRouterProfileStore(&store);err==nil||!strings.Contains(err.Error(),"duplicate"){t.Fatalf("expected duplicate rejection, got %v",err)}
}
