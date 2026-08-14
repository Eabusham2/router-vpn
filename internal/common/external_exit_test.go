package common

import (
	"strings"
	"testing"
)

func TestExternalExitPublicRedactsSecrets(t *testing.T) {
	x := ExternalExit{ID:"corp",Name:"Corp",Protocol:"shadowsocks",Endpoint:"203.0.113.7",Port:8388,Cipher:"2022-blake3-aes-256-gcm",Password:"secret"}
	if err := NormalizeExternalExit(&x); err != nil { t.Fatal(err) }
	p := ExternalExitPublicView(x)
	if !p.Configured { t.Fatal("expected configured public view") }
	if strings.Contains(strings.Join([]string{p.ID,p.Name,p.Protocol,p.Endpoint,p.ServerName}," "), "secret") { t.Fatal("secret leaked to public view") }
}

func TestNormalizeExternalAliases(t *testing.T) {
	cases := map[string]string{"wg":"wireguard","ovpn":"openvpn","ss":"shadowsocks","socks":"socks5"}
	for in,want := range cases {
		x:=ExternalExit{ID:"x",Protocol:in,Endpoint:"203.0.113.8",Port:1080,Username:"u",Password:"p",Cipher:"aes-256-gcm",Config:"[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\n"}
		if want=="openvpn" { x.Config="client\ndev tun\nremote 203.0.113.8 1194 udp\n<ca>\nx\n</ca>\n" }
		if want=="shadowsocks" { x.Password="secret" }
		if want=="socks5" { x.Cipher=""; x.Config="" }
		if err:=NormalizeExternalExit(&x);err!=nil{t.Fatalf("%s: %v",in,err)}
		if x.Protocol!=want{t.Fatalf("%s normalized to %s want %s",in,x.Protocol,want)}
	}
}

func TestOpenVPNSafeInlineProfile(t *testing.T) {
	raw := `client
proto udp
dev tun
remote 203.0.113.9 1194
remote-cert-tls server
<ca>
CERT
</ca>
<cert>
CERT
</cert>
<key>
KEY
</key>
`
	clean,host,port,err:=SanitizeOpenVPNConfig(raw)
	if err!=nil{t.Fatal(err)}
	if host!="203.0.113.9"||port!=1194{t.Fatalf("unexpected remote %s:%d",host,port)}
	if !strings.Contains(clean,"<key>") { t.Fatal("inline key unexpectedly removed") }
}

func TestOpenVPNRejectsExecutionAndHostFileDirectives(t *testing.T) {
	blocked := []string{
		"script-security 3", "up /tmp/pwn", "plugin evil.so", "config /etc/passwd",
		"auth-user-pass /etc/passwd", "ca /etc/ssl/private/key", "log /root/out", "management 127.0.0.1 5555",
	}
	for _,line:=range blocked{
		raw:="client\ndev tun\nremote 203.0.113.9 1194\n"+line+"\n"
		if _,_,_,err:=SanitizeOpenVPNConfig(raw);err==nil{t.Fatalf("expected %q to be rejected",line)}
	}
}

func TestOpenVPNRequiresSingleRemote(t *testing.T) {
	for _,raw:=range []string{
		"client\ndev tun\n",
		"client\ndev tun\nremote 203.0.113.1 1194\nremote 203.0.113.2 1194\n",
	}{
		if _,_,_,err:=SanitizeOpenVPNConfig(raw);err==nil{t.Fatal("expected remote-count rejection")}
	}
}

func TestOpenVPNRejectsTapAndUnclosedInline(t *testing.T) {
	if _,_,_,err:=SanitizeOpenVPNConfig("client\ndev tap\nremote 203.0.113.1 1194\n");err==nil{t.Fatal("expected TAP rejection")}
	if _,_,_,err:=SanitizeOpenVPNConfig("client\ndev tun\nremote 203.0.113.1 1194\n<ca>\nx\n");err==nil{t.Fatal("expected unclosed inline block rejection")}
}

func TestExternalStoreRejectsDuplicateAndMissingSelection(t *testing.T) {
	wg:=ExternalExit{ID:"a",Protocol:"wireguard",Config:"[Interface]\nPrivateKey=x\n[Peer]\nPublicKey=y\n"}
	s:=ExternalExitStore{SelectedID:"missing",Exits:[]ExternalExit{wg}}
	if err:=NormalizeExternalExitStore(&s);err==nil{t.Fatal("expected missing selection rejection")}
	s=ExternalExitStore{Exits:[]ExternalExit{wg,wg}}
	if err:=NormalizeExternalExitStore(&s);err==nil{t.Fatal("expected duplicate id rejection")}
}
