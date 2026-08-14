package main

import (
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestPublicRouterProfileRedactsSecrets(t *testing.T) {
	p:=common.RouterProfile{SchemaVersion:3,ID:"home",Name:"Home",NodeKind:"router-vpn",Endpoint:"203.0.113.2",RouterAPI:"http://10.77.0.1:8787",APIToken:"admin-secret",AdGuardIPv4:"10.77.0.1",SocksHost:"10.77.0.1",SocksPort:1080,SocksUsername:"proxy-user",SocksPassword:"proxy-secret",NodeProofID:strings.Repeat("a",64),Location:"Austin",Latitude:30,Longitude:-97,DNSMode:"home"}
	view:=publicProfileFor(p)
	b,err:=json.Marshal(view);if err!=nil{t.Fatal(err)}
	s:=string(b)
	for _,secret:=range []string{"admin-secret","proxy-user","proxy-secret",strings.Repeat("a",64)}{if strings.Contains(s,secret){t.Fatalf("public profile leaked secret %q: %s",secret,s)}}
	if !strings.Contains(s,"10.77.0.1")||!strings.Contains(s,"Austin"){t.Fatalf("safe product metadata missing: %s",s)}
	if !view.Editable{t.Fatal("Router VPN profile should remain editable through non-secret settings view")}
}

func TestPublicExternalProfileRedactsAllProtocolCredentials(t *testing.T) {
	p:=common.RouterProfile{SchemaVersion:3,ID:"ext",Name:"External",NodeKind:"external",Endpoint:"vpn.example.com",Location:"Dallas",External:&common.ExternalNodeConfig{Protocol:"openvpn",ExpectedPublicIP:"203.0.113.9",OpenVPN:&common.ExternalOpenVPNConfig{Config:"client\nremote 198.51.100.9 443 tcp\n<key>PRIVATEKEY</key>",Username:"alice",Password:"password123"}}}
	view:=publicProfileFor(p)
	b,err:=json.Marshal(view);if err!=nil{t.Fatal(err)}
	s:=string(b)
	for _,secret:=range []string{"PRIVATEKEY","alice","password123","remote 198.51.100.9"}{if strings.Contains(s,secret){t.Fatalf("public external view leaked %q: %s",secret,s)}}
	for _,safe:=range []string{"external","openvpn","203.0.113.9","vpn.example.com","Dallas"}{if !strings.Contains(s,safe){t.Fatalf("missing safe external metadata %q: %s",safe,s)}}
	if view.Editable{t.Fatal("old Router-VPN settings form must not edit external private protocol data")}
}

func TestPublicProfileStoreDoesNotLeakExternalWireGuardKeys(t *testing.T) {
	key:="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	store:=common.RouterProfileStore{SchemaVersion:3,SelectedID:"wg",Profiles:[]common.RouterProfile{{SchemaVersion:3,ID:"wg",Name:"WG",NodeKind:"external",Endpoint:"198.51.100.20",External:&common.ExternalNodeConfig{Protocol:"wireguard",ExpectedPublicIP:"203.0.113.20",WireGuard:&common.ExternalWireGuardConfig{PrivateKey:key,PeerPublicKey:key,Addresses:[]string{"10.0.0.2/32"},Endpoint:"198.51.100.20:51820",AllowedIPs:[]string{"0.0.0.0/0"}}}}}}
	b,err:=json.Marshal(publicProfileStoreFor(store));if err!=nil{t.Fatal(err)}
	if strings.Contains(string(b),key){t.Fatalf("public store leaked WireGuard key: %s",b)}
}
