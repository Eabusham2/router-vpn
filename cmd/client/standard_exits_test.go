package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testWGKey(seed byte) string { return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{seed}), 32))) }

func validTestStandardExit(protocol string) standardExit {
	e := standardExit{ID:"exit-test",Name:"Test",Protocol:protocol,Server:"203.0.113.10",ServerPort:443,ExpectedPublicIP:"1.1.1.1"}
	switch protocol {
	case "socks5": e.Username="u";e.Password="p"
	case "shadowsocks": e.Method="2022-blake3-aes-256-gcm";e.Secret="secret"
	case "hysteria2": e.Secret="secret";e.TLSServerName="vpn.example.com"
	case "wireguard": e.WGAddresses=[]string{"10.50.0.2/32"};e.WGPrivateKey=testWGKey('a');e.WGPeerPublicKey=testWGKey('b');e.WGAllowedIPs=[]string{"0.0.0.0/0","::/0"};e.WGMTU=1380
	}
	return e
}

func TestStandardExitCapabilitiesAreTruthful(t *testing.T) {
	caps := standardExitCapabilities(); got := map[string]bool{}; reason := map[string]string{}
	for _, c := range caps { got[c.Protocol]=c.Supported; reason[c.Protocol]=c.Reason }
	for _, p := range []string{"wireguard","socks5","shadowsocks","hysteria2"} { if !got[p] { t.Fatalf("%s should be supported",p) } }
	if got["openvpn"] || !strings.Contains(reason["openvpn"],"1.13") { t.Fatalf("OpenVPN must fail closed with pinned-runtime reason: %#v",caps) }
}

func TestStandardExitValidationRejectsOpenVPNAndMissingProof(t *testing.T) {
	e:=validTestStandardExit("socks5");e.ExpectedPublicIP="";if err:=validateStandardExit(&e);err==nil||!strings.Contains(err.Error(),"expected_public_ip"){t.Fatalf("unexpected: %v",err)}
	o:=validTestStandardExit("socks5");o.Protocol="openvpn";if err:=validateStandardExit(&o);err==nil||!strings.Contains(err.Error(),"OpenVPN"){t.Fatalf("unexpected: %v",err)}
}

func TestStandardExitCompilerOwnsDetour(t *testing.T) {
	for _, protocol := range []string{"socks5","shadowsocks","hysteria2"} {
		e:=validTestStandardExit(protocol);endpoint,out,err:=standardExitRuntimeParts(e,"entry-wg");if err!=nil{t.Fatal(err)};if endpoint!=nil{t.Fatalf("%s unexpectedly endpoint",protocol)};if out["tag"]!="custom-exit"||out["detour"]!="entry-wg"{t.Fatalf("unsafe outbound: %#v",out)}
	}
	e:=validTestStandardExit("wireguard");endpoint,out,err:=standardExitRuntimeParts(e,"entry-wg");if err!=nil{t.Fatal(err)};if out!=nil||endpoint["type"]!="wireguard"||endpoint["tag"]!="custom-exit"||endpoint["detour"]!="entry-wg"{t.Fatalf("bad WG endpoint: %#v",endpoint)}
}

func TestStandardExitStoreIsPrivateAndRedactionDoesNotLeak(t *testing.T) {
	root:=t.TempDir();old:=os.Getenv("HOMEVPN_ROOT");t.Cleanup(func(){_ = os.Setenv("HOMEVPN_ROOT",old)});_ = os.Setenv("HOMEVPN_ROOT",root)
	e:=validTestStandardExit("shadowsocks");if err:=persistStandardExitStore(standardExitStore{SchemaVersion:1,Exits:[]standardExit{e}});err!=nil{t.Fatal(err)}
	path:=filepath.Join(root,"standard-exits.json");info,err:=os.Lstat(path);if err!=nil{t.Fatal(err)};if runtime.GOOS!="windows"&&info.Mode().Perm()!=0o600{t.Fatalf("mode=%o",info.Mode().Perm())}
	store,err:=loadStandardExitStore();if err!=nil{t.Fatal(err)};if len(store.Exits)!=1||store.Exits[0].Secret!="secret"{t.Fatal("private store did not round-trip")}
	s:=standardExitSummaryFor(store.Exits[0]);if s.HasSecret!=true||strings.Contains(s.Name,"secret"){t.Fatalf("bad summary: %#v",s)}
}

func TestStandardExitStoreRefusesSymlink(t *testing.T) {
	if runtime.GOOS=="windows"{t.Skip("symlink permissions vary on Windows runners")}
	root:=t.TempDir();old:=os.Getenv("HOMEVPN_ROOT");t.Cleanup(func(){_ = os.Setenv("HOMEVPN_ROOT",old)});_ = os.Setenv("HOMEVPN_ROOT",root)
	target:=filepath.Join(root,"target");if err:=os.WriteFile(target,[]byte(`{"schema_version":1,"exits":[]}`),0o600);err!=nil{t.Fatal(err)}
	if err:=os.Symlink(target,filepath.Join(root,"standard-exits.json"));err!=nil{t.Fatal(err)}
	if _,err:=loadStandardExitStore();err==nil||!strings.Contains(err.Error(),"non-symlink"){t.Fatalf("unexpected %v",err)}
}
