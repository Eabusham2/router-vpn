package nativeopenvpn

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func openVPNTestIdentity(t *testing.T, name string, key *ecdsa.PrivateKey) (string, string, *ecdsa.PrivateKey) {
	t.Helper()
	var err error
	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), key
}

func openVPNAuthKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes())
}

func openVPNProfile(cert, key string) Profile {
	profile := "client\nremote 192.0.2.60 1194 udp\npeer-fingerprint " + strings.Repeat("a", 64) + "\nverify-x509-name provider.example name\n"
	if cert != "" {
		profile += "<cert>\n" + cert + "</cert>\n<key>\n" + key + "</key>\n"
	}
	return Profile{Config: profile}
}

func TestOpenVPNPrivateJSONPreservesEscapedBoundedOriginalSource(t *testing.T) {
	profile := openVPNProfile("", "")
	profile.Config += "auth-user-pass\n# " + strings.Repeat("<>", 50000) + "\n"
	profile.Username, profile.Password = "local", " exact password "
	if _, err := CompileProfile(profile, "exit", ""); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(profile)
	if err != nil || len(raw) <= 2*MaxProfileBytes {
		t.Fatal("fixture did not exercise valid JSON expansion")
	}
	var restored Profile
	if err := json.Unmarshal(raw, &restored); err != nil || restored != profile {
		t.Fatal("valid original source changed or was rejected by private import")
	}
	restored.Config = strings.Repeat("#", MaxProfileBytes+1)
	if _, err := CompileProfile(restored, "exit", ""); err == nil {
		t.Fatal("JSON expansion allowance removed the original source bound")
	}
}

func TestOpenVPNPairingUsesIndependentAuthAndCanonicalProviderIdentities(t *testing.T) {
	lc, lk, localKey := openVPNTestIdentity(t, "LocalClient", nil)
	sc, sk, _ := openVPNTestIdentity(t, "ServerClient", nil)
	local, server := openVPNProfile(lc, lk), openVPNProfile(sc, sk)
	localAuth, serverAuth := openVPNAuthKey(t), openVPNAuthKey(t)
	descriptor, err := DescribePeer(server, serverAuth)
	if err != nil {
		t.Fatal(err)
	}
	paired, err := ValidatePairing(local, Pairing{PrivateKey: localAuth, Server: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	a, err := PairingAgreement(localAuth, descriptor.PairingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PairingAgreement(serverAuth, paired.PairingPublicKey)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("pairing owners did not derive the same private agreement")
	}
	encoded, _ := json.Marshal(descriptor)
	for _, secret := range []string{sk, serverAuth, "client_key", "client_certificate", "PRIVATE KEY"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("descriptor leaked private source")
		}
	}
	if paired.ProviderIdentity.CommonName != "localclient" || descriptor.ProviderIdentity.CommonName != "serverclient" {
		t.Fatal("provider name was not canonicalized")
	}
	for name, create := range map[string]func() (Profile, string){
		"same certificate": func() (Profile, string) { return local, serverAuth },
		"reissued same key": func() (Profile, string) {
			cert, key, _ := openVPNTestIdentity(t, "ChangedCN", localKey)
			return openVPNProfile(cert, key), serverAuth
		},
		"same canonical CN": func() (Profile, string) {
			cert, key, _ := openVPNTestIdentity(t, " LOCALCLIENT ", nil)
			return openVPNProfile(cert, key), serverAuth
		},
		"same pairing public identity": func() (Profile, string) {
			raw, _ := base64.StdEncoding.DecodeString(localAuth)
			raw[0] ^= 1
			return server, base64.StdEncoding.EncodeToString(raw)
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile, auth := create()
			other, e := DescribePeer(profile, auth)
			if e == nil {
				_, e = ValidatePairing(local, Pairing{PrivateKey: localAuth, Server: other})
			}
			if e == nil {
				t.Fatal("duplicate provider/pairing owner was accepted")
			}
		})
	}
}

func TestOpenVPNUserPairingKeepsCredentialsOutOfDescriptorsAndRejectsAliases(t *testing.T) {
	local, server := openVPNProfile("", ""), openVPNProfile("", "")
	local.Username, local.Password = " LocalUser ", "local-private-password"
	server.Username, server.Password = "ServerUser", "server-private-password"
	localAuth, serverAuth := openVPNAuthKey(t), openVPNAuthKey(t)
	desc, err := DescribePeer(server, serverAuth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePairing(local, Pairing{PrivateKey: localAuth, Server: desc}); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(desc)
	if bytes.Contains(encoded, []byte(server.Password)) || bytes.Contains(encoded, []byte(serverAuth)) {
		t.Fatal("descriptor exposed a secret")
	}
	server.Username = "LOCALUSER"
	desc, err = DescribePeer(server, serverAuth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ValidatePairing(local, Pairing{PrivateKey: localAuth, Server: desc}); err == nil {
		t.Fatal("canonical username reuse accepted")
	}
}

func TestOpenVPNPairingPreservesCompleteRemoteListAndLegacyProofStaysSingleHost(t *testing.T) {
	p := openVPNProfile("", "")
	p.Username, p.Password = "user", "password"
	p.Config += "remote 192.0.2.60 443 tcp\nremote-random\n"
	endpoint, err := CompileProfile(p, "exit", "")
	if err != nil {
		t.Fatal(err)
	}
	validated, err := ValidateEndpoint(endpoint)
	if err != nil || !reflect.DeepEqual(validated, endpoint) {
		t.Fatal("complete same-host remotes were not preserved")
	}
	if _, err := DescribePeer(p, openVPNAuthKey(t)); err != nil {
		t.Fatal(err)
	}
	p.Config = strings.Replace(p.Config, "192.0.2.60 443", "192.0.2.61 443", 1)
	endpoint, err = CompileProfile(p, "exit", "")
	if err != nil {
		t.Fatal("Local parser lost supported different-host remotes", err)
	}
	if _, err := ValidateEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	if _, err := DescribePeer(p, openVPNAuthKey(t)); err != nil {
		t.Fatal("independent pairing lost a complete different-host transport", err)
	}
	if _, err := SameRemoteHost(endpoint); err == nil {
		t.Fatal("legacy single response accepted different-host remotes")
	}
}

func TestOpenVPNEndpointRoundtripRetainsEveryNativeOptionAndRejectsInjection(t *testing.T) {
	p := openVPNProfile("", "")
	p.Username, p.Password = "user", "password"
	p.Config += "auth-retry nointeract\ntls-version-min 1.2\ntls-version-max 1.3\ntls-cipher provider-policy\ntls-groups X25519\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305\ncipher AES-256-CBC\ndata-ciphers-fallback AES-128-GCM\nauth SHA256\ntun-mtu 1420\nmssfix 1360 mtu\nfragment 1300\nping 10\nping-restart 60\nreneg-sec 3600\nhand-window 60\ntls-timeout 3\nexplicit-exit-notify 2\nallow-compression no\ncompress stub-v2\ncomp-lzo no\npull-filter ignore \"dhcp-option DNS\"\nroute-nopull\nredirect-gateway def1 ipv6\n<tls-auth>\nCONTROL-KEY-MATERIAL\n</tls-auth>\nkey-direction 1\n"
	endpoint, err := CompileProfile(p, "exit", "entry")
	if err != nil {
		t.Fatal(err)
	}
	copy, err := ValidateEndpoint(endpoint)
	if err != nil || !reflect.DeepEqual(copy, endpoint) {
		t.Fatal("supported parser options changed during native validation", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"system tunnel":         func(p map[string]any) { p["system"] = true },
		"host path":             func(p map[string]any) { p["tls"].(map[string]any)["client_key_path"] = "/tmp/private" },
		"arbitrary detour":      func(p map[string]any) { p["detour"] = map[string]any{"route": "bypass"} },
		"native route override": func(p map[string]any) { p["route_table"] = float64(99) },
		"unknown TLS option":    func(p map[string]any) { p["tls"].(map[string]any)["insecure"] = true },
		"unknown control option": func(p map[string]any) {
			p["tls"].(map[string]any)["control_wrap"].(map[string]any)["path"] = "/tmp/key"
		},
		"wrong network":                   func(p map[string]any) { p["network"] = "quic" },
		"extra username without password": func(p map[string]any) { delete(p, "password") },
		"invalid utf8":                    func(p map[string]any) { p["password"] = string([]byte{255}) },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(endpoint)
			var changed map[string]any
			_ = json.Unmarshal(raw, &changed)
			mutate(changed)
			if _, err := ValidateEndpoint(changed); err == nil {
				t.Fatal("malformed native map accepted")
			}
		})
	}
	for _, suffix := range []string{"mssfix 0 fixed\nreneg-sec 0\n", "<tls-crypt>\nWRAP\n</tls-crypt>\n", "<tls-crypt-v2>\nWRAP\n</tls-crypt-v2>\n"} {
		base := openVPNProfile("", "")
		base.Username, base.Password = "user", "password"
		base.Config += suffix
		endpoint, err := CompileProfile(base, "exit", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateEndpoint(endpoint); err != nil {
			t.Fatal("valid disabled option/control wrap rejected", err)
		}
	}
}

func TestOpenVPNPrivateSchemaRejectsUnknownDuplicateNullAndHiddenPEMSecrets(t *testing.T) {
	p := openVPNProfile("", "")
	p.Username, p.Password = "local-user", "local-password"
	server := p
	server.Username = "server-user"
	desc, err := DescribePeer(server, openVPNAuthKey(t))
	if err != nil {
		t.Fatal(err)
	}
	pair := Pairing{PrivateKey: openVPNAuthKey(t), Server: desc}
	raw, _ := json.Marshal(pair)
	for _, value := range []string{"null", "[]", string(raw[:len(raw)-1]) + `,"private_key":"shadow"}`, strings.Replace(string(raw), `"server":`, `"ignored":{},"server":`, 1), strings.Replace(string(raw), `"provider_identity":{`, `"provider_identity":{"password":"secret",`, 1), strings.Replace(string(raw), `"transport":{`, `"transport":{"type":"shadow",`, 1)} {
		var decoded Pairing
		if json.Unmarshal([]byte(value), &decoded) == nil {
			t.Fatal("ambiguous or extra private schema accepted")
		}
	}
	cert, _, _ := openVPNTestIdentity(t, "public-ca", nil)
	p.Config += "<ca>\n" + cert + "-----BEGIN PRIVATE KEY-----\nPRIVATE\n-----END PRIVATE KEY-----\n</ca>\n"
	if _, err := DescribePeer(p, pair.PrivateKey); err == nil {
		t.Fatal("public export retained a private key hidden after CA certificate")
	}
}
