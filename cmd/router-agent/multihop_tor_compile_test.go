package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/multihoprelay"
)

const pairingTorNode = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func pairingTorSource(mode string) map[string]any {
	source := map[string]any{"schema": 1, "id": "operator-tor", "entry_node_id": pairingTorNode,
		"mode": mode, "dns": map[string]any{"mode": "home"}, "adguard_ipv4": "192.168.50.133"}
	if mode == "tor-bridge" {
		line := "obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 52)) + " iat-mode=0"
		source["tor_bridge"] = map[string]any{"transport": "obfs4", "bridges": []string{"Bridge " + line}}
	}
	return source
}

func pairingTorInput(t *testing.T, source map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"entry_node_id": pairingTorNode, "source": source})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCompileServerTorSourceKeepsCanonicalWorkerAuthority(t *testing.T) {
	for _, mode := range []string{"tor", "tor-bridge"} {
		for _, dns := range []map[string]any{
			{"mode": "home"},
			{"mode": "custom", "transport": "tls", "address": "9.9.9.9", "server_name": "dns.quad9.net"},
			{"mode": "rescue"},
		} {
			t.Run(mode+"/"+dns["mode"].(string), func(t *testing.T) {
				source := pairingTorSource(mode)
				source["dns"] = dns
				if dns["mode"] != "home" {
					delete(source, "adguard_ipv4")
				}
				input := pairingTorInput(t, source)
				var output bytes.Buffer
				if err := compileServerTorSource(bytes.NewReader(input), &output); err != nil {
					t.Fatal(err)
				}
				var result struct {
					SourceJSON string                      `json:"source_json"`
					Reference  multihoprelay.TorExitSource `json:"reference"`
				}
				if err := json.Unmarshal(output.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(source)
				policy, err := mobiletor.NewServerTorPolicy(string(raw), pairingTorNode)
				if err != nil || result.SourceJSON != policy.Source() || result.Reference.ID != policy.ID() || result.Reference.Mode != policy.Mode() || result.Reference.SourceSHA256 != policy.SourceSHA256() || result.Reference.DNSPolicySHA256 != policy.DNSPolicySHA256() {
					t.Fatal("operator compiler diverged from the actual worker's immutable source")
				}
				var replay map[string]any
				if json.Unmarshal([]byte(result.SourceJSON), &replay) != nil {
					t.Fatal("canonical source was not a JSON object")
				}
				var second bytes.Buffer
				if compileServerTorSource(bytes.NewReader(pairingTorInput(t, replay)), &second) != nil || !bytes.Equal(output.Bytes(), second.Bytes()) {
					t.Fatal("reprovisioning changed the captured source or DNS hash")
				}
			})
		}
	}
}

func TestCompileServerTorSourceRejectsPrivateInputBeforeOutput(t *testing.T) {
	valid := pairingTorInput(t, pairingTorSource("tor-bridge"))
	inputs := [][]byte{
		nil, []byte("null"), []byte(`{"entry_node_id":"` + pairingTorNode + `","source":null}`),
		append(append([]byte{}, valid...), []byte(`{}`)...),
		bytes.Replace(valid, []byte(`"source":`), []byte(`"source":{},"source":`), 1),
		bytes.Replace(valid, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		append([]byte(`{"unknown":"private-secret-must-not-echo",`), valid[1:]...),
		bytes.Repeat([]byte(" "), (128<<10)+1),
	}
	for _, mutate := range []func(map[string]any){
		func(s map[string]any) { s["entry_node_id"] = strings.Repeat("b", 64) },
		func(s map[string]any) { s["id"] = "../private-secret-must-not-echo" },
		func(s map[string]any) { s["schema"] = true },
		func(s map[string]any) { s["torrc"] = "private-secret-must-not-echo" },
		func(s map[string]any) { s["executable"] = "/tmp/foreign" },
		func(s map[string]any) { s["dns"] = map[string]any{"mode": "home", "address": "192.168.1.53"} },
		func(s map[string]any) {
			s["dns"] = map[string]any{"mode": "custom", "transport": "tcp", "address": "private-secret-must-not-echo"}
		},
		func(s map[string]any) { s["dns"] = map[string]any{"mode": "home", "bootstrap": "system"} },
		func(s map[string]any) {
			s["tor_bridge"] = map[string]any{"transport": "obfs4", "bridges": []string{"private-secret-must-not-echo\nDisableNetwork 0"}}
		},
	} {
		source := pairingTorSource("tor-bridge")
		mutate(source)
		inputs = append(inputs, pairingTorInput(t, source))
	}
	for index, input := range inputs {
		var output bytes.Buffer
		err := compileServerTorSource(bytes.NewReader(input), &output)
		if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "private-secret-must-not-echo") {
			t.Fatalf("invalid input %d wrote private partial output or acquired pairing authority", index)
		}
	}
	var output bytes.Buffer
	if compileServerTorSource(pairingTorBrokenReader{}, &output) == nil || output.Len() != 0 {
		t.Fatal("failed input read emitted a partial private result")
	}
	if err := compileServerTorSource(bytes.NewReader(valid), pairingTorShortWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("private output truncation was reported as a complete pairing", err)
	}
}

type pairingTorBrokenReader struct{}

func (pairingTorBrokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type pairingTorShortWriter struct{}

func (pairingTorShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
