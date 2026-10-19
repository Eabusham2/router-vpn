//go:build go1.24

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/nativecomposite"
)

type compositeBundle struct {
	Node     string                       `json:"nodeProofId"`
	Profiles map[string]map[string]string `json:"profiles"`
	Nodes    []struct {
		Endpoint string `json:"endpoint"`
		API      string `json:"router_api"`
	} `json:"routerProfiles"`
}

func relayCompositeAssets(t *testing.T) compositeBundle {
	t.Helper()
	command := exec.Command("go", "run", filepath.Join("..", "..", "deploy", "testfixtures", "composite"), "--exits")
	body, err := command.Output()
	if err != nil {
		t.Fatal("public composite asset generator failed", err)
	}
	var bundle compositeBundle
	if err = json.Unmarshal(body, &bundle); err != nil || len(bundle.Nodes) != 1 || len(bundle.Profiles) != 4 {
		t.Fatal("generated asset bundle incomplete", err)
	}
	return bundle
}
func compositeJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type shortCompositeOutput struct{}

func (shortCompositeOutput) Write([]byte) (int, error) { return 1, nil }

func TestCompositeRelayCompilerUsesBothShippingTransportsAndBoundedStdIO(t *testing.T) {
	bundle := relayCompositeAssets(t)
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		source := compositeJSON(t, bundle.Profiles[mode])
		var output bytes.Buffer
		if err := compileCompositeRelayProfile(bytes.NewReader(source), &output, mode, bundle.Node, bundle.Nodes[0].Endpoint, bundle.Nodes[0].API); err != nil {
			t.Fatal(mode, err)
		}
		var plan map[string]any
		if err := json.Unmarshal(output.Bytes(), &plan); err != nil {
			t.Fatal(err)
		}
		if err := nativecomposite.ValidatePlan(plan, mode, bundle.Node, ""); err != nil {
			t.Fatal("CLI lost an authenticated lane", err)
		}
		if len(plan) != 6 || plan["type"] != nativecomposite.PlanType || plan["tcp"] == nil || plan["udp"] == nil {
			t.Fatal("CLI emitted a runnable single-lane substitute")
		}
		if !bytes.Equal(source, compositeJSON(t, bundle.Profiles[mode])) {
			t.Fatal("CLI changed captured assets")
		}
		if err := compileCompositeRelayProfile(bytes.NewReader(source), failedRelayOutput{}, mode, bundle.Node, bundle.Nodes[0].Endpoint, bundle.Nodes[0].API); err == nil {
			t.Fatal("private output error was discarded")
		}
		if err := compileCompositeRelayProfile(bytes.NewReader(source), shortCompositeOutput{}, mode, bundle.Node, bundle.Nodes[0].Endpoint, bundle.Nodes[0].API); !errors.Is(err, io.ErrShortWrite) {
			t.Fatal("partial private output was reported complete")
		}
		for _, fault := range []string{"node", "server", "api-public", "api-user", "api-port", "missing-UDP", "weak-UDP", "foreign-UDP", "weak-TLS", "missing-helper", "extra-helper"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				assets := map[string]string{}
				for name, value := range bundle.Profiles[mode] {
					assets[name] = value
				}
				node, server, api := bundle.Node, bundle.Nodes[0].Endpoint, bundle.Nodes[0].API
				raw, err := base64.StdEncoding.DecodeString(assets["sing-box.json"])
				if err != nil {
					t.Fatal(err)
				}
				var graph map[string]any
				if err = json.Unmarshal(raw, &graph); err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "node":
					node = "malformed-node"
				case "server":
					server = "192.0.2.99"
				case "api-public":
					api = "http://8.8.8.8:8787"
				case "api-user":
					api = "http://user@10.88.0.1:8787"
				case "api-port":
					api = "http://10.88.0.1"
				case "missing-UDP":
					graph["outbounds"] = graph["outbounds"].([]any)[:1]
				case "weak-UDP":
					graph["outbounds"].([]any)[1].(map[string]any)["type"] = "direct"
				case "foreign-UDP":
					graph["outbounds"].([]any)[1].(map[string]any)["server"] = "192.0.2.99"
				case "weak-TLS":
					graph["outbounds"].([]any)[1].(map[string]any)["tls"].(map[string]any)["insecure"] = true
				case "missing-helper":
					delete(assets, "xray.json")
					delete(assets, "sslocal.json")
				case "extra-helper":
					assets["run.sh"] = base64.StdEncoding.EncodeToString([]byte("private-must-not-echo"))
				}
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString(compositeJSON(t, graph))
				var result bytes.Buffer
				err = compileCompositeRelayProfile(bytes.NewReader(compositeJSON(t, assets)), &result, mode, node, server, api)
				if err == nil || result.Len() != 0 || strings.Contains(err.Error(), "private-must-not-echo") {
					t.Fatal("invalid captured source emitted private or incomplete output")
				}
			})
		}
		for _, raw := range [][]byte{nil, []byte(`{"secret":"private-must-not-echo"}`), bytes.Repeat([]byte{'x'}, nativecomposite.MaxSize+1)} {
			var result bytes.Buffer
			err := compileCompositeRelayProfile(bytes.NewReader(raw), &result, mode, bundle.Node, bundle.Nodes[0].Endpoint, bundle.Nodes[0].API)
			if err == nil || result.Len() != 0 || strings.Contains(err.Error(), "private-must-not-echo") {
				t.Fatal("bounded stdin did not fail closed")
			}
		}
	}
	for _, mode := range []string{"", "reality-vision", "shadowsocks", "max-quic-wg", "tor"} {
		var result bytes.Buffer
		if err := compileCompositeRelayProfile(bytes.NewReader(compositeJSON(t, bundle.Profiles["max"])), &result, mode, bundle.Node, bundle.Nodes[0].Endpoint, bundle.Nodes[0].API); err == nil || result.Len() != 0 {
			t.Fatal("unrequested mode reached paired output")
		}
	}
}

func TestCompositeRelayPairerCallsOnlyTheShippingOfflineCompilers(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("private Linux relay pairing runs in the authoritative Linux Go gate")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python is required for the private relay pairing regression")
	}
	command := exec.Command(python, filepath.Join("..", "..", "deploy", "test_relay_composite_pairing.py"))
	command.Dir = "."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("private composite pairing contract: %v\n%s", err, output)
	}
}
