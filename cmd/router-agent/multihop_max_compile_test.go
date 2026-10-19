package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

type maxCapturedFixture struct {
	Files  map[string]string `json:"files"`
	Policy map[string]string `json:"policy"`
	Graph  map[string]any    `json:"graph"`
}

func maxRelayAssets(t *testing.T) map[string]maxCapturedFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "captured-max.json")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-run", "^TestExportMAXMobileProfiles$", "-count=1", "./internal/mobilemultihop")
	command.Dir = filepath.Join("..", "..")
	command.Env = append(os.Environ(), "ROUTERVPN_MAX_PROFILE_FIXTURES="+path)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("shipping complete MAX asset fixture: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]maxCapturedFixture
	if err = json.Unmarshal(raw, &result); err != nil || len(result) != 4 {
		t.Fatal("MAX capture fixture omitted a complete family", err)
	}
	return result
}

func maxRelayJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCompleteMAXRelayCompilerRetainsCapturedNativeChainAndBoundedStdIO(t *testing.T) {
	for mode, fixture := range maxRelayAssets(t) {
		policy, source := fixture.Policy, maxRelayJSON(t, fixture.Files)
		var result bytes.Buffer
		compile := func(reader io.Reader, writer io.Writer) error {
			return compileMAXRelayProfile(reader, writer, mode, policy["node_id"], policy["endpoint"], policy["router_api"])
		}
		if err := compile(bytes.NewReader(source), &result); err != nil {
			t.Fatal(mode, err)
		}
		var plan map[string]any
		if err := json.Unmarshal(result.Bytes(), &plan); err != nil || len(plan) != 2 {
			t.Fatal("CLI omitted complete private MAX plan", err)
		}
		base, outputs := plan["endpoint"].(map[string]any), plan["outbounds"].([]any)
		if err := multihoprelay.ValidateMAXChain(base, outputs, mode, policy["node_id"], "", multihoprelay.MAXRelayTags(), ""); err != nil {
			t.Fatal("CLI output does not retain every mandatory encryption owner", err)
		}
		captured := fixture.Graph["endpoints"].([]any)[0].(map[string]any)
		for _, field := range []string{"type", "mode", "node_id", "private_key", "pq", "peers", "address", "mtu", "amnezia"} {
			if !reflect.DeepEqual(base[field], captured[field]) {
				t.Fatal("private relay compiler replaced captured base identity", field)
			}
		}
		if !bytes.Equal(source, maxRelayJSON(t, fixture.Files)) {
			t.Fatal("offline compiler changed source asset ownership")
		}
		if err := compile(bytes.NewReader(source), pqShortWriter{}); !errors.Is(err, io.ErrShortWrite) {
			t.Fatal("partial MAX plan was reported complete", err)
		}
		if err := compile(bytes.NewReader(source), failedRelayOutput{}); err == nil {
			t.Fatal("private MAX output error was discarded")
		}
		for _, reader := range []io.Reader{pqReadFault{}, bytes.NewReader(nil), bytes.NewReader(bytes.Repeat([]byte{'x'}, maxMAXPairingBytes+1)), bytes.NewReader([]byte(`{"private-sentinel":"bad"}`))} {
			var output bytes.Buffer
			if err := compile(reader, &output); err == nil || output.Len() != 0 || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("invalid or oversized MAX input emitted private output")
			}
		}
		for _, fault := range []string{"mode", "node", "endpoint", "private-API", "API-auth", "missing-PQ", "same-PQ-peer", "missing-middle", "missing-outer", "helper", "env-command", "duplicate-asset", "weaker-chain"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				assets := map[string]string{}
				for name, value := range fixture.Files {
					assets[name] = value
				}
				selected, node, server, api := mode, policy["node_id"], policy["endpoint"], policy["router_api"]
				switch fault {
				case "mode":
					selected = multihoprelay.MAXBaseMode(mode)
				case "node":
					node = "invalid"
				case "endpoint":
					server = "192.0.2.99"
				case "private-API":
					api = "http://127.0.0.1:8787"
				case "API-auth":
					api = "http://private-sentinel@10.77.0.1:8787"
				case "missing-PQ":
					delete(assets, "rosenpass-client-secret")
				case "same-PQ-peer":
					assets["rosenpass-server-public"] = assets["rosenpass-client-public"]
				case "missing-middle":
					delete(assets, "middle-sing-box.json")
				case "missing-outer":
					delete(assets, "outer-xray.json")
					delete(assets, "cert.pem")
				case "helper":
					assets["run.sh"] = base64.StdEncoding.EncodeToString([]byte("private-sentinel"))
				case "env-command", "weaker-chain":
					raw, err := base64.StdEncoding.DecodeString(assets["chain.env"])
					if err != nil {
						t.Fatal(err)
					}
					if fault == "env-command" {
						raw = append(raw, []byte("COMMAND=private-sentinel\n")...)
					} else {
						raw = bytes.ReplaceAll(raw, []byte("PQ_BASE=1"), []byte("PQ_BASE=0"))
					}
					assets["chain.env"] = base64.StdEncoding.EncodeToString(raw)
				}
				encoded := maxRelayJSON(t, assets)
				if fault == "duplicate-asset" {
					encoded = append([]byte(`{"chain.env":"private-sentinel",`), encoded[1:]...)
				}
				var output bytes.Buffer
				err := compileMAXRelayProfile(bytes.NewReader(encoded), &output, selected, node, server, api)
				if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "private-sentinel") {
					t.Fatal("partial or unowned MAX graph did not fail before publication")
				}
			})
		}
	}
}

func TestCompleteMAXPrivatePairerUsesShippingOfflineCompilers(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("operator relay pairing runs in the authoritative Linux Go gate")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python is required for the private MAX pairing regression")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, filepath.Join("..", "..", "deploy", "test_relay_max_pairing.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("complete MAX private pairing: %v\n%s", err, output)
	}
}
