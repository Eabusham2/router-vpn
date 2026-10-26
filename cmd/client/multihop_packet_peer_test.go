package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func TestNativeMultihopPacketServerRejectsCanonicalPeerReuseBeforePUT(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) { nativeMultihopPacketServerPeerGuard(t, mode) })
	}
}

func nativeMultihopPacketServerPeerGuard(t *testing.T, mode string) {
	t.Helper()
	root, selection := nativeMultihopCapturedFixture(t, "wg", "off")
	selection.ExitMode = mode
	first, err := captureNativeMultihopSelection(context.Background(), root, selection, []string{mode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	public := first.Native.localPacketPublic[mode]
	seed, full, split := byte('p'), "wg.conf", "wg-socks.conf"
	if mode != "wg" {
		seed, full, split = 'v', "awg.conf", "awg-socks.conf"
	}
	private, err := base64.StdEncoding.DecodeString(testWGKey(seed))
	if err != nil {
		t.Fatal(err)
	}
	alias := append([]byte(nil), private...)
	alias[0] ^= 7
	alias[31] ^= 128
	originalKey, _ := ecdh.X25519().NewPrivateKey(private)
	aliasKey, _ := ecdh.X25519().NewPrivateKey(alias)
	if originalKey.Equal(aliasKey) || !originalKey.PublicKey().Equal(aliasKey.PublicKey()) {
		t.Fatal("fixture lost its different private encodings of one public identity")
	}
	for _, name := range []string{full, split} {
		path := filepath.Join(root, "generated", "exit", mode, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		changed := strings.ReplaceAll(string(raw), testWGKey(seed), base64.StdEncoding.EncodeToString(alias))
		if changed == string(raw) {
			t.Fatal("fixture did not change the captured private source")
		}
		if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if first.Native.validate(first) == nil {
		t.Fatal("changed private source retained old capture ownership")
	}
	selection, err = captureNativeMultihopSelection(context.Background(), root, selection, []string{mode}, nil)
	if err != nil || public == "" || selection.Native.localPacketPublic[mode] != public {
		t.Fatal("recaptured alias changed the canonical local peer identity", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:1098")
	if err != nil {
		t.Fatal(err)
	}
	var gate sync.Mutex
	var offered multihoprelay.Capabilities
	var answer multihoprelay.Lease
	var puts atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/multihop/lease" || r.Host != "10.77.0.1:8787" || r.Header.Get("Authorization") != "Bearer "+selection.Entry.APIToken {
			http.Error(w, "incorrect captured control lane", http.StatusForbidden)
			return
		}
		gate.Lock()
		catalog, lease := offered, answer
		gate.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(catalog)
		case http.MethodPut:
			puts.Add(1)
			var request multihoprelay.Request
			if json.NewDecoder(r.Body).Decode(&request) != nil || request != lease.Request {
				http.Error(w, "changed lease owner", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(lease)
		default:
			http.Error(w, "unexpected control method", http.StatusMethodNotAllowed)
		}
	}))
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	serverKey, _ := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("z", 32)))
	independent := base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes())
	if independent == public {
		t.Fatal("independent fixture peer reused the local identity")
	}
	for _, fault := range []string{"same-private", "same-public-alias", "missing-server", "missing-local", "wrong-node", "wrong-layer", "malformed-key", "independent"} {
		t.Run(fault, func(t *testing.T) {
			command := &exec.Cmd{}
			app := &app{cmd: command}
			request := multihoprelay.Request{SessionID: strings.Repeat("1", 32), EntryNodeID: selection.Entry.NodeProofID, ExitID: selection.Exit.ID, ExitMode: mode, Port: 26241, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48)}
			lease := multihoprelay.Lease{Request: request, NodeID: selection.Entry.NodeProofID, ExitNodeID: selection.Exit.NodeProofID, Host: "10.77.0.1", Port: request.Port, Username: request.Username, Password: request.Password, ExpiresAt: time.Now().Add(time.Minute)}
			owner := &desktopRelayOwner{app: app, command: command, entry: selection.Entry, request: request, expected: lease, localPacketPublic: selection.Native.localPacketPublic[mode]}
			exit := multihoprelay.Capability{ID: selection.Exit.ID, Mode: mode, NodeID: selection.Exit.NodeProofID, PublicKey: independent}
			switch fault {
			case "same-private":
				exit.PublicKey = base64.StdEncoding.EncodeToString(originalKey.PublicKey().Bytes())
			case "same-public-alias":
				exit.PublicKey = base64.StdEncoding.EncodeToString(aliasKey.PublicKey().Bytes())
			case "missing-server":
				exit.PublicKey = ""
			case "missing-local":
				owner.localPacketPublic = ""
			case "wrong-node":
				exit.NodeID = strings.Repeat("f", 64)
			case "wrong-layer":
				exit.Layer = "aes-256-gcm"
			case "malformed-key":
				exit.PublicKey = "invalid"
			}
			gate.Lock()
			offered = multihoprelay.Capabilities{NodeID: selection.Entry.NodeProofID, Execution: "server", Exits: []multihoprelay.Capability{exit}}
			answer = lease
			gate.Unlock()
			before := puts.Load()
			if err := owner.put(context.Background()); err == nil || puts.Load() != before {
				t.Fatal("lease PUT ran before independent peer discovery")
			}
			err := owner.available(context.Background())
			if fault != "independent" {
				if err == nil || owner.put(context.Background()) == nil || puts.Load() != before {
					t.Fatal("unsafe or unowned server peer reached PUT", fault)
				}
				return
			}
			if err != nil || owner.serverPacketPublic != independent {
				t.Fatal("independent captured peer was not accepted", err)
			}
			if owner.request.ExpectedPacketPublicKey != independent || owner.expected.Request != owner.request {
				t.Fatal("prepared listener receipt did not adopt the exact public key pin")
			}
			gate.Lock()
			answer.Request = owner.request
			gate.Unlock()
			if err := owner.put(context.Background()); err != nil || puts.Load() != before+1 || !owner.renewed {
				t.Fatal("independent peer did not acquire its exact owned lease", err)
			}
			if err := owner.put(context.Background()); err != nil || puts.Load() != before+2 {
				t.Fatal("owned renewal lost its independent peer guard", err)
			}
			for _, changed := range []string{"", public, base64.StdEncoding.EncodeToString(make([]byte, 32))} {
				gate.Lock()
				offered.Exits[0].PublicKey = changed
				gate.Unlock()
				if err := owner.put(context.Background()); err == nil || puts.Load() != before+2 || owner.serverPacketPublic != independent || owner.request.ExpectedPacketPublicKey != independent {
					t.Fatal("changed, missing or reused renewal identity reached PUT or replaced the original pin")
				}
				gate.Lock()
				offered.Exits[0].PublicKey = independent
				gate.Unlock()
				if err := owner.available(context.Background()); err != nil {
					t.Fatal("original paired identity could not be revalidated", err)
				}
			}
			app.mu.Lock()
			app.cmd = &exec.Cmd{}
			app.mu.Unlock()
			if err := owner.put(context.Background()); err == nil || puts.Load() != before+2 {
				t.Fatal("retired runtime renewed a replacement owner's lease")
			}
		})
	}
}
