package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func savedNodeChainFixture(t *testing.T, count int) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a := setupProfileTestApp(t)
	root := clientRoot(a)
	a.profiles.Profiles = nil
	var selected []common.MultihopNodeSelection
	for i := 0; i < count; i++ {
		p, assets := viaEntryBaseFixture(t, "wg")
		oldEndpoint := p.Endpoint
		p.ID, p.Endpoint, p.Name = fmt.Sprintf("node-%d", i), fmt.Sprintf("203.0.113.%d", i+20), fmt.Sprintf("Node %d", i)
		p.APIToken, p.StartLayer = fmt.Sprintf("private-api-%d", i), "off"
		p.MTUPolicy, p.ManualMTU, p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "manual", 1340+i, "custom", "udp", "9.9.9.9", 5300+i
		p.StartupMode = "last"
		client, _ := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat(string(rune(i+20)), 32)))
		server, _ := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat(string(rune(i+40)), 32)))
		for name, raw := range assets {
			assets[name] = []byte(strings.NewReplacer(oldEndpoint, p.Endpoint, testWGKey('p'), base64.StdEncoding.EncodeToString(client.Bytes()), testWGKey('q'), base64.StdEncoding.EncodeToString(server.PublicKey().Bytes())).Replace(string(raw)))
		}
		p.NodeProofID, _ = nodeProofIDFromWGConfig(assets["wg.conf"])
		if err := common.NormalizeRouterProfile(&p); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"wg", "shadowsocks"} {
			dir := filepath.Join(root, "generated", p.ID, mode)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			files := assets
			if mode == "shadowsocks" {
				files = map[string][]byte{"sing-box.json": []byte(fmt.Sprintf(`{"outbounds":[{"type":"shadowsocks","tag":"proxy","server":%q,"server_port":8388,"method":"2022-blake3-aes-256-gcm","password":%q}]}`, p.Endpoint, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))))}
			}
			for name, raw := range files {
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		mode := "wg"
		if i == count-1 {
			mode = "shadowsocks"
		}
		selected = append(selected, common.MultihopNodeSelection{ID: p.ID, Mode: mode})
		a.profiles.Profiles = append(a.profiles.Profiles, p)
	}
	control := &a.profiles.Profiles[count-1]
	control.MultihopEnabled, control.MultihopExecution = true, "local"
	control.MultihopNodes = append([]common.MultihopNodeSelection(nil), selected...)
	a.profiles.SelectedID, a.state.RouterID = control.ID, control.ID
	return a, selected
}

func saveOrderedConnectionFixture(t *testing.T, a *app, nodes []common.MultihopNodeSelection) string {
	t.Helper()
	response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{
		"name": "Ordered saved path", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": "local", "multihop_nodes": nodes,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("ordered save status=%d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Profile connectionProfileRecord `json:"profile"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Profile.ID
}

func TestConnectionProfileOrderedThreeAndFourNodesRestoreIndependentPolicy(t *testing.T) {
	for _, count := range []int{3, 4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, nodes := savedNodeChainFixture(t, count)
			id := saveOrderedConnectionFixture(t, a, nodes)
			store, err := loadConnectionProfileStore(a)
			if err != nil || len(store.Profiles) != 1 || len(store.Profiles[0].NodeChain) != count || len(store.Profiles[0].Hops) != 0 {
				t.Fatalf("ordered storage is incomplete: %v", err)
			}
			raw, _ := os.ReadFile(connectionProfileStorePath(a))
			for _, secret := range []string{"private-api-", "private_key", "api_token", "preshared_key", "password"} {
				if strings.Contains(strings.ToLower(string(raw)), secret) {
					t.Fatalf("saved source reference copied %s", secret)
				}
			}
			for i := range a.profiles.Profiles {
				a.profiles.Profiles[i].DNSPort, a.profiles.Profiles[i].ManualMTU, a.profiles.Profiles[i].StartupMode = 5353, 1400, "manual"
			}
			response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if response.Code != http.StatusOK {
				t.Fatalf("ordered load status=%d: %s", response.Code, response.Body.String())
			}
			for i, p := range a.profiles.Profiles {
				if p.DNSPort != 5300+i || p.ManualMTU != 1340+i || p.StartupMode != "last" || p.APIToken != fmt.Sprintf("private-api-%d", i) {
					t.Fatal("ordered restore lost a member's independent saved policy or credential reference")
				}
			}
			if !reflect.DeepEqual(a.profiles.Profiles[count-1].MultihopNodes, nodes) || a.state.Connected || a.cmd != nil {
				t.Fatal("ordered load truncated/reordered selection or launched an unproved runtime")
			}
		})
	}
}

func TestConnectionProfileOrderedRestoreRejectsMiddleReplacementWithoutMutation(t *testing.T) {
	for _, change := range []string{"credential", "proof", "asset", "removed"} {
		t.Run(change, func(t *testing.T) {
			a, nodes := savedNodeChainFixture(t, 3)
			id := saveOrderedConnectionFixture(t, a, nodes)
			switch change {
			case "credential":
				a.profiles.Profiles[1].APIToken += "-replacement"
			case "proof":
				a.profiles.Profiles[1].NodeProofID = strings.Repeat("a", 64)
			case "asset":
				path := filepath.Join(clientRoot(a), "generated", nodes[1].ID, "wg", "wg.conf")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, []byte("\n# replacement-source\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "removed":
				a.profiles.Profiles = append(a.profiles.Profiles[:1], a.profiles.Profiles[2:]...)
			}
			before := cloneRouterProfileStore(a.profiles)
			response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if response.Code != http.StatusConflict || !reflect.DeepEqual(a.profiles, before) || a.cmd != nil || a.state.Connected {
				t.Fatalf("middle replacement was accepted or partially applied: status=%d %s", response.Code, response.Body.String())
			}
		})
	}
}
