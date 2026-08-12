package main

import (
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func mhProfile(id, endpoint string) common.RouterProfile {
	return common.RouterProfile{ID: id, Name: strings.ToUpper(id), Endpoint: endpoint, SocksHost: "192.168.50.133", SocksPort: 1080}
}

func TestResolveMultihopSelectionDefaultsAndRejectsUnsafeSelections(t *testing.T) {
	control := mhProfile("control", "198.51.100.10")
	control.MultihopEnabled = true
	control.MultihopEntryID = "entry"
	control.MultihopExitID = "exit"
	control.BaseTunnel = "auto"
	entry := mhProfile("entry", "203.0.113.11")
	entry.BaseTunnel = "awg"
	exit := mhProfile("exit", "203.0.113.12")
	profiles := []common.RouterProfile{control, entry, exit}

	sel, err := resolveMultihopSelection(control, profiles, multihopConnectRequest{})
	if err != nil { t.Fatal(err) }
	if sel.Entry.ID != "entry" || sel.Exit.ID != "exit" || sel.Base != "awg" || sel.ExitMode != "shadowsocks" {
		t.Fatalf("unexpected defaults: %+v", sel)
	}
	if _, err := resolveMultihopSelection(control, profiles, multihopConnectRequest{EntryID:"entry", ExitID:"entry"}); err == nil {
		t.Fatal("same-node multihop was accepted")
	}
	if _, err := resolveMultihopSelection(control, profiles, multihopConnectRequest{ExitMode:"reality-vision"}); err == nil {
		t.Fatal("unsupported exit transport was accepted")
	}
	badEntry := entry; badEntry.SocksHost = ""
	if _, err := resolveMultihopSelection(control, []common.RouterProfile{control,badEntry,exit}, multihopConnectRequest{}); err == nil {
		t.Fatal("entry without private SOCKS was accepted")
	}
}

func TestMultihopCommandUsesConfiguredRuntimeRootNotScriptsDirectory(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", "/tmp/router-vpn-data")
	a := &app{cfg: common.ClientConfig{ScriptsDir: "/tmp/router-vpn-data/modes"}}
	sel := multihopSelection{Control: mhProfile("control","198.51.100.10"), Entry: mhProfile("entry","203.0.113.11"), Exit: mhProfile("exit","203.0.113.12"), Base:"wg", ExitMode:"shadowsocks"}
	cmd := multihopCommand(a, sel)
	if cmd.Dir != "/tmp/router-vpn-data/modes" { t.Fatalf("unexpected working directory: %s", cmd.Dir) }
	joined := strings.Join(cmd.Env, "\n")
	if !strings.Contains(joined, "HOMEVPN_ROOT=/tmp/router-vpn-data") { t.Fatalf("runtime root missing from env: %s", joined) }
	if strings.Contains(joined, "HOMEVPN_ROOT=.") { t.Fatal("multihop controller regressed to scripts-dir HOMEVPN_ROOT") }
}

func TestMultihopNodeSummariesNeverExposeSecrets(t *testing.T) {
	p := mhProfile("node","203.0.113.20")
	p.APIToken = "top-secret-token"
	p.SocksUsername = "secret-user"
	p.SocksPassword = "secret-pass"
	p.Location = "Austin"
	p.LatencyMedianMs = 12.3
	nodes := multihopNodeSummaries([]common.RouterProfile{p})
	if len(nodes) != 1 || nodes[0].ID != "node" || nodes[0].Location != "Austin" || nodes[0].LatencyMedianMs != 12.3 { t.Fatalf("bad summary: %+v", nodes) }
	formatted := strings.ToLower(strings.Join([]string{nodes[0].ID,nodes[0].Name,nodes[0].Location,nodes[0].Endpoint,nodes[0].BaseTunnel},"|"))
	for _, secret := range []string{"top-secret-token","secret-user","secret-pass"} {
		if strings.Contains(formatted, secret) { t.Fatalf("multihop status leaked %s", secret) }
	}
}
