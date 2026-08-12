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
