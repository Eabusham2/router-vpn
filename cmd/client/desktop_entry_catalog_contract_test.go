package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// The profile fixture consumes the real controller catalog. Do not derive its
// advertised modes from the GTK array: that would bless a chooser-only change.
func TestDesktopEntryCatalogContracts(t *testing.T) {
	a := desktopSpeedLabFormApp(t)
	entry, _ := profileByID(a.profiles.Profiles, "entry")
	final, _ := profileByID(a.profiles.Profiles, "exit-router")
	final.ID = "exit"
	a.profiles.Profiles = []common.RouterProfile{entry, final}
	a.profiles.SelectedID = final.ID
	imports := []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect"}
	for _, protocol := range imports {
		original, _ := desktopExternalNativeFixture(t, protocol)
		original.ID, original.Name = "imported-"+protocol, "Original "+protocol
		a.profiles.Profiles = append(a.profiles.Profiles, original)
	}
	status := httptest.NewRecorder()
	a.nativeMultihopStatus(status, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil))
	var daily struct {
		Supported []string `json:"supported_entry_modes"`
		Paired    []string `json:"paired_entry_modes"`
		Execution []string `json:"imported_entry_executions"`
	}
	if status.Code != http.StatusOK || json.Unmarshal(status.Body.Bytes(), &daily) != nil {
		t.Fatal("actual main/profile entry catalog failed")
	}
	paired := mobilemultihop.NodeMultihopEntryModes()
	expected := append(slices.Clone(paired), imports...)
	slices.Sort(expected)
	actual := slices.Clone(daily.Supported)
	slices.Sort(actual)
	if len(paired) != 19 || len(actual) != 24 || !reflect.DeepEqual(actual, expected) ||
		!reflect.DeepEqual(daily.Paired, paired) || !reflect.DeepEqual(daily.Execution, []string{"local"}) {
		t.Fatal("main/profile catalog lost original imported identities or paired execution boundaries")
	}
	options := httptest.NewRecorder()
	a.speedLabOptions(options, httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil))
	var temporary struct {
		Supported []string `json:"supported_entry_modes"`
	}
	if options.Code != http.StatusOK || json.Unmarshal(options.Body.Bytes(), &temporary) != nil || !reflect.DeepEqual(temporary.Supported, paired) {
		t.Fatal("temporary Router Speed Lab advertised an unrelated entry contract")
	}
	for _, protocol := range imports {
		if normalized, err := normalizeConnectionProfileEntryMode(protocol); err != nil || normalized != protocol {
			t.Fatal("main/profile lost canonical imported selection", protocol, err)
		}
		for _, execution := range []string{"local", "server", "auto"} {
			request := speedLabRequest{EntryID: entry.ID, ExitID: final.ID, EntryMode: protocol, ExitMode: "shadowsocks", Execution: execution}
			if _, err := a.resolveSpeedLabTemporaryMultihop(request, final, entry, a.profiles.Profiles); err == nil {
				t.Fatal("temporary paired entry borrowed imported transport authority", protocol, execution)
			}
			// A preserved main profile's saved import must not become WG when
			// the temporary form leaves its explicit mode empty.
			saved := cloneRouterProfile(final)
			saved.MultihopEntryMode = protocol
			request.EntryMode = ""
			if _, err := a.resolveSpeedLabTemporaryMultihop(request, saved, entry, a.profiles.Profiles); err == nil {
				t.Fatal("temporary path silently replaced the saved imported mode", protocol, execution)
			}
		}
	}
	if path := os.Getenv("ROUTERVPN_CONNECTION_PROFILE_FORM_CATALOG"); path != "" {
		if err := os.WriteFile(path, status.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDesktopEntryCatalogOriginalImportedAuthority(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			root, original := desktopImportedFixture(t, protocol, "reality-vision")
			before := mustImportedJSON(t, original)
			profiles := []common.RouterProfile{original.Entry, original.Exit}
			request := multihopConnectRequest{EntryID: original.Entry.ID, ExitID: original.Exit.ID, EntryMode: protocol, ExitMode: original.ExitMode, Execution: "local"}
			selected, err := resolveNativeMultihopSelection(original.Control, profiles, request)
			if err != nil {
				t.Fatal(err)
			}
			captured, err := captureNativeMultihopSelection(context.Background(), root, selected, []string{original.ExitMode}, nil)
			if err != nil || captured.Native == nil || !captured.Native.imported || captured.Native.validate(captured) != nil || captured.EntryMode != protocol ||
				captured.Entry.ID != original.Entry.ID || captured.Exit.ID != original.Exit.ID || captured.Control.ID != original.Exit.ID {
				t.Fatal("canonical main/profile selection lost its independently captured native path", err)
			}
			for _, execution := range []string{"server", "auto"} {
				request.Execution = execution
				if _, err := resolveNativeMultihopSelection(original.Control, profiles, request); err == nil {
					t.Fatal("imported profile granted unavailable execution", execution)
				}
			}
			request.Execution, request.EntryMode = "local", "wg"
			if _, err := resolveNativeMultihopSelection(original.Control, profiles, request); err == nil {
				t.Fatal("paired mode replaced original imported protocol")
			}
			if string(before) != string(mustImportedJSON(t, original)) {
				t.Fatal("catalog admission changed the original source profiles")
			}
		})
	}
}
