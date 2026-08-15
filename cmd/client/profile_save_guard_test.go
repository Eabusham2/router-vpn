package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestGenericProfileSaveRejectsExternalCreation(t *testing.T) {
	a := &app{
		cfg:      common.ClientConfig{ProfilesFile: filepath.Join(t.TempDir(), "routers.json")},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion},
		state:    state{Mode: "off", Phase: "off"},
	}
	// Exercise the generic endpoint guard directly. The payload deliberately
	// does not need to be a fully valid external profile because this endpoint
	// must reject the external profile class before any private-profile import
	// or persistence path is reached.
	body := []byte(`{"schema_version":3,"id":"external-create-test","name":"External WG","node_kind":"external","endpoint":"203.0.113.8","external":{"protocol":"wireguard"}}`)
	body = bytes.ReplaceAll(body, []byte{'\\', '"'}, []byte{'"'})
	rr := httptest.NewRecorder()
	a.saveProfile(rr, httptest.NewRequest("POST", "/api/profile/save", bytes.NewReader(body)))
	if rr.Code != 400 {
		t.Fatalf("generic save external creation status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "/api/external-profile/import") {
		t.Fatalf("generic save did not direct external creation to validated import path: %s", rr.Body.String())
	}
	if len(a.profiles.Profiles) != 0 {
		t.Fatalf("generic save mutated profile store after rejected external creation: %#v", a.profiles.Profiles)
	}
}

func TestGenericProfileSaveCannotOverwriteStoredExternalSecrets(t *testing.T) {
	private := privateHTTPTestProfile()
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(t.TempDir(), "routers.json")},
		profiles: common.RouterProfileStore{
			SchemaVersion: common.RouterProfileStoreVersion,
			SelectedID:    private.ID,
			Profiles:      []common.RouterProfile{private},
		},
		state: state{Mode: "off", Phase: "off", RouterID: private.ID},
	}
	incoming := common.RouterProfile{
		SchemaVersion: common.RouterProfileSchemaVersion,
		ID:            private.ID,
		Name:          "Redacted public copy",
		NodeKind:      "router-vpn",
		Endpoint:      "vpn.example.com",
	}
	body, err := json.Marshal(incoming)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	a.saveProfile(rr, httptest.NewRequest("POST", "/api/profile/save", bytes.NewReader(body)))
	if rr.Code != 409 {
		t.Fatalf("generic save stored-external overwrite status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "/api/external-profile/import") {
		t.Fatalf("overwrite rejection did not direct caller to validated external import path: %s", rr.Body.String())
	}
	if len(a.profiles.Profiles) != 1 {
		t.Fatalf("stored external profile count changed after rejected overwrite: %d", len(a.profiles.Profiles))
	}
	stored := a.profiles.Profiles[0]
	if stored.NodeKind != "external" || stored.External == nil || stored.External.WireGuard == nil {
		t.Fatalf("stored external profile shape was damaged: %#v", stored)
	}
	if got := stored.External.WireGuard.PrivateKey; got != testWGPrivateKey {
		t.Fatalf("stored WireGuard private key changed after rejected generic save: %q", got)
	}
	if got := stored.External.WireGuard.PresharedKey; got != testWGPresharedKey {
		t.Fatalf("stored WireGuard preshared key changed after rejected generic save: %q", got)
	}
	if got := stored.APIToken; got != "ROUTER_ADMIN_SECRET_DO_NOT_LEAK" {
		t.Fatalf("stored private API token changed after rejected generic save: %q", got)
	}
}
