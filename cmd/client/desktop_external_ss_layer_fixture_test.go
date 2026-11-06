package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"router-vpn/internal/common"
)

// The public lifecycle fixture compares the complete saved source with its
// original capture. Its arbitrary transport values must use the same types as
// an imported JSON node; otherwise a port can differ only by Go number type.
func TestDesktopSSLayerFixturePreservesImportedJSONTypes(t *testing.T) {
	modes := []string{common.StartLayerOff, common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR}
	for i, entryMode := range modes {
		for j, exitMode := range modes {
			t.Run(fmt.Sprintf("entry%d-exit%d", i, j), func(t *testing.T) {
				p, e, _ := desktopSSEntryFixture(t, "always", desktopSSEntryMethods[1], desktopSSEntryMethods[2], "tcp")
				desktopSSProvisionLayer(&e, entryMode, "10.94.0.1", 'a')
				desktopSSProvisionLayer(&p, exitMode, "10.93.0.1", 'b')
				original := common.RouterProfileStore{SelectedID: p.ID, Profiles: []common.RouterProfile{p, e}}
				if err := common.NormalizeRouterProfileStore(&original); err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(original)
				if err != nil {
					t.Fatal(err)
				}
				var saved common.RouterProfileStore
				if err = json.Unmarshal(raw, &saved); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(original, saved) {
					for index, profile := range original.Profiles {
						if layer := profile.External.StartLayer; layer != nil {
							t.Logf("profile %d port types: captured=%T persisted=%T", index, layer.Transport["server_port"], saved.Profiles[index].External.StartLayer.Transport["server_port"])
						}
					}
					t.Fatal("fixture source differs after unchanged JSON persistence")
				}
			})
		}
	}
}
