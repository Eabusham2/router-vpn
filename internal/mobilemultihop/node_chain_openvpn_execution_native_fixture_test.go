package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Native ownership tests consume the actual shared compiler's independent
// private Local/Server profiles. Exporting them proves no connected endpoint.
func TestNodeChainOpenVPNExecutionNativeFixtures(t *testing.T) {
	for _, count := range []int{1, 2, 6} {
		for _, network := range []string{"tcp", "udp"} {
			name := fmt.Sprintf("%d-%s", count+2, network)
			t.Run(name, func(t *testing.T) {
				local, server := nodeChainOpenVPNServerSourceFixture(t, count, "wg", network, "")
				original, err := NewNodeChain(startJSON(t, local))
				if err != nil {
					t.Fatal(err)
				}
				for _, execution := range []string{"server", "auto"} {
					prep, err := NewNodeChainOpenVPNExecutionPreparation(original, execution)
					if err != nil {
						t.Fatal("native OpenVPN fixture lost shared preparation", err)
					}
					retained, err := prep.OriginalOpenVPNSource()
					if err != nil || retained != original || !prep.RequiresOpenVPNExecutionObserver() {
						t.Fatal("native fixture replaced original shared source", err)
					}
				}
				if _, err = NewNodeChainOpenVPNServerPolicy(startJSON(t, server)); err != nil {
					t.Fatal("native fixture lost independent Server source", err)
				}
				if directory := os.Getenv("ROUTERVPN_OPENVPN_EXECUTION_NATIVE_FIXTURES"); directory != "" {
					raw, err := json.Marshal(struct {
						Local  string `json:"local"`
						Server string `json:"server"`
					}{startJSON(t, local), startJSON(t, server)})
					if err != nil || os.WriteFile(filepath.Join(directory, name+".json"), raw, 0600) != nil {
						t.Fatal("could not export original private execution fixture", err)
					}
				}
			})
		}
	}
}
