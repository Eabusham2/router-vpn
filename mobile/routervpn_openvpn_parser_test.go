package libbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNativeOpenVPNQuotedControlsAreRejected(t *testing.T) {
	for _, c := range []byte{1, 2, 11, 12, 31, 127} {
		for _, wrap := range []string{"\"", "'"} {
			option := "verify-x509-name " + wrap + "do-not-leak" + string(c) + "name" + wrap + " name\n"
			_, err := RouterOpenVPNEndpoint(fixture+option, "user", "password", "exit", "")
			if err == nil {
				t.Fatalf("accepted quoted control %d", c)
			}
			if strings.Contains(err.Error(), "do-not-leak") {
				t.Fatal("error leaked profile contents")
			}
		}
		_, err := RouterOpenVPNEndpoint(fixture+"verify-x509-name do-not-leak\\"+string(c)+" name\n", "user", "password", "exit", "")
		if err == nil {
			t.Fatalf("accepted escaped control %d", c)
		}
	}
}

func TestNativeOpenVPNQuotedAndEscapedArguments(t *testing.T) {
	for _, option := range []string{`verify-x509-name "VPN Server" name`, `verify-x509-name 'VPN Server' name`, `verify-x509-name VPN\ Server name`} {
		encoded, err := RouterOpenVPNEndpoint(fixture+option+"\n", "user", "password", "exit", "")
		var endpoint map[string]any
		if err != nil || json.Unmarshal([]byte(encoded), &endpoint) != nil || endpoint["tls"].(map[string]any)["server_name"] != "VPN Server" {
			t.Fatal("valid OpenVPN quoting changed")
		}
	}
	_, err := RouterOpenVPNEndpoint(strings.Replace(fixture, "client\n", "client\t # comment\n", 1), "user", "password", "exit", "")
	if err != nil {
		t.Fatal("tab-separated comments changed")
	}
}
