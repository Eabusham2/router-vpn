package libbox

import (
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
		_, err := routerOpenVPNWords("verify-x509-name do-not-leak\\" + string(c))
		if err == nil {
			t.Fatalf("accepted escaped control %d", c)
		}
	}
}

func TestNativeOpenVPNQuotedAndEscapedArguments(t *testing.T) {
	for _, option := range []string{`verify-x509-name "VPN Server" name`, `verify-x509-name 'VPN Server' name`, `verify-x509-name VPN\ Server name`} {
		words, err := routerOpenVPNWords(option)
		if err != nil || len(words) != 3 || words[1] != "VPN Server" {
			t.Fatal("valid OpenVPN quoting changed")
		}
	}
	words, err := routerOpenVPNWords("client\t # comment")
	if err != nil || len(words) != 1 || words[0] != "client" {
		t.Fatal("tab-separated comments changed")
	}
}
