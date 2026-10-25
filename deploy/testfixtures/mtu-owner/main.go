// A subprocess boundary fixture for the shipping Python/PowerShell optimizers.
// No sockets or interfaces are opened. Kernel/native ownership itself is
// exercised by cmd/client tests; this fixture drives malformed/retired replies
// and verifies that the actual packaged consumers reject them.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type fixture struct {
	Owner     string `json:"owner_token"`
	Interface string `json:"interface"`
	Family    int    `json:"family"`
	Index     int    `json:"index"`
	MTU       int    `json:"mtu"`
	Identity  string `json:"identity"`
	Mode      string `json:"mode"`
}

func main() {
	path := os.Getenv("MTU_OWNER_FIXTURE")
	raw, err := os.ReadFile(path)
	var state fixture
	if err != nil || json.Unmarshal(raw, &state) != nil || len(os.Args) < 2 {
		os.Exit(17)
	}
	log, err := os.OpenFile(path+".calls", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(18)
	}
	_ = json.NewEncoder(log).Encode(os.Args[1:])
	_ = log.Close()
	if state.Mode == "retired" || state.Mode == "exit-failure" {
		os.Exit(19)
	}
	if os.Args[1] == "--mtu-owner-set" && len(os.Args) == 3 {
		value, parseErr := strconv.Atoi(os.Args[2])
		if parseErr != nil || value < 576 || value > 9000 || state.Mode == "set-fails" {
			os.Exit(20)
		}
		state.MTU = value
		if state.Mode == "change-reader" {
			state.Index++
			state.Identity = fmt.Sprintf("native-owned-reader:%d", state.Index)
		}
		if state.Mode == "retire-after-set" {
			state.Mode = "retired"
		}
		encoded, _ := json.Marshal(state)
		if os.WriteFile(path, encoded, 0600) != nil {
			os.Exit(21)
		}
		if state.Mode == "retired" {
			os.Exit(22)
		}
	} else if os.Args[1] != "--mtu-owner-read" || len(os.Args) != 2 {
		os.Exit(23)
	}
	reply := map[string]any{"owner_token": state.Owner, "interface": state.Interface, "family": state.Family,
		"index": state.Index, "mtu": state.MTU, "identity": state.Identity}
	switch state.Mode {
	case "wrong-token":
		reply["owner_token"] = strings.Repeat("f", 32)
	case "wrong-interface":
		reply["interface"] = "replacement"
	case "wrong-family":
		reply["family"] = 6
	case "wrong-index":
		reply["index"] = 0
	case "string-number":
		reply["mtu"] = "1400"
	case "float-number":
		reply["index"] = 1.5
	case "boolean-number":
		reply["family"] = true
	case "empty-identity":
		reply["identity"] = ""
	case "control-identity":
		reply["identity"] = "old\nnew"
	case "long-identity":
		reply["identity"] = strings.Repeat("x", 257)
	case "unknown":
		reply["extra"] = "discard-me"
	case "null":
		reply["mtu"] = nil
	case "set-wrong-readback":
		if os.Args[1] == "--mtu-owner-set" {
			reply["mtu"] = state.MTU + 1
		}
	}
	encoded, _ := json.Marshal(reply)
	switch state.Mode {
	case "duplicate":
		encoded = []byte(`{"owner_token":"` + state.Owner + `",` + string(encoded[1:]))
	case "escaped-duplicate":
		encoded = []byte(`{"owner_\u0074oken":"` + state.Owner + `",` + string(encoded[1:]))
	case "array":
		encoded = append(append([]byte("["), encoded...), ']')
	case "trailing":
		encoded = append(encoded, []byte(" {}")...)
	case "oversized":
		encoded = append(encoded, []byte(strings.Repeat(" ", 5000))...)
	case "invalid-utf8":
		encoded = []byte{0xff}
	case "stderr":
		_, _ = os.Stderr.WriteString("unexpected helper warning")
	}
	_, _ = os.Stdout.Write(encoded)
}
