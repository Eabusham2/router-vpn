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
	OriginalInterface string `json:"original_interface,omitempty"`
	InterfacePolicy string `json:"interface_policy,omitempty"`
	Sets int `json:"sets,omitempty"`
	ReadFault string `json:"read_fault,omitempty"`
	ReadFaultAfterSets int `json:"read_fault_after_sets,omitempty"`
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
		previous := state.MTU
		state.MTU = value
		state.Sets++
		if state.Mode == "darwin-reader" && value != previous {
			state.Index++
			state.Interface = fmt.Sprintf("utun%d", state.Index)
			state.Identity = fmt.Sprintf("native-owned-reader:%d", state.Index)
		}
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
	// A one-shot read fault can follow a successfully acknowledged final set.
	// This exercises the consumer's final read/rollback boundary with the real
	// helper process, while every native/OS observation remains a test double.
	replyMode := state.Mode
	if os.Args[1] == "--mtu-owner-read" && state.ReadFault != "" && state.Sets >= state.ReadFaultAfterSets {
		replyMode, state.ReadFault = state.ReadFault, ""
		encoded, _ := json.Marshal(state)
		if os.WriteFile(path, encoded, 0600) != nil {
			os.Exit(24)
		}
	}
	reply := map[string]any{"owner_token": state.Owner, "interface": state.Interface, "family": state.Family,
		"index": state.Index, "mtu": state.MTU, "identity": state.Identity}
	if state.OriginalInterface != "" {
		reply["original_interface"] = state.OriginalInterface
	}
	if state.InterfacePolicy != "" {
		reply["interface_policy"] = state.InterfacePolicy
	}
	switch replyMode {
	case "scope-wrong-original":
		reply["original_interface"] = "utun999"
	case "scope-wrong-policy":
		reply["interface_policy"] = "darwin-any-interface"
	case "scope-missing-original":
		delete(reply, "original_interface")
	case "scope-missing-policy":
		delete(reply, "interface_policy")
	case "scope-missing-core":
		delete(reply, "identity")
	case "scope-empty-extras":
		reply["original_interface"], reply["interface_policy"] = "", ""
	case "scope-empty-original":
		reply["original_interface"] = ""
	case "scope-empty-policy":
		reply["interface_policy"] = ""
	case "scope-current-fixed":
		reply["interface"] = "router-vpn"
	case "scope-current-upper":
		reply["interface"] = "UTUN992"
	case "scope-current-unicode":
		reply["interface"] = "utun９９２"
	case "scope-current-separator":
		reply["interface"] = "utun-992"
	case "scope-current-empty-number":
		reply["interface"] = "utun"
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
