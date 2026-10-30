package main

import (
	"encoding/hex"
	"errors"
)

const windowsPreparedProtectionUtilityFlag = "--windows-physical-prepared"

type windowsPreparedProtectionReceipt struct {
	Schema         int    `json:"schema"`
	Prepared       bool   `json:"prepared"`
	SessionID      string `json:"session_id"`
	SourceSHA256   string `json:"source_sha256"`
	NetworkID      string `json:"network_id"`
	Policy         string `json:"policy"`
	BaselineSHA256 string `json:"baseline_sha256"`
}

func parseWindowsPreparedProtectionUtility(args []string) (windowsPreparedProtectionReceipt, bool, error) {
	var zero windowsPreparedProtectionReceipt
	if len(args) == 0 || args[0] != windowsPreparedProtectionUtilityFlag {
		return zero, false, nil
	}
	if len(args) != 6 {
		return zero, true, errors.New("--windows-physical-prepared requires exactly session, source, network, policy and baseline")
	}
	for index, size := range []int{16, 32, 16} {
		value := args[index+1]
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != size || hex.EncodeToString(decoded) != value {
			return zero, true, errors.New("Windows prepared protection requires canonical captured identities")
		}
	}
	if args[4] != "on-connect" && args[4] != "always" {
		return zero, true, errors.New("Windows prepared protection requires a captured strict policy")
	}
	baseline, err := hex.DecodeString(args[5])
	if err != nil || len(baseline) != 32 || hex.EncodeToString(baseline) != args[5] {
		return zero, true, errors.New("Windows prepared protection requires its complete captured baseline")
	}
	return windowsPreparedProtectionReceipt{Schema: 1, SessionID: args[1], SourceSHA256: args[2], NetworkID: args[3], Policy: args[4], BaselineSHA256: args[5]}, true, nil
}
