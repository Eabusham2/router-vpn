package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWindowsPreparedProtectionUtilityCapture(t *testing.T) {
	session, source, network, baseline := strings.Repeat("ab", 16), strings.Repeat("cd", 32), strings.Repeat("ef", 16), strings.Repeat("dc", 32)
	for _, policy := range []string{"on-connect", "always"} {
		args := []string{windowsPreparedProtectionUtilityFlag, session, source, network, policy, baseline}
		record, handled, err := parseWindowsPreparedProtectionUtility(args)
		if !handled || err != nil || record.Prepared || record.Schema != 1 || record.SessionID != session ||
			record.SourceSHA256 != source || record.NetworkID != network || record.Policy != policy || record.BaselineSHA256 != baseline {
			t.Fatal("prepared utility parsing changed or prematurely proved its captured request", record, handled, err)
		}
		record.Prepared = true // Only the native reader sets this in production.
		raw, err := json.Marshal(record)
		want := `{"schema":1,"prepared":true,"session_id":"` + session + `","source_sha256":"` + source + `","network_id":"` + network + `","policy":"` + policy + `","baseline_sha256":"` + baseline + `"}`
		if err != nil || string(raw) != want {
			t.Fatal("prepared utility grammar changed", string(raw), err)
		}
		for _, mutate := range []func([]string) []string{
			func(v []string) []string { return v[:5] },
			func(v []string) []string { return append(v, "extra") },
			func(v []string) []string { v[1] = strings.ToUpper(v[1]); return v },
			func(v []string) []string { v[2] += "00"; return v },
			func(v []string) []string { v[3] = v[3][:30]; return v },
			func(v []string) []string { v[2] = strings.Repeat("z", 64); return v },
			func(v []string) []string { v[4] = "off"; return v },
			func(v []string) []string { v[4] = "Always"; return v },
			func(v []string) []string { v[5] = strings.ToUpper(v[5]); return v },
			func(v []string) []string { v[5] = ""; return v },
			func(v []string) []string { v[1] += "\n"; return v },
		} {
			changed := mutate(append([]string(nil), args...))
			if got, handled, err := parseWindowsPreparedProtectionUtility(changed); !handled || err == nil || got != (windowsPreparedProtectionReceipt{}) {
				t.Fatal("prepared utility accepted malformed authority or emitted a receipt", changed, got, handled, err)
			}
		}
	}
	for _, args := range [][]string{nil, {"--verify-native-runtime"}, {windowsProtectionUtilityFlag, "status"}} {
		if got, handled, err := parseWindowsPreparedProtectionUtility(args); handled || err != nil || got != (windowsPreparedProtectionReceipt{}) {
			t.Fatal("prepared utility captured another command", args)
		}
	}
}
