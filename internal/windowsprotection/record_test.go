package windowsprotection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func ownerRecordFixture() OwnerRecord {
	return OwnerRecord{
		Schema: OwnerRecordSchema, Kind: OwnerRecordKind, OwnerID: strings.Repeat("e", 32),
		Capture: Capture{SessionID: strings.Repeat("a", 32), SourceSHA256: strings.Repeat("b", 64),
			ConfigSHA256: strings.Repeat("c", 64), NetworkID: strings.Repeat("d", 32), Generation: 7},
		Controller: Controller{PID: 4040, StartTimeUTCTicks: 638974560000000000, SID: "S-1-5-21-1-2-3-1001", AuthenticationID: 9, SessionID: 2},
		Policy:     "on-connect",
	}
}

func TestWindowsProtectionOwnerRecordRoundTrip(t *testing.T) {
	record := ownerRecordFixture()
	body, err := CanonicalOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"schema":2,"kind":"routervpn-owned-legacy-protection","owner_id":"` + strings.Repeat("e", 32) +
		`","capture":{"session_id":"` + strings.Repeat("a", 32) + `","source_sha256":"` + strings.Repeat("b", 64) +
		`","config_sha256":"` + strings.Repeat("c", 64) + `","network_id":"` + strings.Repeat("d", 32) + `","generation":7},` +
		`"controller":{"pid":4040,"start_time_utc_ticks":638974560000000000,"sid":"S-1-5-21-1-2-3-1001","authentication_id":9,"session_id":2},"policy":"on-connect"}`
	if string(body) != expected {
		t.Fatal("owner record changed its exact protocol encoding")
	}
	decoded, err := ParseOwnerRecord(body)
	if err != nil || decoded != record {
		t.Fatal("owner record lost a captured identity on round trip", err)
	}
	for _, policy := range []string{"on-connect", "always"} {
		for _, generation := range []uint64{1, 1<<53 + 1, math.MaxUint64} {
			changed := record
			changed.Policy, changed.Capture.Generation = policy, generation
			changed.Controller.PID, changed.Controller.SessionID = math.MaxUint32, 0
			changed.Controller.AuthenticationID = math.MaxUint64
			changed.Controller.StartTimeUTCTicks = 3155378975999999999
			body, err := CanonicalOwnerRecord(changed)
			actual, parseErr := ParseOwnerRecord(body)
			if err != nil || parseErr != nil || actual != changed {
				t.Fatal("owner record rounded or discarded a bounded native identity", err, parseErr)
			}
		}
	}
}

func TestWindowsProtectionOwnerRecordInvalidFields(t *testing.T) {
	changes := map[string]func(*OwnerRecord){
		"legacy-schema":         func(r *OwnerRecord) { r.Schema = 1 },
		"future-schema":         func(r *OwnerRecord) { r.Schema++ },
		"wrong-kind":            func(r *OwnerRecord) { r.Kind = "routervpn-owned-wfp-protection" },
		"no-owner":              func(r *OwnerRecord) { r.OwnerID = "" },
		"owner-uppercase":       func(r *OwnerRecord) { r.OwnerID = strings.ToUpper(r.OwnerID) },
		"owner-long":            func(r *OwnerRecord) { r.OwnerID += "1" },
		"session-missing":       func(r *OwnerRecord) { r.Capture.SessionID = "" },
		"source-short":          func(r *OwnerRecord) { r.Capture.SourceSHA256 = strings.Repeat("b", 63) },
		"source-uppercase":      func(r *OwnerRecord) { r.Capture.SourceSHA256 = strings.Repeat("B", 64) },
		"configuration-nonhex":  func(r *OwnerRecord) { r.Capture.ConfigSHA256 = strings.Repeat("g", 64) },
		"network-path":          func(r *OwnerRecord) { r.Capture.NetworkID = `C:\unrelated\network` },
		"zero-generation":       func(r *OwnerRecord) { r.Capture.Generation = 0 },
		"no-process":            func(r *OwnerRecord) { r.Controller.PID = 0 },
		"zero-creation":         func(r *OwnerRecord) { r.Controller.StartTimeUTCTicks = 0 },
		"negative-creation":     func(r *OwnerRecord) { r.Controller.StartTimeUTCTicks = -1 },
		"creation-out-of-range": func(r *OwnerRecord) { r.Controller.StartTimeUTCTicks = 3155378976000000000 },
		"no-token":              func(r *OwnerRecord) { r.Controller.AuthenticationID = 0 },
		"no-sid":                func(r *OwnerRecord) { r.Controller.SID = "" },
		"sid-alias":             func(r *OwnerRecord) { r.Controller.SID = "BA" },
		"policy-off":            func(r *OwnerRecord) { r.Policy = "off" },
		"policy-coerced":        func(r *OwnerRecord) { r.Policy = "Always" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			record := ownerRecordFixture()
			change(&record)
			if record.Validate() == nil {
				t.Fatal("invalid protection owner fields were admitted")
			}
			if _, err := CanonicalOwnerRecord(record); err == nil {
				t.Fatal("invalid protection owner fields were encoded")
			}
			body, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseOwnerRecord(body); err == nil {
				t.Fatal("invalid protection owner fields were parsed")
			}
			if _, err := OwnerRecordSHA256(body); err == nil {
				t.Fatal("invalid protection owner fields acquired a trusted digest")
			}
		})
	}
}

func TestWindowsProtectionOwnerRecordStrictEncoding(t *testing.T) {
	body, err := CanonicalOwnerRecord(ownerRecordFixture())
	if err != nil {
		t.Fatal(err)
	}
	valid := string(body)
	alter := func(old, replacement string) string {
		if strings.Count(valid, old) != 1 {
			t.Fatal("ambiguous malformed-input fixture")
		}
		return strings.Replace(valid, old, replacement, 1)
	}
	inputs := []string{
		"", "null", "[]", "{}", "\xef\xbb\xbf" + valid, " " + valid, valid + "\n", valid + " null", valid + valid,
		strings.Repeat(" ", OwnerRecordLimit+1),
		`{"schema":2,` + valid[1:],
		alter(`"schema":2`, `"Schema":2`), alter(`"schema":2`, `"sch\u0065ma":2`),
		alter(`"schema":2`, `"schema":"2"`), alter(`"schema":2`, `"schema":2.0`),
		alter(`"schema":2`, `"schema":null`), alter(`"schema":2,`, ""),
		alter(`"capture":{`, `"capture":{"unknown":1,`),
		alter(`"generation":7`, `"generation":7,"generation":7`),
		alter(`"generation":7`, `"generation":null`), alter(`"generation":7`, `"generation":true`),
		alter(`"generation":7`, `"generation":"7"`), alter(`"generation":7`, `"generation":7e0`),
		alter(`"generation":7`, `"generation":-1`), alter(`"generation":7`, `"generation":18446744073709551616`),
		alter(`"pid":4040`, `"pid":4294967296`), alter(`"pid":4040`, `"pid":-1`),
		alter(`"start_time_utc_ticks":638974560000000000`, `"start_time_utc_ticks":9223372036854775808`),
		alter(`"authentication_id":9`, `"authentication_id":18446744073709551616`),
		alter(`"session_id":2`, `"session_id":4294967296`), alter(`"session_id":2`, `"session_id":null`),
		alter(`"controller":{`, `"controller":{"path":"C:\\another.exe",`),
		alter(`"policy":"on-connect"`, `"policy":"on-connect","unexpected":false`),
	}
	zeroSession := ownerRecordFixture()
	zeroSession.Controller.SessionID = 0
	zeroRaw, err := CanonicalOwnerRecord(zeroSession)
	if err != nil {
		t.Fatal(err)
	}
	inputs = append(inputs, strings.Replace(string(zeroRaw), `,"session_id":0}`, `}`, 1))
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		t.Fatal(err)
	}
	inputs = append(inputs, pretty.String())
	for index, input := range inputs {
		if _, err := ParseOwnerRecord([]byte(input)); err == nil {
			t.Fatalf("noncanonical owner encoding was admitted at case %d", index)
		}
		if _, err := OwnerRecordSHA256([]byte(input)); err == nil {
			t.Fatalf("noncanonical owner encoding acquired a digest at case %d", index)
		}
	}
}

func TestWindowsProtectionOwnerRecordSID(t *testing.T) {
	for _, sid := range []string{
		"S-1-0-0", "S-1-5-18", "S-1-5-21-1-2-3-1001", "S-1-12-1-1-2-3-4",
		"S-1-4294967295-4294967295", "S-1-0x000100000000-1", "S-1-0xFFFFFFFFFFFF-4294967295", "S-1-0xffffffffffff-1",
		"S-1-5" + strings.Repeat("-4294967295", 15),
	} {
		record := ownerRecordFixture()
		record.Controller.SID = sid
		if _, err := CanonicalOwnerRecord(record); err != nil {
			t.Fatal("bounded standard SID syntax was rejected", err)
		}
	}
	for _, sid := range []string{
		"BA", "S-1-5", "s-1-5-18", "S-2-5-18", "S-01-5-18", "S-1-05-18", "S-1-5-018",
		"S-1-5--1", "S-1-5-+1", "S-1-5-1.0", "S-1-5-1e0", "S-1-5- 1", "S-1-5-1\x00",
		"S-1-4294967296-1", "S-1-5-4294967296", "S-1-5" + strings.Repeat("-1", 16),
		"S-1-0X000100000000-1", "S-1-0x100000000-1", "S-1-0x000000000005-18",
		"S-1-0x1000000000000-1", "S-1-0xGGGGGGGGGGGG-1", "S-1-0x+00100000000-1", "S-1-0x0001_0000000-1",
	} {
		record := ownerRecordFixture()
		record.Controller.SID = sid
		if record.Controller.Validate() == nil {
			t.Fatal("malformed or aliased Windows SID was admitted")
		}
	}
}

func TestWindowsProtectionOwnerRecordDigest(t *testing.T) {
	original := ownerRecordFixture()
	body, err := CanonicalOwnerRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := OwnerRecordSHA256(body)
	want := sha256.Sum256(body)
	if err != nil || digest != hex.EncodeToString(want[:]) || len(digest) != 64 {
		t.Fatal("owner digest did not bind its exact validated bytes", err)
	}
	changes := []func(*OwnerRecord){
		func(r *OwnerRecord) { r.OwnerID = strings.Repeat("f", 32) },
		func(r *OwnerRecord) { r.Capture.SessionID = strings.Repeat("1", 32) },
		func(r *OwnerRecord) { r.Capture.SourceSHA256 = strings.Repeat("2", 64) },
		func(r *OwnerRecord) { r.Capture.ConfigSHA256 = strings.Repeat("3", 64) },
		func(r *OwnerRecord) { r.Capture.NetworkID = strings.Repeat("4", 32) },
		func(r *OwnerRecord) { r.Capture.Generation++ },
		func(r *OwnerRecord) { r.Controller.PID++ },
		func(r *OwnerRecord) { r.Controller.StartTimeUTCTicks++ },
		func(r *OwnerRecord) { r.Controller.SID = "S-1-5-21-1-2-3-1002" },
		func(r *OwnerRecord) { r.Controller.AuthenticationID++ },
		func(r *OwnerRecord) { r.Controller.SessionID++ },
		func(r *OwnerRecord) { r.Policy = "always" },
	}
	for _, change := range changes {
		record := original
		change(&record)
		changed, err := CanonicalOwnerRecord(record)
		actual, hashErr := OwnerRecordSHA256(changed)
		if err != nil || hashErr != nil || actual == digest {
			t.Fatal("owner digest failed to bind a changed native capture", err, hashErr)
		}
	}
	parsed, err := ParseOwnerRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	clear(body)
	if parsed != original {
		t.Fatal("parsed owner retained mutable caller bytes")
	}
}
