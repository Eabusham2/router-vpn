package mobiletor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func desktopProtectionRecordFixture() DesktopProtectionTransferRecord {
	return DesktopProtectionTransferRecord{Schema: 1, Kind: "routervpn-windows-protection-transfer-v1", SessionID: strings.Repeat("a", 32),
		SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), Policy: "always",
		Predecessor: &DesktopWindowsProtectionTarget{Capture: DesktopSocketCapture{SessionID: strings.Repeat("d", 32),
			SourceSHA256: strings.Repeat("e", 64), NetworkID: strings.Repeat("f", 32)}, Policy: "on-connect", BaselineSHA256: strings.Repeat("1", 64)}}
}

func TestDesktopProtectionTransferRecordRoundTrip(t *testing.T) {
	for _, initial := range []bool{false, true} {
		record := desktopProtectionRecordFixture()
		if initial {
			record.Predecessor = nil
		}
		raw, err := CanonicalDesktopProtectionTransferRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := ParseDesktopProtectionTransferRecord(raw)
		if err != nil {
			t.Fatal(err)
		}
		again, err := CanonicalDesktopProtectionTransferRecord(actual)
		if err != nil || !bytes.Equal(again, raw) || !bytes.Contains(raw, []byte(`"predecessor":`)) {
			t.Fatal("private transfer did not preserve explicit complete predecessor state", err)
		}
		first, _ := DesktopProtectionTransferRecordSHA256(record)
		second, _ := DesktopProtectionTransferRecordSHA256(actual)
		if first == "" || first != second {
			t.Fatal("canonical transfer changed its captured digest")
		}
		if actual.Predecessor != nil {
			actual.Predecessor.BaselineSHA256 = strings.Repeat("2", 64)
			if record.Predecessor.BaselineSHA256 != strings.Repeat("1", 64) {
				t.Fatal("parsed transfer retained the caller's mutable predecessor")
			}
		}
	}
}

func TestDesktopProtectionTransferRecordRejectsChangedFields(t *testing.T) {
	for _, name := range []string{"schema", "kind", "session", "source", "config", "policy", "old-session", "old-source", "old-network", "old-policy", "old-baseline", "reused-session"} {
		t.Run(name, func(t *testing.T) {
			r := desktopProtectionRecordFixture()
			switch name {
			case "schema":
				r.Schema = 2
			case "kind":
				r.Kind = "routervpn-node-profile"
			case "session":
				r.SessionID = strings.Repeat("A", 32)
			case "source":
				r.SourceSHA256 = ""
			case "config":
				r.ConfigSHA256 = strings.Repeat("c", 63)
			case "policy":
				r.Policy = "off"
			case "old-session":
				r.Predecessor.Capture.SessionID = ""
			case "old-source":
				r.Predecessor.Capture.SourceSHA256 = strings.Repeat("E", 64)
			case "old-network":
				r.Predecessor.Capture.NetworkID = strings.Repeat("f", 31)
			case "old-policy":
				r.Predecessor.Policy = "off"
			case "old-baseline":
				r.Predecessor.BaselineSHA256 = ""
			case "reused-session":
				r.Predecessor.Capture.SessionID = r.SessionID
			}
			if r.Validate() == nil {
				t.Fatal("invalid captured protection transfer was admitted")
			}
			raw, _ := json.Marshal(r)
			if _, err := ParseDesktopProtectionTransferRecord(raw); err == nil {
				t.Fatal("invalid captured transfer acquired canonical private input")
			}
			if digest, err := DesktopProtectionTransferRecordSHA256(r); err == nil || digest != "" {
				t.Fatal("invalid captured transfer acquired a launch digest")
			}
		})
	}
}

func TestDesktopProtectionTransferRecordStrictEncoding(t *testing.T) {
	r := desktopProtectionRecordFixture()
	raw, _ := CanonicalDesktopProtectionTransferRecord(r)
	for _, candidate := range [][]byte{
		nil, []byte("null"), []byte("{}"), append(append([]byte(nil), raw...), '\n'), append([]byte(" "), raw...),
		append(append([]byte(nil), raw...), raw...), []byte(strings.Repeat(" ", DesktopProtectionTransferRecordLimit+1)),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1.0`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"unknown":false`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"Schema":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1,`), nil, 1),
		bytes.Replace(raw, []byte(`"capture":{`), []byte(`"capture":{"network_id":"`+r.Predecessor.Capture.NetworkID+`",`), 1),
	} {
		if _, err := ParseDesktopProtectionTransferRecord(candidate); err == nil {
			t.Fatal("noncanonical transfer input was admitted")
		}
	}
	r.Predecessor = nil
	raw, _ = CanonicalDesktopProtectionTransferRecord(r)
	if _, err := ParseDesktopProtectionTransferRecord(bytes.Replace(raw, []byte(`,"predecessor":null`), nil, 1)); err == nil {
		t.Fatal("omitted predecessor was treated as explicit initial absence")
	}
}

func TestDesktopProtectionRetirementRecordExactOutcomes(t *testing.T) {
	expected := desktopProtectionRecordFixture()
	digest, _ := DesktopProtectionTransferRecordSHA256(expected)
	own := DesktopWindowsProtectionTarget{Capture: DesktopSocketCapture{SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256,
		NetworkID: strings.Repeat("2", 32)}, Policy: expected.Policy, BaselineSHA256: strings.Repeat("3", 64)}
	for _, target := range []*DesktopWindowsProtectionTarget{&own, expected.Predecessor} {
		r := DesktopProtectionRetirementRecord{Schema: 1, Kind: "routervpn-windows-protection-retired-v1", TransferSHA256: digest, Target: target}
		raw, err := CanonicalDesktopProtectionRetirementRecord(r, expected)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := ParseDesktopProtectionRetirementRecord(raw, expected)
		if err != nil || actual.Target == nil || *actual.Target != *target {
			t.Fatal("joined receipt lost its exact permitted outcome", err)
		}
	}
	for _, name := range []string{"schema", "kind", "transfer", "absent", "session", "source", "policy", "network", "digest", "changed-old"} {
		t.Run(name, func(t *testing.T) {
			target := own
			r := DesktopProtectionRetirementRecord{Schema: 1, Kind: "routervpn-windows-protection-retired-v1", TransferSHA256: digest, Target: &target}
			switch name {
			case "schema":
				r.Schema++
			case "kind":
				r.Kind = "unowned"
			case "transfer":
				r.TransferSHA256 = strings.Repeat("0", 64)
			case "absent":
				r.Target = nil
			case "session":
				target.Capture.SessionID = strings.Repeat("4", 32)
			case "source":
				target.Capture.SourceSHA256 = strings.Repeat("4", 64)
			case "policy":
				target.Policy = "on-connect"
			case "network":
				target.Capture.NetworkID = ""
			case "digest":
				target.BaselineSHA256 = ""
			case "changed-old":
				target = *expected.Predecessor
				target.BaselineSHA256 = strings.Repeat("4", 64)
			}
			if r.Validate(expected) == nil {
				t.Fatal("retirement receipt adopted an uncaptured protection outcome")
			}
		})
	}
	expected.Predecessor = nil
	digest, _ = DesktopProtectionTransferRecordSHA256(expected)
	initial := DesktopProtectionRetirementRecord{Schema: 1, Kind: "routervpn-windows-protection-retired-v1", TransferSHA256: digest}
	raw, err := CanonicalDesktopProtectionRetirementRecord(initial, expected)
	if err != nil {
		t.Fatal("proved unchanged initial absence was rejected", err)
	}
	for _, candidate := range [][]byte{
		bytes.Replace(raw, []byte(`,"target":null`), nil, 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"unknown":true`), 1),
		append(append([]byte(nil), raw...), '\n'),
	} {
		if _, err := ParseDesktopProtectionRetirementRecord(candidate, expected); err == nil {
			t.Fatal("noncanonical protection retirement input was admitted")
		}
	}
}
