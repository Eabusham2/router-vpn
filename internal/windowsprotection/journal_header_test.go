package windowsprotection

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func journalHeaderFixture() journalHeader {
	identity := func(index uint64) journalObjectIdentity {
		return journalObjectIdentity{VolumeSerial: 0xffffffff, FileIndex: 1<<63 + index}
	}
	return journalHeader{Schema: 1, Kind: "routervpn-owned-wfp-journal-files", JournalID: strings.Repeat("a", 32),
		DesktopSID: "S-1-5-21-100-200-300-1001", MachineVolume: "abcd1234-5678-abcd-1234-56789abcdef0", DataVolume: "abcd1234-5678-abcd-1234-56789abcdef0",
		Data: identity(1), Root: identity(2), Header: identity(3), Lock: identity(4), Slots: [2]journalObjectIdentity{identity(5), identity(6)}}
}

func TestWindowsProtectionJournalHeaderIdentity(t *testing.T) {
	header := journalHeaderFixture()
	raw, err := canonicalJournalHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := parseJournalHeader(raw)
	if err != nil || actual != header || actual.Header.FileIndex != 1<<63+3 || bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("journal header changed exact native identity or canonical bytes", err)
	}
	otherVolume := header
	otherVolume.DataVolume = "ffffffff-5678-abcd-1234-56789abcdef0"
	otherVolume.Data.VolumeSerial = 0
	otherVolume.Data.FileIndex = header.Root.FileIndex
	if _, err := canonicalJournalHeader(otherVolume); err != nil {
		t.Fatal("separate original Data volume was rejected", err)
	}
	changes := map[string]func(*journalHeader){
		"schema":               func(h *journalHeader) { h.Schema++ },
		"kind":                 func(h *journalHeader) { h.Kind = "legacy" },
		"journal":              func(h *journalHeader) { h.JournalID = strings.Repeat("A", 32) },
		"desktop-sid":          func(h *journalHeader) { h.DesktopSID = "admin" },
		"machine-volume":       func(h *journalHeader) { h.MachineVolume = strings.ToUpper(h.MachineVolume) },
		"data-volume":          func(h *journalHeader) { h.DataVolume = "C:" },
		"data-file":            func(h *journalHeader) { h.Data.FileIndex = 0 },
		"data-alias":           func(h *journalHeader) { h.Data = h.Root },
		"data-volume-identity": func(h *journalHeader) { h.Data.VolumeSerial-- },
		"root-file":            func(h *journalHeader) { h.Root.FileIndex = 0 },
		"header-file":          func(h *journalHeader) { h.Header.FileIndex = 0 },
		"header-volume":        func(h *journalHeader) { h.Header.VolumeSerial-- },
		"lock-alias":           func(h *journalHeader) { h.Lock = h.Header },
		"slot-alias":           func(h *journalHeader) { h.Slots[1] = h.Slots[0] },
		"slot-file":            func(h *journalHeader) { h.Slots[0].FileIndex = 0 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			broken := header
			change(&broken)
			if _, err := canonicalJournalHeader(broken); err == nil {
				t.Fatal("invalid file or original-user header acquired a canonical encoding")
			}
			raw, _ := json.Marshal(broken)
			if _, err := parseJournalHeader(raw); err == nil {
				t.Fatal("invalid file or original-user header acquired parsed identity")
			}
		})
	}
}

func TestWindowsProtectionJournalHeaderStrictEncoding(t *testing.T) {
	raw, err := canonicalJournalHeader(journalHeaderFixture())
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string][]byte{
		"empty": nil, "unbounded": bytes.Repeat([]byte("a"), journalHeaderLimit+1),
		"whitespace": append([]byte(" "), raw...), "trailing": append(append([]byte(nil), raw...), '\n'),
		"duplicate":   bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		"alias":       bytes.Replace(raw, []byte(`"schema"`), []byte(`"Schema"`), 1),
		"missing":     bytes.Replace(raw, []byte(`"schema":1,`), nil, 1),
		"unknown":     bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"unknown":true`), 1),
		"float":       bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1.0`), 1),
		"string-file": bytes.Replace(raw, []byte(`"file_index":9223372036854775809`), []byte(`"file_index":"9223372036854775809"`), 1),
		"extra-slot":  bytes.Replace(raw, []byte(`}]}`), []byte(`},{"volume_serial":4294967295,"file_index":9223372036854775815}]}`), 1),
	}
	for name, input := range changes {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, input) {
				t.Fatal("header encoding negative did not change its bytes")
			}
			if _, err := parseJournalHeader(input); err == nil {
				t.Fatal("noncanonical journal header encoding was admitted")
			}
		})
	}
}
