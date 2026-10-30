package windowsprotection

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const journalHeaderLimit = 4096

// These are immutable comparison values read from retained native handles.
// Decoding this header grants no file, controller or protection authority.
type journalObjectIdentity struct {
	VolumeSerial uint32 `json:"volume_serial"`
	FileIndex    uint64 `json:"file_index"`
}

type journalHeader struct {
	Schema        int                      `json:"schema"`
	Kind          string                   `json:"kind"`
	JournalID     string                   `json:"journal_id"`
	DesktopSID    string                   `json:"desktop_sid"`
	MachineVolume string                   `json:"machine_volume"`
	DataVolume    string                   `json:"data_volume"`
	Data          journalObjectIdentity    `json:"data"`
	Root          journalObjectIdentity    `json:"root"`
	Header        journalObjectIdentity    `json:"header"`
	Lock          journalObjectIdentity    `json:"lock"`
	Slots         [2]journalObjectIdentity `json:"slots"`
}

func journalVolumeID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, digit := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if digit != '-' {
				return false
			}
		} else if !(digit >= '0' && digit <= '9' || digit >= 'a' && digit <= 'f') {
			return false
		}
	}
	return true
}

func (header journalHeader) validate() error {
	if header.Schema != 1 || header.Kind != "routervpn-owned-wfp-journal-files" || !lowerHex(header.JournalID, 32) ||
		!validSID(header.DesktopSID) || !journalVolumeID(header.MachineVolume) || !journalVolumeID(header.DataVolume) || header.Data.FileIndex == 0 {
		return errors.New("Windows protection journal header lost its bounded user and volume identity")
	}
	seen := map[uint64]bool{}
	for _, file := range []journalObjectIdentity{header.Root, header.Header, header.Lock, header.Slots[0], header.Slots[1]} {
		if file.FileIndex == 0 || file.VolumeSerial != header.Root.VolumeSerial || seen[file.FileIndex] {
			return errors.New("Windows protection journal header lost distinct retained file identities")
		}
		seen[file.FileIndex] = true
	}
	if header.DataVolume == header.MachineVolume && (header.Data.VolumeSerial != header.Root.VolumeSerial || seen[header.Data.FileIndex]) {
		return errors.New("Windows protection journal cannot alias its original private data directory")
	}
	return nil
}

func canonicalJournalHeader(header journalHeader) ([]byte, error) {
	if err := header.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(header)
	if err != nil || len(raw) == 0 || len(raw) > journalHeaderLimit {
		return nil, errors.New("Windows protection journal header exceeds its fixed bound")
	}
	return raw, nil
}

func parseJournalHeader(raw []byte) (journalHeader, error) {
	if len(raw) == 0 || len(raw) > journalHeaderLimit {
		return journalHeader{}, errors.New("Windows protection journal header is empty or unbounded")
	}
	var header journalHeader
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&header); err != nil {
		return journalHeader{}, errors.New("Windows protection journal header has unsupported fields or types")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return journalHeader{}, errors.New("Windows protection journal header has trailing content")
	}
	canonical, err := canonicalJournalHeader(header)
	if err != nil || !bytes.Equal(raw, canonical) {
		return journalHeader{}, errors.New("Windows protection journal header is not its exact canonical encoding")
	}
	return header, nil
}
