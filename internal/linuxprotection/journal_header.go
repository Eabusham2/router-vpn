package linuxprotection

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const JournalHeaderLimit = 8192

// JournalHeader binds the stable sibling directory and four immutable native
// file identities. Creator is historical comparison data; a new controller
// must prove retirement/recovery before it can append under its own lifetime.
type JournalHeader struct {
	Schema    int             `json:"schema"`
	Kind      string          `json:"kind"`
	JournalID string          `json:"journal_id"`
	Creator   ParentRecord    `json:"creator"`
	Root      NativeObject    `json:"root"`
	Header    NativeObject    `json:"header"`
	Lock      NativeObject    `json:"lock"`
	Slots     [2]NativeObject `json:"slots"`
}

func (h JournalHeader) Validate() error {
	if h.Schema != 1 || h.Kind != "routervpn-owned-nft-journal-files" || !lowerHex(h.JournalID, 32) || h.Creator.Validate() != nil ||
		!h.Root.protected(true, true) || h.Root.Mode&0777 != 0700 || h.Root.Device != h.Creator.InstallationAnchor.Device {
		return errors.New("Linux journal header lost its protected sibling root and original creator")
	}
	seen := map[[2]uint64]bool{}
	for _, object := range []NativeObject{h.Creator.InstallationAnchor, h.Creator.Root, h.Creator.Image, h.Creator.InstallLock, h.Creator.ProcessLock, h.Root} {
		key := [2]uint64{object.Device, object.Inode}
		if seen[key] {
			return errors.New("Linux journal directory aliases its retained installation")
		}
		seen[key] = true
	}
	for _, object := range []NativeObject{h.Header, h.Lock, h.Slots[0], h.Slots[1]} {
		key := [2]uint64{object.Device, object.Inode}
		if !object.protected(false, true) || object.Mode&0777 != 0600 || object.Device != h.Root.Device || seen[key] {
			return errors.New("Linux journal header lost distinct protected file identities")
		}
		seen[key] = true
	}
	return nil
}

func CanonicalJournalHeader(h JournalHeader) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(h)
	if err != nil || len(body) == 0 || len(body) > JournalHeaderLimit {
		return nil, errors.New("Linux journal header exceeds its fixed bound")
	}
	return body, nil
}

func ParseJournalHeader(body []byte) (JournalHeader, error) {
	if len(body) == 0 || len(body) > JournalHeaderLimit {
		return JournalHeader{}, errors.New("Linux journal header is empty or unbounded")
	}
	var header JournalHeader
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&header) != nil {
		return JournalHeader{}, errors.New("Linux journal header contains unsupported fields or types")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return JournalHeader{}, errors.New("Linux journal header contains trailing content")
	}
	canonical, err := CanonicalJournalHeader(header)
	if err != nil || !bytes.Equal(canonical, body) {
		return JournalHeader{}, errors.New("Linux journal header is not its exact canonical encoding")
	}
	return header, nil
}

func JournalLockBytes(journalID string) ([]byte, error) {
	if !lowerHex(journalID, 32) {
		return nil, errors.New("Linux journal lock lost its immutable directory identity")
	}
	return []byte("RouterVPN-owned-nft-journal-lock/1\n" + journalID + "\n"), nil
}
