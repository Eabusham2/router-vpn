// Package standardengine defines the fixed inherited standard-engine boundary.
// It contains no process, routing or protection adoption by saved metadata.
package standardengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

const LibraryEnvironment = "ROUTERVPN_SEALED_CRONET_FD"
const LibraryFD = 6
const ChannelFD = 7
const ParentFD = 8
const CaptureFD = 9
const ConfigFD = 4
const DirectoryFD = 5
const MaxConfig = 8 << 20

type Capture struct {
	Schema          int    `json:"schema"`
	Session         string `json:"session"`
	ConfigSHA256    string `json:"config_sha256"`
	Mode            string `json:"mode"`
	DeadlineNS      int64  `json:"deadline_ns"`
	CleanupDevice   uint64 `json:"cleanup_device"`
	CleanupInode    uint64 `json:"cleanup_inode"`
	OperationDevice uint64 `json:"operation_device"`
	OperationInode  uint64 `json:"operation_inode"`
	OperationSize   int64  `json:"operation_size"`
	OperationLayout int    `json:"operation_layout"`
}

func digest(value string, size int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == size && hex.EncodeToString(raw) == value && !bytes.Equal(raw, make([]byte, size))
}

func (c Capture) Canonical() ([]byte, error) {
	if c.Schema != 1 || !digest(c.Session, 16) || !digest(c.ConfigSHA256, 32) || c.DeadlineNS < 1 || c.CleanupDevice == 0 || c.CleanupInode == 0 || c.OperationDevice == 0 || c.OperationInode == 0 || c.OperationSize != OperationSize || c.OperationLayout != OperationLayout {
		return nil, errors.New("standard engine has no exact original bounded capture")
	}
	switch c.Mode {
	case "standard-wireguard", "standard-socks5", "standard-http-connect", "standard-https-connect", "standard-shadowsocks", "standard-hysteria2":
	default:
		return nil, errors.New("standard engine capture names another protocol")
	}
	return json.Marshal(c)
}

func DecodeCapture(raw []byte, expected string) (Capture, error) {
	var c Capture
	if len(raw) == 0 || len(raw) > 2048 || !digest(expected, 32) || json.Unmarshal(raw, &c) != nil {
		return c, errors.New("standard engine capture is malformed")
	}
	canonical, err := c.Canonical()
	if err != nil || !bytes.Equal(canonical, raw) || SHA256(raw) != expected {
		return c, errors.New("standard engine lost its original canonical capture")
	}
	return c, nil
}

func SHA256(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

type Ready struct {
	Schema         int    `json:"schema"`
	CaptureSHA256  string `json:"capture_sha256"`
	NetworkReceipt string `json:"network_receipt"`
}

func (r Ready) Canonical() ([]byte, error) {
	if r.Schema != 1 || !digest(r.CaptureSHA256, 32) || len(r.NetworkReceipt) == 0 || len(r.NetworkReceipt) > 16<<10 || strings.TrimSpace(r.NetworkReceipt) != r.NetworkReceipt {
		return nil, errors.New("standard engine readiness omitted its original routing ledger")
	}
	return json.Marshal(r)
}

func DecodeReady(raw []byte, expected string) (Ready, error) {
	var r Ready
	if len(raw) == 0 || len(raw) > 32<<10 || json.Unmarshal(raw, &r) != nil {
		return r, errors.New("standard engine readiness exceeds its frame")
	}
	canonical, err := r.Canonical()
	if err != nil || !bytes.Equal(canonical, raw) || r.CaptureSHA256 != expected {
		return r, errors.New("standard engine readiness belongs to another source")
	}
	return r, nil
}
