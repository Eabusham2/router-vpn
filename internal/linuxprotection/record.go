// Package linuxprotection defines Linux native comparison records. Decoding
// these records does not open a process, retain a lock, or authorize nftables
// adoption. The installed controller keeps those original kernel owners.
package linuxprotection

import (
	"encoding/hex"
	"errors"
	"math"
	"strings"
)

const (
	linuxTypeMask  = 0170000
	linuxRegular   = 0100000
	linuxDirectory = 0040000
	linuxFIFO      = 0010000
)

type NativeObject struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

func (o NativeObject) regular() bool { return o.Inode != 0 && o.Mode&linuxTypeMask == linuxRegular }
func (o NativeObject) protected(directory, private bool) bool {
	want := uint32(linuxRegular)
	if directory {
		want = linuxDirectory
	}
	return o.Inode != 0 && o.UID == 0 && o.Mode&linuxTypeMask == want && o.Mode&0022 == 0 && (!private || o.Mode&0077 == 0)
}

// ParentRecord is the immutable identity of the actual installed bootstrap,
// including its original user-created pipe and retained installation locks.
// Generation identifies one in-memory capture; BootID prevents another boot's
// PID/start-tick pair from being mistaken for that original native process.
type ParentRecord struct {
	Generation         string       `json:"generation"`
	BootID             string       `json:"boot_id"`
	ProcessID          int          `json:"process_id"`
	ProcProcessID      int          `json:"proc_process_id"`
	StartTicks         uint64       `json:"start_ticks"`
	CallerUID          uint32       `json:"caller_uid"`
	InstallationAnchor NativeObject `json:"installation_anchor"`
	Root               NativeObject `json:"root"`
	Image              NativeObject `json:"image"`
	Input              NativeObject `json:"input"`
	InstallLock        NativeObject `json:"install_lock"`
	ProcessLock        NativeObject `json:"process_lock"`
	NetworkNamespace   NativeObject `json:"network_namespace"`
	PIDNamespace       NativeObject `json:"pid_namespace"`
}

func (r ParentRecord) Validate() error {
	if !lowerHex(r.Generation, 32) || !BootIDValid(r.BootID) || !nativePID(r.ProcessID) || !nativePID(r.ProcProcessID) ||
		r.StartTicks == 0 || r.CallerUID == 0 || r.CallerUID == math.MaxUint32 || !r.InstallationAnchor.protected(true, false) || !r.Root.protected(true, false) ||
		!r.Image.protected(false, false) || r.Image.Mode&0111 == 0 || !r.InstallLock.protected(false, true) || !r.ProcessLock.protected(false, true) ||
		r.Input.Inode == 0 || r.Input.Mode&linuxTypeMask != linuxFIFO || r.Input.UID != r.CallerUID || r.Input.Mode&0077 != 0 ||
		!r.NetworkNamespace.regular() || !r.PIDNamespace.regular() {
		return errors.New("Linux parent record lost its bounded process, original pipe, protected files or namespaces")
	}
	objects := []NativeObject{r.InstallationAnchor, r.Root, r.Image, r.InstallLock, r.ProcessLock, r.Input, r.NetworkNamespace, r.PIDNamespace}
	seen := map[[2]uint64]bool{}
	for _, object := range objects {
		identity := [2]uint64{object.Device, object.Inode}
		if seen[identity] {
			return errors.New("Linux parent record aliases separate captured native objects")
		}
		seen[identity] = true
	}
	return nil
}

// ProcessRecord records a child or guardian observed through its actual
// retained process/channel owner. This value alone is never a process handle.
type ProcessRecord struct {
	BootID           string       `json:"boot_id"`
	ProcessID        int          `json:"process_id"`
	ProcProcessID    int          `json:"proc_process_id"`
	ParentProcessID  int          `json:"parent_process_id"`
	StartTicks       uint64       `json:"start_ticks"`
	UID              uint32       `json:"uid"`
	GID              uint32       `json:"gid"`
	Image            NativeObject `json:"image"`
	NetworkNamespace NativeObject `json:"network_namespace"`
	PIDNamespace     NativeObject `json:"pid_namespace"`
}

func (r ProcessRecord) Validate() error {
	if !BootIDValid(r.BootID) || !nativePID(r.ProcessID) || !nativePID(r.ProcProcessID) || !nativePID(r.ParentProcessID) ||
		r.ProcessID == r.ParentProcessID || r.StartTicks == 0 || r.UID != 0 || r.GID != 0 ||
		!r.Image.protected(false, false) || r.Image.Mode&0111 == 0 || !r.NetworkNamespace.regular() || !r.PIDNamespace.regular() ||
		r.NetworkNamespace == r.PIDNamespace {
		return errors.New("Linux native process record lost its privileged creation, image or namespace identity")
	}
	return nil
}

func nativePID(pid int) bool { return pid > 0 && uint64(pid) <= math.MaxInt32 }
func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(raw) == value
}

func BootIDValid(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for _, i := range []int{8, 13, 18, 23} {
		if value[i] != '-' {
			return false
		}
	}
	return lowerHex(strings.ReplaceAll(value, "-", ""), 32)
}
