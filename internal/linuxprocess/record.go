// Package linuxprocess retains Linux kernel process witnesses and inherited
// channels. Its serialized observations identify those witnesses; decoding an
// observation never creates a process owner or authorizes native mutation.
package linuxprocess

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

type Object struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

type Observation struct {
	BootID           string `json:"boot_id"`
	ProcessID        int    `json:"process_id"`
	ProcProcessID    int    `json:"proc_process_id"`
	ProcParentID     int    `json:"proc_parent_id"`
	StartTicks       uint64 `json:"start_ticks"`
	Image            Object `json:"image"`
	NetworkNamespace Object `json:"network_namespace"`
	PIDNamespace     Object `json:"pid_namespace"`
}

type Stat struct {
	ProcessID int
	ParentID  int
	Start     uint64
	State     byte
}

// ParseStat reads only the bounded native identity fields. The executable's
// comm may contain spaces and parentheses; it is never treated as a path.
func ParseStat(raw []byte) (Stat, error) {
	invalid := errors.New("Linux process has no bounded native stat identity")
	if len(raw) == 0 || len(raw) > 8192 {
		return Stat{}, invalid
	}
	text := string(raw)
	begin, end := strings.Index(text, " ("), strings.LastIndex(text, ") ")
	if begin < 1 || end <= begin+1 {
		return Stat{}, invalid
	}
	pid, err := strconv.ParseUint(text[:begin], 10, 31)
	fields := strings.Fields(text[end+2:])
	if err != nil || pid == 0 || strconv.FormatUint(pid, 10) != text[:begin] || len(fields) < 20 || len(fields) > 64 || len(fields[0]) != 1 {
		return Stat{}, invalid
	}
	parent, err := strconv.ParseUint(fields[1], 10, 31)
	if err != nil || strconv.FormatUint(parent, 10) != fields[1] {
		return Stat{}, invalid
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 || strconv.FormatUint(start, 10) != fields[19] {
		return Stat{}, invalid
	}
	return Stat{ProcessID: int(pid), ParentID: int(parent), Start: start, State: fields[0][0]}, nil
}

func ValidBootID(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for _, i := range []int{8, 13, 18, 23} {
		if value[i] != '-' {
			return false
		}
	}
	plain := strings.ReplaceAll(value, "-", "")
	raw, err := hex.DecodeString(plain)
	return len(plain) == 32 && err == nil && hex.EncodeToString(raw) == plain
}

func (o Observation) Validate() error {
	if !ValidBootID(o.BootID) || o.ProcessID < 1 || uint64(o.ProcessID) > 1<<31-1 || o.ProcProcessID < 1 || uint64(o.ProcProcessID) > 1<<31-1 ||
		o.ProcParentID < 0 || uint64(o.ProcParentID) > 1<<31-1 || o.StartTicks == 0 || o.Image.Inode == 0 ||
		o.Image.Mode&0170000 != 0100000 || o.Image.Mode&0111 == 0 || o.Image.Mode&06022 != 0 || o.Image.UID != 0 || o.Image.GID != 0 ||
		o.NetworkNamespace.Inode == 0 || o.PIDNamespace.Inode == 0 || o.NetworkNamespace.Mode&0170000 != 0100000 ||
		o.PIDNamespace.Mode&0170000 != 0100000 || (o.NetworkNamespace.Device == o.PIDNamespace.Device && o.NetworkNamespace.Inode == o.PIDNamespace.Inode) {
		return errors.New("Linux process observation lost its exact privileged native identity")
	}
	return nil
}
