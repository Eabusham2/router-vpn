package linuxprocess

import (
	"fmt"
	"strings"
	"testing"
)

func testProcessStat(pid, parent, start string) []byte {
	return []byte(fmt.Sprintf("%s (comm ) with ( spaces)) S %s%s %s 0 0\n", pid, parent, strings.Repeat(" 0", 17), start))
}

func TestProcessStatPreservesNativeBirth(t *testing.T) {
	got, err := ParseStat(testProcessStat("41", "7", "890"))
	if err != nil || got != (Stat{ProcessID: 41, ParentID: 7, Start: 890, State: 'S'}) {
		t.Fatal("native comm parsing changed the task's real identity", got, err)
	}
	for _, values := range [][3]string{{"0", "7", "890"}, {"041", "7", "890"}, {"2147483648", "7", "890"},
		{"41", "-7", "890"}, {"41", "07", "890"}, {"41", "7", "0"}, {"41", "7", "0890"}, {"41", "7", "18446744073709551616"}} {
		if _, err := ParseStat(testProcessStat(values[0], values[1], values[2])); err == nil {
			t.Fatal("accepted malformed native identity", values)
		}
	}
	for _, raw := range [][]byte{nil, []byte("41 (missing) S 7"), []byte(strings.Repeat("a", 8193)),
		append(testProcessStat("41", "7", "890"), []byte(strings.Repeat(" 0", 65))...)} {
		if _, err := ParseStat(raw); err == nil {
			t.Fatal("accepted unbounded or incomplete native stat")
		}
	}
}

func TestProcessObservationRequiresPrivilegedObjects(t *testing.T) {
	base := Observation{BootID: "42a45b21-993e-4441-bc0c-fb977b152ad0", ProcessID: 41, ProcProcessID: 945, ProcParentID: 940,
		StartTicks: 890, Image: Object{Device: 1, Inode: 2, Mode: 0100755},
		NetworkNamespace: Object{Device: 3, Inode: 4, Mode: 0100444}, PIDNamespace: Object{Device: 3, Inode: 5, Mode: 0100444}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Observation){
		"zero-birth": func(o *Observation) { o.StartTicks = 0 }, "unbounded-pid": func(o *Observation) { o.ProcessID = 1 << 31 },
		"zero-proc-pid": func(o *Observation) { o.ProcProcessID = 0 }, "negative-parent": func(o *Observation) { o.ProcParentID = -1 },
		"foreign-uid": func(o *Observation) { o.Image.UID = 1000 }, "foreign-gid": func(o *Observation) { o.Image.GID = 1000 },
		"writable-image": func(o *Observation) { o.Image.Mode |= 0020 }, "setuid-image": func(o *Observation) { o.Image.Mode |= 04000 },
		"non-executable": func(o *Observation) { o.Image.Mode = 0100644 }, "image-symlink": func(o *Observation) { o.Image.Mode = 0120755 },
		"same-namespace":    func(o *Observation) { o.PIDNamespace = o.NetworkNamespace },
		"missing-namespace": func(o *Observation) { o.NetworkNamespace.Inode = 0 },
		"empty-boot":        func(o *Observation) { o.BootID = "00000000-0000-0000-0000-000000000000" },
		"noncanonical-boot": func(o *Observation) { o.BootID = strings.ToUpper(o.BootID) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			change(&changed)
			if changed.Validate() == nil {
				t.Fatal("accepted a changed privileged process comparison")
			}
		})
	}
}
