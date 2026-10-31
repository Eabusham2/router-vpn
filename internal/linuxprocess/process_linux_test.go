//go:build linux

package linuxprocess

import (
	"strings"
	"testing"
)

func TestProcessStatusRequiresCompleteNamespaceCredentials(t *testing.T) {
	base := "Name:\tbounded-test\nTgid:\t945\nPid:\t945\nPPid:\t940\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nNStgid:\t945\t41\nNSpid:\t945\t41\n"
	if err := statusIdentity([]byte(base), 41, 945, 940); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"sender-namespace":  strings.ReplaceAll(base, "945\t41", "945\t42"),
		"proc-namespace":    strings.ReplaceAll(base, "945\t41", "946\t41"),
		"thread-group":      strings.Replace(base, "Tgid:\t945", "Tgid:\t946", 1),
		"parent":            strings.Replace(base, "PPid:\t940", "PPid:\t939", 1),
		"filesystem-uid":    strings.Replace(base, "Uid:\t0\t0\t0\t0", "Uid:\t0\t0\t0\t1000", 1),
		"saved-gid":         strings.Replace(base, "Gid:\t0\t0\t0\t0", "Gid:\t0\t0\t1000\t0", 1),
		"missing-namespace": strings.Replace(base, "NSpid:\t945\t41\n", "", 1),
		"duplicate":         base + "Pid:\t945\n", "too-large": strings.Repeat("a", 65537),
		"noncanonical-middle": strings.ReplaceAll(base, "945\t41", "945\t0042\t41"),
		"namespace-depth":     strings.ReplaceAll(base, "945\t41", "945\t"+strings.Repeat("42\t", 31)+"41"),
	} {
		t.Run(name, func(t *testing.T) {
			if statusIdentity([]byte(raw), 41, 945, 940) == nil {
				t.Fatal("accepted incomplete or substituted native task status")
			}
		})
	}
}
