//go:build linux

package linuxprocess

import (
	"bytes"
	"strings"
	"testing"
)

func TestPidFDReadbackRequiresExactNativeTask(t *testing.T) {
	base := "pos:\t0\nflags:\t02000002\nmnt_id:\t4\nino:\t50\nPid:\t945\nNSpid:\t945\t41\n"
	if err := pidFDIdentity([]byte(base), 41, 945); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"retired":         strings.Replace(base, "Pid:\t945", "Pid:\t-1", 1),
		"foreign":         strings.Replace(base, "Pid:\t945", "Pid:\t946", 1),
		"wrong-native":    strings.Replace(base, "945\t41", "945\t42", 1),
		"missing-mapping": strings.Replace(base, "NSpid:\t945\t41\n", "", 1),
		"missing-pid":     strings.Replace(base, "Pid:\t945\n", "", 1),
		"duplicate-pid":   base + "Pid:\t945\n", "duplicate-namespace": base + "NSpid:\t945\t41\n",
		"noncanonical":        strings.Replace(base, "945\t41", "945\t042\t41", 1),
		"too-many-namespaces": strings.Replace(base, "945\t41", "945\t"+strings.Repeat("42\t", 31)+"41", 1),
		"too-large":           strings.Repeat("a", 4097), "ordinary-file": "pos:\t0\nflags:\t02000000\nino:\t500\n",
	} {
		t.Run(name, func(t *testing.T) {
			if pidFDIdentity([]byte(raw), 41, 945) == nil {
				t.Fatal("pidfd comparison accepted a foreign, retired or unbounded task")
			}
		})
	}
}

func TestBootstrapRequiresCanonicalCaptureAndChallenge(t *testing.T) {
	message := bootstrapMessage{Schema: 1, Kind: "routervpn-linux-child-bootstrap-v1", Step: "parent",
		CaptureSHA256: strings.Repeat("a", 64), Challenge: strings.Repeat("b", 64), ParentSHA256: strings.Repeat("c", 64),
		ChildChannel: Object{Device: 9, Inode: 40, Mode: 0140777}}
	body, err := encodeBootstrap(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBootstrap(body)
	if err != nil || decoded != message {
		t.Fatal("exact native challenge did not round trip", err)
	}
	for _, raw := range [][]byte{nil, append([]byte(" "), body...), append(append([]byte{}, body...), '\n'),
		append(append([]byte{}, body...), body...), bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"unknown":0`), 1),
		bytes.Repeat([]byte{'x'}, 2049)} {
		if _, err := decodeBootstrap(raw); err == nil {
			t.Fatal("noncanonical bootstrap bytes acquired captured authority")
		}
	}
	for name, change := range map[string]func(*bootstrapMessage){
		"zero-context":        func(m *bootstrapMessage) { m.CaptureSHA256 = strings.Repeat("0", 64) },
		"no-challenge":        func(m *bootstrapMessage) { m.Challenge = "" },
		"parent-claims-child": func(m *bootstrapMessage) { m.ChildSHA256 = strings.Repeat("d", 64) },
		"child-without-birth": func(m *bootstrapMessage) { m.Step = "child" },
		"wrong-step":          func(m *bootstrapMessage) { m.Step = "restore" },
		"wrong-channel-kind":  func(m *bootstrapMessage) { m.ChildChannel.Mode = 0100600 },
		"wrong-channel-owner": func(m *bootstrapMessage) { m.ChildChannel.UID = 1000 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := message
			change(&changed)
			if _, err := encodeBootstrap(changed); err == nil {
				t.Fatal("malformed bootstrap captured comparison was accepted")
			}
		})
	}
}
