package windowsbootstrap

import (
	"bytes"
	"strings"
	"testing"
)

func TestWindowsBootstrapPrivateAndPublicFrames(t *testing.T) {
	first, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCredentials()
	if err != nil || first == second {
		t.Fatal("new bootstrap reused another launch identity", err)
	}
	private, err := EncodeCredentials(first)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCredentials(private)
	if err != nil || decoded != first {
		t.Fatal("private frame lost its exact credentials", err)
	}
	pin := strings.Repeat("b", 64)
	public, err := EncodeHello(731, pin)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := DecodeHello(public, 731)
	if err != nil || hello.ProcessID != 731 || hello.TLSPin != pin {
		t.Fatal("public frame lost its exact retained capture", err)
	}
	if bytes.Contains(public, []byte(first.AccessToken)) || bytes.Contains(public, []byte(first.OwnerToken)) {
		t.Fatal("public hello exposed private authority")
	}
	for _, pid := range []uint32{0, 730, 732} {
		if _, err := DecodeHello(public, pid); err == nil {
			t.Fatal("another retained process acquired the public TLS pin")
		}
	}
	for _, frame := range [][]byte{private, public} {
		decode := func(raw []byte) error { _, err := DecodeCredentials(raw); return err }
		if bytes.Equal(frame, public) {
			decode = func(raw []byte) error { _, err := DecodeHello(raw, 731); return err }
		}
		for _, broken := range [][]byte{
			nil, frame[:len(frame)-1], append(append([]byte(nil), frame...), '\n'),
			append(append([]byte(nil), frame[:len(frame)-1]...), []byte("{}\n")...),
			bytes.Replace(frame, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
			bytes.Replace(frame, []byte(`"schema":1`), []byte(`"schema":1,"\u0073chema":1`), 1),
			bytes.Replace(frame, []byte(`"schema":1`), []byte(`"Schema":1`), 1),
			bytes.Replace(frame, []byte(`"schema":1`), []byte(`"schema":1,"extra":false`), 1),
			bytes.Replace(frame, []byte(`"schema":1`), []byte(`"schema":null`), 1),
			bytes.Replace(frame, []byte(`"schema":1`), []byte(`"schema":1.0`), 1),
			bytes.Replace(frame, []byte(`"schema":1`), []byte(`"schema":2`), 1),
			append([]byte(strings.Repeat(" ", 384)), frame...),
		} {
			if err := decode(broken); err == nil {
				t.Fatal("ambiguous bootstrap frame was accepted", string(broken))
			}
		}
	}
	for _, invalid := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 65)} {
		if _, err := EncodeHello(731, invalid); err == nil {
			t.Fatal("invalid TLS pin acquired a hello")
		}
		if _, err := EncodeCredentials(Credentials{invalid, first.OwnerToken}); err == nil {
			t.Fatal("invalid access credential acquired a private frame")
		}
	}
	if _, err := EncodeHello(0, pin); err == nil {
		t.Fatal("zero PID acquired a hello")
	}
	if _, err := EncodeCredentials(Credentials{first.AccessToken, ""}); err == nil {
		t.Fatal("missing shutdown owner acquired a private frame")
	}
}

func TestWindowsBootstrapRendezvousDoesNotCarryCredentials(t *testing.T) {
	pipe := pipePrefix + strings.Repeat("a", 32)
	image := `C:\Router VPN\RouterVPN.exe`
	arguments, err := Arguments(pipe, 731, image)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseArguments(arguments)
	if err != nil || parsed.PipeName != pipe || parsed.ParentPID != 731 || parsed.ParentImage != image {
		t.Fatal("public rendezvous changed", err)
	}
	for _, broken := range [][]string{
		nil, arguments[:3], append(append([]string(nil), arguments...), "extra"),
		{ControllerArgument, pipe, "0731", image}, {ControllerArgument, pipe, "0", image},
		{ControllerArgument, pipe, "-1", image}, {ControllerArgument, pipe, "4294967296", image},
		{ControllerArgument, pipe + "a", "731", image}, {ControllerArgument, `\\remote\pipe\x`, "731", image},
		{ControllerArgument, pipe, "731", image + "\n"}, {ControllerArgument, pipe, "731", strings.Repeat("a", 1025)},
	} {
		if _, err := ParseArguments(broken); err == nil {
			t.Fatal("invalid launch rendezvous was admitted", broken)
		}
	}
	if !Requested(arguments) || !Requested([]string{ControllerArgument + "=unexpected"}) || Requested([]string{"--verify-native-runtime"}) {
		t.Fatal("owned launch dispatch confused ordinary utilities with malformed bootstrap")
	}
}
