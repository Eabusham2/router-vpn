package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestOwnedControllerFrameKeepsCancellationForCapturedChild(t *testing.T) {
	frame := []byte(`{"schema":1,"access_token":"` + testLocalControllerAccess + `","owner_token":"` + testControllerOwner + `"}` + "\n")
	input := bytes.NewReader(append(append([]byte{}, frame...), 'x'))
	got, err := readOwnedControllerFrame(input)
	if err != nil || !bytes.Equal(got, frame) {
		t.Fatal("bounded launch frame changed", err)
	}
	if access, owner, err := decodeOwnedControllerHandshake(got); err != nil || access != testLocalControllerAccess || owner != testControllerOwner {
		t.Fatal("private identity did not survive the supervisor relay", err)
	}
	if next, err := input.ReadByte(); err != nil || next != 'x' {
		t.Fatal("supervisor consumed the child's cancellation byte", err)
	}
	for _, invalid := range [][]byte{nil, []byte("{}"), bytes.Repeat([]byte{'x'}, 385)} {
		if _, err = readOwnedControllerFrame(bytes.NewReader(invalid)); err == nil {
			t.Fatal("unbounded or incomplete launch frame accepted")
		}
	}
}

type ownedControllerStalledReader struct{}

func (ownedControllerStalledReader) Read([]byte) (int, error) { return 0, nil }

func TestOwnedControllerFrameDoesNotSpinOnNoProgress(t *testing.T) {
	if _, err := readOwnedControllerFrame(ownedControllerStalledReader{}); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal(err)
	}
}

func TestOwnedControllerSupervisorReceiptBindsActualPhasePIDOwnerAndExit(t *testing.T) {
	for _, phase := range []string{"started", "joined"} {
		var body bytes.Buffer
		exitCode := 0
		if phase == "joined" {
			exitCode = 7
		}
		if err := writeOwnedControllerSupervisorReceipt(&body, phase, 7341, exitCode, testLocalControllerAccess, testControllerOwner); err != nil {
			t.Fatal(err)
		}
		var receipt ownedControllerSupervisorReceipt
		var fields map[string]json.RawMessage
		if decodeRelayControlJSON(body.Bytes(), &receipt) != nil || json.Unmarshal(body.Bytes(), &fields) != nil || len(fields) != 5 ||
			receipt.Schema != 1 || receipt.Phase != phase || receipt.ProcessID != 7341 || receipt.ExitCode != exitCode {
			t.Fatal("supervisor receipt changed its actual join result")
		}
		if bytes.Contains(body.Bytes(), []byte(testLocalControllerAccess)) || bytes.Contains(body.Bytes(), []byte(testControllerOwner)) {
			t.Fatal("private credentials entered supervisor receipt")
		}
		if receipt.Proof != ownedControllerSupervisorMAC(testLocalControllerAccess, phase, 7341, testControllerOwner, exitCode) {
			t.Fatal("supervisor did not authenticate actual receipt")
		}
		for name, foreign := range map[string]string{
			"secret":  ownedControllerSupervisorMAC(strings.Repeat("d", 64), phase, 7341, testControllerOwner, exitCode),
			"phase":   ownedControllerSupervisorMAC(testLocalControllerAccess, phase+"-old", 7341, testControllerOwner, exitCode),
			"process": ownedControllerSupervisorMAC(testLocalControllerAccess, phase, 7342, testControllerOwner, exitCode),
			"owner":   ownedControllerSupervisorMAC(testLocalControllerAccess, phase, 7341, strings.Repeat("e", 32), exitCode),
			"exit":    ownedControllerSupervisorMAC(testLocalControllerAccess, phase, 7341, testControllerOwner, exitCode+1),
		} {
			if foreign == receipt.Proof {
				t.Fatal("supervisor receipt did not bind", name)
			}
		}
	}
}

func TestOwnedControllerSupervisorCannotInventStartedOrJoinedReceipt(t *testing.T) {
	for _, value := range []struct {
		phase         string
		pid, code     int
		secret, owner string
	}{
		{"started", 0, 0, testLocalControllerAccess, testControllerOwner},
		{"started", 123, 1, testLocalControllerAccess, testControllerOwner},
		{"discovered", 123, 0, testLocalControllerAccess, testControllerOwner},
		{"joined", 123, 0, "", testControllerOwner},
		{"joined", 123, 0, testLocalControllerAccess, ""},
		{"joined", 123, -2, testLocalControllerAccess, testControllerOwner},
		{"joined", 123, 256, testLocalControllerAccess, testControllerOwner},
	} {
		var output bytes.Buffer
		if err := writeOwnedControllerSupervisorReceipt(&output, value.phase, value.pid, value.code, value.secret, value.owner); err == nil || output.Len() != 0 {
			t.Fatal("invalid supervisor identity produced a receipt")
		}
	}
}
