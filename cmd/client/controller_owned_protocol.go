package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

const macOSOwnedControllerArgument = "--macos-owned-controller"
const macOSControllerSupervisorArgument = "--macos-controller-supervisor"

func decodeOwnedControllerHandshake(frame []byte) (string, string, error) {
	var request struct {
		Schema      int    `json:"schema"`
		AccessToken string `json:"access_token"`
		OwnerToken  string `json:"owner_token"`
	}
	var fields map[string]json.RawMessage
	if len(frame) > 384 || len(frame) == 0 || frame[len(frame)-1] != '\n' || bytes.Count(frame, []byte{'\n'}) != 1 ||
		decodeRelayControlJSON(frame, &request) != nil || json.Unmarshal(frame, &fields) != nil || len(fields) != 3 ||
		fields["schema"] == nil || fields["access_token"] == nil || fields["owner_token"] == nil ||
		request.Schema != 1 || !validLocalControllerSecret(request.AccessToken) || !validControllerOwnerToken(request.OwnerToken) {
		return "", "", errors.New("the native controller requires one exact private launch identity")
	}
	return request.AccessToken, request.OwnerToken, nil
}

// Read exactly the first frame. A buffered read must not consume a later
// cancellation byte which belongs to the child holding the user's lifetime.
func readOwnedControllerFrame(reader io.Reader) ([]byte, error) {
	frame := make([]byte, 0, 384)
	var next [1]byte
	for len(frame) < 384 {
		n, err := reader.Read(next[:])
		if n == 1 {
			frame = append(frame, next[0])
			if next[0] == '\n' {
				return frame, nil
			}
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
	}
	return nil, errors.New("the native controller launch identity is oversized")
}

type ownedControllerSupervisorReceipt struct {
	Schema    int    `json:"schema"`
	Phase     string `json:"phase"`
	ProcessID int    `json:"process_id"`
	ExitCode  int    `json:"exit_code"`
	Proof     string `json:"proof"`
}

func ownedControllerSupervisorMAC(secret, phase string, pid int, owner string, exitCode int) string {
	return localControllerMAC(secret, "routervpn-controller-supervisor\n"+phase+"\n"+strconv.Itoa(pid)+"\n"+owner+"\n"+strconv.Itoa(exitCode))
}

func writeOwnedControllerSupervisorReceipt(writer io.Writer, phase string, pid, exitCode int, secret, owner string) error {
	if !validLocalControllerSecret(secret) || !validControllerOwnerToken(owner) || pid <= 0 ||
		(phase != "started" && phase != "joined") || exitCode < -1 || exitCode > 255 || (phase == "started" && exitCode != 0) {
		return errors.New("the native supervisor has no captured process receipt")
	}
	receipt := ownedControllerSupervisorReceipt{Schema: 1, Phase: phase, ProcessID: pid, ExitCode: exitCode,
		Proof: ownedControllerSupervisorMAC(secret, phase, pid, owner, exitCode)}
	frame, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	frame = append(frame, '\n')
	for len(frame) > 0 {
		n, err := writer.Write(frame)
		if n < 0 || n > len(frame) {
			return io.ErrShortWrite
		}
		frame = frame[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
