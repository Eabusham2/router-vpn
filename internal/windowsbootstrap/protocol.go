// Package windowsbootstrap describes the bounded private launcher/controller
// handshake. Public rendezvous fields never authenticate a process: both ends
// must first retain and verify the actual kernel pipe peer and executable.
package windowsbootstrap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

const ControllerArgument = "--windows-owned-controller"
const pipePrefix = `\\.\pipe\RouterVPN-Controller-v1-`

type Rendezvous struct {
	PipeName    string
	ParentPID   uint32
	ParentImage string
}

func Requested(arguments []string) bool {
	for _, argument := range arguments {
		if strings.HasPrefix(argument, ControllerArgument) {
			return true
		}
	}
	return false
}

func Arguments(pipe string, parentPID uint32, parentImage string) ([]string, error) {
	arguments := []string{ControllerArgument, pipe, strconv.FormatUint(uint64(parentPID), 10), parentImage}
	if _, err := ParseArguments(arguments); err != nil {
		return nil, err
	}
	return arguments, nil
}

func ParseArguments(arguments []string) (Rendezvous, error) {
	if len(arguments) != 4 || arguments[0] != ControllerArgument ||
		!strings.HasPrefix(arguments[1], pipePrefix) || !validHex(strings.TrimPrefix(arguments[1], pipePrefix), 32) ||
		len(arguments[3]) == 0 || len(arguments[3]) > 1024 || strings.ContainsAny(arguments[3], "\x00\r\n") {
		return Rendezvous{}, errors.New("the Windows controller requires its exact public launch rendezvous")
	}
	pid, err := strconv.ParseUint(arguments[2], 10, 32)
	if err != nil || pid == 0 || strconv.FormatUint(pid, 10) != arguments[2] {
		return Rendezvous{}, errors.New("the Windows controller launch parent is invalid")
	}
	return Rendezvous{arguments[1], uint32(pid), arguments[3]}, nil
}

type Credentials struct {
	AccessToken string
	OwnerToken  string
}

func NewCredentials() (Credentials, error) {
	var access [32]byte
	var owner [16]byte
	if _, err := rand.Read(access[:]); err != nil {
		return Credentials{}, err
	}
	if _, err := rand.Read(owner[:]); err != nil {
		return Credentials{}, err
	}
	return Credentials{hex.EncodeToString(access[:]), hex.EncodeToString(owner[:])}, nil
}

func EncodeCredentials(credentials Credentials) ([]byte, error) {
	if !validHex(credentials.AccessToken, 64) || !validHex(credentials.OwnerToken, 32) {
		return nil, errors.New("the Windows controller requires independent bounded launch credentials")
	}
	return frame(struct {
		Schema int    `json:"schema"`
		Access string `json:"access_token"`
		Owner  string `json:"owner_token"`
	}{1, credentials.AccessToken, credentials.OwnerToken})
}

func DecodeCredentials(data []byte) (Credentials, error) {
	fields, err := exactFrame(data, "schema", "access_token", "owner_token")
	var schema int
	var credentials Credentials
	if err != nil || json.Unmarshal(fields["schema"], &schema) != nil || schema != 1 ||
		json.Unmarshal(fields["access_token"], &credentials.AccessToken) != nil || !validHex(credentials.AccessToken, 64) ||
		json.Unmarshal(fields["owner_token"], &credentials.OwnerToken) != nil || !validHex(credentials.OwnerToken, 32) {
		return Credentials{}, errors.New("the Windows controller launch credentials are invalid or ambiguous")
	}
	return credentials, nil
}

type Hello struct {
	ProcessID uint32
	TLSPin    string
}

// The leaf pin is public. It becomes authority only after the launcher checks
// this pipe against its retained UAC process/image and real elevated token.
func EncodeHello(pid uint32, pin string) ([]byte, error) {
	if pid == 0 || !validHex(pin, 64) {
		return nil, errors.New("the Windows controller has no captured public TLS identity")
	}
	return frame(struct {
		Schema int    `json:"schema"`
		PID    uint32 `json:"process_id"`
		Pin    string `json:"tls_pin"`
	}{1, pid, pin})
}

func DecodeHello(data []byte, expectedPID uint32) (Hello, error) {
	fields, err := exactFrame(data, "schema", "process_id", "tls_pin")
	var schema int
	var hello Hello
	if err != nil || expectedPID == 0 || json.Unmarshal(fields["schema"], &schema) != nil || schema != 1 ||
		json.Unmarshal(fields["process_id"], &hello.ProcessID) != nil || hello.ProcessID != expectedPID ||
		json.Unmarshal(fields["tls_pin"], &hello.TLSPin) != nil || !validHex(hello.TLSPin, 64) {
		return Hello{}, errors.New("the Windows controller public hello differs from its retained launch")
	}
	return hello, nil
}

func frame(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func exactFrame(data []byte, expected ...string) (map[string]json.RawMessage, error) {
	if len(data) == 0 || len(data) > 384 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return nil, errors.New("Windows bootstrap frame is missing or unbounded")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("Windows bootstrap requires an exact object")
	}
	fields := make(map[string]json.RawMessage, len(expected))
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || fields[name] != nil || len(fields) >= len(expected) {
			return nil, errors.New("Windows bootstrap object repeats or adds a field")
		}
		known := false
		for _, candidate := range expected {
			known = known || name == candidate
		}
		var value json.RawMessage
		if !known || decoder.Decode(&value) != nil {
			return nil, errors.New("Windows bootstrap object contains an unknown field")
		}
		fields[name] = value
	}
	closing, err := decoder.Token()
	var extra any
	if err != nil || closing != json.Delim('}') || len(fields) != len(expected) || decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("Windows bootstrap object is incomplete or has trailing data")
	}
	return fields, nil
}

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' && digit < 'a' || digit > 'f' {
			return false
		}
	}
	return true
}
