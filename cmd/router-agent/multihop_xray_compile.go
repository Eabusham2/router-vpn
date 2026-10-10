package main

import (
	"errors"
	"io"
	"router-vpn/internal/applexray"
	"router-vpn/internal/mobilemultihop"
)

// This offline command shares the phone apps' strict native profile compiler.
// No agent config, interface, credentials file or live listener is opened.
func compileNativeRelayProfile(input io.Reader, output io.Writer, mode string) error {
	if !applexray.SingleTransportMode(mode) {
		return errors.New("unsupported native relay profile mode")
	}
	raw, err := io.ReadAll(io.LimitReader(input, (8<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 8<<20 {
		return errors.New("invalid bounded native relay profile")
	}
	encoded, err := mobilemultihop.CompileProxyEntry(string(raw), mode)
	if err != nil || len(encoded) == 0 || len(encoded) > 4<<20 {
		return errors.New("native relay profile failed exact protocol validation")
	}
	_, err = io.WriteString(output, encoded+"\n")
	return err
}
