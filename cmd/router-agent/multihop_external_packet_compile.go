package main

import (
	"encoding/json"
	"errors"
	"io"

	"router-vpn/internal/applexray"
	"router-vpn/internal/multihoprelay"
)

// Both private inputs arrive only on bounded stdin. The result contains only
// the server-owned private peer plus public descriptions of the two clients;
// it never copies the Local private key/PSK into the private server registry.
func compileExternalPacketPair(input io.Reader, output io.Writer) error {
	bad := errors.New("external packet pairing requires exact independent client/server peer captures")
	raw, err := io.ReadAll(io.LimitReader(input, (256<<10)+1))
	if err != nil || len(raw) == 0 || len(raw) > 256<<10 {
		return bad
	}
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 4 {
		return bad
	}
	alias, ok := object["alias"].(string)
	if !ok {
		return bad
	}
	selected, ok := object["selected_layer"].(string)
	if !ok {
		return bad
	}
	ext, ok := object["external"].(map[string]any)
	if !ok {
		return bad
	}
	server, ok := object["server_peer_profile"].(map[string]any)
	if !ok {
		return bad
	}
	protocol, ok := ext["protocol"].(string)
	if !ok || !multihoprelay.ExternalPacketMode(protocol) {
		return bad
	}
	var layer *multihoprelay.StartLayer
	if selected == "" || selected == "off" {
		if _, present := ext["start_layer"]; present {
			return bad
		}
	} else {
		if !multihoprelay.ValidLayerMode(selected) {
			return bad
		}
		data, err := json.Marshal(ext["start_layer"])
		if err != nil {
			return bad
		}
		layer = &multihoprelay.StartLayer{}
		if json.Unmarshal(data, layer) != nil || layer.Mode != selected {
			return bad
		}
	}
	paired, err := multihoprelay.PairExternalPacket(alias, protocol, ext, server, layer)
	if err != nil {
		return bad
	}
	encoded, err := json.Marshal(paired)
	if err != nil || len(encoded) > 256<<10 {
		return bad
	}
	encoded = append(encoded, '\n')
	n, err := output.Write(encoded)
	if err == nil && n != len(encoded) {
		return io.ErrShortWrite
	}
	return err
}

func describeExternalPacketPeer(input io.Reader, output io.Writer) error {
	bad := errors.New("server peer public descriptor requires one bounded private WG/AWG profile")
	raw, err := io.ReadAll(io.LimitReader(input, (128<<10)+1))
	if err != nil || len(raw) == 0 || len(raw) > 128<<10 {
		return bad
	}
	profile, err := applexray.Object(raw)
	if err != nil {
		return bad
	}
	public, err := multihoprelay.ExternalPacketServerDescriptor(profile)
	if err != nil {
		return bad
	}
	data, err := json.Marshal(public)
	if err != nil {
		return bad
	}
	data = append(data, '\n')
	n, err := output.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
