package main

import (
	"encoding/json"
	"errors"
	"io"

	"router-vpn/internal/applexray"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

func compileExternalOpenVPNPair(input io.Reader, output io.Writer) error {
	bad := errors.New("external OpenVPN pairing requires bounded independent private client/server captures")
	raw, err := io.ReadAll(io.LimitReader(input, (2<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
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
	external, ok := object["external"].(map[string]any)
	if !ok || external["protocol"] != "openvpn" {
		return bad
	}
	server, ok := object["server_peer_profile"].(map[string]any)
	if !ok {
		return bad
	}
	var layer *multihoprelay.StartLayer
	if _, mapped := external["openvpn_start_layers"]; mapped {
		profile, err1 := json.Marshal(external["openvpn"])
		probes, err2 := json.Marshal(external["openvpn_response_probes"])
		layers, err3 := json.Marshal(external["openvpn_start_layers"])
		if err1 != nil || err2 != nil || err3 != nil || nativeopenvpn.ValidateStartLayers(string(profile), string(probes), string(layers), selected) != nil { return bad }
	} else if selected == "" || selected == "off" {
		if _, exists := external["start_layer"]; exists {
			return bad
		}
	} else {
		if !multihoprelay.ValidLayerMode(selected) {
			return bad
		}
		body, err := json.Marshal(external["start_layer"])
		layer = &multihoprelay.StartLayer{}
		if err != nil || json.Unmarshal(body, layer) != nil || layer.Mode != selected {
			return bad
		}
	}
	paired, err := multihoprelay.PairExternalOpenVPN(alias, external, server, layer)
	if err != nil {
		return bad
	}
	return writeExternalOpenVPNOutput(output, paired, 2<<20)
}

func describeExternalOpenVPNPeer(input io.Reader, output io.Writer) error {
	bad := errors.New("OpenVPN public descriptor requires one bounded original private provider profile and dedicated pairing key")
	raw, err := io.ReadAll(io.LimitReader(input, (512<<10)+1))
	if err != nil || len(raw) == 0 || len(raw) > 512<<10 {
		return bad
	}
	profile, err := applexray.Object(raw)
	if err != nil {
		return bad
	}
	public, err := multihoprelay.ExternalOpenVPNServerDescriptor(profile)
	if err != nil {
		return bad
	}
	return writeExternalOpenVPNOutput(output, public, 512<<10)
}

func writeExternalOpenVPNOutput(output io.Writer, value any, limit int) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > limit {
		return errors.New("OpenVPN pairing result exceeds its private source bound")
	}
	encoded = append(encoded, '\n')
	n, err := output.Write(encoded)
	if err == nil && n != len(encoded) {
		return io.ErrShortWrite
	}
	return err
}
