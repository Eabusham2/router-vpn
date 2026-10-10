package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

// Compile an operator-selected layer offline. Source credentials arrive only
// through bounded stdin; no service, route or user configuration is accessed.
func compileRelayStartLayer(input io.Reader, output io.Writer, endpoint, api string) error {
	bad := errors.New("invalid captured relay Start Layer")
	raw, err := io.ReadAll(io.LimitReader(input, 16385))
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		return bad
	}
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 2 || object["mode"] == nil || object["profile"] == nil {
		return bad
	}
	var source struct {
		Mode    string            `json:"mode"`
		Profile map[string]string `json:"profile"`
	}
	if json.Unmarshal(raw, &source) != nil || len(source.Profile) != 1 {
		return bad
	}
	mode, err := common.NormalizeStartLayerMode(source.Mode)
	if err != nil || !multihoprelay.ValidLayerMode(mode) {
		return bad
	}
	encoded, err := json.Marshal(source.Profile)
	if err != nil {
		return bad
	}
	value, err := mobilemultihop.CompileProxyEntry(string(encoded), "shadowsocks")
	if err != nil {
		return bad
	}
	var transport map[string]any
	if json.Unmarshal([]byte(value), &transport) != nil {
		return bad
	}
	host, ok := transport["server"].(string)
	expected, e1 := netip.ParseAddr(endpoint)
	actual, e2 := netip.ParseAddr(host)
	if !ok || e1 != nil || e2 != nil || expected != actual {
		return bad
	}
	layer := multihoprelay.StartLayer{Mode: mode, API: api, Transport: transport}
	// Validate the same strict node, key and private-service rules as runtime.
	// Nothing returned by WrapStartLayer is launched or used to mutate the input.
	if _, _, err = multihoprelay.WrapStartLayer(transport, "shadowsocks", &layer, multihoprelay.ExitStartLayerTag, ""); err != nil {
		return bad
	}
	bytes, err := json.Marshal(layer)
	if err != nil || len(bytes) > 16384 {
		return bad
	}
	_, err = output.Write(append(bytes, '\n'))
	return err
}
