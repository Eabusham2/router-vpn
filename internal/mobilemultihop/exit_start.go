package mobilemultihop

import (
	"encoding/json"
	"errors"
	"router-vpn/internal/multihoprelay"
)

// NewWithStartLayers composes both captured layers before creating any native
// engine. Each exit candidate still ends at the same proved node; the local
// candidate adds the exit's AES leg through entry, while the server candidate
// requires the exact corresponding operator-provisioned encryption mode.
func NewWithStartLayers(config, metadata, entrySource, exitSource string) (*Controller, error) {
	if exitSource == "" {
		return NewWithEntryStartLayer(config, metadata, entrySource)
	}
	var meta Metadata
	if exactJSON([]byte(metadata), &meta, 16384) != nil {
		return nil, errors.New("invalid captured two-layer metadata")
	}
	if err := validateMetadataIdentityPins(metadata, meta); err != nil {
		return nil, err
	}
	if MAXMode(meta.ExitMode) || CompositeMode(meta.ExitMode) {
		return nil, errors.New("complete exit graph already owns its captured Start Layer")
	}
	var source EntryStartLayer
	if exactJSON([]byte(exitSource), &source, 16384) != nil || source.Profile == nil || !multihoprelay.ValidLayerMode(source.Mode) || meta.ExitStartLayer != source.Mode {
		return nil, errors.New("exit layer is missing, unrequested or different from captured selection")
	}
	profile, e := json.Marshal(source.Profile)
	if e != nil {
		return nil, e
	}
	text, e := CompileProxyEntry(string(profile), "shadowsocks")
	if e != nil {
		return nil, errors.New("exit layer requires the selected node's self-contained AES source")
	}
	var outer map[string]any
	if exactJSON([]byte(text), &outer, 4<<20) != nil {
		return nil, errors.New("invalid captured exit AES transport")
	}
	meta.ExitStartLayer = ""
	base, e := json.Marshal(meta)
	if e != nil {
		return nil, e
	}
	controller, e := NewWithEntryStartLayer(config, string(base), entrySource)
	if e != nil {
		return nil, e
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = controller.Close()
		}
	}()
	var graph map[string]any
	if exactJSON([]byte(controller.config), &graph, 4<<20) != nil {
		return nil, errors.New("invalid owned multihop execution graph")
	}
	var local map[string]any
	for _, name := range []string{"outbounds", "endpoints"} {
		values, _ := graph[name].([]any)
		for _, raw := range values {
			out, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid exit transport")
			}
			if out["tag"] == multihoprelay.ExitStartLayerTag {
				return nil, errors.New("exit Start Layer tag already owned")
			}
			if out["tag"] == LocalTag {
				if local != nil {
					return nil, errors.New("ambiguous native exit owner")
				}
				local = out
			}
		}
	}
	if local == nil || local["detour"] != controller.meta.EntryTag {
		return nil, errors.New("local exit no longer traverses captured entry")
	}
	original := map[string]any{}
	for key, value := range local {
		if key != "detour" {
			original[key] = value
		}
	}
	layer := &multihoprelay.StartLayer{Mode: source.Mode, API: controller.meta.ExitAPI, Transport: outer}
	inside, encrypted, e := multihoprelay.WrapStartLayer(original, controller.meta.ExitMode, layer, multihoprelay.ExitStartLayerTag, controller.meta.EntryTag)
	if e != nil {
		return nil, e
	}
	for key := range local {
		delete(local, key)
	}
	for key, value := range inside {
		local[key] = value
	}
	outbounds, ok := graph["outbounds"].([]any)
	if !ok {
		return nil, errors.New("owned outbound manager missing")
	}
	graph["outbounds"] = append(outbounds, encrypted)
	encoded, e := json.Marshal(graph)
	if e != nil || len(encoded) > 4<<20 {
		return nil, errors.New("layered exit graph exceeds bound")
	}
	controller.meta.ExitStartLayer = source.Mode
	controller.proposal.ExitStartLayer = source.Mode
	controller.expected.Request = controller.proposal
	controller.config = string(encoded)
	accepted = true
	return controller, nil
}
