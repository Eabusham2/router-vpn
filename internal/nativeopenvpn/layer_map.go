package nativeopenvpn

import (
	"encoding/json"
)

const LayerMapType = "routervpn-openvpn-layer-map"

// LayerMap is the compiled native dialer contract. Original remote order and
// identity remain outside the private service mapping. One captured predecessor
// owns every child dialer; callers cannot inject per-remote arbitrary detours.
type LayerMap struct {
	Mode    string      `json:"mode"`
	Remotes []Remote    `json:"remotes"`
	Layers  StartLayers `json:"layers"`
	Detour  string      `json:"detour,omitempty"`
}

func (mapping LayerMap) Validate() error {
	if !validStartLayerMode(mapping.Mode) || len(mapping.Remotes) < 2 || len(mapping.Remotes) > 16 || len(mapping.Layers) < 2 || len(mapping.Layers) > 16 || mapping.Detour != "" && !startLayerIdent(mapping.Detour) {
		return errStartLayers
	}
	hosts := map[string]bool{}
	for _, remote := range mapping.Remotes {
		layer, exists := mapping.Layers[remote.Host]
		if remote.Validate() != nil || !exists || layer.Validate(remote.Host, mapping.Mode) != nil {
			return errStartLayers
		}
		hosts[remote.Host] = true
	}
	if len(hosts) != len(mapping.Layers) {
		return errStartLayers
	}
	raw, err := json.Marshal(mapping.Layers)
	if err != nil || len(raw) > MaxStartLayersBytes {
		return errStartLayers
	}
	return nil
}

func (mapping *LayerMap) UnmarshalJSON(raw []byte) error {
	fields, err := pairingObject(raw, MaxStartLayersBytes+16<<10)
	if err != nil || len(fields) < 3 || len(fields) > 4 {
		return errStartLayers
	}
	for key := range fields {
		if key != "mode" && key != "remotes" && key != "layers" && key != "detour" {
			return errStartLayers
		}
	}
	if value, present := fields["detour"]; present {
		if _, ok := value.(string); !ok {
			return errStartLayers
		}
	}
	remotes, ok := fields["remotes"].([]any)
	if !ok || len(remotes) < 2 || len(remotes) > 16 {
		return errStartLayers
	}
	for _, rawRemote := range remotes {
		remote, ok := rawRemote.(map[string]any)
		if !ok || len(remote) != 3 {
			return errStartLayers
		}
		if _, ok := remote["host"].(string); !ok {
			return errStartLayers
		}
		if _, ok := remote["network"].(string); !ok {
			return errStartLayers
		}
		if _, ok := remote["port"].(float64); !ok {
			return errStartLayers
		}
	}
	type plain LayerMap
	var result plain
	if json.Unmarshal(raw, &result) != nil || LayerMap(result).Validate() != nil {
		return errStartLayers
	}
	*mapping = LayerMap(result)
	return nil
}
