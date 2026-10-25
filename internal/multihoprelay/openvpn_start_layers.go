package multihoprelay

import (
	"encoding/json"
	"errors"
	"router-vpn/internal/nativeopenvpn"
)

const OpenVPNStartLayerMapTag = "routervpn-exit-start-layer-map"

// ExitLayerMode preserves singular legacy layer identity and adds only the
// explicit per-host OpenVPN mapping. Invalid maps still fail full validation.
func ExitLayerMode(exit Exit) string {
	if exit.Mode == "openvpn" && exit.External != nil && exit.External.OpenVPNStartLayers != nil {
		return exit.External.OpenVPNStartLayers.Mode()
	}
	return LayerMode(exit.StartLayer)
}

func OpenVPNLayersRequired(exit Exit) bool {
	return OpenVPNRemoteRequired(exit) && exit.External.OpenVPNStartLayers != nil
}

// WrapOpenVPNStartLayers keeps the original OpenVPN remote list unchanged.
// The native mapper owns real per-host encrypted transports and translates only
// the selected physical dial, so receipts retain original provider identity.
func WrapOpenVPNStartLayers(transport map[string]any, probes nativeopenvpn.ResponseProbes, layers nativeopenvpn.StartLayers, selectedMode, tag, via string) (map[string]any, map[string]any, error) {
	bad := errors.New("OpenVPN mapped Start Layer differs from its captured original transport")
	inner, err := nativeopenvpn.ValidateEndpoint(transport)
	if err != nil || !ident.MatchString(tag) || tag == via || via != "" && !ident.MatchString(via) || inner["tag"] == tag || layers.Validate(inner, probes, selectedMode) != nil {
		return nil, nil, bad
	}
	remotes, err := nativeopenvpn.Remotes(inner)
	if err != nil {
		return nil, nil, bad
	}
	mapping := nativeopenvpn.LayerMap{Mode: selectedMode, Remotes: remotes, Layers: layers, Detour: via}
	if mapping.Validate() != nil {
		return nil, nil, bad
	}
	encoded, err := json.Marshal(mapping)
	var outer map[string]any
	if err != nil || json.Unmarshal(encoded, &outer) != nil {
		return nil, nil, bad
	}
	outer["type"], outer["tag"] = nativeopenvpn.LayerMapType, tag
	inner["detour"] = tag
	return inner, outer, nil
}

func externalPublicOpenVPNLayers(layers nativeopenvpn.StartLayers) any {
	public := map[string]any{}
	for host, layer := range layers {
		public[host] = externalPublicLayer(&StartLayer{Mode: layer.Mode, API: layer.API, Transport: layer.Transport})
	}
	return public
}

func externalOpenVPNLayerSecrets(layers nativeopenvpn.StartLayers) any {
	secrets := map[string]any{}
	for host, layer := range layers {
		secrets[host] = layer.Transport["password"]
	}
	return secrets
}
