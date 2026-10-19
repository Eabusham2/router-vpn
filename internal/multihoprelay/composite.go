package multihoprelay

import "router-vpn/internal/nativecomposite"

const CompositePrefix = "routervpn-relay-composite-"

func compositePlan(exit Exit) (map[string]any, error) {
	if err := nativecomposite.ValidatePlan(exit.Transport, exit.Mode, exit.NodeID, ""); err != nil {
		return nil, err
	}
	if exit.StartLayer == nil {
		return copyMap(exit.Transport)
	}
	return nativecomposite.WithStartLayer(exit.Transport, exit.Mode, exit.NodeID, exit.StartLayer.Mode, exit.StartLayer.API, exit.StartLayer.Transport)
}
