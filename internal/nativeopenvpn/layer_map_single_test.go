package nativeopenvpn

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestOpenVPNNativeLayerMapSingleHostKeepsOriginalIdentity(t *testing.T) {
	for _, mode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, multiplePorts := range []bool{false, true} {
			layers := remoteLayers(mode)
			delete(layers, "192.0.2.61")
			mapping := LayerMap{Mode: mode, Remotes: []Remote{{Host: "192.0.2.60", Port: 1194, Network: "udp"}}, Layers: layers, Detour: "original-entry"}
			if multiplePorts {
				mapping.Remotes = append(mapping.Remotes, Remote{Host: "192.0.2.60", Port: 443, Network: "tcp"})
			}
			if err := mapping.Validate(); err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(mapping)
			var decoded LayerMap
			if json.Unmarshal(encoded, &decoded) != nil || !reflect.DeepEqual(mapping, decoded) {
				t.Fatal("single-host native contract changed")
			}
			endpoint := map[string]any{"server": "192.0.2.60", "server_port": float64(1194), "network": "udp"}
			if layers.Validate(endpoint, ResponseProbes{"192.0.2.60": {URL: "https://192.0.2.60/response"}}, mode) == nil {
				t.Fatal("native map relaxed ordinary paired multi-host response policy")
			}
			for _, fault := range []string{"missing-layer", "foreign-host", "private-remote", "wrong-port", "wrong-network", "extra-layer", "foreign-layer-host"} {
				t.Run(mode+"/"+fault+"/"+map[bool]string{false: "one-port", true: "two-ports"}[multiplePorts], func(t *testing.T) {
					var changed LayerMap
					if json.Unmarshal(encoded, &changed) != nil {
						t.Fatal("fixture")
					}
					switch fault {
					case "missing-layer":
						delete(changed.Layers, "192.0.2.60")
					case "foreign-host":
						changed.Remotes[0].Host = "192.0.2.99"
					case "private-remote":
						changed.Remotes[0].Host = "10.93.0.1"
					case "wrong-port":
						changed.Remotes[0].Port = 0
					case "wrong-network":
						changed.Remotes[0].Network = "ip"
					case "extra-layer":
						changed.Layers["192.0.2.61"] = remoteLayers(mode)["192.0.2.61"]
					case "foreign-layer-host":
						changed.Layers["192.0.2.60"].Transport["server"] = "192.0.2.61"
					}
					if changed.Validate() == nil {
						t.Fatal("uncaptured layer map admitted", fault)
					}
				})
			}
		}
	}
}
