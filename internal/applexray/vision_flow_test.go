package applexray

import (
	"bytes"
	"encoding/json"
	"testing"
)

func visionSource(t *testing.T, mode, flow string) []byte {
	t.Helper()
	value, err := Object(sampleConfig(mode))
	if err != nil {
		t.Fatal(err)
	}
	remote(value)["users"].([]any)[0].(map[string]any)["flow"] = flow
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func TestVisionUDP443RetainsExplicitOriginalFlow(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "split", "max"} {
		for _, flow := range []string{VisionFlow, VisionUDP443Flow} {
			t.Run(mode+"/"+flow, func(t *testing.T) {
				raw := visionSource(t, mode, flow)
				original := append([]byte(nil), raw...)
				plan, err := Prepare(mode, raw)
				if err != nil {
					t.Fatal(err)
				}
				native, err := Object(plan.JSON)
				if err != nil || remote(native)["users"].([]any)[0].(map[string]any)["flow"] != flow {
					t.Fatal("native preparation changed the captured flow", err)
				}
				graph, err := Compile(mode, wrapperFor(mode), raw)
				if err != nil {
					t.Fatal(err)
				}
				compiled, _ := Object(graph)
				outbound := compiled["outbounds"].([]any)[0].(map[string]any)
				if outbound["mode"] != mode || outbound["config_json"] != string(original) || !bytes.Equal(raw, original) {
					t.Fatal("composition rewrote the original client or changed its mode identity")
				}
				restored, err := Compile(mode, graph, raw)
				if err != nil || !bytes.Equal(restored, graph) {
					t.Fatal("same original flow failed saved-wrapper restoration", err)
				}
				other := VisionUDP443Flow
				if flow == other {
					other = VisionFlow
				}
				if _, err := Compile(mode, graph, visionSource(t, mode, other)); err == nil {
					t.Fatal("a different original flow reused the saved wrapper")
				}
			})
		}
	}
}

func TestVisionUDP443PreservesIndependentStartLayer(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision"} {
		for _, flow := range []string{VisionFlow, VisionUDP443Flow} {
			for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(mode+"/"+flow+"/"+layer, func(t *testing.T) {
					raw := visionSource(t, mode, flow)
					original := append([]byte(nil), raw...)
					aes, policy := startSource(layer, mode, "http://10.77.0.1:8787")
					graph, err := ComposeStartLayer(mode, wrapperFor(mode), raw, aes, policy)
					if err != nil {
						t.Fatal(err)
					}
					compiled, _ := Object(graph)
					outbound := compiled["outbounds"].([]any)[0].(map[string]any)
					inner, err := Object([]byte(outbound["config_json"].(string)))
					if err != nil || remote(inner)["users"].([]any)[0].(map[string]any)["flow"] != flow || outbound["detour"] != StartLayerTag || !bytes.Equal(original, raw) {
						t.Fatal("Start Layer borrowed or rewrote the captured client flow", err)
					}
					if _, err := Prepare(mode, []byte(outbound["config_json"].(string))); err != nil {
						t.Fatal("layered native client lost its explicit flow", err)
					}
				})
			}
		}
	}
}

func TestVisionUDP443DoesNotWidenFlowAdmission(t *testing.T) {
	for _, flow := range []any{nil, true, 443, "", "xtls-rprx-vision-udp443 ", "xtls-rprx-vision-udp", "xtls-rprx-direct", "XTLS-RPRX-VISION-UDP443", []any{VisionUDP443Flow}} {
		value, _ := Object(sampleConfig("reality-vision"))
		remote(value)["users"].([]any)[0].(map[string]any)["flow"] = flow
		raw, _ := json.Marshal(value)
		if _, err := Prepare("reality-vision", raw); err == nil {
			t.Fatalf("malformed/foreign Vision flow accepted: %T", flow)
		}
	}
	for _, flow := range []string{VisionFlow, VisionUDP443Flow} {
		if _, err := Prepare("reality-xhttp", visionSource(t, "reality-xhttp", flow)); err == nil {
			t.Fatal("explicit Vision capability changed XHTTP's required empty flow")
		}
	}
}
