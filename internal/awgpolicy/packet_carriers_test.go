package awgpolicy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func packetCarriersFixture(count int) (map[string]any, map[string]map[string]any) {
	packet := map[string]any{"tag": "packet", "type": "wireguard", "detour": "ss-0", "peers": []any{map[string]any{"address": "192.0.2.1", "port": 51820}}}
	all := map[string]map[string]any{"packet": packet, "entry": {"tag": "entry", "type": "wireguard", "mtu": 2000}}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	for i := 0; i < count; i++ {
		tag, next := fmt.Sprintf("ss-%d", i), "entry"
		if i+1 < count {
			next = fmt.Sprintf("ss-%d", i+1)
		}
		all[tag] = map[string]any{"tag": tag, "type": "shadowsocks", "method": "2022-blake3-aes-256-gcm", "password": key, "server": "198.51.100.2", "server_port": 8388, "detour": next}
	}
	return packet, all
}

func TestNestedPacketEnvelopeCompleteCarrierArithmetic(t *testing.T) {
	for _, row := range []struct {
		name               string
		mutate             func(map[string]any, map[string]map[string]any)
		data, control, cap int
	}{
		{"two-aes", func(map[string]any, map[string]map[string]any) {}, 176, 292, 1824},
		{"identity-chain", func(_ map[string]any, all map[string]map[string]any) {
			key := all["ss-0"]["password"].(string)
			all["ss-0"]["password"] = key + ":" + key + ":" + key
		}, 200, 316, 1792},
		{"aes128", func(_ map[string]any, all map[string]map[string]any) {
			all["ss-0"]["method"] = "2022-blake3-aes-128-gcm"
			all["ss-0"]["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 16)))
		}, 176, 292, 1824},
		{"chacha", func(_ map[string]any, all map[string]map[string]any) {
			all["ss-0"]["method"] = "2022-blake3-chacha20-poly1305"
		}, 200, 316, 1792},
		{"inner-ipv6", func(p map[string]any, _ map[string]map[string]any) {
			p["peers"].([]any)[0].(map[string]any)["address"] = "2001:db8::1"
		}, 188, 304, 1808},
		{"intermediate-ipv6", func(_ map[string]any, a map[string]map[string]any) { a["ss-0"]["server"] = "2001:db8::2" }, 188, 304, 1808},
		{"outer-ipv6", func(_ map[string]any, a map[string]map[string]any) { a["ss-1"]["server"] = "2001:db8::3" }, 196, 312, 1792},
		{"inner-port53", func(p map[string]any, _ map[string]map[string]any) {
			p["peers"].([]any)[0].(map[string]any)["port"] = 53
		}, 176, 1044, 1824},
		{"intermediate-port53", func(_ map[string]any, a map[string]map[string]any) { a["ss-0"]["server_port"] = 53 }, 176, 986, 1824},
		{"whitening", func(_ map[string]any, a map[string]map[string]any) { a["ss-0"]["type"] = "routervpn-aes-xor" }, 176, 292, 1824},
	} {
		t.Run(row.name, func(t *testing.T) {
			p, all := packetCarriersFixture(2)
			row.mutate(p, all)
			e, entry, err := NestedPacketEnvelope(p, all)
			if err != nil || entry != nil && entry["tag"] != "entry" || entry == nil || e.DataOverhead != row.data || e.ControlMax != row.control {
				t.Fatal("lost exact complete carrier envelope", e, err)
			}
			cap, err := e.Capacity(2000, 2000, false)
			if err != nil || cap != row.cap {
				t.Fatal("wrong Auto cap", cap, err)
			}
			if _, err = e.Capacity(2000, 2000, true); err == nil {
				t.Fatal("Fixed request was silently clamped")
			}
			if cap, err = e.Capacity(2000, row.cap, true); err != nil || cap != row.cap {
				t.Fatal("fitting Fixed request changed", cap, err)
			}
			if _, err = e.Capacity(1400, 1280, false); err == nil {
				t.Fatal("undersized carrier admitted")
			}
		})
	}
}

func TestNestedPacketEnvelopeRefusesForeignGraphAndMalformedCarrier(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any, map[string]map[string]any){
		"missing":      func(_ map[string]any, a map[string]map[string]any) { delete(a, "ss-1") },
		"cycle":        func(_ map[string]any, a map[string]map[string]any) { a["ss-1"]["detour"] = "ss-0" },
		"packet-cycle": func(_ map[string]any, a map[string]map[string]any) { a["ss-1"]["detour"] = "packet" },
		"foreign-tag":  func(_ map[string]any, a map[string]map[string]any) { a["ss-1"]["tag"] = "other" },
		"detour-type":  func(_ map[string]any, a map[string]map[string]any) { a["ss-1"]["detour"] = []any{"entry"} },
		"hostname":     func(_ map[string]any, a map[string]map[string]any) { a["ss-1"]["server"] = "example.invalid" },
		"bad-key":      func(_ map[string]any, a map[string]map[string]any) { a["ss-1"]["password"] = "invalid" },
		"short-key": func(_ map[string]any, a map[string]map[string]any) {
			a["ss-1"]["password"] = base64.StdEncoding.EncodeToString(make([]byte, 16))
		},
		"method": func(_ map[string]any, a map[string]map[string]any) { a["ss-1"]["method"] = "aes-256-gcm" },
		"chacha-chain": func(_ map[string]any, a map[string]map[string]any) {
			a["ss-1"]["method"] = "2022-blake3-chacha20-poly1305"
			key := a["ss-1"]["password"].(string)
			a["ss-1"]["password"] = key + ":" + key
		},
		"tcp-only": func(_ map[string]any, a map[string]map[string]any) { a["ss-1"]["network"] = "tcp" },
		"uot": func(_ map[string]any, a map[string]map[string]any) {
			a["ss-1"]["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
		},
		"port": func(_ map[string]any, a map[string]map[string]any) { a["ss-1"]["server_port"] = float64(1.5) },
	} {
		t.Run(name, func(t *testing.T) {
			p, a := packetCarriersFixture(2)
			mutate(p, a)
			if _, _, err := NestedPacketEnvelope(p, a); err == nil {
				t.Fatal("malformed carrier admitted")
			}
		})
	}
}

func TestNestedPacketEnvelopeRetainsAWGControlAndJunk(t *testing.T) {
	for _, field := range []string{"s1", "s2", "s3", "jmax"} {
		t.Run(field, func(t *testing.T) {
			p, a := packetCarriersFixture(2)
			p["type"] = Type
			params := map[string]any{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10-19", "h2": "20-29", "h3": "30-39", "h4": "40-49"}
			params[field] = "1280"
			params["s4"] = "0"
			p["amnezia"] = params
			e, _, err := NestedPacketEnvelope(p, a)
			if err != nil {
				t.Fatal(err)
			}
			// The data fits 1500, but enabled original control/junk may not.
			outer := e.DataOverhead + 1280
			if field != "jmax" {
				if _, err = e.Capacity(outer, 1280, false); err == nil {
					t.Fatal("oversized original control admitted", field, e, outer)
				}
			} else if _, err = e.Capacity(outer, 1280, false); err != nil {
				t.Fatal("fitting junk budget refused", err)
			}
			if field == "jmax" {
				params["jc"] = "0"
				off, _, err := NestedPacketEnvelope(p, a)
				if err != nil || off.ControlMax != 348 {
					t.Fatal("disabled junk still counted", off, err)
				}
			}
		})
	}
}

func TestNestedPacketEnvelopeExactPortKeysAndGraphBounds(t *testing.T) {
	for _, raw := range []any{int(53), float64(53), json.Number("53")} {
		p, all := packetCarriersFixture(1)
		p["peers"].([]any)[0].(map[string]any)["port"] = raw
		all["ss-0"]["server_port"] = raw
		e, _, err := NestedPacketEnvelope(p, all)
		if err != nil || e.ControlMax != 986 {
			t.Fatal("exact integer port representation refused", raw, e, err)
		}
	}
	for _, raw := range []any{nil, "53", true, float64(53.5), json.Number("53.5"), json.Number("65536"), 0, -1} {
		p, all := packetCarriersFixture(1)
		all["ss-0"]["server_port"] = raw
		if _, _, err := NestedPacketEnvelope(p, all); err == nil {
			t.Fatal("noncanonical port admitted", raw)
		}
	}
	for _, count := range []int{64, 65} {
		p, all := packetCarriersFixture(1)
		key := all["ss-0"]["password"].(string)
		all["ss-0"]["password"] = strings.TrimSuffix(strings.Repeat(key+":", count), ":")
		e, _, err := NestedPacketEnvelope(p, all)
		if count == 65 {
			if err == nil {
				t.Fatal("65 identity keys admitted")
			}
			continue
		}
		if err != nil || e.DataOverhead != 1118 {
			t.Fatal("64 original identity headers omitted", e, err)
		}
	}
	// Packet + fourteen proxies + preceding packet = sixteen exact owners.
	// The next proxy must not sneak a seventeenth owner through the terminal arm.
	for _, count := range []int{14, 15} {
		p, all := packetCarriersFixture(count)
		_, entry, err := NestedPacketEnvelope(p, all)
		if count == 14 {
			if err != nil || entry == nil {
				t.Fatal("bounded exact graph refused", err)
			}
		} else if err == nil {
			t.Fatal("seventeenth graph owner admitted")
		}
	}
}
