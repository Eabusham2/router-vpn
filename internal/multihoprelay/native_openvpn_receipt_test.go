package multihoprelay

import (
	"encoding/json"
	"router-vpn/internal/nativeopenvpn"
	"strings"
	"testing"
	"time"
)

func TestNativeOpenVPNReceiptCapturesExactPrivateOwnerAndFreshness(t *testing.T) {
	now := time.Now()
	capture := NativeOpenVPNCapture{Schema: 1, SessionID: strings.Repeat("a", 32), ConfigSHA256: strings.Repeat("b", 64), ExternalFingerprint: strings.Repeat("c", 64), ExternalAttempt: strings.Repeat("d", 32)}
	receipt := NativeOpenVPNReceipt{Capture: capture, RequestID: strings.Repeat("e", 32), Remote: nativeopenvpn.RemoteReceipt{Remote: nativeopenvpn.Remote{Host: "203.0.113.21", Port: 443, Network: "tcp"}, Generation: 2, ConnectedAt: now.Add(-time.Second).UnixMilli()}, HeartbeatAt: now.UnixMilli()}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var decoded NativeOpenVPNReceipt
	if json.Unmarshal(raw, &decoded) != nil || decoded != receipt || decoded.Validate(capture, now) != nil {
		t.Fatal("owned receipt did not roundtrip")
	}
	for name, mutate := range map[string]func(*NativeOpenVPNReceipt){
		"other session":     func(r *NativeOpenVPNReceipt) { r.Capture.SessionID = strings.Repeat("e", 32) },
		"other source":      func(r *NativeOpenVPNReceipt) { r.Capture.ConfigSHA256 = strings.Repeat("e", 64) },
		"other fingerprint": func(r *NativeOpenVPNReceipt) { r.Capture.ExternalFingerprint = strings.Repeat("e", 64) },
		"other attempt":     func(r *NativeOpenVPNReceipt) { r.Capture.ExternalAttempt = strings.Repeat("e", 32) },
		"stale":             func(r *NativeOpenVPNReceipt) { r.HeartbeatAt = now.Add(-4 * time.Second).UnixMilli() },
		"future":            func(r *NativeOpenVPNReceipt) { r.HeartbeatAt = now.Add(2 * time.Second).UnixMilli() },
		"no handshake":      func(r *NativeOpenVPNReceipt) { r.Remote.ConnectedAt = 0 },
		"no generation":     func(r *NativeOpenVPNReceipt) { r.Remote.Generation = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := receipt
			mutate(&changed)
			if changed.Validate(capture, now) == nil {
				t.Fatal("unowned native receipt accepted")
			}
		})
	}
	good := string(raw)
	for _, bad := range []string{"null", "[]", good + "{}", strings.TrimSuffix(good, "}") + `,"private_key":"hidden"}`, strings.Replace(good, `"schema":1`, `"schema":1,"schema":1`, 1), strings.Replace(good, `"generation":2`, `"generation":2,"generation":3`, 1), strings.Replace(good, `"remote":{`, `"remote":null,"discarded":{`, 1)} {
		if json.Unmarshal([]byte(bad), &decoded) == nil {
			t.Fatal("non-exact private receipt decoded")
		}
	}
}
