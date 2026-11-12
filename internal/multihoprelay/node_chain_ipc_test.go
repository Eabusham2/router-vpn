package multihoprelay

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ipcChainCapture(t *testing.T, count int) NodeChainCapture {
	t.Helper()
	key := func(seed byte) string {
		k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	}
	source := NodeChainDescriptor{Schema: 1, EntryID: "original-entry", EntryNodeID: strings.Repeat("1", 64), EntryMode: "wg", SourceSHA256: strings.Repeat("2", 64), DNSPolicySHA256: strings.Repeat("3", 64)}
	request := NodeChainRequest{Schema: 1, SessionID: strings.Repeat("4", 32), EntryNodeID: source.EntryNodeID, SourceSHA256: source.SourceSHA256, DNSPolicySHA256: source.DNSPolicySHA256, Epoch: strings.Repeat("5", 64), Peer: "10.77.0.2", AcquireExpiresAt: 1794484810, Port: 26240}
	for i := 0; i < count; i++ {
		member := NodeChainMember{Position: i + 1, ProfileID: fmt.Sprintf("suffix-%d", i), NodeID: fmt.Sprintf("%064x", 100+i), Mode: []string{"wg", "awg2-fast", "awg2-strong"}[i%3], StartLayer: "off", ClientPublicKey: key(byte(11 + i)), ServerPublicKey: key(byte(41 + i))}
		if i == count-1 {
			member.Mode = "shadowsocks"
			member.ClientPublicKey = ""
			member.ServerPublicKey = ""
		}
		source.Members = append(source.Members, member)
		request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, key(byte(71+i)))
		request.Users = append(request.Users, NodeChainUser{Position: i + 1, Username: fmt.Sprintf("%048x", 200+i*2), Password: fmt.Sprintf("%048x", 201+i*2)})
	}
	digest, err := source.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request.DescriptorSHA256 = digest
	return NodeChainCapture{Schema: 1, Request: request, Source: source, RegistrySHA256: digest, OwnerID: strings.Repeat("6", 64), Peer: request.Peer, Host: "10.77.0.1", BootstrapDeadline: time.Unix(1794484890, 0).UTC()}
}
func ipcJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNodeChainIPCCompleteCanonicalBounds(t *testing.T) {
	for _, count := range []int{1, 3, 7} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			capture := ipcChainCapture(t, count)
			raw := ipcJSON(t, capture)
			restored, err := DecodeNodeChainCapture(raw)
			if err != nil || !reflect.DeepEqual(restored, capture) {
				t.Fatal("complete original capture was not retained", err)
			}
			raw = ipcJSON(t, capture.Request)
			if len(raw) > 4<<10 {
				t.Fatalf("maximum request no longer fits shipping HTTP limit: %d", len(raw))
			}
			request, nonce, err := DecodeNodeChainLeaseRequest(raw, false)
			if err != nil || nonce != "" || !reflect.DeepEqual(request, capture.Request) {
				t.Fatal("complete create/delete request rejected", err)
			}
			status := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"status_nonce":"`+strings.Repeat("a", 64)+`"}`)...)
			request, nonce, err = DecodeNodeChainLeaseRequest(status, true)
			if err != nil || nonce != strings.Repeat("a", 64) || !reflect.DeepEqual(request, capture.Request) {
				t.Fatal("complete status request rejected", err)
			}
			if len(status) > 4<<10 {
				t.Fatal("maximum status exceeds HTTP bound")
			}
		})
	}
	for _, operation := range []string{"snapshot", "bootstrap", "stop"} {
		t.Run(operation, func(t *testing.T) {
			request := NodeChainIPCRequest{1, operation, strings.Repeat("a", 64), strings.Repeat("b", 64)}
			actual, err := DecodeNodeChainIPCRequest(ipcJSON(t, request))
			if err != nil || actual != request {
				t.Fatal("canonical original IPC request rejected", err)
			}
		})
	}
}

func TestNodeChainIPCRejectsAmbiguousOrMissingAuthority(t *testing.T) {
	request := NodeChainIPCRequest{1, "snapshot", strings.Repeat("a", 64), strings.Repeat("b", 64)}
	raw := string(ipcJSON(t, request))
	cases := map[string]string{"duplicate": strings.Replace(raw, `"schema":1`, `"schema":1,"schema":1`, 1), "case-alias": strings.Replace(raw, `"schema"`, `"Schema"`, 1), "unknown": strings.Replace(raw, `"schema":1`, `"schema":1,"extra":false`, 1), "missing-schema": strings.Replace(raw, `"schema":1,`, "", 1), "missing-capture": strings.Replace(raw, `,"capture_sha256":"`+request.CaptureSHA256+`"`, "", 1), "null-capture": strings.Replace(raw, `"`+request.CaptureSHA256+`"`, `null`, 1), "array": `[` + raw + `]`, "null": `null`, "second-value": raw + raw, "wrong-type": strings.Replace(raw, `"schema":1`, `"schema":"1"`, 1), "unknown-operation": strings.Replace(raw, `snapshot`, `activate`, 1), "oversized": raw + strings.Repeat(" ", 1024)}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeNodeChainIPCRequest([]byte(body)); err == nil {
				t.Fatal("ambiguous authority was accepted")
			}
		})
	}
}

func TestNodeChainIPCLeaseNestedAuthorityAndStatusSeparation(t *testing.T) {
	raw := string(ipcJSON(t, ipcChainCapture(t, 7).Request))
	status := raw[:len(raw)-1] + `,"status_nonce":"` + strings.Repeat("c", 64) + `"}`
	cases := map[string]string{"duplicate-user": strings.Replace(raw, `"position":1`, `"position":1,"position":1`, 1), "case-user": strings.Replace(raw, `"password"`, `"Password"`, 1), "unknown-user": strings.Replace(raw, `"position":1`, `"position":1,"admin":true`, 1), "missing-user-position": strings.Replace(raw, `"position":1,`, "", 1), "null-users": strings.Replace(raw, `"users":[`, `"users":null,"ignored":[`, 1), "missing-port": strings.Replace(raw, `"listen_port":26240,`, "", 1), "missing-local-pins": strings.Replace(raw, `"local_packet_public_keys"`, `"old_local_packet_public_keys"`, 1), "null-nonce": raw[:len(raw)-1] + `,"status_nonce":null}`, "duplicate-nonce": status[:len(status)-1] + `,"status_nonce":"` + strings.Repeat("c", 64) + `"}`, "extra-value": raw + ` null`}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			for _, statusMode := range []bool{false, true} {
				if _, _, err := DecodeNodeChainLeaseRequest([]byte(body), statusMode); err == nil {
					t.Fatalf("ambiguous nested request accepted in status=%v", statusMode)
				}
			}
		})
	}
	if _, _, err := DecodeNodeChainLeaseRequest([]byte(status), false); err == nil {
		t.Fatal("status nonce accepted as create/delete authority")
	}
	if _, _, err := DecodeNodeChainLeaseRequest([]byte(raw), true); err == nil {
		t.Fatal("status accepted without its fresh nonce")
	}
}

func TestNodeChainIPCResponseReceiptCompleteness(t *testing.T) {
	capture := ipcChainCapture(t, 7)
	digest, _ := capture.Digest()
	nonce := strings.Repeat("d", 64)
	receipt := NodeChainReceipt{Schema: 1, SessionID: capture.Request.SessionID, OwnerID: capture.OwnerID, Peer: capture.Peer, SourceSHA256: capture.Source.SourceSHA256, RegistrySHA256: capture.RegistrySHA256, DNSPolicySHA256: capture.Source.DNSPolicySHA256, CaptureSHA256: digest, Nonce: nonce, Sequence: 1, HeartbeatAt: 1794484800000, Phase: NodeChainReady, FrontReady: true, TrafficAllowed: true, DNSProven: true, PublicProven: true, ProofAt: 1794484799000}
	for _, member := range capture.Source.Members {
		receipt.Prefixes = append(receipt.Prefixes, NodeChainPrefixReceipt{member.Position, member.ProfileID, member.NodeID, member.Mode, true, 1.25})
	}
	response := NodeChainIPCResponse{1, "snapshot", nonce, digest, true, &receipt}
	raw := string(ipcJSON(t, response))
	actual, err := DecodeNodeChainIPCResponse([]byte(raw))
	if err != nil || !reflect.DeepEqual(actual, response) {
		t.Fatal("complete maximum receipt rejected", err)
	}
	cases := map[string]string{"missing-ok": strings.Replace(raw, `"ok":true,`, "", 1), "missing-ready": strings.Replace(raw, `"front_ready":true,`, "", 1), "missing-proof": strings.Replace(raw, `"proven":true,`, "", 1), "duplicate-proof": strings.Replace(raw, `"proven":true`, `"proven":false,"proven":true`, 1), "alias-proof": strings.Replace(raw, `"response_ms"`, `"Response_MS"`, 1), "null-receipt": strings.Replace(raw, `"receipt":{`, `"receipt":null,"ignored":{`, 1), "missing-receipt": string(ipcJSON(t, NodeChainIPCResponse{1, "snapshot", nonce, digest, true, nil})), "false-with-receipt": strings.Replace(raw, `"ok":true`, `"ok":false`, 1), "extra-closed-receipt": strings.Replace(raw, `"operation":"snapshot"`, `"operation":"closed"`, 1), "oversized": raw + strings.Repeat(" ", NodeChainIPCMaximumBytes)}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeNodeChainIPCResponse([]byte(body)); err == nil {
				t.Fatal("incomplete native receipt was accepted")
			}
		})
	}
	for _, operation := range []string{"bootstrap", "stop", "closed"} {
		r := NodeChainIPCResponse{1, operation, capture.OwnerID, digest, true, nil}
		if _, err := DecodeNodeChainIPCResponse(ipcJSON(t, r)); err != nil {
			t.Fatal(operation, err)
		}
	}
}

func TestNodeChainIPCCaptureRejectsNestedSubstitution(t *testing.T) {
	raw := string(ipcJSON(t, ipcChainCapture(t, 7)))
	for name, body := range map[string]string{"duplicate-request": strings.Replace(raw, `"listen_port":26240`, `"listen_port":26240,"listen_port":26240`, 1), "alias-source": strings.Replace(raw, `"entry_mode"`, `"Entry_Mode"`, 1), "missing-host": strings.Replace(raw, `,"host":"10.77.0.1"`, "", 1), "null-deadline": strings.Replace(raw, `"bootstrap_deadline":"2026-11-12T12:01:30Z"`, `"bootstrap_deadline":null`, 1), "foreign-source": strings.Replace(raw, `"entry_mode":"wg"`, `"entry_mode":"awg2-fast"`, 1)} {
		t.Run(name, func(t *testing.T) {
			if body == raw {
				t.Fatal("negative witness did not alter source")
			}
			if _, err := DecodeNodeChainCapture([]byte(body)); err == nil {
				t.Fatal("ambiguous staged capture accepted")
			}
		})
	}
}
