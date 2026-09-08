package main

import (
	"context"
	"net"
	"testing"
)

func TestLocalDNSProxyProofRejectsWrongAndIncompleteResponses(t *testing.T) {
	for _, kind := range []string{"valid", "wrong-question", "wrong-id", "header-only", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 65536)
				n, addr, err := conn.ReadFrom(buf)
				if err != nil {
					return
				}
				buf[2] |= 128
				switch kind {
				case "wrong-question":
					buf[13] = 'z'
				case "wrong-id":
					buf[0]++
				case "header-only":
					n = 12
				case "truncated":
					buf[2] |= 2
				}
				conn.WriteTo(buf[:n], addr)
			}()
			t.Cleanup(func() { conn.Close(); <-done })
			if err := probeLocalDNSProxyContext(context.Background(), conn.LocalAddr().String()); (err == nil) != (kind == "valid") {
				t.Fatalf("%s: proof error=%v", kind, err)
			}
		})
	}
}
