package httpupgrade

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// The same test runs against unmodified WebTunnel v0.0.7 as a negative control.
func TestClientPreservesApplicationBytesBufferedWithUpgradeHeaders(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	prefix := []byte("first real tunneled bytes after HTTP upgrade")
	go func() {
		defer server.Close()
		if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
			return
		}
		response := []byte("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n")
		// One write forces bufio to read the stream prefix with the headers.
		server.Write(append(response, prefix...))
	}()
	transport, err := NewHTTPUpgradeTransport(&Config{Host: "bridge.example", Path: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := transport.Client(client)
	if err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(prefix))
	if _, err := io.ReadFull(wrapped, received); err != nil || !bytes.Equal(received, prefix) {
		t.Error("WebTunnel discarded application bytes buffered with upgrade headers")
	}
}

func TestServerPreservesPipelinedClientBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	server.SetDeadline(time.Now().Add(time.Second))
	prefix := []byte("owned pipelined client tunnel bytes")
	go func() {
		defer client.Close()
		request := []byte("GET /owned HTTP/1.1\r\nHost: bridge.example\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n")
		if _, err := client.Write(append(request, prefix...)); err != nil {
			return
		}
		http.ReadResponse(bufio.NewReader(client), nil)
	}()
	transport, err := NewHTTPUpgradeTransport(&Config{Host: "bridge.example", Path: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := transport.Server(server)
	if err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(prefix))
	if _, err := io.ReadFull(wrapped, received); err != nil || !bytes.Equal(received, prefix) {
		t.Fatal("WebTunnel discarded the client's pipelined stream bytes", err)
	}
}
