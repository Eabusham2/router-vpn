package mobiletor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func controlFixture(t *testing.T, reply string) *Control {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		reader := bufio.NewReader(server)
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}
		_, _ = io.WriteString(server, reply)
	}()
	control, err := NewControl(client)
	if err != nil {
		t.Fatal(err)
	}
	return control
}

func bootstrapReply(progress, circuit, listener string) string {
	return fmt.Sprintf("650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED\r\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=%s TAG=done SUMMARY=\"Done\"\r\n250-status/circuit-established=%s\r\n250-net/listeners/socks=%s\r\n250 OK\r\n", progress, circuit, listener)
}

func TestControlReadsActualBootstrapAndListener(t *testing.T) {
	c := controlFixture(t, bootstrapReply("100", "1", `"127.0.0.1:19050"`))
	status, err := c.Bootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Progress != 100 || !status.CircuitEstablished || status.SOCKSAddress != "127.0.0.1:19050" {
		t.Fatal(status)
	}
}

func TestControlRejectsAmbiguousAndUnownedReadback(t *testing.T) {
	for _, reply := range []string{
		bootstrapReply("100", "1", `"0.0.0.0:19050"`),
		bootstrapReply("100", "1", `"127.0.0.1:19050" "127.0.0.1:19051"`),
		bootstrapReply("101", "1", `"127.0.0.1:19050"`),
		bootstrapReply("100 PROGRESS=0", "1", `"127.0.0.1:19050"`),
		"250-status/circuit-established=1\r\n250 OK\r\n",
		"250+status/circuit-established=\r\n1\r\n.\r\n250 OK\r\n",
		"250-" + strings.Repeat("x", 8192) + "\r\n250 OK\r\n",
		"551 internal secret must never reach error message\r\n",
	} {
		c := controlFixture(t, reply)
		if _, err := c.Bootstrap(context.Background()); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid control reply accepted or leaked: %v", err)
		}
		if err := c.EnableNetwork(context.Background()); err == nil {
			t.Fatal("failed control stream reused")
		}
	}
}

func TestControlCancellationUnblocksAndRetiresStream(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c, _ := NewControl(client)
	defer c.Close()
	read := make(chan struct{})
	go func() { _, _ = bufio.NewReader(server).ReadString('\n'); close(read) }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.EnableNetwork(ctx) }()
	<-read
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled command succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("control read ignored cancellation")
	}
	if err := c.EnableNetwork(context.Background()); err == nil {
		t.Fatal("canceled stream reused")
	}
}
