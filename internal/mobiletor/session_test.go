package mobiletor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

type exchange struct{ command, reply string }

func sessionFixture(t *testing.T, exchanges []exchange) *Control {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	t.Cleanup(func() { client.Close(); server.Close(); <-done })
	go func() {
		defer close(done)
		reader := bufio.NewReader(server)
		for _, item := range exchanges {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line != item.command+"\r\n" {
				t.Error("native control operation did not follow owned session ordering")
				server.Close()
				return
			}
			if _, err := io.WriteString(server, item.reply); err != nil {
				return
			}
		}
	}()
	control, err := NewControl(client)
	if err != nil {
		t.Fatal(err)
	}
	return control
}

const idleConfigReply = "250-DisableNetwork=1\r\n250-SocksPort=0\r\n250-UseBridges=0\r\n250-Bridge\r\n250 ClientTransportPlugin\r\n"

func inventoryReply(busy string) string {
	var reply strings.Builder
	for _, key := range idleInventories {
		if key == "orconn-status" && busy != "" {
			reply.WriteString("250+orconn-status=\r\n" + busy + "\r\n.\r\n")
		} else {
			reply.WriteString("250-" + key + "=\r\n")
		}
	}
	return reply.String() + "250 OK\r\n"
}

func idleExchanges(reply string) []exchange {
	return []exchange{
		{"SETCONF DisableNetwork=1 SocksPort=0 UseBridges=0 Bridge ClientTransportPlugin", "250 OK\r\n"},
		{"SIGNAL CLEARDNSCACHE", "250 OK\r\n"},
		{"GETCONF " + configurationKeys, idleConfigReply},
		{"GETINFO " + strings.Join(idleInventories, " "), reply},
	}
}

func TestResidentConfigureReadbackAndReleaseClearPreviousSession(t *testing.T) {
	plan, err := NewPlan(common.ExternalTorBridgeConfig{Bridges: []string{obfs4Bridge}})
	if err != nil {
		t.Fatal(err)
	}
	sequence := idleExchanges(inventoryReply(""))
	sequence = append(sequence,
		exchange{`SETCONF DisableNetwork=1 SocksPort="auto IsolateSOCKSAuth" UseBridges=1 ClientTransportPlugin="obfs4 socks5 127.0.0.1:18443" Bridge="` + obfs4Bridge + `"`, "250 OK\r\n"},
		exchange{"GETCONF " + configurationKeys, "250-DisableNetwork=1\r\n250-SocksPort=auto IsolateSOCKSAuth\r\n250-UseBridges=1\r\n250-Bridge=" + obfs4Bridge + "\r\n250 ClientTransportPlugin=obfs4 socks5 127.0.0.1:18443\r\n"},
		exchange{"SETCONF DisableNetwork=0", "250 OK\r\n"},
	)
	sequence = append(sequence, idleExchanges(inventoryReply(""))...)
	control := sessionFixture(t, sequence)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := control.Configure(ctx, plan, map[string]string{"obfs4": "127.0.0.1:18443"}); err != nil {
		t.Fatal(err)
	}
	if err := control.EnableNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	if err := control.Quiesce(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestQuiesceWaitsForOldORConnectionsToDisappear(t *testing.T) {
	sequence := idleExchanges(inventoryReply("$OLD CONNECTED"))
	sequence = append(sequence, exchange{"GETINFO " + strings.Join(idleInventories, " "), inventoryReply("")})
	control := sessionFixture(t, sequence)
	if err := control.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestQuiesceRejectsStaleCredentialsAndAmbiguousReadback(t *testing.T) {
	for _, reply := range []string{
		strings.Replace(idleConfigReply, "250-Bridge\r\n", "250-Bridge="+obfs4Bridge+"\r\n", 1),
		strings.Replace(idleConfigReply, "DisableNetwork=1", "DisableNetwork=0", 1),
		strings.Replace(idleConfigReply, "250-SocksPort=0\r\n", "250-SocksPort=0\r\n250-SocksPort=9050\r\n", 1),
		strings.Replace(idleConfigReply, "250 ClientTransportPlugin\r\n", "250 OK\r\n", 1),
	} {
		sequence := idleExchanges("")[:3]
		sequence[2].reply = reply
		control := sessionFixture(t, sequence)
		if err := control.Quiesce(context.Background()); err == nil {
			t.Fatal("unverified old session released")
		}
		if err := control.EnableNetwork(context.Background()); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("failed resident control was not retired: %v", err)
		}
	}
}

func TestBusyResidentCannotReturnToIdleAfterCancellation(t *testing.T) {
	sequence := idleExchanges(inventoryReply("$OLD CONNECTED"))
	control := sessionFixture(t, sequence)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := control.Quiesce(ctx); err == nil {
		t.Fatal("live OR connection released")
	}
	if err := control.EnableNetwork(context.Background()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("busy canceled resident reused: %v", err)
	}
}

func TestResidentConfigurationRejectsMutatedPlanBeforeChangingCore(t *testing.T) {
	plan, err := NewPlan(common.ExternalTorBridgeConfig{Bridges: []string{obfs4Bridge}})
	if err != nil {
		t.Fatal(err)
	}
	plan.Bridges[0].Line += "\r\nSETCONF DisableNetwork=0"
	control := sessionFixture(t, nil)
	if err := control.Configure(context.Background(), plan, map[string]string{"obfs4": "127.0.0.1:18443"}); err == nil {
		t.Fatal("mutated bridge reached resident controller")
	}
}

func TestBoundedControlDataBlocksAndDotEscaping(t *testing.T) {
	control := controlFixture(t, "250+orconn-status=\r\n..one\r\ntwo\r\n.\r\n250 OK\r\n")
	values, err := control.command(context.Background(), "GETINFO orconn-status")
	if err != nil || len(values) != 1 || values[0] != "orconn-status=.one\ntwo" {
		t.Fatal(values, err)
	}
	for _, reply := range []string{
		"250+orconn-status=\r\n.bad\r\n.\r\n250 OK\r\n",
		"250+orconn-status\r\n.\r\n250 OK\r\n",
		"250+orconn-status=\r\n" + strings.Repeat(strings.Repeat("x", 1024)+"\r\n", 65) + ".\r\n250 OK\r\n",
	} {
		control := controlFixture(t, reply)
		if _, err := control.command(context.Background(), "GETINFO orconn-status"); err == nil {
			t.Fatal("malformed or oversized inventory accepted")
		}
	}
}

func TestResidentArgumentsDoNotRetainSessionSecretsOrListeners(t *testing.T) {
	arguments, err := ResidentArguments("/private/tor")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(arguments, "\x00")
	for _, required := range []string{"--DisableNetwork\x001", "--SocksPort\x000", "--UseBridges\x000", "--ControlPort\x000"} {
		if !strings.Contains(joined, required) {
			t.Fatal("resident core starts with live networking or listeners")
		}
	}
	for _, argument := range arguments {
		if argument == "--Bridge" || argument == "--ClientTransportPlugin" {
			t.Fatal("resident argv retained session transport credentials")
		}
	}
}
