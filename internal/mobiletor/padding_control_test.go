package mobiletor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var paddingTestIdentity = PaddingIdentity{SessionSHA256: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64), Generation: 7}

const paddingTestCapability = "version=1 direction=outgoing min_rate_kbps=32 max_rate_kbps=192 default_rate_kbps=192 max_ttl_ms=10000 max_pending_cells=1 accounting=tor-link-cell username_hex_lengths=32,64 password_hex_length=64 generation_highwater=6"

func paddingTestStatus(state string) string {
	expires, reason, queued, channel, pending := 4999, "active", 2, 2, 0
	if state != "running" {
		expires, reason = 0, "controller"
		if state == "stopping" {
			channel, pending = 1, 1
		}
	}
	return fmt.Sprintf("version=1 state=%s reason=%s session=%s source=%s generation=7 rate_kbps=192 expires_ms=%d queued_cells=%d queued_cell_bytes=%d channel_cells=%d channel_cell_bytes=%d dropped_cells=0 dropped_cell_bytes=0 pending_cells=%d last_circuit=17", state, reason, paddingTestIdentity.SessionSHA256, paddingTestIdentity.SourceSHA256, expires, queued, 514*queued, channel, 514*channel, pending)
}

func paddingTestReply(value string) string { return "250 " + value + "\r\n" }

func paddingTestReplace(source, key, value string) string {
	fields := strings.Split(source, " ")
	for i, field := range fields {
		if strings.HasPrefix(field, key+"=") {
			fields[i] = key + "=" + value
			return strings.Join(fields, " ")
		}
	}
	panic("unknown fixture key")
}

func TestPaddingControlExactCapabilityAndOwnedCommands(t *testing.T) {
	for _, length := range []int{32, 64} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			client, peer := net.Pipe()
			control, _ := NewControl(client)
			t.Cleanup(func() { control.Close(); peer.Close() })
			arguments, _ := paddingTestIdentity.arguments()
			username, password := strings.Repeat("c", length), strings.Repeat("d", 64)
			expected := []string{"ROUTERVPN_PADDING INFO", "ROUTERVPN_PADDING START " + arguments + " 192 5000 " + username + " " + password,
				"ROUTERVPN_PADDING RENEW " + arguments + " 5000", "ROUTERVPN_PADDING STATUS " + arguments,
				"ROUTERVPN_PADDING STOP " + arguments, "ROUTERVPN_PADDING STATUS " + arguments}
			responses := []string{paddingTestCapability, paddingTestStatus("running"), paddingTestStatus("running"), paddingTestStatus("running"), paddingTestStatus("stopping"), paddingTestStatus("stopped")}
			done := make(chan error, 1)
			go func() {
				reader := bufio.NewReader(peer)
				for i, command := range expected {
					line, err := reader.ReadString('\n')
					if err != nil {
						done <- err
						return
					}
					if line != command+"\r\n" {
						done <- fmt.Errorf("operation %d used another captured command", i)
						return
					}
					if _, err := io.WriteString(peer, paddingTestReply(responses[i])); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			capability, err := control.PaddingInfo(ctx)
			if err != nil || capability.GenerationHighWater != 6 {
				t.Fatal(capability, err)
			}
			started, err := control.StartPadding(ctx, paddingTestIdentity, 192, 5*time.Second, username, password)
			if err != nil || started.State != "running" || started.ChannelBytes != 1028 {
				t.Fatal(started, err)
			}
			if _, err := control.RenewPadding(ctx, paddingTestIdentity, 192, 5*time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := control.PaddingStatus(ctx, paddingTestIdentity, 192); err != nil {
				t.Fatal(err)
			}
			stopping, err := control.StopPadding(ctx, paddingTestIdentity, 192)
			if err != nil || stopping.State != "stopping" || stopping.PendingCells != 1 || stopping.ChannelCells != 1 {
				t.Fatal("queued ciphertext was falsely reported drained", stopping, err)
			}
			stopped, err := control.PaddingStatus(ctx, paddingTestIdentity, 192)
			if err != nil || stopped.State != "stopped" || stopped.PendingCells != 0 || stopped.ChannelCells != 2 {
				t.Fatal(stopped, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPaddingControlRejectsUnownedOrMalformedReceipts(t *testing.T) {
	changes := map[string][]string{
		"version": {"2"}, "session": {strings.Repeat("c", 64)}, "source": {strings.Repeat("a", 64)}, "generation": {"6", "07", "8"},
		"state": {"idle", "stopping", "stopped"}, "reason": {"controller", "secret"}, "rate_kbps": {"32", "0192", "193"},
		"expires_ms": {"0", "10001", "-1", "5000.0", "0001"}, "pending_cells": {"1", "2"}, "last_circuit": {"0", "4294967296"},
		"queued_cells": {"0", "1", "18446744073709551615"}, "queued_cell_bytes": {"0", "1027", "1030"},
		"channel_cells": {"0", "3"}, "channel_cell_bytes": {"1029", "1026"}, "dropped_cells": {"1"}, "dropped_cell_bytes": {"514"},
	}
	replies := []string{"250 OK\r\n", paddingTestReply(paddingTestStatus("running") + " private=secret"),
		paddingTestReply(strings.Replace(paddingTestStatus("running"), "state=running", "state=running state=running", 1)),
		paddingTestReply(strings.Replace(paddingTestStatus("running"), "state=running", "state=running\t", 1)),
		"551 user-private-secret\r\n"}
	for key, values := range changes {
		for _, value := range values {
			replies = append(replies, paddingTestReply(paddingTestReplace(paddingTestStatus("running"), key, value)))
		}
	}
	for i, reply := range replies {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			control := controlFixture(t, reply)
			status, err := control.PaddingStatus(t.Context(), paddingTestIdentity, 192)
			if err == nil || strings.Contains(err.Error(), "secret") || status != (PaddingStatus{}) {
				t.Fatal("invalid reply gained authority or leaked its contents", err)
			}
			if err := control.conn.SetDeadline(time.Time{}); err == nil {
				t.Fatal("malformed receipt did not retire its socket immediately")
			}
			if err := control.EnableNetwork(t.Context()); err == nil {
				t.Fatal("malformed receipt left its stream reusable")
			}
		})
	}
}

func TestPaddingControlCapabilityAndLifetimeCannotExpand(t *testing.T) {
	for key, value := range map[string]string{"version": "2", "direction": "both", "min_rate_kbps": "0", "max_rate_kbps": "193", "default_rate_kbps": "193", "max_ttl_ms": "10001", "max_pending_cells": "2", "accounting": "physical", "username_hex_lengths": "64", "password_hex_length": "32", "generation_highwater": "9223372036854775808"} {
		t.Run(key, func(t *testing.T) {
			control := controlFixture(t, paddingTestReply(paddingTestReplace(paddingTestCapability, key, value)))
			if _, err := control.PaddingInfo(t.Context()); err == nil {
				t.Fatal("changed capability was accepted")
			}
			if err := control.conn.SetDeadline(time.Time{}); err == nil {
				t.Fatal("capability failure did not retire its socket immediately")
			}
			if err := control.EnableNetwork(t.Context()); err == nil {
				t.Fatal("capability failure retained control authority")
			}
		})
	}
	for _, action := range []string{"start", "renew", "stop"} {
		t.Run(action, func(t *testing.T) {
			control := controlFixture(t, paddingTestReply(paddingTestStatus("running")))
			var err error
			switch action {
			case "start":
				_, err = control.StartPadding(t.Context(), paddingTestIdentity, 192, time.Second, strings.Repeat("c", 32), strings.Repeat("d", 64))
			case "renew":
				_, err = control.RenewPadding(t.Context(), paddingTestIdentity, 192, time.Second)
			case "stop":
				_, err = control.StopPadding(t.Context(), paddingTestIdentity, 192)
			}
			if err == nil {
				t.Fatal("operation exceeded its captured lifetime or ignored stop")
			}
		})
	}
}

func TestPaddingControlAcceptsConservedMixedLinkCellsAndRetirement(t *testing.T) {
	for _, state := range []string{"running", "stopping", "stopped"} {
		for _, width := range []uint64{512, 514} {
			reply := paddingTestStatus(state)
			reply = paddingTestReplace(reply, "queued_cell_bytes", strconv.FormatUint(2*width, 10))
			channel := 2 * width
			if state == "stopping" {
				channel = width
			}
			reply = paddingTestReplace(reply, "channel_cell_bytes", strconv.FormatUint(channel, 10))
			if _, err := parsePaddingStatus([]string{reply}, paddingTestIdentity, 192); err != nil {
				t.Fatal(state, width, err)
			}
		}
	}
	for _, reason := range []string{"owner", "disabled", "expired", "configuration", "shutdown", "send-error", "controller"} {
		reply := paddingTestReplace(paddingTestStatus("stopped"), "reason", reason)
		reply = paddingTestReplace(reply, "channel_cells", "1")
		reply = paddingTestReplace(reply, "channel_cell_bytes", "512")
		reply = paddingTestReplace(reply, "dropped_cells", "1")
		reply = paddingTestReplace(reply, "dropped_cell_bytes", "514")
		reply = paddingTestReplace(reply, "queued_cell_bytes", "1026")
		if _, err := parsePaddingStatus([]string{reply}, paddingTestIdentity, 192); err != nil {
			t.Fatal(reason, err)
		}
	}
}

type paddingWriteCounter struct {
	net.Conn
	writes atomic.Int32
}

func (c *paddingWriteCounter) Write(value []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(value)
}

func TestPaddingControlBadArgumentsNeverWriteOrRetireCurrentOwner(t *testing.T) {
	for _, fault := range []string{"session", "source", "generation-zero", "generation-large", "username-short", "username-middle", "username-case", "password-short", "password-injection", "rate-low", "rate-high", "ttl-low", "ttl-high", "ttl-fraction"} {
		t.Run(fault, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			counted := &paddingWriteCounter{Conn: client}
			control, _ := NewControl(counted)
			defer control.Close()
			identity, rate, ttl := paddingTestIdentity, 192, 5*time.Second
			username, password := strings.Repeat("c", 32), strings.Repeat("d", 64)
			switch fault {
			case "session":
				identity.SessionSHA256 = strings.Repeat("a", 32)
			case "source":
				identity.SourceSHA256 = strings.Repeat("B", 64)
			case "generation-zero":
				identity.Generation = 0
			case "generation-large":
				identity.Generation = math.MaxUint64
			case "username-short":
				username = strings.Repeat("c", 31)
			case "username-middle":
				username = strings.Repeat("c", 48)
			case "username-case":
				username = strings.Repeat("C", 32)
			case "password-short":
				password = strings.Repeat("d", 32)
			case "password-injection":
				password = strings.Repeat("d", 64) + "\r\nSIGNAL HALT"
			case "rate-low":
				rate = 31
			case "rate-high":
				rate = 193
			case "ttl-low":
				ttl = 99 * time.Millisecond
			case "ttl-high":
				ttl = 10001 * time.Millisecond
			case "ttl-fraction":
				ttl += time.Microsecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			if _, err := control.StartPadding(ctx, identity, rate, ttl, username, password); err == nil || counted.writes.Load() != 0 {
				t.Fatal("invalid policy reached the native control socket", err)
			}
			if err := client.SetDeadline(time.Time{}); err != nil {
				t.Fatal("invalid request retired the existing owner", err)
			}
		})
	}
}

func TestPaddingControlCancellationRetiresOnlyItsCapturedStream(t *testing.T) {
	client, peer := net.Pipe()
	control, _ := NewControl(client)
	defer control.Close()
	defer peer.Close()
	entered := make(chan struct{})
	go func() { _, _ = bufio.NewReader(peer).ReadString('\n'); close(entered) }()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := control.PaddingStatus(ctx, paddingTestIdentity, 192); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled control read adopted a result")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled native control read did not join")
	}
	if _, err := control.PaddingStatus(t.Context(), paddingTestIdentity, 192); err == nil {
		t.Fatal("cancelled stream reused")
	}
	replacement := controlFixture(t, paddingTestReply(paddingTestCapability))
	if _, err := replacement.PaddingInfo(t.Context()); err != nil {
		t.Fatal("old cancellation retired a replacement owner", err)
	}
}
