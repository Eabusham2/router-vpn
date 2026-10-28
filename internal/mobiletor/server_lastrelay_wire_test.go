package mobiletor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type serverLastRelayFrontFixture struct {
	calls  atomic.Int32
	closed atomic.Bool
}

func (f *serverLastRelayFrontFixture) Cancel() { f.closed.Store(true) }
func (f *serverLastRelayFrontFixture) Serve(ctx context.Context, connection net.Conn) error {
	f.calls.Add(1)
	var request serverLastRelayRequest
	if err := serverLastRelayRead(connection, &request); err != nil {
		return err
	}
	if err := request.validate(); err != nil || ctx.Err() != nil {
		return errServerLastRelay
	}
	if err := serverLastRelayWrite(connection, serverLastRelayResponse{Request: request}); err != nil {
		return err
	}
	_, err := io.Copy(connection, connection)
	return err
}

func serverLastRelayRequestFixture() serverLastRelayRequest {
	return serverLastRelayRequest{Schema: 1, Action: "open", OwnerID: strings.Repeat("a", 64), SessionID: strings.Repeat("b", 32),
		SourceSHA256: strings.Repeat("c", 64), RegistrySHA256: strings.Repeat("d", 64), DNSPolicySHA256: strings.Repeat("e", 64),
		Handle: strings.Repeat("1", 64), Nonce: strings.Repeat("2", 64), Target: "https://1.1.1.1/cdn-cgi/trace"}
}

func TestServerLastRelayFrontRequiresSeparateCommandAndExactAuthentication(t *testing.T) {
	var ordinary atomic.Int32
	front := serverFrontFixture(t, func(context.Context, string, string) (net.Conn, error) {
		ordinary.Add(1)
		return nil, errors.New("ordinary path must not receive private control")
	})
	owner := new(serverLastRelayFrontFixture)
	if front.SetComparison(owner) != nil || front.SetComparison(owner) == nil {
		t.Fatal("comparison owner could be replaced")
	}
	dial := (&net.Dialer{}).DialContext
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, test := range []struct {
		label, address, password string
		command                  byte
	}{
		{"ordinary", serverLastRelayAddress, strings.Repeat("b", 48), 1},
		{"ordinary token", "1." + strings.Repeat("a", 32) + "." + strings.Repeat("b", 32) + ".lastrelay.routervpn.invalid:1", strings.Repeat("b", 48), 1},
		{"wrong credential", serverLastRelayAddress, strings.Repeat("c", 48), serverLastRelayCommand},
		{"unproved", serverLastRelayAddress, strings.Repeat("b", 48), serverLastRelayCommand},
		{"changed target", "example.com:443", strings.Repeat("b", 48), serverLastRelayCommand},
	} {
		connection, err := dialServerTorCommand(ctx, front.Address(), strings.Repeat("a", 48), test.password, test.address, test.command, dial)
		if connection != nil {
			_ = connection.Close()
		}
		if err == nil || ordinary.Load() != 0 || owner.calls.Load() != 0 {
			t.Fatal(test.label, "escaped authenticated capability admission", err)
		}
	}
	if front.Enable() != nil || front.SetComparison(new(serverLastRelayFrontFixture)) == nil {
		t.Fatal("enabled front accepted a replacement owner")
	}
	connection, err := dialServerTorCommand(ctx, front.Address(), strings.Repeat("a", 48), strings.Repeat("b", 48), serverLastRelayAddress, serverLastRelayCommand, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	request := serverLastRelayRequestFixture()
	if serverLastRelayWrite(connection, request) != nil {
		t.Fatal("private request failed")
	}
	var response serverLastRelayResponse
	if serverLastRelayRead(connection, &response) != nil || response.Request != request || response.Closed || response.Anchor != nil {
		t.Fatal("private response lost exact request identity")
	}
	if _, err := connection.Write([]byte("actual retained bytes")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("actual retained bytes"))
	if _, err := io.ReadFull(connection, data); err != nil || string(data) != "actual retained bytes" || ordinary.Load() != 0 || owner.calls.Load() != 1 {
		t.Fatal("private stream did not carry actual bytes separately from CONNECT", err)
	}
	if err := front.Close(ctx); err != nil || !owner.closed.Load() {
		t.Fatal("front shutdown did not retire captured comparison owner", err)
	}
}

func TestServerLastRelayMissingCapabilityNeverFallsBackToDNSOrOrdinaryDial(t *testing.T) {
	var calls atomic.Int32
	front := serverFrontFixture(t, func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected physical or selected-DNS fallback")
	})
	if front.Enable() != nil {
		t.Fatal("enable failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := dialServerTorCommand(ctx, front.Address(), strings.Repeat("a", 48), strings.Repeat("b", 48), serverLastRelayAddress, serverLastRelayCommand, (&net.Dialer{}).DialContext)
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil || calls.Load() != 0 {
		t.Fatal("missing capability became ordinary traffic", err)
	}
}

func TestServerLastRelayFrontIndependentlyRejectsRawReservedCONNECT(t *testing.T) {
	var ordinary atomic.Int32
	front := serverFrontFixture(t, func(context.Context, string, string) (net.Conn, error) {
		ordinary.Add(1)
		return nil, errors.New("reserved target reached ordinary DNS/dial")
	})
	owner := new(serverLastRelayFrontFixture)
	if front.SetComparison(owner) != nil || front.Enable() != nil {
		t.Fatal("private front fixture failed")
	}
	for _, host := range []string{"lastrelay.routervpn.invalid", "x.lastrelay.routervpn.invalid", "LASTRELAY.ROUTERVPN.INVALID", "x.LastRelay.RouterVPN.Invalid", "lastrelay.routervpn.invalid.", "x.lastrelay.routervpn.invalid."} {
		t.Run(host, func(t *testing.T) {
			// Bypass every client-side validator: a third-party authenticated
			// SOCKS peer can write these bytes directly to the running front.
			connection, err := net.DialTimeout("tcp4", front.Address(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			if _, err := connection.Write([]byte{5, 1, 2}); err != nil {
				t.Fatal(err)
			}
			var authReply [2]byte
			if _, err := io.ReadFull(connection, authReply[:]); err != nil || authReply != [2]byte{5, 2} {
				t.Fatal("authentication selection", err)
			}
			auth := append([]byte{1, 48}, strings.Repeat("a", 48)...)
			auth = append(auth, 48)
			auth = append(auth, strings.Repeat("b", 48)...)
			if _, err := connection.Write(auth); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(connection, authReply[:]); err != nil || authReply != [2]byte{1, 0} {
				t.Fatal("authentication", err)
			}
			request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
			request = append(request, 0, 1)
			if _, err := connection.Write(request); err != nil {
				t.Fatal(err)
			}
			var reply [10]byte
			if _, err := io.ReadFull(connection, reply[:]); err != nil || reply[0] != 5 || reply[1] == 0 {
				t.Fatal("raw reserved CONNECT was not rejected", reply, err)
			}
			if ordinary.Load() != 0 || owner.calls.Load() != 0 {
				t.Fatal("raw reserved CONNECT reached a data or comparison owner")
			}
		})
	}
}

func TestServerLastRelayFramesRejectDuplicateUnknownOversizedAndTruncatedFields(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate": `{"schema":1,"schema":1}`,
		"unknown":   `{"schema":1,"unexpected":true}`,
		"trailing":  `{"schema":1} {"schema":1}`,
		"array":     `[]`,
		"truncated": `{"schema":`,
	} {
		t.Run(name, func(t *testing.T) {
			raw := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
			raw = append(raw, body...)
			var request serverLastRelayRequest
			if serverLastRelayRead(bytes.NewReader(raw), &request) == nil {
				t.Fatal("malformed private request was accepted")
			}
		})
	}
	for _, size := range []uint32{0, serverLastRelayFrameLimit + 1, 0xffffffff, 1} {
		var request serverLastRelayRequest
		if serverLastRelayRead(bytes.NewReader(binary.BigEndian.AppendUint32(nil, size)), &request) == nil {
			t.Fatal("invalid frame length accepted", size)
		}
	}
}

func TestServerLastRelayFrameDoesNotConsumeFollowingTLSBytes(t *testing.T) {
	var wire bytes.Buffer
	request := serverLastRelayRequestFixture()
	if serverLastRelayWrite(&wire, request) != nil {
		t.Fatal("frame failed")
	}
	wire.Write([]byte{22, 3, 3, 0, 1, 99})
	var got serverLastRelayRequest
	if serverLastRelayRead(&wire, &got) != nil || got != request || !bytes.Equal(wire.Bytes(), []byte{22, 3, 3, 0, 1, 99}) {
		t.Fatal("framed metadata consumed retained TLS stream bytes")
	}
}

func TestServerLastRelayWireIdentityAndTargetCannotExpand(t *testing.T) {
	valid := serverLastRelayRequestFixture()
	if valid.validate() != nil {
		t.Fatal("valid captured frame rejected")
	}
	for name, change := range map[string]func(*serverLastRelayRequest){
		"schema":         func(r *serverLastRelayRequest) { r.Schema = 2 },
		"owner":          func(r *serverLastRelayRequest) { r.OwnerID = "selected node" },
		"session":        func(r *serverLastRelayRequest) { r.SessionID = strings.Repeat("a", 64) },
		"nonce":          func(r *serverLastRelayRequest) { r.Nonce = "" },
		"action":         func(r *serverLastRelayRequest) { r.Action = "SETCONF" },
		"target":         func(r *serverLastRelayRequest) { r.Target = "https://example.com/cdn-cgi/trace" },
		"private target": func(r *serverLastRelayRequest) { r.Target = "https://127.0.0.1/cdn-cgi/trace" },
		"address":        func(r *serverLastRelayRequest) { r.Address = "1.1.1.1:443" },
		"probe fallback": func(r *serverLastRelayRequest) { r.Action, r.Address = "probe", "example.com:443" },
	} {
		t.Run(name, func(t *testing.T) {
			r := valid
			change(&r)
			if r.validate() == nil {
				t.Fatal("uncaptured input accepted")
			}
		})
	}
}
