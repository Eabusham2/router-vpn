package snowflake_client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/transport/v4"
	"router-vpn/internal/mobiletor"
	"router-vpn/mobile/torpt/internal/pionnet"
)

// The fixture implements the actual RFC 5780 alternate-address exchange.
// It sends a wrong transaction ID first, so accepting stale STUN replies
// would incorrectly classify the strict fixture as an open mapping.
func TestCapturedSnowflakeNATMappingAndAlternateResponse(t *testing.T) {
	for _, mode := range []string{"open", "strict"} {
		t.Run(mode, func(t *testing.T) {
			primary, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
			if err != nil {
				primary.Close()
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			var mutex sync.Mutex
			transactions := make(map[[stun.TransactionIDSize]byte]bool)
			var repeated atomic.Bool
			serve := func(socket *net.UDPConn, alternate bool) {
				defer workers.Done()
				for {
					var raw [2048]byte
					n, source, err := socket.ReadFromUDP(raw[:])
					if err != nil {
						return
					}
					request := &stun.Message{Raw: append([]byte(nil), raw[:n]...)}
					if request.Decode() != nil || request.Type != stun.BindingRequest {
						continue
					}
					mutex.Lock()
					if transactions[request.TransactionID] {
						repeated.Store(true)
					}
					transactions[request.TransactionID] = true
					mutex.Unlock()
					via := socket
					if request.Contains(stun.AttrChangeRequest) {
						via = other
					}
					alternateAddress := other.LocalAddr().(*net.UDPAddr)
					// A structurally valid stale response must not be accepted.
					stale, _ := stun.Build(stun.TransactionID, stun.BindingSuccess,
						&stun.XORMappedAddress{IP: source.IP, Port: source.Port},
						&stun.OtherAddress{IP: alternateAddress.IP, Port: alternateAddress.Port})
					_, _ = via.WriteToUDP(stale.Raw, source)
					mappedPort := source.Port
					if alternate && mode == "strict" {
						mappedPort = mappedPort%65535 + 1
					}
					response, _ := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess,
						&stun.XORMappedAddress{IP: source.IP, Port: mappedPort},
						&stun.OtherAddress{IP: alternateAddress.IP, Port: alternateAddress.Port})
					_, _ = via.WriteToUDP(response.Raw, source)
				}
			}
			workers.Add(2)
			go serve(primary, false)
			go serve(other, true)
			defer func() { primary.Close(); other.Close(); workers.Wait() }()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var packets, queries atomic.Int32
			lower, err := mobiletor.NewNetwork(ctx, func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("NAT must not open TCP")
			}, func(call context.Context, kind, address string) (net.PacketConn, error) {
				conn, err := (&net.ListenConfig{}).ListenPacket(call, kind, address)
				if err != nil {
					return nil, err
				}
				packets.Add(1)
				return &countedPacket{PacketConn: conn, live: &packets}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			network, err := pionnet.New(ctx, lower, func(context.Context, string, string) ([]netip.Addr, error) {
				queries.Add(1)
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}, []*transport.Interface{})
			if err != nil {
				t.Fatal(err)
			}
			defer network.Close(context.Background())
			value, err := detectNAT(ctx, network, "stun.example:"+strconv.Itoa(primary.LocalAddr().(*net.UDPAddr).Port))
			if err != nil || value != mode {
				t.Fatalf("captured RFC 5780 classification = %s, %v", value, err)
			}
			if packets.Load() != 0 || queries.Load() == 0 || repeated.Load() {
				t.Fatal("NAT sockets were not drained, DNS was bypassed, or a transaction ID was reused")
			}
		})
	}
}
