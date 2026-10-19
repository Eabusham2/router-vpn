package torpt

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/pion/transport/v4"
	"router-vpn/internal/mobiletor"
	"router-vpn/mobile/torpt/internal/pionnet"
	snowflake "router-vpn/mobile/torpt/internal/snowflake"
)

type NetworkOptions struct {
	Resolve    pionnet.Resolve
	Interfaces []*transport.Interface
}

type snowflakeTransport struct{ network NetworkOptions }

func newSnowflakeTransport(options NetworkOptions) (clientTransport, error) {
	if options.Resolve == nil {
		return nil, errors.New("Snowflake requires its captured VPN DNS resolver")
	}
	interfaces, err := pionnet.CaptureInterfaces(options.Interfaces)
	if err != nil {
		return nil, err
	}
	options.Interfaces = interfaces
	return &snowflakeTransport{network: options}, nil
}

func (t *snowflakeTransport) Dial(ctx context.Context, bridge mobiletor.Bridge, lower *mobiletor.Network) (net.Conn, error) {
	owned, err := pionnet.New(ctx, lower, t.network.Resolve, t.network.Interfaces)
	if err != nil {
		return nil, err
	}
	client, err := snowflake.NewSnowflakeClient(ctx, snowflake.ClientConfig{
		BrokerURL: bridge.Arguments["url"], FrontDomains: strings.Split(bridge.Arguments["front"], ","),
		ICEAddresses: strings.Split(bridge.Arguments["ice"], ","), UTLSClientID: bridge.Arguments["utls-imitate"],
		BridgeFingerprint: bridge.Arguments["fingerprint"],
	}, owned, owned.DialContext)
	if err != nil {
		owned.Close(context.Background())
		return nil, err
	}
	connection, err := client.Dial()
	if err != nil {
		owned.Close(context.Background())
		return nil, err
	}
	return connection, nil
}
