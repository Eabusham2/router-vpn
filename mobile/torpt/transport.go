package torpt

import (
	"context"
	"errors"
	"net"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"

	"router-vpn/internal/mobiletor"
)

func newClientTransport(name string) (clientTransport, error) {
	var transport base.Transport
	switch name {
	case "obfs4":
		transport = &obfs4.Transport{}
	default:
		return nil, errors.New("requested native Tor transport is not integrated")
	}
	factory, err := transport.ClientFactory("")
	if err != nil {
		return nil, errors.New("native Tor transport factory failed")
	}
	return &dialedTransport{factory: factory}, nil
}

type dialedTransport struct{ factory base.ClientFactory }

func (t *dialedTransport) Dial(ctx context.Context, bridge mobiletor.Bridge, lower *mobiletor.Network) (net.Conn, error) {
	args := make(pt.Args, len(bridge.Arguments))
	for key, value := range bridge.Arguments {
		args.Add(key, value)
	}
	if bridge.Transport == "obfs4" && len(args["iat-mode"]) == 0 {
		// The shared profile schema permits the standard no-IAT default.
		args.Add("iat-mode", "0")
	}
	// obfs4 ParseArgs generates an ephemeral ntor key. It must be called for
	// each connection; caching this result would reuse a handshake identity.
	parsed, err := t.factory.ParseArgs(&args)
	if err != nil {
		return nil, errors.New("native Tor transport arguments were rejected")
	}
	connection, err := t.factory.Dial("tcp", bridge.Target, func(network, address string) (net.Conn, error) {
		return lower.DialContext(ctx, network, address)
	}, parsed)
	if err != nil {
		return connection, errors.New("native Tor transport handshake failed")
	}
	return connection, nil
}
