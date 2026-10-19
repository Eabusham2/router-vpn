// Package utlsclient preserves the requested pinned uTLS fingerprint while
// correcting an inconsistent randomized hybrid key-share advertisement.
package utlsclient

import (
	"errors"
	"net"
	"slices"

	utls "github.com/refraction-networking/utls"
)

func Client(raw net.Conn, configuration *utls.Config, id utls.ClientHelloID) (*utls.UConn, error) {
	if id.Client != utls.HelloRandomized.Client && id.Client != utls.HelloRandomizedALPN.Client && id.Client != utls.HelloRandomizedNoALPN.Client {
		return utls.UClient(raw, configuration, id), nil
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, err
	}
	var groups *utls.SupportedCurvesExtension
	var shares *utls.KeyShareExtension
	for _, extension := range spec.Extensions {
		switch value := extension.(type) {
		case *utls.SupportedCurvesExtension:
			groups = value
		case *utls.KeyShareExtension:
			shares = value
		case *utls.ALPNExtension:
			if configuration != nil && len(configuration.NextProtos) > 0 {
				value.AlpnProtocols = slices.Clone(configuration.NextProtos)
			}
		}
	}
	if shares != nil {
		if groups == nil {
			return nil, errors.New("native randomized TLS hello has key shares without supported groups")
		}
		advertised := slices.Contains(groups.Curves, utls.X25519MLKEM768)
		sent := slices.ContainsFunc(shares.KeyShares, func(share utls.KeyShare) bool { return share.Group == utls.X25519MLKEM768 })
		// uTLS v1.8.2 flips independent coins for these two extensions, but
		// its TLS 1.3 retry handler does not support a requested ML-KEM share.
		// Keep hybrid key exchange whenever either coin selected it. ApplyPreset
		// below generates the real fresh ML-KEM and X25519 key material.
		if advertised && !sent {
			shares.KeyShares = append([]utls.KeyShare{{Group: utls.X25519MLKEM768}}, shares.KeyShares...)
		}
		if sent && !advertised {
			groups.Curves = append([]utls.CurveID{utls.X25519MLKEM768}, groups.Curves...)
		}
	}
	if configuration == nil {
		configuration = &utls.Config{}
	} else {
		configuration = configuration.Clone()
	}
	// This is the normal policy for upstream-generated, non-custom hellos.
	configuration.PreferSkipResumptionOnNilExtension = true
	connection := utls.UClient(raw, configuration, utls.HelloCustom)
	if err := connection.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	return connection, nil
}
