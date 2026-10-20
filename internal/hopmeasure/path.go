package hopmeasure

import (
	"context"
	"errors"
)

// ProvePath is synchronous proof on a supplied retained path. It cannot choose
// or fall back to the default network because Engine owns every socket.
func ProvePath(ctx context.Context, engine Engine, hop Hop) (float64, error) {
	service, err := New(engine, []Hop{hop})
	if err != nil {
		return 0, err
	}
	defer service.Close()
	return service.prove(ctx, service.hops[0])
}

// MeasurePath measures actual transferred payload bytes and elapsed time.
// Kind=public-path uses the fixed Speed Lab HTTPS origin; private-node keeps
// authenticated private receipts. Mobile MTU supplies an OS-VPN-bound Engine,
// never the internal outbound adapter used by ordinary per-hop measurements.
// Successful payload delivery is not an authenticated packet-size/PMTU proof.
func MeasurePath(ctx context.Context, engine Engine, hop Hop, size int) (Result, error) {
	if size < 65536 || size > 1<<20 {
		return Result{}, errors.New("MTU transfer exceeds its byte budget")
	}
	service, err := New(engine, []Hop{hop})
	if err != nil {
		return Result{}, err
	}
	defer service.Close()
	hop = service.hops[0]
	result := Result{ID: hop.ID, Role: hop.Role, Kind: hop.Kind, Label: hop.Label}
	result.Idle, err = service.latency(ctx, hop, 3)
	if err != nil {
		return result, err
	}
	result.Download, err = service.transfer(ctx, hop, size, false, result.Idle)
	if err != nil {
		return result, err
	}
	result.Upload, err = service.transfer(ctx, hop, size, true, result.Idle)
	if err != nil {
		return result, err
	}
	if _, err = service.prove(ctx, hop); err != nil {
		return result, err
	}
	result.Ready = true
	return result, nil
}
