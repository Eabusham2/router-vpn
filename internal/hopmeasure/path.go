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
	return service.prove(ctx, hop)
}

// MeasurePath is shared by MTU tuning and measures actual private transfer bytes
// and elapsed time. Mobile MTU supplies an OS-VPN-bound Engine, not the internal
// outbound adapter used by ordinary per-hop measurements.
func MeasurePath(ctx context.Context, engine Engine, hop Hop, size int) (Result, error) {
	if size < 65536 || size > 1<<20 {
		return Result{}, errors.New("private MTU transfer exceeds its byte budget")
	}
	service, err := New(engine, []Hop{hop})
	if err != nil {
		return Result{}, err
	}
	defer service.Close()
	result := Result{ID: hop.ID, Role: hop.Role}
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
