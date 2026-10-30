package mobiletor

import (
	"context"
	"errors"
)

type desktopPFBaselineBackend struct {
	read    func(context.Context) (DesktopDarwinPFBaselineProof, error)
	ready   func(context.Context) error
	replace func(context.Context) error
}

// The native caller derives target and replacement from the shared baseline
// compiler. Public metadata cannot supply either a filter record or a writer.
// The caller persists the successful plan's exact previous/target pair before
// requesting apply; any apply failure keeps that transition receipt intact.
func desktopPFTransitionBaseline(ctx context.Context, request DesktopDarwinPFBaselineRequest, target DesktopDarwinPFBaselineProof, apply bool, backend desktopPFBaselineBackend) (DesktopDarwinPFBaselineResult, error) {
	var result DesktopDarwinPFBaselineResult
	raw, err := EncodeDesktopDarwinPFBaselineRequest(request)
	if err != nil || ctx == nil || !target.valid() || target.Present != (request.Action == "replace") ||
		backend.read == nil || backend.ready == nil || backend.replace == nil {
		return result, errors.Join(err, errors.New("Darwin PF transition has no exact compiled policy and native owner"))
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	previous, err := backend.read(ctx)
	if err != nil || !request.accepts(previous) {
		return result, errors.Join(err, errors.New("Darwin PF baseline changed its retained exact owner"))
	}
	result = DesktopDarwinPFBaselineResult{Schema: 1, RequestSHA256: desktopPFDigest(raw), Previous: previous, Target: target}
	if previous != target {
		if err := backend.ready(ctx); err != nil {
			return DesktopDarwinPFBaselineResult{}, err
		}
		// Child retirement/ownership inspection can take time. A replacement
		// during that inspection must not be overwritten by this older plan.
		fresh, err := backend.read(ctx)
		if err != nil || fresh != previous {
			return DesktopDarwinPFBaselineResult{}, errors.Join(err, errors.New("Darwin PF baseline changed during captured-child retirement proof"))
		}
	}
	if err := ctx.Err(); err != nil {
		return DesktopDarwinPFBaselineResult{}, err
	}
	if !apply {
		return result, nil
	}
	if previous != target {
		if err := backend.replace(ctx); err != nil {
			// The native transaction may already have committed. Never turn a
			// late failure/cancellation into authority to erase the saved plan.
			return DesktopDarwinPFBaselineResult{}, err
		}
	}
	actual, err := backend.read(ctx)
	if err != nil || actual != target || ctx.Err() != nil {
		return DesktopDarwinPFBaselineResult{}, errors.Join(err, ctx.Err(), errors.New("Darwin PF baseline did not independently prove its exact target namespace and rules"))
	}
	result.Applied = true
	return result, nil
}
