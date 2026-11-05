package mobiletor

import (
	"context"
	"router-vpn/internal/common"
)

func ObservationContextOnly(err error) bool { return common.ObservationContextOnly(err) }
func ObservationContextExpired(ctx context.Context, err error) bool {
	return common.ObservationContextExpired(ctx, err)
}
