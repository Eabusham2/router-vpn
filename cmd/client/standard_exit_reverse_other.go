//go:build !linux

package main

import (
	"context"
	"router-vpn/internal/common"
)

func captureStandardReverse(context.Context, *app, common.RouterProfile, standardExit, bool) (standardReversePreparation, error) {
	return nil, nil
}
