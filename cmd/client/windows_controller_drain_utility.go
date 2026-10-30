package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"router-vpn/internal/controllertransport"
)

const windowsControllerDrainUtilityFlag = "--windows-controller-drain"

func parseWindowsControllerDrainUtility(args []string) (pid uint32, pin string, handled bool, err error) {
	if len(args) == 0 || args[0] != windowsControllerDrainUtilityFlag {
		return 0, "", false, nil
	}
	invalid := errors.New("--windows-controller-drain requires exactly the captured decimal process ID and public TLS pin")
	if len(args) != 3 {
		return 0, "", true, invalid
	}
	value, parseErr := strconv.ParseUint(args[1], 10, 32)
	if parseErr != nil || value == 0 || strconv.FormatUint(value, 10) != args[1] || len(args[2]) != 64 {
		return 0, "", true, invalid
	}
	for _, char := range args[2] {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return 0, "", true, invalid
		}
	}
	return uint32(value), args[2], true, nil
}

// The helper receives no bearer, shutdown secret or configurable destination.
// Its only successful output is a bounded observation of the same live process
// and TLS leaf captured when that controller launched this dataplane owner.
func writeCapturedControllerDrain(ctx context.Context, owner controllertransport.Process, pin string, output io.Writer) error {
	if ctx == nil || output == nil {
		return errors.New("the controller drain utility requires a bounded owner and output")
	}
	draining, err := controllertransport.ReadDrain(ctx, owner, pin)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := owner.Alive(); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Schema   int    `json:"schema"`
		PID      uint32 `json:"process_id"`
		Draining bool   `json:"draining"`
	}{1, owner.PID(), draining})
}
