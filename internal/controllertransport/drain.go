package controllertransport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

const DrainPath = "/api/controller/drain"
const drainLimit = 1024
const drainTimeout = 400 * time.Millisecond

// ReadDrain is the bounded observation needed by an already-owned native
// wrapper while the controller is draining. It carries no bearer, shutdown
// secret, request body or caller-selected URL. The public pin and retained
// process must have come from that wrapper's authenticated controller launch.
// A transport/identity error is unknown, never an instruction to stop a newer
// owner. This function closes and joins its private transport before returning.
func ReadDrain(ctx context.Context, owner Process, pin string) (bool, error) {
	client, err := newPinnedClient(owner, pin, BaseURL)
	if err != nil {
		return false, err
	}
	defer client.Close()
	return client.readDrain(ctx)
}

func (client *Client) readDrain(parent context.Context) (bool, error) {
	if parent == nil {
		return false, errors.New("the captured native drain requires a bounded caller")
	}
	if err := parent.Err(); err != nil {
		return false, err
	}
	finish, err := client.begin()
	if err != nil {
		return false, err
	}
	defer finish()
	owned, stop := ownedContext(parent, client.ctx)
	defer stop()
	ctx, cancel := context.WithTimeout(owned, drainTimeout)
	defer cancel()
	target := *client.base
	target.Path = DrainPath
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return false, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > drainLimit {
		return false, errors.New("the captured native drain returned no bounded status")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, drainLimit+1))
	if err != nil || len(raw) > drainLimit {
		return false, errors.Join(err, errors.New("the captured native drain status is incomplete or oversized"))
	}
	var receipt struct {
		Schema   int    `json:"schema"`
		PID      uint32 `json:"process_id"`
		Draining *bool  `json:"draining"`
	}
	if err := exactObject(raw, &receipt, "schema", "process_id", "draining"); err != nil ||
		receipt.Schema != 1 || receipt.PID != client.owner.PID() || receipt.Draining == nil {
		return false, errors.New("the captured native drain status has a different or ambiguous owner")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := client.owner.Alive(); err != nil {
		return false, err
	}
	return *receipt.Draining, nil
}
