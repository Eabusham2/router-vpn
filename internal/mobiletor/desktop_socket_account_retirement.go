package mobiletor

import (
	"context"
	"errors"
	"time"
)

// The independent observer must query the system namespace without reusing
// this process's previously occupied Libinfo entry. Deletion alone is not an
// absence proof. Keep every observation within the original deletion deadline;
// never flush a global cache or accept an unknown/occupied lookup as absent.
func desktopDarwinWaitForUIDAbsence(ctx context.Context, uid uint32, inspect func(uint32) (bool, error)) error {
	if ctx == nil || inspect == nil || uid < 0x40000000 || uid >= 0x80000000 {
		return errors.New("Darwin physical identity retirement has no valid captured lookup")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, errors.New("Darwin physical identity retirement has no independent absent readback"))
		}
		absent, err := inspect(uid)
		if err != nil {
			return errors.Join(err, errors.New("Darwin physical identity retirement native lookup failed"))
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(err, errors.New("Darwin physical identity retirement readback completed after its deadline"))
		}
		if absent {
			return nil
		}
		select {
		case <-ctx.Done():
		case <-tick.C:
		}
	}
}

// This read-only protocol is separate from socket creation and account
// mutation. It carries no path, credential, directory record, or rules.
type desktopDarwinUIDRequest struct {
	Operation string
	Sequence  uint64
	Capture   DesktopSocketCapture
	UID       uint32
}

type desktopDarwinUIDReply struct {
	Sequence uint64
	Capture  DesktopSocketCapture
	UID      uint32
	State    string
}

func (r desktopDarwinUIDRequest) validate() error {
	if r.Operation != "observe-uid" || r.Sequence != 1 || !r.Capture.valid() || r.UID < 0x40000000 || r.UID >= 0x80000000 {
		return errors.New("Darwin identity observer has no exact captured request")
	}
	return nil
}

func (r desktopDarwinUIDRequest) acknowledgment() desktopDarwinUIDRequest {
	r.Operation, r.Sequence = "observed-uid-ack", 2
	return r
}

func (r desktopDarwinUIDReply) absent(request desktopDarwinUIDRequest) (bool, error) {
	if request.validate() != nil || r.Sequence != request.Sequence || r.Capture != request.Capture || r.UID != request.UID {
		return false, errors.New("Darwin identity observer changed its captured lookup")
	}
	switch r.State {
	case "absent":
		return true, nil
	case "occupied":
		return false, nil
	default:
		return false, errors.New("Darwin identity observer returned an unknown lookup state")
	}
}
