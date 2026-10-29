package controllerbridge

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"router-vpn/internal/controllertransport"
)

const frameTimeout = 15 * time.Second

// Stream's methods must not return until their entered native I/O has joined.
// Close revokes admission, cancels and joins I/O before releasing the handle.
// The native Pipe adapter implements this with its exact OVERLAPPED ownership.
type Stream interface {
	ReadContext(context.Context, []byte) (int, error)
	WriteContext(context.Context, []byte) (int, error)
	Close() error
}

type Forwarder interface {
	Request(context.Context, string, string, []byte, int64) (controllertransport.Response, error)
}

type pending struct {
	ctx      context.Context
	cancel   context.CancelFunc
	reserved uint64
}

type server struct {
	stream   Stream
	forward  Forwarder
	ctx      context.Context
	cancel   context.CancelCauseFunc
	mu       sync.Mutex
	write    sync.Locker
	pending  map[uint64]*pending
	last     uint64
	reserved uint64
	workers  sync.WaitGroup
	stopOnce sync.Once
	closeErr error
}

// Serve is called only after both sides have verified their actual retained
// process/image/pipe peers. It owns the whole channel until all forwarding and
// entered pipe I/O has joined. Closing one GUI channel never closes a different
// GUI's channel or the shared pinned controller client.
func Serve(ctx context.Context, stream Stream, forward Forwarder) error {
	return serve(ctx, stream, forward, new(sync.Mutex))
}

// writer is always a private mutex in production. The package's lifecycle test
// uses an observing mutex to prove a response is actually queued before it
// cancels that exact request, without changing stream or forwarding behavior.
func serve(ctx context.Context, stream Stream, forward Forwarder, writer sync.Locker) error {
	if ctx == nil || stream == nil || forward == nil || writer == nil {
		return ErrProtocol
	}
	owned, cancel := context.WithCancelCause(ctx)
	s := &server{stream: stream, forward: forward, ctx: owned, cancel: cancel, pending: make(map[uint64]*pending), write: writer}
	done := context.AfterFunc(owned, func() { s.stop(context.Cause(owned)) })
	err := s.read()
	s.stop(err)
	done()
	s.workers.Wait()
	return errors.Join(err, s.closeErr)
}

func (s *server) stop(cause error) {
	s.stopOnce.Do(func() {
		s.cancel(cause)
		s.mu.Lock()
		for _, request := range s.pending {
			request.cancel()
		}
		s.mu.Unlock()
		s.closeErr = s.stream.Close()
	})
}

func readExact(ctx context.Context, stream Stream, buffer []byte) error {
	for len(buffer) != 0 {
		chunk := buffer
		if len(chunk) > 4096 {
			chunk = chunk[:4096]
		}
		n, err := stream.ReadContext(ctx, chunk)
		if n < 0 || n > len(chunk) {
			return ErrProtocol
		}
		buffer = buffer[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return ctx.Err()
}

func writeExact(ctx context.Context, stream Stream, buffer []byte) error {
	for len(buffer) != 0 {
		chunk := buffer
		if len(chunk) > 4096 {
			chunk = chunk[:4096]
		}
		n, err := stream.WriteContext(ctx, chunk)
		if n < 0 || n > len(chunk) {
			return ErrProtocol
		}
		buffer = buffer[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return ctx.Err()
}

func (s *server) read() error {
	for {
		var raw [HeaderSize]byte
		// An idle channel has no arbitrary UI timeout. Once the first byte is
		// consumed, the complete frame must finish under the channel deadline.
		if err := readExact(s.ctx, s.stream, raw[:1]); err != nil {
			return err
		}
		frame, stop := context.WithTimeout(s.ctx, frameTimeout)
		err := func() error {
			if err := readExact(frame, s.stream, raw[1:]); err != nil {
				return err
			}
			header, err := DecodeHeader(raw[:])
			if err != nil {
				return err
			}
			if header.Kind == Cancel {
				return s.cancelRequest(header.ID)
			}
			if header.Kind != Request {
				return ErrProtocol
			}
			request, err := s.reserve(header)
			if err != nil {
				return err
			}
			path := make([]byte, header.PathLength)
			if err := readExact(frame, s.stream, path); err != nil {
				return err
			}
			target, method := string(path), header.HTTPMethod()
			if ValidateTarget(target) != nil || header.BodyLength > RequestBodyLimit(method, target) {
				return ErrProtocol
			}
			body := make([]byte, header.BodyLength)
			if err := readExact(frame, s.stream, body); err != nil {
				return err
			}
			s.workers.Add(1)
			go s.execute(header, request, method, target, body)
			return nil
		}()
		stop()
		if err != nil {
			return err
		}
	}
}

func (s *server) reserve(h Header) (*pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	charge := uint64(h.BodyLength) + uint64(h.ResponseLimit) + uint64(h.PathLength)
	if s.ctx.Err() != nil || s.last == ^uint64(0) || h.ID != s.last+1 || len(s.pending) >= MaxPending || charge > MaxReserved || s.reserved > MaxReserved-charge {
		return nil, ErrProtocol
	}
	ctx, cancel := context.WithTimeout(s.ctx, time.Duration(h.TimeoutMS)*time.Millisecond)
	request := &pending{ctx: ctx, cancel: cancel, reserved: charge}
	s.pending[h.ID] = request
	s.last = h.ID
	s.reserved += charge
	return request, nil
}

func (s *server) cancelRequest(id uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == 0 || id > s.last {
		return ErrProtocol
	}
	if request := s.pending[id]; request != nil {
		request.cancel()
	}
	// A cancellation can cross the terminal response on the wire. An earlier
	// ID with no reservation is already joined; it can never name a replacement.
	return nil
}

func (s *server) execute(h Header, request *pending, method, target string, body []byte) {
	defer s.workers.Done()
	defer request.cancel()
	defer func() {
		s.mu.Lock()
		if s.pending[h.ID] == request {
			delete(s.pending, h.ID)
			s.reserved -= request.reserved
		}
		s.mu.Unlock()
	}()
	var result controllertransport.Response
	err := request.ctx.Err()
	if err == nil {
		result, err = s.forward.Request(request.ctx, method, target, body, int64(h.ResponseLimit))
	}
	body = nil
	reply := Header{Kind: Response, ID: h.ID, Status: uint16(result.Status), BodyLength: uint32(len(result.Body))}
	payload := result.Body
	switch {
	case request.ctx.Err() != nil:
		reply = Header{Kind: Cancelled, ID: h.ID}
		payload = nil
	case err != nil:
		// Native errors may contain private request context. The channel reports
		// a fixed bounded failure; real controller HTTP errors retain their body.
		payload = []byte("The captured local controller request failed.")
		reply = Header{Kind: Failure, ID: h.ID, BodyLength: uint32(len(payload))}
	case result.Status < 100 || result.Status > 599 || uint64(len(result.Body)) > uint64(h.ResponseLimit):
		s.stop(ErrProtocol)
		return
	}
	if err := s.reply(request, reply, payload); err != nil {
		s.stop(err)
	}
}

func (s *server) reply(request *pending, header Header, body []byte) error {
	s.write.Lock()
	defer s.write.Unlock()
	// The operation may have completed behind another response whose native
	// writer is still blocked. Reclassify this exact owner after acquiring the
	// publication slot; never publish an earlier snapshot of cancellation.
	if request.ctx.Err() != nil {
		header = Header{Kind: Cancelled, ID: header.ID}
		body = nil
	}
	raw, err := header.Encode()
	if err != nil || uint64(len(body)) != uint64(header.BodyLength) {
		return ErrProtocol
	}
	ctx, stop := context.WithTimeout(s.ctx, frameTimeout)
	defer stop()
	if err := writeExact(ctx, s.stream, raw[:]); err != nil {
		return err
	}
	return writeExact(ctx, s.stream, body)
}
